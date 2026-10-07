//! Format-2 chunked load / commit / migrate. Called from [`super::RedbHistoryStore`].

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata};
use tracing::debug;
use uuid::Uuid;

use super::keys::{chunk_key, chunk_prefix_end, set_chunk_prefix, set_id_key, user_set_key};
use super::shared::{self, Kind, SharedRef};
use super::tables::{
    IMAGE_BLOBS, PAIR_BLOBS, PRESERVED_BLOBS, SETS_BLOB, SETS_HEADER, SETS_MANIFEST, SETS_META,
    SETS_NAME, SETS_POLICY, SetMetaValue, THUMB_BLOBS, USER_SETS,
};
use super::{FORK_RECEIPTS, FORK_RECEIPT_TIMES, RedbHistoryStore, StoreError};
use crate::chat_images::{
    ExtractedImage, defer_image_payloads, extract_images_from_user_message, materialize_full,
    normalize_pair_for_commit, ui_thumb_jpeg,
};
use crate::config::PrivacyLevel;
use crate::enc_key::EncryptionKey;
use crate::history::crypto;
use crate::history::ops::page_history;
use crate::history::types::{
    BlobFormat, HeaderV1, ImageId, ImagePayloadV1, LogicalSnapshot, ManifestPair, ManifestV1,
    PairId, PairPayloadV1, SetId, SetPage, SetSnapshot, SetSummary, SetVersion, ThumbPayloadV1,
};
use crate::operation_receipt::Receipt;

/// The new set a fork creates; its history is a prefix of the source.
pub struct ForkSpec<'a> {
    pub set_id: SetId,
    pub version: SetVersion,
    pub display_name: &'a str,
    pub privacy_level: PrivacyLevel,
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(super) fn collect_prefix_keys<T>(table: &T, set_id: SetId) -> Result<Vec<Vec<u8>>, StoreError>
where
    T: ReadableTableMetadata + ReadableTable<&'static [u8], &'static [u8]>,
{
    let prefix = set_chunk_prefix(set_id);
    let mut keys = Vec::new();
    if let Some(end) = chunk_prefix_end(set_id) {
        let iter = table.range(prefix.as_slice()..end.as_slice())?;
        for entry in iter {
            let (k, _) = entry?;
            keys.push(k.value().to_vec());
        }
    }
    Ok(keys)
}

impl RedbHistoryStore {
    pub fn load_logical(
        &self,
        user_id: &str,
        set_id: SetId,
        key: &EncryptionKey,
    ) -> Result<LogicalSnapshot, StoreError> {
        let meta = self.load_meta(user_id, set_id)?;
        if !meta.blob_format.is_chunked() {
            let snap = self.load_snapshot(user_id, set_id, key)?;
            return Ok(LogicalSnapshot::from_normalized(snap));
        }
        Ok(LogicalSnapshot::from_normalized(
            self.load_logical_chunked(user_id, set_id, &meta, key)?,
        ))
    }

    fn load_logical_chunked(
        &self,
        user_id: &str,
        set_id: SetId,
        meta: &SetMetaValue,
        key: &EncryptionKey,
    ) -> Result<SetSnapshot, StoreError> {
        Ok(self.load_chunked_window(user_id, set_id, meta, key, |total| 0..total)?.0)
    }

    /// Header, name, policy and manifest plus only the pairs in the range
    /// `window` picks from the pair count. The snapshot's `history` and
    /// `pair_ids` hold just that range.
    fn load_chunked_window(
        &self,
        user_id: &str,
        set_id: SetId,
        meta: &SetMetaValue,
        key: &EncryptionKey,
        window: impl FnOnce(usize) -> std::ops::Range<usize>,
    ) -> Result<(SetSnapshot, ManifestV1, std::ops::Range<usize>), StoreError> {
        let txn = self.db.begin_read()?;
        let id_key = set_id_key(set_id);
        let header_table = txn.open_table(SETS_HEADER)?;
        let manifest_table = txn.open_table(SETS_MANIFEST)?;
        let pair_table = txn.open_table(PAIR_BLOBS)?;
        let preserved = txn.open_table(PRESERVED_BLOBS)?;
        let name_table = txn.open_table(SETS_NAME)?;

        let manifest_blob = manifest_table
            .get(id_key.as_slice())?
            .ok_or(StoreError::NotFound)?;
        let manifest =
            crypto::open_manifest_v1(user_id, set_id, meta.version, manifest_blob.value(), key)?;
        let header_blob = header_table
            .get(id_key.as_slice())?
            .ok_or(StoreError::NotFound)?;
        let header = crypto::open_header_v1(
            user_id,
            manifest.header_sealed_in.unwrap_or(set_id),
            meta.header_generation,
            header_blob.value(),
            key,
        )?;
        let display_name = match name_table.get(id_key.as_slice())? {
            Some(blob) => crypto::open_name_v1(user_id, set_id, blob.value(), key)?,
            None => String::new(),
        };

        let total = manifest.pairs.len();
        let wanted = window(total);
        let start = wanted.start.min(total);
        let range = start..wanted.end.clamp(start, total);
        let mut history = Vec::with_capacity(range.len());
        let mut pair_ids = Vec::with_capacity(range.len());
        for entry in &manifest.pairs[range.clone()] {
            let origin = manifest.sealed_in(set_id, entry.pair_id.as_uuid());
            let pair_blob = shared::read_blob(
                &pair_table,
                &preserved,
                Kind::Pair,
                set_id,
                origin,
                entry.pair_id.as_uuid(),
                entry.generation,
            )?
            .ok_or(StoreError::NotFound)?;
            let pair = crypto::open_pair_v1(
                user_id,
                origin,
                entry.pair_id,
                entry.generation,
                &pair_blob,
                key,
            )?;
            history.push((pair.user, pair.assistant));
            pair_ids.push(entry.pair_id);
        }

        let snapshot = SetSnapshot {
            set_id,
            version: meta.version,
            display_name,
            memory: header.memory,
            system_prompt: header.system_prompt,
            history,
            pair_ids,
            is_default: meta.is_default,
            privacy_level: self.load_policy(user_id, set_id, key)?,
        };
        Ok((snapshot, manifest, range))
    }

    /// Expand a cached logical snapshot into the public materialized DTO.
    /// The cache entry is never mutated: callers get an owned copy.
    pub fn materialize_snapshot(
        &self,
        user_id: &str,
        logical: &LogicalSnapshot,
        key: &EncryptionKey,
    ) -> Result<SetSnapshot, StoreError> {
        let inner = logical.as_snapshot();
        if inner.pair_ids.is_empty() {
            return Ok(inner.clone());
        }
        let meta = self.load_meta(user_id, inner.set_id)?;
        if !meta.blob_format.is_chunked() {
            return Ok(inner.clone());
        }
        let manifest = self.load_manifest(user_id, inner.set_id, meta.version, key)?;
        let images = self.images_for_entries(user_id, inner.set_id, &manifest, &manifest.pairs, key)?;
        let mut snap = inner.clone();
        for (user, _) in &mut snap.history {
            *user = materialize_full(user, &images);
        }
        Ok(snap)
    }

    pub fn load_manifest(
        &self,
        user_id: &str,
        set_id: SetId,
        version: SetVersion,
        key: &EncryptionKey,
    ) -> Result<ManifestV1, StoreError> {
        let _ = self.load_meta(user_id, set_id)?;
        let txn = self.db.begin_read()?;
        let table = txn.open_table(SETS_MANIFEST)?;
        let blob = table
            .get(set_id_key(set_id).as_slice())?
            .ok_or(StoreError::NotFound)?;
        Ok(crypto::open_manifest_v1(
            user_id,
            set_id,
            version,
            blob.value(),
            key,
        )?)
    }

    pub fn load_image_by_id(
        &self,
        user_id: &str,
        set_id: SetId,
        image_id: ImageId,
        key: &EncryptionKey,
    ) -> Result<Option<ImagePayloadV1>, StoreError> {
        let sealed_in = self.image_sealed_in(user_id, set_id, image_id, key)?;
        self.open_image(user_id, set_id, sealed_in, image_id, key)
    }

    /// Set holding (and bound into the AAD of) one image/thumb of a chunked set.
    fn image_sealed_in(
        &self,
        user_id: &str,
        set_id: SetId,
        image_id: ImageId,
        key: &EncryptionKey,
    ) -> Result<SetId, StoreError> {
        let meta = self.load_meta(user_id, set_id)?;
        if !meta.blob_format.is_chunked() {
            return Ok(set_id);
        }
        let manifest = self.load_manifest(user_id, set_id, meta.version, key)?;
        Ok(manifest.sealed_in(set_id, image_id.as_uuid()))
    }

    fn open_image(
        &self,
        user_id: &str,
        set_id: SetId,
        sealed_in: SetId,
        image_id: ImageId,
        key: &EncryptionKey,
    ) -> Result<Option<ImagePayloadV1>, StoreError> {
        let txn = self.db.begin_read()?;
        let blob = shared::read_blob(
            &txn.open_table(IMAGE_BLOBS)?,
            &txn.open_table(PRESERVED_BLOBS)?,
            Kind::Image,
            set_id,
            sealed_in,
            image_id.as_uuid(),
            0,
        )?;
        match blob {
            Some(blob) => Ok(Some(crypto::open_image_v1(
                user_id, sealed_in, image_id, &blob, key,
            )?)),
            None => Ok(None),
        }
    }

    fn images_for_entries(
        &self,
        user_id: &str,
        set_id: SetId,
        manifest: &ManifestV1,
        entries: &[ManifestPair],
        key: &EncryptionKey,
    ) -> Result<HashMap<ImageId, (String, Vec<u8>)>, StoreError> {
        let mut images = HashMap::new();
        for entry in entries {
            for image_id in &entry.image_ids {
                let sealed_in = manifest.sealed_in(set_id, image_id.as_uuid());
                if let Some(payload) = self.open_image(user_id, set_id, sealed_in, *image_id, key)? {
                    images.insert(*image_id, (payload.mime, payload.bytes));
                }
            }
        }
        Ok(images)
    }

    pub fn load_thumb_by_id(
        &self,
        user_id: &str,
        set_id: SetId,
        image_id: ImageId,
        key: &EncryptionKey,
    ) -> Result<Option<(String, Vec<u8>)>, StoreError> {
        let sealed_in = self.image_sealed_in(user_id, set_id, image_id, key)?;
        self.open_thumb(user_id, set_id, sealed_in, image_id, key)
    }

    fn open_thumb(
        &self,
        user_id: &str,
        set_id: SetId,
        sealed_in: SetId,
        image_id: ImageId,
        key: &EncryptionKey,
    ) -> Result<Option<(String, Vec<u8>)>, StoreError> {
        let txn = self.db.begin_read()?;
        let blob = shared::read_blob(
            &txn.open_table(THUMB_BLOBS)?,
            &txn.open_table(PRESERVED_BLOBS)?,
            Kind::Thumb,
            set_id,
            sealed_in,
            image_id.as_uuid(),
            0,
        )?;
        match blob {
            Some(blob) => {
                let payload = crypto::open_thumb_v1(user_id, sealed_in, image_id, &blob, key)?;
                Ok(Some((payload.mime, payload.bytes)))
            }
            None => Ok(None),
        }
    }

    pub fn load_page(
        &self,
        user_id: &str,
        set_id: SetId,
        key: &EncryptionKey,
        limit: Option<usize>,
        before: Option<usize>,
        thumbnails: bool,
    ) -> Result<SetPage, StoreError> {
        let meta = self.load_meta(user_id, set_id)?;
        if !meta.blob_format.is_chunked() {
            let snap = self.load_snapshot(user_id, set_id, key)?;
            let page = page_history(snap.history.len(), limit, before);
            let mut history = page.slice(&snap.history).to_vec();
            if thumbnails {
                for (user, _) in &mut history {
                    *user = defer_image_payloads(user);
                }
            }
            return Ok(SetPage {
                set_id,
                version: snap.version,
                display_name: snap.display_name,
                memory: snap.memory,
                system_prompt: snap.system_prompt,
                is_default: snap.is_default,
                privacy_level: snap.privacy_level,
                history,
                history_start: page.start,
                history_total: page.total,
                has_more: page.has_more,
            });
        }

        let (logical, manifest, range) = self.load_chunked_window(user_id, set_id, &meta, key, |total| {
            let page = page_history(total, limit, before);
            page.start..page.end
        })?;
        let page = page_history(manifest.pairs.len(), limit, before);
        let window = &manifest.pairs[range];
        let slice = &logical.history;

        let history = if thumbnails {
            // Text only — client fetches thumbs via GET /history_image?size=thumb.
            slice
                .iter()
                .map(|(u, a)| (defer_image_payloads(u), a.clone()))
                .collect()
        } else {
            let images = self.images_for_entries(user_id, set_id, &manifest, window, key)?;
            slice
                .iter()
                .map(|(u, a)| (materialize_full(u, &images), a.clone()))
                .collect()
        };

        Ok(SetPage {
            set_id,
            version: logical.version,
            display_name: logical.display_name,
            memory: logical.memory,
            system_prompt: logical.system_prompt,
            is_default: logical.is_default,
            privacy_level: logical.privacy_level,
            history,
            history_start: page.start,
            history_total: manifest.pairs.len(),
            has_more: page.has_more,
        })
    }

    pub fn load_pair(
        &self,
        user_id: &str,
        set_id: SetId,
        pair_index: usize,
        key: &EncryptionKey,
    ) -> Result<(SetVersion, (String, String)), StoreError> {
        let meta = self.load_meta(user_id, set_id)?;
        if !meta.blob_format.is_chunked() {
            let snap = self.load_snapshot(user_id, set_id, key)?;
            let pair = snap
                .history
                .get(pair_index)
                .cloned()
                .ok_or(StoreError::InvalidInput)?;
            return Ok((snap.version, pair));
        }
        let (logical, manifest, _) = self.load_chunked_window(user_id, set_id, &meta, key, |_| {
            pair_index..pair_index.saturating_add(1)
        })?;
        let (user, assistant) = logical
            .history
            .into_iter()
            .next()
            .ok_or(StoreError::InvalidInput)?;
        let entry = manifest
            .pairs
            .get(pair_index)
            .ok_or(StoreError::InvalidInput)?;
        let images =
            self.images_for_entries(user_id, set_id, &manifest, std::slice::from_ref(entry), key)?;
        Ok((
            logical.version,
            (materialize_full(&user, &images), assistant),
        ))
    }

    pub fn load_image(
        &self,
        user_id: &str,
        set_id: SetId,
        pair_index: usize,
        image_index: usize,
        key: &EncryptionKey,
    ) -> Result<(String, Vec<u8>), StoreError> {
        let meta = self.load_meta(user_id, set_id)?;
        if !meta.blob_format.is_chunked() {
            let snap = self.load_snapshot(user_id, set_id, key)?;
            let pair = snap
                .history
                .get(pair_index)
                .ok_or(StoreError::InvalidInput)?;
            let payload = crate::chat_images::nth_image_data_url(&pair.0, image_index)
                .and_then(|url| crate::chat_images::decode_image_data_url(&url))
                .ok_or(StoreError::NotFound)?;
            return Ok(payload);
        }
        let manifest = self.load_manifest(user_id, set_id, meta.version, key)?;
        let entry = manifest
            .pairs
            .get(pair_index)
            .ok_or(StoreError::InvalidInput)?;
        let image_id = entry
            .image_ids
            .get(image_index)
            .copied()
            .ok_or(StoreError::NotFound)?;
        let sealed_in = manifest.sealed_in(set_id, image_id.as_uuid());
        let payload = self
            .open_image(user_id, set_id, sealed_in, image_id, key)?
            .ok_or(StoreError::NotFound)?;
        Ok((payload.mime, payload.bytes))
    }

    /// One UI thumbnail. Decrypts `THUMB_BLOBS` only; falls back to resizing the
    /// full image if the thumb row is missing.
    pub fn load_thumb(
        &self,
        user_id: &str,
        set_id: SetId,
        pair_index: usize,
        image_index: usize,
        key: &EncryptionKey,
    ) -> Result<(String, Vec<u8>), StoreError> {
        let meta = self.load_meta(user_id, set_id)?;
        if !meta.blob_format.is_chunked() {
            let (mime, bytes) = self.load_image(user_id, set_id, pair_index, image_index, key)?;
            if let Some(jpeg) = ui_thumb_jpeg(&bytes) {
                return Ok(("image/jpeg".into(), jpeg));
            }
            return Ok((mime, bytes));
        }
        let manifest = self.load_manifest(user_id, set_id, meta.version, key)?;
        let entry = manifest
            .pairs
            .get(pair_index)
            .ok_or(StoreError::InvalidInput)?;
        let image_id = entry
            .image_ids
            .get(image_index)
            .copied()
            .ok_or(StoreError::NotFound)?;
        let sealed_in = manifest.sealed_in(set_id, image_id.as_uuid());
        if let Some(thumb) = self.open_thumb(user_id, set_id, sealed_in, image_id, key)? {
            return Ok(thumb);
        }
        if let Some(img) = self.open_image(user_id, set_id, sealed_in, image_id, key)? {
            if let Some(jpeg) = ui_thumb_jpeg(&img.bytes) {
                return Ok(("image/jpeg".into(), jpeg));
            }
            return Ok((img.mime, img.bytes));
        }
        Err(StoreError::NotFound)
    }

    /// Split a v0/v1 whole-set blob into chunks in one write transaction.
    pub fn migrate_set_to_chunks(
        &self,
        user_id: &str,
        set_id: SetId,
        key: &EncryptionKey,
    ) -> Result<bool, StoreError> {
        let meta = self.load_meta(user_id, set_id)?;
        if meta.blob_format.is_chunked() {
            return Ok(false);
        }
        let started = std::time::Instant::now();
        let snap = self.load_snapshot(user_id, set_id, key)?;
        let src_bytes: usize = snap.history.iter().map(|(u, a)| u.len() + a.len()).sum();

        let header = HeaderV1 {
            memory: snap.memory.clone(),
            system_prompt: snap.system_prompt.clone(),
        };
        let header_blob = crypto::seal_header_v1(user_id, set_id, 0, &header, key)?;
        let name_blob = crypto::seal_name_v1(user_id, set_id, &snap.display_name, key)?;

        let mut sealed_pairs = Vec::new();
        let mut sealed_images = Vec::new();
        let mut sealed_thumbs = Vec::new();
        let mut manifest_pairs = Vec::new();

        for (user, assistant) in &snap.history {
            let pair_id = PairId::new();
            let (ref_user, imgs) = extract_images_from_user_message(user);
            let image_ids: Vec<ImageId> = imgs.iter().map(|i| i.image_id).collect();
            for img in imgs {
                seal_extracted(
                    user_id,
                    set_id,
                    &img,
                    key,
                    &mut sealed_images,
                    &mut sealed_thumbs,
                )?;
            }
            let payload = PairPayloadV1 {
                user: ref_user,
                assistant: assistant.clone(),
            };
            let blob = crypto::seal_pair_v1(user_id, set_id, pair_id, 0, &payload, key)?;
            sealed_pairs.push((pair_id, blob));
            manifest_pairs.push(ManifestPair {
                pair_id,
                generation: 0,
                image_ids,
            });
        }

        let image_count = sealed_images.len();
        let manifest = ManifestV1 {
            pairs: manifest_pairs,
            ..ManifestV1::default()
        };
        let manifest_blob =
            crypto::seal_manifest_v1(user_id, set_id, meta.version, &manifest, key)?;

        let mut new_meta = meta.clone();
        new_meta.blob_format = BlobFormat::AeadChunkedV2;
        new_meta.header_generation = 0;
        new_meta.pair_count = Some(manifest.pairs.len() as u32);
        let meta_bytes = new_meta.encode();
        let id_key = set_id_key(set_id);

        let txn = self.db.begin_write()?;
        {
            let mut meta_table = txn.open_table(SETS_META)?;
            let current = {
                let existing = meta_table
                    .get(id_key.as_slice())?
                    .ok_or(StoreError::NotFound)?;
                SetMetaValue::decode(existing.value())
                    .ok_or(StoreError::Database("corrupt set meta".into()))?
            };
            if current.blob_format.is_chunked() {
                return Ok(false);
            }
            if current.version != meta.version {
                return Err(StoreError::Conflict {
                    current: current.version,
                });
            }
            meta_table.insert(id_key.as_slice(), meta_bytes.as_slice())?;

            let mut header_table = txn.open_table(SETS_HEADER)?;
            header_table.insert(id_key.as_slice(), header_blob.as_slice())?;
            let mut manifest_table = txn.open_table(SETS_MANIFEST)?;
            manifest_table.insert(id_key.as_slice(), manifest_blob.as_slice())?;
            let mut name_table = txn.open_table(SETS_NAME)?;
            name_table.insert(id_key.as_slice(), name_blob.as_slice())?;

            let mut pair_table = txn.open_table(PAIR_BLOBS)?;
            for (pair_id, blob) in &sealed_pairs {
                let ck = chunk_key(set_id, pair_id.as_uuid());
                pair_table.insert(ck.as_slice(), blob.as_slice())?;
            }
            let mut image_table = txn.open_table(IMAGE_BLOBS)?;
            for (image_id, blob) in &sealed_images {
                let ck = chunk_key(set_id, image_id.as_uuid());
                image_table.insert(ck.as_slice(), blob.as_slice())?;
            }
            let mut thumb_table = txn.open_table(THUMB_BLOBS)?;
            for (image_id, blob) in &sealed_thumbs {
                let ck = chunk_key(set_id, image_id.as_uuid());
                thumb_table.insert(ck.as_slice(), blob.as_slice())?;
            }
            let mut blob_table = txn.open_table(SETS_BLOB)?;
            blob_table.remove(id_key.as_slice())?;
        }
        txn.commit()?;

        tracing::info!(
            %set_id,
            pair_count = manifest.pairs.len(),
            image_count,
            src_bytes,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "history_chunk_migrate"
        );
        Ok(true)
    }

    /// Create `fork` as a new chunked set holding the first `pair_count` pairs
    /// of `source_id` at `source_version`.
    ///
    /// Copy-on-write: the fork's manifest points at the source's sealed
    /// pair/image/thumb blobs and the header ciphertext is copied verbatim, so
    /// no history payload is opened, copied or sealed. Only the fork's own
    /// manifest, name and policy are sealed. A `receipt` commits in the same
    /// transaction.
    pub fn create_chunked_fork(
        &self,
        user_id: &str,
        source_id: SetId,
        source_version: SetVersion,
        pair_count: usize,
        fork: &ForkSpec<'_>,
        key: &EncryptionKey,
        receipt: Option<&Receipt>,
    ) -> Result<SetSummary, StoreError> {
        let set_id = fork.set_id;
        let name_blob = crypto::seal_name_v1(user_id, set_id, fork.display_name, key)?;
        let policy_blob = crypto::seal_policy_v1(user_id, set_id, fork.privacy_level, key)?;
        let sealed_receipt = receipt
            .map(|receipt| receipt.seal(user_id, key).map_err(|_| StoreError::Crypto))
            .transpose()?;
        let now = now_millis();
        let id_key = set_id_key(set_id);
        let source_key = set_id_key(source_id);

        // Read the source inside the write transaction: the references below
        // must be in place before the source can next overwrite a blob.
        let txn = self.db.begin_write()?;
        {
            let mut meta_table = txn.open_table(SETS_META)?;
            let source_meta = meta_table
                .get(source_key.as_slice())?
                .and_then(|value| SetMetaValue::decode(value.value()))
                .ok_or(StoreError::NotFound)?;
            if source_meta.user_id != user_id {
                return Err(StoreError::Forbidden);
            }
            if source_meta.version != source_version || !source_meta.blob_format.is_chunked() {
                return Err(StoreError::Conflict {
                    current: source_meta.version,
                });
            }
            if meta_table.get(id_key.as_slice())?.is_some() {
                return Err(StoreError::InvalidInput);
            }
            let source_manifest = {
                let table = txn.open_table(SETS_MANIFEST)?;
                let blob = table
                    .get(source_key.as_slice())?
                    .ok_or(StoreError::NotFound)?;
                crypto::open_manifest_v1(
                    user_id,
                    source_id,
                    source_meta.version,
                    blob.value(),
                    key,
                )?
            };
            if pair_count == 0 || pair_count > source_manifest.pairs.len() {
                return Err(StoreError::InvalidInput);
            }
            let header_blob = txn
                .open_table(SETS_HEADER)?
                .get(source_key.as_slice())?
                .ok_or(StoreError::NotFound)?
                .value()
                .to_vec();

            let mut manifest = ManifestV1 {
                pairs: source_manifest.pairs[..pair_count].to_vec(),
                sealed_in: Default::default(),
                header_sealed_in: Some(source_manifest.header_sealed_in.unwrap_or(source_id)),
            };
            for entry in &manifest.pairs {
                let pair_origin = source_manifest.sealed_in(source_id, entry.pair_id.as_uuid());
                manifest.sealed_in.insert(entry.pair_id.as_uuid(), pair_origin);
                shared::add_ref(
                    &txn,
                    set_id,
                    &SharedRef {
                        kind: Kind::Pair,
                        origin: pair_origin,
                        id: entry.pair_id.as_uuid(),
                        generation: entry.generation,
                    },
                )?;
                for image_id in &entry.image_ids {
                    let image_origin = source_manifest.sealed_in(source_id, image_id.as_uuid());
                    manifest.sealed_in.insert(image_id.as_uuid(), image_origin);
                    shared::add_ref(
                        &txn,
                        set_id,
                        &SharedRef {
                            kind: Kind::Image,
                            origin: image_origin,
                            id: image_id.as_uuid(),
                            generation: 0,
                        },
                    )?;
                }
            }
            let manifest_blob =
                crypto::seal_manifest_v1(user_id, set_id, fork.version, &manifest, key)?;
            let meta = SetMetaValue {
                user_id: user_id.to_owned(),
                version: fork.version,
                created_at: now,
                updated_at: now,
                is_default: false,
                blob_format: BlobFormat::AeadChunkedV2,
                header_generation: source_meta.header_generation,
                pair_count: Some(pair_count as u32),
            };

            meta_table.insert(id_key.as_slice(), meta.encode().as_slice())?;
            txn.open_table(SETS_HEADER)?
                .insert(id_key.as_slice(), header_blob.as_slice())?;
            txn.open_table(SETS_MANIFEST)?
                .insert(id_key.as_slice(), manifest_blob.as_slice())?;
            txn.open_table(SETS_NAME)?
                .insert(id_key.as_slice(), name_blob.as_slice())?;
            txn.open_table(SETS_POLICY)?
                .insert(id_key.as_slice(), policy_blob.as_slice())?;
            txn.open_table(USER_SETS)?
                .insert(user_set_key(user_id, set_id).as_slice(), now)?;
        }
        if let (Some(receipt), Some(sealed)) = (receipt, sealed_receipt) {
            Self::purge_fork_receipts(&txn, receipt.created_at)?;
            let receipt_id = format!("{user_id}:{}", receipt.operation_id.as_str());
            txn.open_table(FORK_RECEIPT_TIMES)?
                .insert(receipt_id.as_str(), receipt.created_at)?;
            txn.open_table(FORK_RECEIPTS)?
                .insert(receipt_id.as_str(), sealed.as_slice())?;
        }
        txn.commit()?;
        Ok(SetSummary {
            set_id,
            version: fork.version,
            display_name: fork.display_name.to_owned(),
            updated_at: now,
            is_default: false,
            privacy_level: fork.privacy_level,
        })
    }

    /// CAS commit of a chunked snapshot. Normalizes pair texts to
    /// `[IMAGE:img:…]` refs **in place** (single `normalize_pair_for_commit`
    /// pass, no re-decode) and returns the sealed logical shape for the cache
    /// together with the new version.
    pub fn commit_chunked(
        &self,
        user_id: &str,
        expected: SetVersion,
        mut snapshot: SetSnapshot,
        key: &EncryptionKey,
        known: Option<&SetSnapshot>,
    ) -> Result<(SetVersion, LogicalSnapshot), StoreError> {
        let set_id = snapshot.set_id;
        if snapshot.pair_ids.len() != snapshot.history.len() {
            return Err(StoreError::InvalidInput);
        }
        let new_version = expected.next();
        if new_version.get() == expected.get() {
            return Err(StoreError::InvalidInput);
        }

        let current_meta = self.load_meta(user_id, set_id)?;
        let durable_policy = self.load_policy(user_id, set_id, key)?;
        if current_meta.user_id != user_id {
            return Err(StoreError::Forbidden);
        }
        if current_meta.version != expected {
            return Err(StoreError::Conflict {
                current: current_meta.version,
            });
        }

        let old_manifest = if current_meta.blob_format.is_chunked() {
            self.load_manifest(user_id, set_id, current_meta.version, key)?
        } else {
            ManifestV1::default()
        };
        let old_by_id: HashMap<PairId, &ManifestPair> =
            old_manifest.pairs.iter().map(|p| (p.pair_id, p)).collect();
        // Plaintext already known at `expected` (CAS-checked above) stands in
        // for decrypting each stored pair.
        let known_by_id: HashMap<PairId, &(String, String)> = known
            .filter(|k| k.set_id == set_id && k.version == expected && k.pair_ids.len() == k.history.len())
            .map(|k| k.pair_ids.iter().copied().zip(k.history.iter()).collect())
            .unwrap_or_default();

        let old_header = if current_meta.blob_format.is_chunked() {
            let txn = self.db.begin_read()?;
            let table = txn.open_table(SETS_HEADER)?;
            let blob = table
                .get(set_id_key(set_id).as_slice())?
                .ok_or(StoreError::NotFound)?;
            crypto::open_header_v1(
                user_id,
                old_manifest.header_sealed_in.unwrap_or(set_id),
                current_meta.header_generation,
                blob.value(),
                key,
            )?
        } else {
            HeaderV1 {
                memory: snapshot.memory.clone(),
                system_prompt: snapshot.system_prompt.clone(),
            }
        };

        let header_changed = old_header.memory != snapshot.memory
            || old_header.system_prompt != snapshot.system_prompt;
        let header_generation = if header_changed {
            current_meta.header_generation.saturating_add(1)
        } else {
            current_meta.header_generation
        };
        let new_header = HeaderV1 {
            memory: snapshot.memory.clone(),
            system_prompt: snapshot.system_prompt.clone(),
        };

        let mut new_manifest_pairs = Vec::with_capacity(snapshot.history.len());
        let mut pair_writes: Vec<(PairId, Vec<u8>)> = Vec::new();
        let mut image_writes: Vec<(ImageId, Vec<u8>)> = Vec::new();
        let mut thumb_writes: Vec<(ImageId, Vec<u8>)> = Vec::new();
        let mut delete_pair_ids: HashSet<PairId> = old_by_id.keys().copied().collect();
        let mut delete_image_ids: HashSet<ImageId> = HashSet::new();

        for idx in 0..snapshot.history.len() {
            let pair_id = snapshot.pair_ids[idx];
            delete_pair_ids.remove(&pair_id);
            let norm = {
                let stored_ids = old_by_id
                    .get(&pair_id)
                    .map(|p| p.image_ids.as_slice())
                    .unwrap_or(&[]);
                normalize_pair_for_commit(&snapshot.history[idx].0, stored_ids)
            };
            for dropped in &norm.dropped_image_ids {
                delete_image_ids.insert(*dropped);
            }
            for img in &norm.new_images {
                seal_extracted(
                    user_id,
                    set_id,
                    img,
                    key,
                    &mut image_writes,
                    &mut thumb_writes,
                )?;
            }
            let generation = match old_by_id.get(&pair_id) {
                Some(old) => {
                    let unchanged = match known_by_id.get(&pair_id) {
                        Some((user, assistant)) => {
                            *user == norm.user && *assistant == snapshot.history[idx].1
                        }
                        None => {
                            let txn = self.db.begin_read()?;
                            let origin = old_manifest.sealed_in(set_id, pair_id.as_uuid());
                            let blob = shared::read_blob(
                                &txn.open_table(PAIR_BLOBS)?,
                                &txn.open_table(PRESERVED_BLOBS)?,
                                Kind::Pair,
                                set_id,
                                origin,
                                pair_id.as_uuid(),
                                old.generation,
                            )?
                            .ok_or(StoreError::NotFound)?;
                            let stored = crypto::open_pair_v1(
                                user_id,
                                origin,
                                pair_id,
                                old.generation,
                                &blob,
                                key,
                            )?;
                            stored.user == norm.user && stored.assistant == snapshot.history[idx].1
                        }
                    };
                    if unchanged {
                        // Already durable: keep ciphertext, record the ref shape.
                        snapshot.history[idx].0 = norm.user;
                        new_manifest_pairs.push(ManifestPair {
                            pair_id,
                            generation: old.generation,
                            image_ids: norm.image_ids,
                        });
                        continue;
                    }
                    old.generation.saturating_add(1)
                }
                None => 0,
            };
            let payload = PairPayloadV1 {
                user: norm.user,
                assistant: snapshot.history[idx].1.clone(),
            };
            let blob = crypto::seal_pair_v1(user_id, set_id, pair_id, generation, &payload, key)?;
            pair_writes.push((pair_id, blob));
            // Move the sealed ref text back: no second copy of the user string.
            snapshot.history[idx].0 = payload.user;
            new_manifest_pairs.push(ManifestPair {
                pair_id,
                generation,
                image_ids: norm.image_ids,
            });
        }

        for removed in &delete_pair_ids {
            if let Some(old) = old_by_id.get(removed) {
                for id in &old.image_ids {
                    delete_image_ids.insert(*id);
                }
            }
        }

        // Unchanged pairs and images keep pointing at their origin; anything
        // sealed by this commit lives in this set.
        let rewritten: HashSet<Uuid> = pair_writes
            .iter()
            .map(|(id, _)| id.as_uuid())
            .chain(image_writes.iter().map(|(id, _)| id.as_uuid()))
            .collect();
        let mut sealed_in = std::collections::BTreeMap::new();
        for entry in &new_manifest_pairs {
            let ids = std::iter::once(entry.pair_id.as_uuid())
                .chain(entry.image_ids.iter().map(|id| id.as_uuid()));
            for id in ids {
                if let Some(origin) = old_manifest.sealed_in.get(&id) {
                    if !rewritten.contains(&id) {
                        sealed_in.insert(id, *origin);
                    }
                }
            }
        }
        let manifest = ManifestV1 {
            pairs: new_manifest_pairs,
            sealed_in,
            header_sealed_in: None,
        };
        let released: Vec<SharedRef> = {
            let kept = shared_refs(&manifest);
            shared_refs(&old_manifest)
                .into_iter()
                .filter(|r| !kept.contains(r))
                .collect()
        };
        let header_blob =
            crypto::seal_header_v1(user_id, set_id, header_generation, &new_header, key)?;
        let manifest_blob = crypto::seal_manifest_v1(user_id, set_id, new_version, &manifest, key)?;
        let name_blob = crypto::seal_name_v1(user_id, set_id, &snapshot.display_name, key)?;
        let policy_blob = crypto::seal_policy_v1(
            user_id,
            set_id,
            crate::config::PrivacyLevel::default_chat(),
            key,
        )?;
        let now = now_millis();
        let id_key = set_id_key(set_id);
        let new_meta = SetMetaValue {
            user_id: user_id.to_owned(),
            version: new_version,
            created_at: current_meta.created_at,
            updated_at: now,
            is_default: current_meta.is_default,
            blob_format: BlobFormat::AeadChunkedV2,
            header_generation,
            pair_count: Some(manifest.pairs.len() as u32),
        };
        let meta_bytes = new_meta.encode();

        let txn = self.db.begin_write()?;
        {
            let mut meta_table = txn.open_table(SETS_META)?;
            let existing = {
                let row = meta_table
                    .get(id_key.as_slice())?
                    .ok_or(StoreError::NotFound)?;
                SetMetaValue::decode(row.value())
                    .ok_or(StoreError::Database("corrupt set meta".into()))?
            };
            if existing.user_id != user_id {
                return Err(StoreError::Forbidden);
            }
            if existing.version != expected {
                return Err(StoreError::Conflict {
                    current: existing.version,
                });
            }
            meta_table.insert(id_key.as_slice(), meta_bytes.as_slice())?;

            let mut header_table = txn.open_table(SETS_HEADER)?;
            header_table.insert(id_key.as_slice(), header_blob.as_slice())?;
            let mut manifest_table = txn.open_table(SETS_MANIFEST)?;
            manifest_table.insert(id_key.as_slice(), manifest_blob.as_slice())?;
            let mut name_table = txn.open_table(SETS_NAME)?;
            name_table.insert(id_key.as_slice(), name_blob.as_slice())?;
            let mut policy_table = txn.open_table(super::tables::SETS_POLICY)?;
            if policy_table.get(id_key.as_slice())?.is_none() {
                policy_table.insert(id_key.as_slice(), policy_blob.as_slice())?;
            }

            // Own blobs only: shared ones are released below, never deleted.
            let own = |id: Uuid| !old_manifest.sealed_in.contains_key(&id);
            for (pair_id, _) in &pair_writes {
                shared::preserve(&txn, Kind::Pair, set_id, pair_id.as_uuid())?;
            }
            for pair_id in delete_pair_ids.iter().filter(|id| own(id.as_uuid())) {
                shared::preserve(&txn, Kind::Pair, set_id, pair_id.as_uuid())?;
            }
            for image_id in delete_image_ids.iter().filter(|id| own(id.as_uuid())) {
                shared::preserve(&txn, Kind::Image, set_id, image_id.as_uuid())?;
            }
            let mut pair_table = txn.open_table(PAIR_BLOBS)?;
            for (pair_id, blob) in &pair_writes {
                let ck = chunk_key(set_id, pair_id.as_uuid());
                pair_table.insert(ck.as_slice(), blob.as_slice())?;
            }
            for pair_id in delete_pair_ids.iter().filter(|id| own(id.as_uuid())) {
                let ck = chunk_key(set_id, pair_id.as_uuid());
                pair_table.remove(ck.as_slice())?;
            }
            let mut image_table = txn.open_table(IMAGE_BLOBS)?;
            let mut thumb_table = txn.open_table(THUMB_BLOBS)?;
            for (image_id, blob) in &image_writes {
                let ck = chunk_key(set_id, image_id.as_uuid());
                image_table.insert(ck.as_slice(), blob.as_slice())?;
            }
            for (image_id, blob) in &thumb_writes {
                let ck = chunk_key(set_id, image_id.as_uuid());
                thumb_table.insert(ck.as_slice(), blob.as_slice())?;
            }
            for image_id in delete_image_ids.iter().filter(|id| own(id.as_uuid())) {
                let ck = chunk_key(set_id, image_id.as_uuid());
                image_table.remove(ck.as_slice())?;
                thumb_table.remove(ck.as_slice())?;
            }
            drop((pair_table, image_table, thumb_table));
            for r in &released {
                shared::release_ref(&txn, set_id, r)?;
            }

            let mut user_table = txn.open_table(USER_SETS)?;
            user_table.insert(user_set_key(user_id, set_id).as_slice(), now)?;
            let mut blob_table = txn.open_table(SETS_BLOB)?;
            blob_table.remove(id_key.as_slice())?;
        }
        txn.commit()?;
        debug!(%set_id, version = new_version.get(), "history chunked set committed");
        snapshot.version = new_version;
        // Content commits never flip lifecycle `is_default`; the cached logical
        // shape must carry the durable flag, not the caller's working copy.
        snapshot.is_default = current_meta.is_default;
        snapshot.privacy_level = durable_policy;
        Ok((new_version, LogicalSnapshot::from_normalized(snapshot)))
    }

    pub fn delete_chunks_for_set(&self, set_id: SetId) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        shared::preserve_all(&txn, set_id)?;
        shared::release_all(&txn, set_id)?;
        {
            let id_key = set_id_key(set_id);
            let mut header = txn.open_table(SETS_HEADER)?;
            header.remove(id_key.as_slice())?;
            let mut manifest = txn.open_table(SETS_MANIFEST)?;
            manifest.remove(id_key.as_slice())?;
            for table_def in [PAIR_BLOBS, IMAGE_BLOBS, THUMB_BLOBS] {
                let mut table = txn.open_table(table_def)?;
                let keys = collect_prefix_keys(&table, set_id)?;
                for k in keys {
                    table.remove(k.as_slice())?;
                }
            }
        }
        txn.commit()?;
        Ok(())
    }
}

/// Every blob `manifest` points at in another set.
fn shared_refs(manifest: &ManifestV1) -> HashSet<SharedRef> {
    let mut refs = HashSet::new();
    for entry in &manifest.pairs {
        if let Some(origin) = manifest.sealed_in.get(&entry.pair_id.as_uuid()) {
            refs.insert(SharedRef {
                kind: Kind::Pair,
                origin: *origin,
                id: entry.pair_id.as_uuid(),
                generation: entry.generation,
            });
        }
        for image_id in &entry.image_ids {
            if let Some(origin) = manifest.sealed_in.get(&image_id.as_uuid()) {
                refs.insert(SharedRef {
                    kind: Kind::Image,
                    origin: *origin,
                    id: image_id.as_uuid(),
                    generation: 0,
                });
            }
        }
    }
    refs
}

fn seal_extracted(
    user_id: &str,
    set_id: SetId,
    img: &ExtractedImage,
    key: &EncryptionKey,
    images: &mut Vec<(ImageId, Vec<u8>)>,
    thumbs: &mut Vec<(ImageId, Vec<u8>)>,
) -> Result<(), StoreError> {
    let image = ImagePayloadV1 {
        mime: img.mime.clone(),
        bytes: img.bytes.clone(),
    };
    let thumb = ThumbPayloadV1 {
        mime: img.thumb_mime.clone(),
        bytes: img.thumb_bytes.clone(),
    };
    images.push((
        img.image_id,
        crypto::seal_image_v1(user_id, set_id, img.image_id, &image, key)?,
    ));
    thumbs.push((
        img.image_id,
        crypto::seal_thumb_v1(user_id, set_id, img.image_id, &thumb, key)?,
    ));
    Ok(())
}
