//! Format-2 chunked load / commit / migrate. Called from [`super::RedbHistoryStore`].

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata};
use tracing::debug;

use super::keys::{chunk_key, chunk_prefix_end, set_chunk_prefix, set_id_key, user_set_key};
use super::tables::{
    SetMetaValue, IMAGE_BLOBS, PAIR_BLOBS, SETS_BLOB, SETS_HEADER, SETS_MANIFEST, SETS_META,
    SETS_NAME, THUMB_BLOBS, USER_SETS,
};
use super::{RedbHistoryStore, StoreError};
use crate::chat_images::{
    defer_image_payloads, extract_images_from_user_message, materialize_full,
    normalize_pair_for_commit, ui_thumb_jpeg, ExtractedImage,
};
use crate::enc_key::EncryptionKey;
use crate::history::crypto;
use crate::history::ops::page_history;
use crate::history::types::{
    BlobFormat, HeaderV1, ImageId, ImagePayloadV1, ManifestPair, ManifestV1, PairId, PairPayloadV1,
    SetId, SetPage, SetSnapshot, SetVersion, ThumbPayloadV1,
};

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(super) fn collect_prefix_keys<T>(
    table: &T,
    set_id: SetId,
) -> Result<Vec<Vec<u8>>, StoreError>
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
    ) -> Result<SetSnapshot, StoreError> {
        let meta = self.load_meta(user_id, set_id)?;
        if !meta.blob_format.is_chunked() {
            let snap = self.load_snapshot(user_id, set_id, key)?;
            return Ok(snap);
        }
        self.load_logical_chunked(user_id, set_id, &meta, key)
    }

    fn load_logical_chunked(
        &self,
        user_id: &str,
        set_id: SetId,
        meta: &SetMetaValue,
        key: &EncryptionKey,
    ) -> Result<SetSnapshot, StoreError> {
        let txn = self.db.begin_read()?;
        let id_key = set_id_key(set_id);
        let header_table = txn.open_table(SETS_HEADER)?;
        let manifest_table = txn.open_table(SETS_MANIFEST)?;
        let pair_table = txn.open_table(PAIR_BLOBS)?;
        let name_table = txn.open_table(SETS_NAME)?;

        let header_blob = header_table
            .get(id_key.as_slice())?
            .ok_or(StoreError::NotFound)?;
        let header = crypto::open_header_v1(
            user_id,
            set_id,
            meta.header_generation,
            header_blob.value(),
            key,
        )?;
        let manifest_blob = manifest_table
            .get(id_key.as_slice())?
            .ok_or(StoreError::NotFound)?;
        let manifest =
            crypto::open_manifest_v1(user_id, set_id, meta.version, manifest_blob.value(), key)?;
        let display_name = match name_table.get(id_key.as_slice())? {
            Some(blob) => crypto::open_name_v1(user_id, set_id, blob.value(), key)?,
            None => String::new(),
        };

        let mut history = Vec::with_capacity(manifest.pairs.len());
        let mut pair_ids = Vec::with_capacity(manifest.pairs.len());
        for entry in &manifest.pairs {
            let ck = chunk_key(set_id, entry.pair_id.as_uuid());
            let pair_blob = pair_table
                .get(ck.as_slice())?
                .ok_or(StoreError::NotFound)?;
            let pair = crypto::open_pair_v1(
                user_id,
                set_id,
                entry.pair_id,
                entry.generation,
                pair_blob.value(),
                key,
            )?;
            history.push((pair.user, pair.assistant));
            pair_ids.push(entry.pair_id);
        }

        Ok(SetSnapshot {
            set_id,
            version: meta.version,
            display_name,
            memory: header.memory,
            system_prompt: header.system_prompt,
            history,
            pair_ids,
            is_default: meta.is_default,
        })
    }

    pub fn materialize_snapshot(
        &self,
        user_id: &str,
        logical: &SetSnapshot,
        key: &EncryptionKey,
    ) -> Result<SetSnapshot, StoreError> {
        if logical.pair_ids.is_empty() {
            return Ok(logical.clone());
        }
        let meta = self.load_meta(user_id, logical.set_id)?;
        if !meta.blob_format.is_chunked() {
            return Ok(logical.clone());
        }
        let manifest = self.load_manifest(user_id, logical.set_id, meta.version, key)?;
        let mut images: HashMap<ImageId, (String, Vec<u8>)> = HashMap::new();
        for entry in &manifest.pairs {
            for image_id in &entry.image_ids {
                if let Some(payload) = self.load_image_by_id(user_id, logical.set_id, *image_id, key)?
                {
                    images.insert(*image_id, (payload.mime, payload.bytes));
                }
            }
        }
        let mut snap = logical.clone();
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
        let _ = self.load_meta(user_id, set_id)?;
        let txn = self.db.begin_read()?;
        let table = txn.open_table(IMAGE_BLOBS)?;
        let ck = chunk_key(set_id, image_id.as_uuid());
        match table.get(ck.as_slice())? {
            Some(blob) => Ok(Some(crypto::open_image_v1(
                user_id,
                set_id,
                image_id,
                blob.value(),
                key,
            )?)),
            None => Ok(None),
        }
    }

    pub fn load_thumb_by_id(
        &self,
        user_id: &str,
        set_id: SetId,
        image_id: ImageId,
        key: &EncryptionKey,
    ) -> Result<Option<(String, Vec<u8>)>, StoreError> {
        let _ = self.load_meta(user_id, set_id)?;
        let txn = self.db.begin_read()?;
        let table = txn.open_table(THUMB_BLOBS)?;
        let ck = chunk_key(set_id, image_id.as_uuid());
        match table.get(ck.as_slice())? {
            Some(blob) => {
                let payload = crypto::open_thumb_v1(user_id, set_id, image_id, blob.value(), key)?;
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
                history,
                history_start: page.start,
                history_total: page.total,
                has_more: page.has_more,
            });
        }

        let logical = self.load_logical_chunked(user_id, set_id, &meta, key)?;
        let manifest = self.load_manifest(user_id, set_id, meta.version, key)?;
        let page = page_history(manifest.pairs.len(), limit, before);
        let window = &manifest.pairs[page.start..page.end];
        let slice = page.slice(&logical.history);

        let history = if thumbnails {
            // Text only — client fetches thumbs via GET /history_image?size=thumb.
            slice
                .iter()
                .map(|(u, a)| (defer_image_payloads(u), a.clone()))
                .collect()
        } else {
            let mut images: HashMap<ImageId, (String, Vec<u8>)> = HashMap::new();
            for entry in window {
                for image_id in &entry.image_ids {
                    if let Some(img) = self.load_image_by_id(user_id, set_id, *image_id, key)? {
                        images.insert(*image_id, (img.mime, img.bytes));
                    }
                }
            }
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
        let logical = self.load_logical_chunked(user_id, set_id, &meta, key)?;
        let (user, assistant) = logical
            .history
            .get(pair_index)
            .cloned()
            .ok_or(StoreError::InvalidInput)?;
        let manifest = self.load_manifest(user_id, set_id, meta.version, key)?;
        let entry = manifest
            .pairs
            .get(pair_index)
            .ok_or(StoreError::InvalidInput)?;
        let mut images = HashMap::new();
        for image_id in &entry.image_ids {
            if let Some(img) = self.load_image_by_id(user_id, set_id, *image_id, key)? {
                images.insert(*image_id, (img.mime, img.bytes));
            }
        }
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
            let pair = snap.history.get(pair_index).ok_or(StoreError::InvalidInput)?;
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
        let payload = self
            .load_image_by_id(user_id, set_id, image_id, key)?
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
        if let Some(thumb) = self.load_thumb_by_id(user_id, set_id, image_id, key)? {
            return Ok(thumb);
        }
        if let Some(img) = self.load_image_by_id(user_id, set_id, image_id, key)? {
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
                seal_extracted(user_id, set_id, &img, key, &mut sealed_images, &mut sealed_thumbs)?;
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
                SetMetaValue::decode(existing.value()).ok_or(StoreError::Database(
                    "corrupt set meta".into(),
                ))?
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

    pub fn commit_chunked(
        &self,
        user_id: &str,
        expected: SetVersion,
        snapshot: &SetSnapshot,
        key: &EncryptionKey,
    ) -> Result<SetVersion, StoreError> {
        let set_id = snapshot.set_id;
        if snapshot.pair_ids.len() != snapshot.history.len() {
            return Err(StoreError::InvalidInput);
        }
        let new_version = expected.next();
        if new_version.get() == expected.get() {
            return Err(StoreError::InvalidInput);
        }

        let current_meta = self.load_meta(user_id, set_id)?;
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
            ManifestV1 { pairs: Vec::new() }
        };
        let old_by_id: HashMap<PairId, &ManifestPair> = old_manifest
            .pairs
            .iter()
            .map(|p| (p.pair_id, p))
            .collect();

        let old_header = if current_meta.blob_format.is_chunked() {
            let txn = self.db.begin_read()?;
            let table = txn.open_table(SETS_HEADER)?;
            let blob = table
                .get(set_id_key(set_id).as_slice())?
                .ok_or(StoreError::NotFound)?;
            crypto::open_header_v1(
                user_id,
                set_id,
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

        let header_changed =
            old_header.memory != snapshot.memory || old_header.system_prompt != snapshot.system_prompt;
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

        for (pair_id, (user, assistant)) in snapshot.pair_ids.iter().zip(snapshot.history.iter()) {
            delete_pair_ids.remove(pair_id);
            let stored_ids = old_by_id
                .get(pair_id)
                .map(|p| p.image_ids.as_slice())
                .unwrap_or(&[]);
            let norm = normalize_pair_for_commit(user, stored_ids);
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
            let generation = match old_by_id.get(pair_id) {
                Some(old) => {
                    let txn = self.db.begin_read()?;
                    let table = txn.open_table(PAIR_BLOBS)?;
                    let ck = chunk_key(set_id, pair_id.as_uuid());
                    let blob = table.get(ck.as_slice())?.ok_or(StoreError::NotFound)?;
                    let stored = crypto::open_pair_v1(
                        user_id,
                        set_id,
                        *pair_id,
                        old.generation,
                        blob.value(),
                        key,
                    )?;
                    if stored.user == norm.user && stored.assistant == *assistant {
                        new_manifest_pairs.push(ManifestPair {
                            pair_id: *pair_id,
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
                assistant: assistant.clone(),
            };
            let blob = crypto::seal_pair_v1(user_id, set_id, *pair_id, generation, &payload, key)?;
            pair_writes.push((*pair_id, blob));
            new_manifest_pairs.push(ManifestPair {
                pair_id: *pair_id,
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

        let manifest = ManifestV1 {
            pairs: new_manifest_pairs,
        };
        let header_blob = crypto::seal_header_v1(user_id, set_id, header_generation, &new_header, key)?;
        let manifest_blob = crypto::seal_manifest_v1(user_id, set_id, new_version, &manifest, key)?;
        let name_blob = crypto::seal_name_v1(user_id, set_id, &snapshot.display_name, key)?;
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
                SetMetaValue::decode(row.value()).ok_or(StoreError::Database(
                    "corrupt set meta".into(),
                ))?
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

            let mut pair_table = txn.open_table(PAIR_BLOBS)?;
            for (pair_id, blob) in &pair_writes {
                let ck = chunk_key(set_id, pair_id.as_uuid());
                pair_table.insert(ck.as_slice(), blob.as_slice())?;
            }
            for pair_id in &delete_pair_ids {
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
            for image_id in &delete_image_ids {
                let ck = chunk_key(set_id, image_id.as_uuid());
                image_table.remove(ck.as_slice())?;
                thumb_table.remove(ck.as_slice())?;
            }

            let mut user_table = txn.open_table(USER_SETS)?;
            user_table.insert(user_set_key(user_id, set_id).as_slice(), now)?;
            let mut blob_table = txn.open_table(SETS_BLOB)?;
            blob_table.remove(id_key.as_slice())?;
        }
        txn.commit()?;
        debug!(%set_id, version = new_version.get(), "history chunked set committed");
        Ok(new_version)
    }

    pub fn delete_chunks_for_set(&self, set_id: SetId) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
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


