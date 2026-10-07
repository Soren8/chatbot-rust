//! Copy-on-write sharing of sealed pair/image/thumb blobs between sets.
//!
//! A fork's manifest names, per pair or image, the origin set whose chunk key
//! holds the ciphertext and whose id is in its AAD (`ManifestV1::sealed_in`).
//! Forking adds one reference per shared blob; nothing is copied or sealed.
//! Before a set overwrites or deletes one of its own blobs that another set
//! still references, the ciphertext moves to `PRESERVED_BLOBS`.

use redb::{ReadableTable, Table, WriteTransaction};
use uuid::Uuid;

use super::StoreError;
use super::keys::chunk_key;
use super::tables::{BLOB_REFS, HELD_REFS, IMAGE_BLOBS, PAIR_BLOBS, PRESERVED_BLOBS, THUMB_BLOBS};
use crate::history::types::SetId;

/// Stored blob kind. A reference to an image covers its thumb too.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum Kind {
    Pair = 0,
    Image = 1,
    Thumb = 2,
}

/// One shared blob: `generation` is the pair generation, 0 for images.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct SharedRef {
    pub kind: Kind,
    pub origin: SetId,
    pub id: Uuid,
    pub generation: u32,
}

fn shared_key(kind: Kind, origin: SetId, id: Uuid, generation: u32) -> [u8; 37] {
    let mut key = [0u8; 37];
    key[0] = kind as u8;
    key[1..17].copy_from_slice(origin.as_bytes());
    key[17..33].copy_from_slice(id.as_bytes());
    key[33..].copy_from_slice(&generation.to_le_bytes());
    key
}

fn held_key(holder: SetId, r: &SharedRef) -> [u8; 53] {
    let mut key = [0u8; 53];
    key[..16].copy_from_slice(holder.as_bytes());
    key[16..].copy_from_slice(&shared_key(r.kind, r.origin, r.id, r.generation));
    key
}

fn blob_kinds(kind: Kind) -> &'static [Kind] {
    match kind {
        Kind::Pair => &[Kind::Pair],
        Kind::Image | Kind::Thumb => &[Kind::Image, Kind::Thumb],
    }
}

fn live_table(
    txn: &WriteTransaction,
    kind: Kind,
) -> Result<Table<'_, &'static [u8], &'static [u8]>, StoreError> {
    Ok(txn.open_table(match kind {
        Kind::Pair => PAIR_BLOBS,
        Kind::Image => IMAGE_BLOBS,
        Kind::Thumb => THUMB_BLOBS,
    })?)
}

/// Ciphertext of one blob read by set `own`: its own row, or the preserved or
/// still-live row of `origin`.
pub(super) fn read_blob<T>(
    live: &T,
    preserved: &T,
    kind: Kind,
    own: SetId,
    origin: SetId,
    id: Uuid,
    generation: u32,
) -> Result<Option<Vec<u8>>, StoreError>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    if origin != own {
        let key = shared_key(kind, origin, id, generation);
        if let Some(blob) = preserved.get(key.as_slice())? {
            return Ok(Some(blob.value().to_vec()));
        }
    }
    Ok(live
        .get(chunk_key(origin, id).as_slice())?
        .map(|blob| blob.value().to_vec()))
}

pub(super) fn add_ref(
    txn: &WriteTransaction,
    holder: SetId,
    r: &SharedRef,
) -> Result<(), StoreError> {
    if txn
        .open_table(HELD_REFS)?
        .insert(held_key(holder, r).as_slice(), ())?
        .is_some()
    {
        return Ok(());
    }
    let mut refs = txn.open_table(BLOB_REFS)?;
    let key = shared_key(r.kind, r.origin, r.id, r.generation);
    let count = refs.get(key.as_slice())?.map(|v| v.value()).unwrap_or(0);
    refs.insert(key.as_slice(), count + 1)?;
    Ok(())
}

pub(super) fn release_ref(
    txn: &WriteTransaction,
    holder: SetId,
    r: &SharedRef,
) -> Result<(), StoreError> {
    if txn
        .open_table(HELD_REFS)?
        .remove(held_key(holder, r).as_slice())?
        .is_none()
    {
        return Ok(());
    }
    let mut refs = txn.open_table(BLOB_REFS)?;
    let key = shared_key(r.kind, r.origin, r.id, r.generation);
    let count = refs.get(key.as_slice())?.map(|v| v.value()).unwrap_or(0);
    if count > 1 {
        refs.insert(key.as_slice(), count - 1)?;
        return Ok(());
    }
    refs.remove(key.as_slice())?;
    let mut preserved = txn.open_table(PRESERVED_BLOBS)?;
    for kind in blob_kinds(r.kind) {
        preserved.remove(shared_key(*kind, r.origin, r.id, r.generation).as_slice())?;
    }
    Ok(())
}

/// Release every blob `holder` points at.
pub(super) fn release_all(txn: &WriteTransaction, holder: SetId) -> Result<(), StoreError> {
    let held: Vec<SharedRef> = {
        let table = txn.open_table(HELD_REFS)?;
        let start = held_key(
            holder,
            &bound(Kind::Pair, SetId::from_uuid(Uuid::nil()), Uuid::nil(), 0),
        );
        let end = held_key(
            holder,
            &bound(
                Kind::Thumb,
                SetId::from_uuid(Uuid::max()),
                Uuid::max(),
                u32::MAX,
            ),
        );
        let mut out = Vec::new();
        for entry in table.range(start.as_slice()..=end.as_slice())? {
            let (key, _) = entry?;
            out.push(
                parse_shared(&key.value()[16..])
                    .ok_or(StoreError::Database("corrupt held ref".into()))?,
            );
        }
        out
    };
    for r in &held {
        release_ref(txn, holder, r)?;
    }
    Ok(())
}

/// Before `own` overwrites or deletes its blob `id`, move each still-referenced
/// generation's ciphertext to `PRESERVED_BLOBS`.
pub(super) fn preserve(
    txn: &WriteTransaction,
    kind: Kind,
    own: SetId,
    id: Uuid,
) -> Result<(), StoreError> {
    let generations: Vec<u32> = {
        let refs = txn.open_table(BLOB_REFS)?;
        let start = shared_key(kind, own, id, 0);
        let end = shared_key(kind, own, id, u32::MAX);
        let mut out = Vec::new();
        for entry in refs.range(start.as_slice()..=end.as_slice())? {
            let (key, _) = entry?;
            let r =
                parse_shared(key.value()).ok_or(StoreError::Database("corrupt blob ref".into()))?;
            out.push(r.generation);
        }
        out
    };
    if generations.is_empty() {
        return Ok(());
    }
    let mut preserved = txn.open_table(PRESERVED_BLOBS)?;
    for blob_kind in blob_kinds(kind) {
        let live = live_table(txn, *blob_kind)?;
        for generation in &generations {
            let key = shared_key(*blob_kind, own, id, *generation);
            if preserved.get(key.as_slice())?.is_some() {
                continue;
            }
            // An unpreserved referenced generation is the live one.
            if let Some(blob) = live.get(chunk_key(own, id).as_slice())? {
                preserved.insert(key.as_slice(), blob.value())?;
            }
        }
    }
    Ok(())
}

/// `preserve` for every blob of `own` that another set references.
pub(super) fn preserve_all(txn: &WriteTransaction, own: SetId) -> Result<(), StoreError> {
    let mut targets = Vec::new();
    {
        let refs = txn.open_table(BLOB_REFS)?;
        for kind in [Kind::Pair, Kind::Image] {
            let start = shared_key(kind, own, Uuid::nil(), 0);
            let end = shared_key(kind, own, Uuid::max(), u32::MAX);
            for entry in refs.range(start.as_slice()..=end.as_slice())? {
                let (key, _) = entry?;
                let r = parse_shared(key.value())
                    .ok_or(StoreError::Database("corrupt blob ref".into()))?;
                targets.push((r.kind, r.id));
            }
        }
    }
    targets.dedup();
    for (kind, id) in targets {
        preserve(txn, kind, own, id)?;
    }
    Ok(())
}

fn bound(kind: Kind, origin: SetId, id: Uuid, generation: u32) -> SharedRef {
    SharedRef {
        kind,
        origin,
        id,
        generation,
    }
}

fn parse_shared(key: &[u8]) -> Option<SharedRef> {
    if key.len() != 37 {
        return None;
    }
    let kind = match key[0] {
        0 => Kind::Pair,
        1 => Kind::Image,
        2 => Kind::Thumb,
        _ => return None,
    };
    Some(SharedRef {
        kind,
        origin: SetId::from_uuid(Uuid::from_slice(&key[1..17]).ok()?),
        id: Uuid::from_slice(&key[17..33]).ok()?,
        generation: u32::from_le_bytes(key[33..].try_into().ok()?),
    })
}
