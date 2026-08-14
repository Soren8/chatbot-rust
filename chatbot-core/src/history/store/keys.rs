//! redb key encoding — UUIDs and usernames only; never display names.

use crate::history::types::SetId;
use uuid::Uuid;

pub fn set_id_key(set_id: SetId) -> [u8; 16] {
    *set_id.as_bytes()
}

/// Composite key: `user_id_len(u16 le) || user_id || set_id`
pub fn user_set_key(user_id: &str, set_id: SetId) -> Vec<u8> {
    let user_bytes = user_id.as_bytes();
    let mut key = Vec::with_capacity(2 + user_bytes.len() + 16);
    key.extend_from_slice(&(user_bytes.len() as u16).to_le_bytes());
    key.extend_from_slice(user_bytes);
    key.extend_from_slice(set_id.as_bytes());
    key
}

/// Prefix for scanning all sets belonging to a user: `user_id_len || user_id`
pub fn user_sets_prefix(user_id: &str) -> Vec<u8> {
    let user_bytes = user_id.as_bytes();
    let mut key = Vec::with_capacity(2 + user_bytes.len());
    key.extend_from_slice(&(user_bytes.len() as u16).to_le_bytes());
    key.extend_from_slice(user_bytes);
    key
}

/// Exclusive end bound for a redb range over `user_sets_prefix(user)` keys.
///
/// Returns `None` if the prefix is all `0xff` bytes (practically impossible for usernames).
pub fn user_sets_prefix_end(user_id: &str) -> Option<Vec<u8>> {
    let mut end = user_sets_prefix(user_id);
    for i in (0..end.len()).rev() {
        if end[i] != 0xff {
            end[i] += 1;
            return Some(end);
        }
        end[i] = 0;
    }
    None
}

pub fn parse_user_set_key(key: &[u8]) -> Option<(String, SetId)> {
    if key.len() < 2 + 16 {
        return None;
    }
    let len = u16::from_le_bytes([key[0], key[1]]) as usize;
    if key.len() != 2 + len + 16 {
        return None;
    }
    let user = std::str::from_utf8(&key[2..2 + len]).ok()?.to_owned();
    let mut uuid_bytes = [0u8; 16];
    uuid_bytes.copy_from_slice(&key[2 + len..]);
    let set_id = SetId::from_uuid(uuid::Uuid::from_bytes(uuid_bytes));
    Some((user, set_id))
}

pub fn migrated_user_meta_key(user_id: &str) -> String {
    format!("migrated_user:{user_id}")
}

/// Composite chunk key: `set_id (16) || id (16)` — range-scanable by set.
pub fn chunk_key(set_id: SetId, id: Uuid) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(set_id.as_bytes());
    key[16..].copy_from_slice(id.as_bytes());
    key
}

pub fn set_chunk_prefix(set_id: SetId) -> [u8; 16] {
    *set_id.as_bytes()
}

/// Exclusive end bound for a range over one set's chunk keys (increment set_id).
pub fn chunk_prefix_end(set_id: SetId) -> Option<[u8; 16]> {
    let mut end = *set_id.as_bytes();
    for i in (0..end.len()).rev() {
        if end[i] != 0xff {
            end[i] += 1;
            return Some(end);
        }
        end[i] = 0;
    }
    None
}

#[allow(dead_code)]
pub fn parse_chunk_key(key: &[u8]) -> Option<(SetId, Uuid)> {
    if key.len() != 32 {
        return None;
    }
    let mut set_bytes = [0u8; 16];
    let mut id_bytes = [0u8; 16];
    set_bytes.copy_from_slice(&key[..16]);
    id_bytes.copy_from_slice(&key[16..]);
    Some((
        SetId::from_uuid(Uuid::from_bytes(set_bytes)),
        Uuid::from_bytes(id_bytes),
    ))
}
