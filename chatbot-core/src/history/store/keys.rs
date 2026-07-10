//! redb key encoding — UUIDs and usernames only; never display names.

use crate::history::types::SetId;

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
