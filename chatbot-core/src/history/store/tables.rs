//! redb table definitions and meta value encoding.

use redb::TableDefinition;

use crate::history::types::{BlobFormat, SetVersion};

/// set_id (16 bytes) → SetMetaValue bytes
pub const SETS_META: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("sets_meta");

/// set_id (16 bytes) → ciphertext
pub const SETS_BLOB: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("sets_blob");

/// (user, set_id) → updated_at le u64 (for listing/sort without decrypt)
pub const USER_SETS: TableDefinition<'_, &[u8], u64> = TableDefinition::new("user_sets");

/// string key → bytes (schema version, migration flags)
pub const META: TableDefinition<'_, &str, &[u8]> = TableDefinition::new("meta");

pub const SCHEMA_KEY: &str = "schema";
pub const SCHEMA_VERSION: u8 = 1;

/// Binary layout of SETS_META value:
/// ```text
/// user_len:u16 le | user_utf8 | version:u64 le | created_at:u64 le | updated_at:u64 le
/// | is_default:u8 | blob_format:u8
/// ```
#[derive(Debug, Clone)]
pub struct SetMetaValue {
    pub user_id: String,
    pub version: SetVersion,
    pub created_at: u64,
    pub updated_at: u64,
    pub is_default: bool,
    pub blob_format: BlobFormat,
}

impl SetMetaValue {
    pub fn encode(&self) -> Vec<u8> {
        let user = self.user_id.as_bytes();
        let mut buf = Vec::with_capacity(2 + user.len() + 8 + 8 + 8 + 2);
        buf.extend_from_slice(&(user.len() as u16).to_le_bytes());
        buf.extend_from_slice(user);
        buf.extend_from_slice(&self.version.get().to_le_bytes());
        buf.extend_from_slice(&self.created_at.to_le_bytes());
        buf.extend_from_slice(&self.updated_at.to_le_bytes());
        buf.push(if self.is_default { 1 } else { 0 });
        buf.push(self.blob_format.as_u8());
        buf
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 2 {
            return None;
        }
        let user_len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
        let need = 2 + user_len + 8 + 8 + 8 + 2;
        if bytes.len() != need {
            return None;
        }
        let user_id = std::str::from_utf8(&bytes[2..2 + user_len]).ok()?.to_owned();
        let mut o = 2 + user_len;
        let version = SetVersion(u64::from_le_bytes(bytes[o..o + 8].try_into().ok()?));
        o += 8;
        let created_at = u64::from_le_bytes(bytes[o..o + 8].try_into().ok()?);
        o += 8;
        let updated_at = u64::from_le_bytes(bytes[o..o + 8].try_into().ok()?);
        o += 8;
        let is_default = bytes[o] != 0;
        let blob_format = BlobFormat::from_u8(bytes[o + 1])?;
        Some(Self {
            user_id,
            version,
            created_at,
            updated_at,
            is_default,
            blob_format,
        })
    }
}
