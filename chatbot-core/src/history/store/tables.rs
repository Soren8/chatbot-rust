//! redb table definitions and meta value encoding.

use redb::TableDefinition;

use crate::history::types::{BlobFormat, SetVersion};

/// set_id (16 bytes) → SetMetaValue bytes
pub const SETS_META: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("sets_meta");

/// set_id (16 bytes) → whole-set history ciphertext (memory, prompt, all pairs).
///
/// v0/v1 only. Format-2 sets use header/manifest/pair/image/thumb tables instead.
pub const SETS_BLOB: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("sets_blob");

/// set_id (16 bytes) → sealed HeaderV1 (memory + system_prompt).
pub const SETS_HEADER: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("sets_header");

/// set_id (16 bytes) → sealed ManifestV1 (ordered pair/image ids).
pub const SETS_MANIFEST: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("sets_manifest");

/// chunk_key(set_id, pair_id) → sealed PairPayloadV1.
pub const PAIR_BLOBS: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("pair_blobs");

/// chunk_key(set_id, image_id) → sealed ImagePayloadV1 (binary plaintext).
pub const IMAGE_BLOBS: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("image_blobs");

/// chunk_key(set_id, image_id) → sealed ThumbPayloadV1 (binary plaintext).
pub const THUMB_BLOBS: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("thumb_blobs");

/// set_id (16 bytes) → sealed display name (no history / memory / prompt).
///
/// Separate from `SETS_META` (plaintext structure) and `SETS_BLOB` (full snapshot)
/// so `/get_sets` can decrypt names without opening chat content.
pub const SETS_NAME: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("sets_name");

/// (user, set_id) → updated_at le u64 (for listing/sort without decrypt)
pub const USER_SETS: TableDefinition<'_, &[u8], u64> = TableDefinition::new("user_sets");

/// string key → bytes (schema version, migration flags)
pub const META: TableDefinition<'_, &str, &[u8]> = TableDefinition::new("meta");

pub const SCHEMA_KEY: &str = "schema";
pub const SCHEMA_VERSION: u8 = 2;

/// Binary layout of SETS_META value:
/// ```text
/// user_len:u16 le | user_utf8 | version:u64 le | created_at:u64 le | updated_at:u64 le
/// | is_default:u8 | blob_format:u8
/// | [format 2 only] header_generation:u32 le | pair_count:u32 le
/// ```
#[derive(Debug, Clone)]
pub struct SetMetaValue {
    pub user_id: String,
    pub version: SetVersion,
    pub created_at: u64,
    pub updated_at: u64,
    pub is_default: bool,
    pub blob_format: BlobFormat,
    pub header_generation: u32,
    pub pair_count: Option<u32>,
}

impl SetMetaValue {
    pub fn encode(&self) -> Vec<u8> {
        let user = self.user_id.as_bytes();
        let mut buf = Vec::with_capacity(2 + user.len() + 8 + 8 + 8 + 2 + 8);
        buf.extend_from_slice(&(user.len() as u16).to_le_bytes());
        buf.extend_from_slice(user);
        buf.extend_from_slice(&self.version.get().to_le_bytes());
        buf.extend_from_slice(&self.created_at.to_le_bytes());
        buf.extend_from_slice(&self.updated_at.to_le_bytes());
        buf.push(if self.is_default { 1 } else { 0 });
        buf.push(self.blob_format.as_u8());
        // Suffix only on format 2 so previous-image decoders still accept v0/v1 rows.
        if self.blob_format.is_chunked() {
            buf.extend_from_slice(&self.header_generation.to_le_bytes());
            let pair_count = self.pair_count.unwrap_or(0);
            buf.extend_from_slice(&pair_count.to_le_bytes());
        }
        buf
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 2 {
            return None;
        }
        let user_len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
        let base = 2 + user_len + 8 + 8 + 8 + 2;
        if bytes.len() != base && bytes.len() != base + 8 {
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
        o += 2;
        let (header_generation, pair_count) = if bytes.len() == base + 8 {
            if !blob_format.is_chunked() {
                return None;
            }
            let hg = u32::from_le_bytes(bytes[o..o + 4].try_into().ok()?);
            let pc = u32::from_le_bytes(bytes[o + 4..o + 8].try_into().ok()?);
            (hg, Some(pc))
        } else {
            (0, None)
        };
        Some(Self {
            user_id,
            version,
            created_at,
            updated_at,
            is_default,
            blob_format,
            header_generation,
            pair_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::types::BlobFormat;

    #[test]
    fn v1_meta_is_exact_length_and_round_trips() {
        let meta = SetMetaValue {
            user_id: "alice".into(),
            version: SetVersion(3),
            created_at: 1,
            updated_at: 2,
            is_default: true,
            blob_format: BlobFormat::AeadV1,
            header_generation: 9,
            pair_count: Some(4),
        };
        let bytes = meta.encode();
        // header_generation / pair_count must not be written for v1.
        assert_eq!(bytes.len(), 2 + 5 + 8 + 8 + 8 + 2);
        let decoded = SetMetaValue::decode(&bytes).unwrap();
        assert_eq!(decoded.user_id, "alice");
        assert_eq!(decoded.version, SetVersion(3));
        assert_eq!(decoded.header_generation, 0);
        assert_eq!(decoded.pair_count, None);
        assert_eq!(decoded.blob_format, BlobFormat::AeadV1);
    }

    #[test]
    fn format2_meta_writes_suffix() {
        let meta = SetMetaValue {
            user_id: "bob".into(),
            version: SetVersion(7),
            created_at: 1,
            updated_at: 2,
            is_default: false,
            blob_format: BlobFormat::AeadChunkedV2,
            header_generation: 3,
            pair_count: Some(12),
        };
        let bytes = meta.encode();
        assert_eq!(bytes.len(), 2 + 3 + 8 + 8 + 8 + 2 + 8);
        let decoded = SetMetaValue::decode(&bytes).unwrap();
        assert_eq!(decoded.header_generation, 3);
        assert_eq!(decoded.pair_count, Some(12));
        assert!(decoded.blob_format.is_chunked());
    }
}
