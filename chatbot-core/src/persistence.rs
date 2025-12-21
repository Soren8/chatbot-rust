use crate::config::app_config;
use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use base64::Engine;
use fernet::Fernet;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const DEFAULT_SET_NAME: &str = "default";

static USERNAME_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z0-9_-]{1,64}$").expect("username regex"));
static SET_NAME_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z0-9 _-]{1,64}$").expect("set name regex"));

fn current_timestamp() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

#[derive(Debug, Error)]
pub enum PersistenceError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid username")]
    InvalidUsername,
    #[error("invalid set name")]
    InvalidSetName,
    #[error("encryption key required")]
    MissingEncryptionKey,
    #[error("invalid encryption key")]
    InvalidEncryptionKey,
    #[error("fernet decryption failed")]
    DecryptionFailed,
    #[error("utf8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetData {
    pub memory: String,
    pub system_prompt: String,
    pub history: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetMetadata {
    pub created: f64,
    #[serde(default)]
    pub encrypted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<SetData>,
}

impl SetMetadata {
    fn new(encrypted: bool) -> Self {
        Self {
            created: current_timestamp(),
            encrypted,
            data: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LoadedSet {
    pub memory: String,
    pub system_prompt: String,
    pub history: Vec<(String, String)>,
    pub encrypted: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum EncryptionMode<'a> {
    Plaintext,
    Fernet(&'a [u8]),
}

pub struct DataPersistence {
    sets_dir: PathBuf,
    default_system_prompt: String,
}

impl DataPersistence {
    pub fn new() -> Result<Self, PersistenceError> {
        let config = app_config();
        let sets_dir = config.host_data_dir.join("user_sets");
        fs::create_dir_all(&sets_dir)?;

        Ok(Self {
            sets_dir,
            default_system_prompt: config.default_system_prompt.clone(),
        })
    }

    pub fn normalise_username(username: &str) -> Result<String, PersistenceError> {
        let trimmed = username.trim();
        if trimmed.is_empty() || !USERNAME_RE.is_match(trimmed) {
            return Err(PersistenceError::InvalidUsername);
        }
        Ok(trimmed.to_string())
    }

    pub fn normalise_set_name(set_name: Option<&str>) -> Result<String, PersistenceError> {
        Self::normalise_set_name_inner(set_name.unwrap_or(DEFAULT_SET_NAME), true)
    }

    pub fn normalise_custom_set_name(set_name: &str) -> Result<String, PersistenceError> {
        Self::normalise_set_name_inner(set_name, false)
    }

    fn normalise_set_name_inner(
        set_name: &str,
        allow_default: bool,
    ) -> Result<String, PersistenceError> {
        let trimmed = set_name.trim();
        let candidate = if trimmed.is_empty() {
            if allow_default {
                DEFAULT_SET_NAME.to_string()
            } else {
                return Err(PersistenceError::InvalidSetName);
            }
        } else {
            trimmed.to_string()
        };

        if (!allow_default && candidate == DEFAULT_SET_NAME)
            || candidate == "."
            || candidate == ".."
            || !SET_NAME_RE.is_match(&candidate)
        {
            return Err(PersistenceError::InvalidSetName);
        }

        Ok(candidate)
    }

    fn ensure_user_dir(&self, username: &str) -> Result<PathBuf, PersistenceError> {
        let username = Self::normalise_username(username)?;
        let dir = self.sets_dir.join(&username);
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    fn sets_file(&self, username: &str) -> Result<PathBuf, PersistenceError> {
        let user_dir = self.ensure_user_dir(username)?;
        Ok(user_dir.join("sets.json"))
    }

    fn read_sets(
        &self,
        username: &str,
        encryption: Option<EncryptionMode<'_>>,
    ) -> Result<HashMap<String, SetMetadata>, PersistenceError> {
        let path = self.sets_file(username)?;
        if !path.exists() {
            let mut map = HashMap::new();
            map.insert(DEFAULT_SET_NAME.to_string(), SetMetadata::new(false));
            self.write_sets(username, &map, encryption)?;
            return Ok(map);
        }

        let bytes = fs::read(&path)?;
        if bytes.is_empty() {
            let mut map = HashMap::new();
            map.insert(DEFAULT_SET_NAME.to_string(), SetMetadata::new(false));
            self.write_sets(username, &map, encryption)?;
            return Ok(map);
        }

        let mut is_plaintext = false;
        let contents = match encryption.as_ref() {
            Some(mode @ EncryptionMode::Fernet(_)) => match self.decrypt(&bytes, mode.borrow()) {
                Ok(decrypted) => decrypted,
                Err(_) => {
                    is_plaintext = true;
                    String::from_utf8_lossy(&bytes).into_owned()
                }
            },
            _ => {
                is_plaintext = true;
                String::from_utf8_lossy(&bytes).into_owned()
            }
        };

        let raw: HashMap<String, SetMetadata> = serde_json::from_str(&contents)?;
        let mut sanitised = HashMap::new();
        let mut needs_migration = is_plaintext && encryption.is_some();
        let mut migrated_files = Vec::new();

        for (name, mut meta) in raw.into_iter() {
            if let Ok(valid) = Self::normalise_set_name(Some(&name)) {
                if meta.data.is_none() {
                    if let Ok((data, files)) =
                        self.migrate_set_data(username, &valid, encryption.as_ref())
                    {
                        meta.data = Some(data);
                        migrated_files.extend(files);
                        needs_migration = true;
                    }
                }
                sanitised.insert(valid, meta);
            }
        }

        if !sanitised.contains_key(DEFAULT_SET_NAME) {
            sanitised.insert(DEFAULT_SET_NAME.to_string(), SetMetadata::new(false));
            needs_migration = true;
        }

        if needs_migration {
            self.write_sets(username, &sanitised, encryption)?;
            for file in migrated_files {
                let _ = fs::remove_file(file);
            }
        }

        Ok(sanitised)
    }

    fn migrate_set_data(
        &self,
        username: &str,
        set_name: &str,
        encryption: Option<&EncryptionMode<'_>>,
    ) -> Result<(SetData, Vec<PathBuf>), PersistenceError> {
        let mut migrated_files = Vec::new();

        let memory_path = self.file_path(username, set_name, "_memory.txt")?;
        let prompt_path = self.file_path(username, set_name, "_prompt.txt")?;
        let history_path = self.file_path(username, set_name, "_history.json")?;

        let sets = self.read_sets_internal(username)?;
        let metadata = sets.get(set_name);
        let encrypted = metadata.map(|meta| meta.encrypted).unwrap_or(false);

        let file_encryption = if encrypted {
            encryption
                .map(|m| m.borrow())
                .ok_or(PersistenceError::MissingEncryptionKey)?
        } else {
            EncryptionMode::Plaintext
        };

        let memory = if memory_path.exists() {
            let bytes = fs::read(&memory_path)?;
            migrated_files.push(memory_path);
            self.decrypt(&bytes, file_encryption.borrow())?
        } else {
            String::new()
        };

        let prompt = if prompt_path.exists() {
            let bytes = fs::read(&prompt_path)?;
            migrated_files.push(prompt_path);
            self.decrypt(&bytes, file_encryption.borrow())?
        } else {
            self.default_system_prompt.clone()
        };

        let history = if history_path.exists() {
            let bytes = fs::read(&history_path)?;
            migrated_files.push(history_path);
            let decrypted = self.decrypt(&bytes, file_encryption.borrow())?;
            Self::parse_history(&decrypted)?
        } else {
            Vec::new()
        };

        Ok((
            SetData {
                memory,
                system_prompt: prompt,
                history,
            },
            migrated_files,
        ))
    }

    fn read_sets_internal(
        &self,
        username: &str,
    ) -> Result<HashMap<String, SetMetadata>, PersistenceError> {
        let path = self.sets_file(username)?;
        if !path.exists() {
            return Ok(HashMap::new());
        }
        let bytes = fs::read(&path)?;
        if bytes.is_empty() {
            return Ok(HashMap::new());
        }
        // This is only used for metadata check during migration, so we try to parse it as JSON.
        // If it's encrypted, it will fail, but that's okay because we only migrate if it's plaintext.
        let contents = String::from_utf8_lossy(&bytes);
        Ok(serde_json::from_str(&contents).unwrap_or_default())
    }

    fn write_sets(
        &self,
        username: &str,
        sets: &HashMap<String, SetMetadata>,
        encryption: Option<EncryptionMode<'_>>,
    ) -> Result<(), PersistenceError> {
        let path = self.sets_file(username)?;
        let data = serde_json::to_string_pretty(sets)?;
        let payload = match encryption {
            Some(mode) => self.encrypt(&data, mode)?,
            None => data.into_bytes(),
        };
        fs::write(path, payload)?;
        Ok(())
    }

    fn file_path(
        &self,
        username: &str,
        set_name: &str,
        suffix: &str,
    ) -> Result<PathBuf, PersistenceError> {
        let dir = self.ensure_user_dir(username)?;
        Ok(dir.join(format!("{}{}", set_name, suffix)))
    }

    fn build_fernet(key: &[u8]) -> Result<Fernet, PersistenceError> {
        let key_str = std::str::from_utf8(key)?;
        if let Some(fernet) = Fernet::new(key_str) {
            return Ok(fernet);
        }

        let decoded = STANDARD
            .decode(key_str)
            .map_err(|_| PersistenceError::InvalidEncryptionKey)?;
        let reencoded = URL_SAFE.encode(decoded);
        Fernet::new(&reencoded).ok_or(PersistenceError::InvalidEncryptionKey)
    }

    fn encrypt(
        &self,
        content: &str,
        encryption: EncryptionMode<'_>,
    ) -> Result<Vec<u8>, PersistenceError> {
        match encryption {
            EncryptionMode::Plaintext => Ok(content.as_bytes().to_vec()),
            EncryptionMode::Fernet(key) => {
                let fernet = Self::build_fernet(key)?;
                Ok(fernet.encrypt(content.as_bytes()).into_bytes())
            }
        }
    }

    fn decrypt(
        &self,
        content: &[u8],
        encryption: EncryptionMode<'_>,
    ) -> Result<String, PersistenceError> {
        match encryption {
            EncryptionMode::Plaintext => Ok(String::from_utf8_lossy(content).into_owned()),
            EncryptionMode::Fernet(key) => {
                let fernet = Self::build_fernet(key)?;
                let token = std::str::from_utf8(content)?;
                let decrypted = fernet
                    .decrypt(token)
                    .map_err(|_| PersistenceError::DecryptionFailed)?;
                Ok(String::from_utf8_lossy(&decrypted).into_owned())
            }
        }
    }

    pub fn list_sets(
        &self,
        username: &str,
        encryption: Option<EncryptionMode<'_>>,
    ) -> Result<HashMap<String, SetMetadata>, PersistenceError> {
        let mut sets = self.read_sets(username, encryption)?;
        // Strip data before returning metadata
        for meta in sets.values_mut() {
            meta.data = None;
        }
        Ok(sets)
    }

    pub fn create_set(
        &self,
        username: &str,
        set_name: &str,
        encryption: Option<EncryptionMode<'_>>,
    ) -> Result<(), PersistenceError> {
        let username = Self::normalise_username(username)?;
        let set_name = Self::normalise_custom_set_name(set_name)?;

        let mut sets = self.read_sets(&username, encryption)?;
        if sets.contains_key(&set_name) {
            return Err(PersistenceError::InvalidSetName);
        }
        let encrypted_flag = encryption.map(|e| matches!(e, EncryptionMode::Fernet(_))).unwrap_or(false);
        sets.insert(set_name.clone(), SetMetadata::new(encrypted_flag));
        self.write_sets(&username, &sets, encryption)
    }

    pub fn delete_set(
        &self,
        username: &str,
        set_name: &str,
        encryption: Option<EncryptionMode<'_>>,
    ) -> Result<(), PersistenceError> {
        let username = Self::normalise_username(username)?;
        let set_name = Self::normalise_set_name(Some(set_name))?;
        if set_name == DEFAULT_SET_NAME {
            return Err(PersistenceError::InvalidSetName);
        }

        let mut sets = self.read_sets(&username, encryption)?;
        if sets.remove(&set_name).is_none() {
            return Err(PersistenceError::InvalidSetName);
        }
        self.write_sets(&username, &sets, encryption)
    }

    pub fn rename_set(
        &self,
        username: &str,
        old_name: &str,
        new_name: &str,
        encryption: Option<EncryptionMode<'_>>,
    ) -> Result<(), PersistenceError> {
        let username = Self::normalise_username(username)?;
        let old_name = Self::normalise_set_name(Some(old_name))?;
        let new_name = Self::normalise_custom_set_name(new_name)?;

        if old_name == DEFAULT_SET_NAME {
            return Err(PersistenceError::InvalidSetName);
        }

        let mut sets = self.read_sets(&username, encryption)?;
        if !sets.contains_key(&old_name) || sets.contains_key(&new_name) {
            return Err(PersistenceError::InvalidSetName);
        }

        let metadata = sets.remove(&old_name).unwrap();
        sets.insert(new_name.clone(), metadata);
        self.write_sets(&username, &sets, encryption)
    }

    pub fn store_memory(
        &self,
        username: &str,
        set_name: &str,
        memory: &str,
        encryption: EncryptionMode<'_>,
    ) -> Result<(), PersistenceError> {
        let username = Self::normalise_username(username)?;
        let set_name = Self::normalise_set_name(Some(set_name))?;
        let encrypted_flag = matches!(encryption, EncryptionMode::Fernet(_));

        let mut sets = self.read_sets(&username, Some(encryption))?;
        let mut metadata = sets.get(&set_name).cloned().unwrap_or_else(|| SetMetadata::new(encrypted_flag));
        let mut data = metadata.data.unwrap_or_else(|| SetData {
            memory: String::new(),
            system_prompt: self.default_system_prompt.clone(),
            history: Vec::new(),
        });
        data.memory = memory.to_string();
        metadata.data = Some(data);
        metadata.encrypted = encrypted_flag;
        
        sets.insert(set_name, metadata);
        self.write_sets(&username, &sets, Some(encryption))
    }

    pub fn store_system_prompt(
        &self,
        username: &str,
        set_name: &str,
        prompt: &str,
        encryption: EncryptionMode<'_>,
    ) -> Result<(), PersistenceError> {
        let username = Self::normalise_username(username)?;
        let set_name = Self::normalise_set_name(Some(set_name))?;
        let encrypted_flag = matches!(encryption, EncryptionMode::Fernet(_));

        let mut sets = self.read_sets(&username, Some(encryption))?;
        let mut metadata = sets.get(&set_name).cloned().unwrap_or_else(|| SetMetadata::new(encrypted_flag));
        let mut data = metadata.data.unwrap_or_else(|| SetData {
            memory: String::new(),
            system_prompt: self.default_system_prompt.clone(),
            history: Vec::new(),
        });
        data.system_prompt = prompt.to_string();
        metadata.data = Some(data);
        metadata.encrypted = encrypted_flag;
        
        sets.insert(set_name, metadata);
        self.write_sets(&username, &sets, Some(encryption))
    }

    pub fn store_history(
        &self,
        username: &str,
        set_name: &str,
        history: &[(String, String)],
        encryption: EncryptionMode<'_>,
    ) -> Result<(), PersistenceError> {
        let username = Self::normalise_username(username)?;
        let set_name = Self::normalise_set_name(Some(set_name))?;
        let encrypted_flag = matches!(encryption, EncryptionMode::Fernet(_));

        let mut sets = self.read_sets(&username, Some(encryption))?;
        let mut metadata = sets.get(&set_name).cloned().unwrap_or_else(|| SetMetadata::new(encrypted_flag));
        let mut data = metadata.data.unwrap_or_else(|| SetData {
            memory: String::new(),
            system_prompt: self.default_system_prompt.clone(),
            history: Vec::new(),
        });
        data.history = history.to_vec();
        metadata.data = Some(data);
        metadata.encrypted = encrypted_flag;
        
        sets.insert(set_name, metadata);
        self.write_sets(&username, &sets, Some(encryption))
    }

    pub fn load_set(
        &self,
        username: &str,
        set_name: &str,
        encryption: Option<EncryptionMode<'_>>,
    ) -> Result<LoadedSet, PersistenceError> {
        let username = Self::normalise_username(username)?;
        let set_name = Self::normalise_set_name(Some(set_name))?;
        let sets = self.read_sets(&username, encryption)?;
        let metadata = sets.get(&set_name).ok_or(PersistenceError::InvalidSetName)?;
        
        let encrypted = metadata.encrypted;
        let data = metadata.data.as_ref().cloned().unwrap_or_else(|| SetData {
            memory: String::new(),
            system_prompt: self.default_system_prompt.clone(),
            history: Vec::new(),
        });

        Ok(LoadedSet {
            memory: data.memory,
            system_prompt: data.system_prompt,
            history: data.history,
            encrypted,
        })
    }

    fn parse_history(raw: &str) -> Result<Vec<(String, String)>, PersistenceError> {
        let value: serde_json::Value = serde_json::from_str(raw)?;
        let mut pairs = Vec::new();
        if let Some(items) = value.as_array() {
            for item in items.iter() {
                if let Some(arr) = item.as_array() {
                    if arr.len() == 2 {
                        let user = arr[0].as_str().unwrap_or_default().to_string();
                        let assistant = arr[1].as_str().unwrap_or_default().to_string();
                        pairs.push((user, assistant));
                    }
                }
            }
        }
        Ok(pairs)
    }
}

trait BorrowMode<'a> {
    fn borrow(&'a self) -> EncryptionMode<'a>;
}

impl<'a> BorrowMode<'a> for EncryptionMode<'a> {
    fn borrow(&'a self) -> EncryptionMode<'a> {
        match self {
            EncryptionMode::Plaintext => EncryptionMode::Plaintext,
            EncryptionMode::Fernet(key) => EncryptionMode::Fernet(key),
        }
    }
}
