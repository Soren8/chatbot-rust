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
pub struct SetMetadata {
    pub created: f64,
    #[serde(default)]
    pub encrypted: bool,
}

impl SetMetadata {
    fn new(encrypted: bool) -> Self {
        Self {
            created: current_timestamp(),
            encrypted,
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

    fn read_sets(&self, username: &str) -> Result<HashMap<String, SetMetadata>, PersistenceError> {
        let path = self.sets_file(username)?;
        if !path.exists() {
            let mut map = HashMap::new();
            map.insert(DEFAULT_SET_NAME.to_string(), SetMetadata::new(false));
            self.write_sets(username, &map)?;
            return Ok(map);
        }

        let contents = fs::read_to_string(&path)?;
        if contents.trim().is_empty() {
            let mut map = HashMap::new();
            map.insert(DEFAULT_SET_NAME.to_string(), SetMetadata::new(false));
            self.write_sets(username, &map)?;
            return Ok(map);
        }

        let raw: HashMap<String, SetMetadata> = serde_json::from_str(&contents)?;
        let mut sanitised = HashMap::new();
        for (name, meta) in raw.into_iter() {
            if let Ok(valid) = Self::normalise_set_name(Some(&name)) {
                sanitised.insert(valid, meta);
            }
        }
        if !sanitised.contains_key(DEFAULT_SET_NAME) {
            sanitised.insert(DEFAULT_SET_NAME.to_string(), SetMetadata::new(false));
        }
        self.write_sets(username, &sanitised)?;
        Ok(sanitised)
    }

    fn write_sets(
        &self,
        username: &str,
        sets: &HashMap<String, SetMetadata>,
    ) -> Result<(), PersistenceError> {
        let path = self.sets_file(username)?;
        let data = serde_json::to_string_pretty(sets)?;
        fs::write(path, data)?;
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
    ) -> Result<HashMap<String, SetMetadata>, PersistenceError> {
        self.read_sets(username)
    }

    pub fn create_set(&self, username: &str, set_name: &str) -> Result<(), PersistenceError> {
        let username = Self::normalise_username(username)?;
        let set_name = Self::normalise_custom_set_name(set_name)?;

        let mut sets = self.read_sets(&username)?;
        if sets.contains_key(&set_name) {
            return Err(PersistenceError::InvalidSetName);
        }
        sets.insert(set_name.clone(), SetMetadata::new(false));
        self.write_sets(&username, &sets)
    }

    pub fn delete_set(&self, username: &str, set_name: &str) -> Result<(), PersistenceError> {
        let username = Self::normalise_username(username)?;
        let set_name = Self::normalise_set_name(Some(set_name))?;
        if set_name == DEFAULT_SET_NAME {
            return Err(PersistenceError::InvalidSetName);
        }

        let mut sets = self.read_sets(&username)?;
        if sets.remove(&set_name).is_none() {
            return Err(PersistenceError::InvalidSetName);
        }
        self.write_sets(&username, &sets)?;

        let memory_path = self.file_path(&username, &set_name, "_memory.txt")?;
        let prompt_path = self.file_path(&username, &set_name, "_prompt.txt")?;
        let history_path = self.file_path(&username, &set_name, "_history.json")?;
        let _ = fs::remove_file(memory_path);
        let _ = fs::remove_file(prompt_path);
        let _ = fs::remove_file(history_path);

        Ok(())
    }

    pub fn rename_set(
        &self,
        username: &str,
        old_name: &str,
        new_name: &str,
    ) -> Result<(), PersistenceError> {
        let username = Self::normalise_username(username)?;
        let old_name = Self::normalise_set_name(Some(old_name))?;
        let new_name = Self::normalise_custom_set_name(new_name)?;

        if old_name == DEFAULT_SET_NAME {
            return Err(PersistenceError::InvalidSetName);
        }

        let mut sets = self.read_sets(&username)?;
        if !sets.contains_key(&old_name) || sets.contains_key(&new_name) {
            return Err(PersistenceError::InvalidSetName);
        }

        let metadata = sets.remove(&old_name).unwrap();
        sets.insert(new_name.clone(), metadata);
        self.write_sets(&username, &sets)?;

        let suffixes = ["_memory.txt", "_prompt.txt", "_history.json"];
        for suffix in suffixes {
            let old_path = self.file_path(&username, &old_name, suffix)?;
            let new_path = self.file_path(&username, &new_name, suffix)?;
            if old_path.exists() {
                fs::rename(old_path, new_path)?;
            }
        }

        Ok(())
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

        let mut sets = self.read_sets(&username)?;
        sets.insert(set_name.clone(), SetMetadata::new(encrypted_flag));
        self.write_sets(&username, &sets)?;

        let path = self.file_path(&username, &set_name, "_memory.txt")?;
        let payload = self.encrypt(memory, encryption)?;
        fs::write(path, payload)?;
        Ok(())
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

        let mut sets = self.read_sets(&username)?;
        sets.insert(set_name.clone(), SetMetadata::new(encrypted_flag));
        self.write_sets(&username, &sets)?;

        let path = self.file_path(&username, &set_name, "_prompt.txt")?;
        let payload = self.encrypt(prompt, encryption)?;
        fs::write(path, payload)?;
        Ok(())
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

        let mut sets = self.read_sets(&username)?;
        sets.insert(set_name.clone(), SetMetadata::new(encrypted_flag));
        self.write_sets(&username, &sets)?;

        let path = self.file_path(&username, &set_name, "_history.json")?;
        let json = serde_json::to_string(history)?;
        let payload = self.encrypt(&json, encryption)?;
        fs::write(path, payload)?;
        Ok(())
    }

    pub fn load_set(
        &self,
        username: &str,
        set_name: &str,
        encryption: Option<EncryptionMode<'_>>,
    ) -> Result<LoadedSet, PersistenceError> {
        let username = Self::normalise_username(username)?;
        let set_name = Self::normalise_set_name(Some(set_name))?;
        let sets = self.read_sets(&username)?;
        let metadata = sets.get(&set_name);
        let encrypted = metadata.map(|meta| meta.encrypted).unwrap_or(false);

        let file_encryption = if encrypted {
            encryption.ok_or(PersistenceError::MissingEncryptionKey)?
        } else {
            EncryptionMode::Plaintext
        };

        let memory_path = self.file_path(&username, &set_name, "_memory.txt")?;
        let memory = if memory_path.exists() {
            let bytes = fs::read(&memory_path)?;
            self.decrypt(&bytes, file_encryption.borrow())?
        } else {
            String::new()
        };

        let prompt_path = self.file_path(&username, &set_name, "_prompt.txt")?;
        let system_prompt = if prompt_path.exists() {
            let bytes = fs::read(&prompt_path)?;
            self.decrypt(&bytes, file_encryption.borrow())?
        } else {
            self.default_system_prompt.clone()
        };

        let history_path = self.file_path(&username, &set_name, "_history.json")?;
        let history = if history_path.exists() {
            let bytes = fs::read(&history_path)?;
            let decrypted = self.decrypt(&bytes, file_encryption.borrow())?;
            Self::parse_history(&decrypted)?
        } else {
            Vec::new()
        };

        Ok(LoadedSet {
            memory,
            system_prompt,
            history,
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
