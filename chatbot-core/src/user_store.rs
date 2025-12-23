use std::{
    collections::HashMap,
    env, fmt,
    fs::{self, File},
    io::{Read, Write},
    path::PathBuf,
};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bcrypt::verify;
use once_cell::sync::Lazy;
use pbkdf2::pbkdf2_hmac;
use rand::{rngs::OsRng, RngCore};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;

pub const DEFAULT_TIER: &str = "free";
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
const PBKDF2_ITERATIONS: u32 = 100_000;

pub static USERNAME_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z0-9_-]{1,64}$").unwrap());

pub fn normalise_username(input: &str) -> Result<String, String> {
    let candidate = input.trim();
    if candidate.is_empty() {
        return Err("Username and password required.".to_string());
    }

    if !USERNAME_REGEX.is_match(candidate) {
        return Err("Username may only include letters, numbers, '_' or '-'".to_string());
    }

    Ok(candidate.to_string())
}

#[derive(Debug, Serialize, Deserialize)]
struct UserRecord {
    password: String,
    #[serde(default = "default_tier")]
    tier: String,
    #[serde(default)]
    last_set: Option<String>,
    #[serde(default)]
    last_model: Option<String>,
    #[serde(default = "default_render_markdown")]
    render_markdown: bool,
}

fn default_render_markdown() -> bool {
    true
}

fn default_tier() -> String {
    DEFAULT_TIER.to_string()
}

pub struct UserStore {
    base_dir: PathBuf,
    users_file: PathBuf,
    salts_dir: PathBuf,
}

pub enum CreateOutcome {
    Created,
    AlreadyExists,
}

#[derive(Debug)]
pub enum UserStoreError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Crypto(String),
}

impl fmt::Display for UserStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserStoreError::Io(err) => write!(f, "io error: {err}"),
            UserStoreError::Json(err) => write!(f, "json error: {err}"),
            UserStoreError::Crypto(msg) => write!(f, "crypto error: {msg}"),
        }
    }
}

impl std::error::Error for UserStoreError {}

impl From<std::io::Error> for UserStoreError {
    fn from(err: std::io::Error) -> Self {
        UserStoreError::Io(err)
    }
}

impl From<serde_json::Error> for UserStoreError {
    fn from(err: serde_json::Error) -> Self {
        UserStoreError::Json(err)
    }
}

impl UserStore {
    pub fn new() -> Result<Self, UserStoreError> {
        let base = env::var("HOST_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./data"));
        if !base.exists() {
            fs::create_dir_all(&base)?;
        }

        let users_file = base.join("users.json");
        if !users_file.exists() {
            let mut file = File::create(&users_file)?;
            file.write_all(b"{}")?;
        }

        let salts_dir = base.join("salts");
        if !salts_dir.exists() {
            fs::create_dir_all(&salts_dir)?;
        }

        Ok(Self {
            base_dir: base,
            users_file,
            salts_dir,
        })
    }

    pub fn create_user(
        &mut self,
        username: &str,
        hashed_password: &str,
    ) -> Result<CreateOutcome, UserStoreError> {
        let normalised = normalise_username(username).map_err(UserStoreError::Crypto)?;
        let mut users = self.load_users()?;
        if users.contains_key(&normalised) {
            return Ok(CreateOutcome::AlreadyExists);
        }

        users.insert(
            normalised,
            UserRecord {
                password: hashed_password.to_string(),
                tier: DEFAULT_TIER.to_string(),
                last_set: None,
                last_model: None,
                render_markdown: true,
            },
        );

        self.save_users(&users)?;
        Ok(CreateOutcome::Created)
    }

    pub fn validate_user(&self, username: &str, password: &str) -> Result<bool, UserStoreError> {
        let normalised = normalise_username(username).map_err(UserStoreError::Crypto)?;
        let users = self.load_users()?;
        if let Some(record) = users.get(&normalised) {
            verify(password, &record.password)
                .map_err(|err| UserStoreError::Crypto(err.to_string()))
        } else {
            Ok(false)
        }
    }

    pub fn derive_encryption_key(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Vec<u8>, UserStoreError> {
        if password.is_empty() {
            return Err(UserStoreError::Crypto("Password required".into()));
        }

        let normalised = normalise_username(username).map_err(UserStoreError::Crypto)?;
        let salt_path = self.salts_dir.join(format!("{normalised}_salt"));
        let mut salt = [0u8; SALT_LEN];
        if salt_path.exists() {
            let mut file = File::open(&salt_path)?;
            file.read_exact(&mut salt)?;
        } else {
            OsRng.fill_bytes(&mut salt);
            let mut file = File::create(&salt_path)?;
            file.write_all(&salt)?;
        }

        let mut derived = [0u8; KEY_LEN];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, PBKDF2_ITERATIONS, &mut derived);
        let encoded = STANDARD.encode(derived);
        Ok(encoded.into_bytes())
    }

    pub fn user_tier(&self, username: &str) -> Result<String, UserStoreError> {
        let normalised = normalise_username(username).map_err(UserStoreError::Crypto)?;
        let users = self.load_users()?;
        Ok(users
            .get(&normalised)
            .map(|record| record.tier.clone())
            .unwrap_or_else(|| DEFAULT_TIER.to_string()))
    }

    pub fn update_user_preferences(
        &mut self,
        username: &str,
        last_set: Option<String>,
        last_model: Option<String>,
        render_markdown: Option<bool>,
    ) -> Result<(), UserStoreError> {
        let normalised = normalise_username(username).map_err(UserStoreError::Crypto)?;
        let mut users = self.load_users()?;

        if let Some(record) = users.get_mut(&normalised) {
            if let Some(set) = last_set {
                record.last_set = Some(set);
            }
            if let Some(model) = last_model {
                record.last_model = Some(model);
            }
            if let Some(render) = render_markdown {
                record.render_markdown = render;
            }
        } else {
            return Err(UserStoreError::Crypto("User not found".into()));
        }

        self.save_users(&users)?;
        Ok(())
    }

    pub fn user_preferences(
        &self,
        username: &str,
    ) -> Result<(Option<String>, Option<String>, bool), UserStoreError> {
        let normalised = normalise_username(username).map_err(UserStoreError::Crypto)?;
        let users = self.load_users()?;

        if let Some(record) = users.get(&normalised) {
            Ok((
                record.last_set.clone(),
                record.last_model.clone(),
                record.render_markdown,
            ))
        } else {
            Ok((None, None, true))
        }
    }

    pub fn data_dir(&self) -> &PathBuf {
        &self.base_dir
    }

    fn load_users(&self) -> Result<HashMap<String, UserRecord>, UserStoreError> {
        let mut file = File::open(&self.users_file)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        if contents.trim().is_empty() {
            return Ok(HashMap::new());
        }

        let raw: Value = serde_json::from_str(&contents)?;
        let mut users = HashMap::new();
        if let Value::Object(map) = raw {
            for (key, value) in map.into_iter() {
                if let Ok(record) = serde_json::from_value::<UserRecord>(value) {
                    users.insert(key, record);
                }
            }
        }
        Ok(users)
    }

    fn save_users(&self, users: &HashMap<String, UserRecord>) -> Result<(), UserStoreError> {
        let mut file = File::create(&self.users_file)?;
        let json = serde_json::to_string_pretty(users)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }
}
