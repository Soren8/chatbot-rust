use std::{
    collections::HashMap,
    env,
    fs::{self, File},
    fmt,
    io::{Read, Write},
    path::PathBuf,
};

use axum::{
    body::{self, Body},
    http::{header, HeaderValue, Request, Response, StatusCode},
};
use bcrypt::DEFAULT_COST;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_urlencoded::from_bytes;
use tracing::{error, warn};

use chatbot_core::bridge;

static USERNAME_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9_-]{1,64}$").unwrap());

#[derive(Debug, Serialize, Deserialize)]
struct UserRecord {
    password: String,
    #[serde(default = "default_tier")]
    tier: String,
}

fn default_tier() -> String {
    "free".to_string()
}

pub async fn handle_signup_post(request: Request<Body>) -> Result<Response<Body>, (StatusCode, String)> {
    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    let cookie_header = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_owned());

    let body_bytes = body::to_bytes(body, 64 * 1024)
        .await
        .map_err(|err| {
            error!(?err, "failed to read signup body");
            (StatusCode::BAD_REQUEST, "Invalid request body".to_string())
        })?;

    let form: HashMap<String, String> = from_bytes(&body_bytes).map_err(|err| {
        warn!(?err, "failed to parse signup form");
        (StatusCode::BAD_REQUEST, "Invalid form payload".to_string())
    })?;

    let username_raw = form.get("username").map(|s| s.trim()).unwrap_or("");
    let password = form.get("password").map(|s| s.as_str()).unwrap_or("");
    let csrf_token = form.get("csrf_token").map(|s| s.as_str()).unwrap_or("");

    if username_raw.is_empty() || password.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Username and password required.".to_string(),
        ));
    }

    let csrf_valid = bridge::validate_csrf_token(cookie_header.as_deref(), csrf_token)
        .map_err(|err| {
            error!(?err, "failed to validate CSRF token via python bridge");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "bridge error".to_string(),
            )
        })?;

    if !csrf_valid {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid CSRF token".to_string(),
        ));
    }

    let username = match normalise_username(username_raw) {
        Ok(value) => value,
        Err(message) => {
            return Err((StatusCode::BAD_REQUEST, message));
        }
    };

    let hashed = bcrypt::hash(password, DEFAULT_COST).map_err(|err| {
        error!(?err, "failed to hash password");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to create user".to_string(),
        )
    })?;

    let mut store = UserStore::new().map_err(|err| {
        error!(?err, "failed to initialise user store");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to create user".to_string(),
        )
    })?;

    match store.create_user(&username, &hashed) {
        Ok(CreateOutcome::Created) => {}
        Ok(CreateOutcome::AlreadyExists) => {
            return Err((StatusCode::BAD_REQUEST, "User already exists.".to_string()));
        }
        Err(err) => {
            error!(?err, "failed to persist new user");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to create user".to_string(),
            ));
        }
    }

    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, HeaderValue::from_static("/login"))
        .body(Body::empty())
        .map_err(|err| {
            error!(?err, "failed to build redirect response");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Unable to create user".to_string(),
            )
        })
}

fn normalise_username(input: &str) -> Result<String, String> {
    let candidate = input.trim();
    if candidate.is_empty() {
        return Err("Username and password required.".to_string());
    }

    if !USERNAME_REGEX.is_match(candidate) {
        return Err("Username may only include letters, numbers, '_' or '-'".to_string());
    }

    Ok(candidate.to_string())
}

struct UserStore {
    users_file: PathBuf,
}

enum CreateOutcome {
    Created,
    AlreadyExists,
}

enum StoreError {
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl fmt::Debug for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Io(err) => write!(f, "io error: {err}"),
            StoreError::Json(err) => write!(f, "json error: {err}"),
        }
    }
}

impl From<std::io::Error> for StoreError {
    fn from(err: std::io::Error) -> Self {
        StoreError::Io(err)
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(err: serde_json::Error) -> Self {
        StoreError::Json(err)
    }
}

impl UserStore {
    fn new() -> Result<Self, StoreError> {
        let base = env::var("HOST_DATA_DIR").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("./data"));
        if !base.exists() {
            fs::create_dir_all(&base)?;
        }
        let users_file = base.join("users.json");
        if !users_file.exists() {
            let mut file = File::create(&users_file)?;
            file.write_all(b"{}")?;
        }
        Ok(Self { users_file })
    }

    fn create_user(&mut self, username: &str, hashed_password: &str) -> Result<CreateOutcome, StoreError> {
        let mut users = self.load_users()?;
        if users.contains_key(username) {
            return Ok(CreateOutcome::AlreadyExists);
        }
        users.insert(
            username.to_string(),
            UserRecord {
                password: hashed_password.to_string(),
                tier: "free".to_string(),
            },
        );
        self.save_users(&users)?;
        Ok(CreateOutcome::Created)
    }

    fn load_users(&self) -> Result<HashMap<String, UserRecord>, StoreError> {
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

    fn save_users(&self, users: &HashMap<String, UserRecord>) -> Result<(), StoreError> {
        let mut file = File::create(&self.users_file)?;
        let json = serde_json::to_string_pretty(users)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }
}
