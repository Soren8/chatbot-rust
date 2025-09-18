import os
import json
import time
import logging
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict

from app.config import Config

logger = logging.getLogger(__name__)

# Get base data directory from environment or use default
BASE_DATA_DIR = Path(os.getenv('HOST_DATA_DIR', 'data'))

# Update path constants to use Path objects
USERS_FILE = BASE_DATA_DIR / "users.json"
SETS_DIR = BASE_DATA_DIR / "user_sets"
SALT_DIR = BASE_DATA_DIR / "salts"

# Ensure necessary directories exist using Path objects
BASE_DATA_DIR.mkdir(parents=True, exist_ok=True)
SETS_DIR.mkdir(parents=True, exist_ok=True)
SALT_DIR.mkdir(parents=True, exist_ok=True)

import bcrypt
from base64 import b64encode
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Temporary storage for non-logged-in users
TEMPORARY_STORAGE = defaultdict(dict)

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SET_NAME_PATTERN = re.compile(r"^[A-Za-z0-9 _-]{1,64}$")


def validate_username(username: str) -> str:
    """Return a normalised username or raise ValueError if invalid."""
    if not isinstance(username, str):
        raise ValueError("Invalid username")
    candidate = username.strip()
    if not candidate or not USERNAME_PATTERN.fullmatch(candidate):
        raise ValueError("Username must be 1-64 chars of letters, numbers, '_' or '-' only")
    return candidate


def validate_set_name(set_name: str, allow_default: bool = True) -> str:
    """Return a normalised set name or raise ValueError if unsafe."""
    if set_name is None:
        set_name = "default" if allow_default else ""
    if not isinstance(set_name, str):
        raise ValueError("Invalid set name")
    candidate = set_name.strip()
    if allow_default and candidate == "":
        candidate = "default"
    if not candidate:
        raise ValueError("Set name is required")
    if candidate in {".", ".."}:
        raise ValueError("Set name cannot be '.' or '..'")
    if not SET_NAME_PATTERN.fullmatch(candidate):
        raise ValueError("Set name must be 1-64 chars using letters, numbers, spaces, '_' or '-' only")
    return candidate

def _ensure_users_file():
    if not USERS_FILE.exists():
        with USERS_FILE.open("w", encoding="utf-8") as f:
            json.dump({}, f)


_ensure_users_file()


def load_users() -> Dict:
    with USERS_FILE.open("r", encoding="utf-8") as f:
        raw_users = json.load(f) or {}

    migrated_users: Dict[str, Dict] = {}
    for raw_username, data in raw_users.items():
        try:
            username = validate_username(raw_username)
        except ValueError:
            logger.warning("Ignoring user with unsafe username stored on disk: %s", raw_username)
            continue

        if isinstance(data, str):
            entry = {"password": data, "tier": "free"}
        else:
            entry = dict(data)
            entry.setdefault("tier", "free")
        migrated_users[username] = entry

    # Rewrite if migration changed anything
    if migrated_users != raw_users:
        save_users(migrated_users)

    return migrated_users


def save_users(users: Dict):
    safe_users: Dict[str, Dict] = {}
    for raw_username, data in users.items():
        username = validate_username(raw_username)
        safe_users[username] = data
    with USERS_FILE.open("w", encoding="utf-8") as f:
        json.dump(safe_users, f, indent=2)


def get_user_tier(username: str) -> str:
    """Get the user's account tier"""
    username = validate_username(username)
    users = load_users()
    return users.get(username, {}).get("tier", "free")


def set_user_tier(username: str, tier: str):
    """Update a user's account tier"""
    username = validate_username(username)
    users = load_users()
    if username in users:
        users[username]["tier"] = tier
        save_users(users)
        return True
    return False


def create_user(username: str, password: str) -> bool:
    """
    Create a new user with Free tier by default
    """
    username = validate_username(username)
    users = load_users()
    if username in users:
        return False

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users[username] = {
        "password": hashed_password.decode('utf-8'),
        "tier": "free"
    }
    save_users(users)
    return True


def validate_user(username: str, password: str) -> bool:
    """
    Validate a username and password against stored hashed credentials.
    """
    username = validate_username(username)
    users = load_users()
    if username in users:
        stored_pass = users[username].get("password", "")
        return bcrypt.checkpw(password.encode('utf-8'), stored_pass.encode('utf-8'))
    return False


def get_user_salt(username: str) -> bytes:
    """Retrieve or generate a per-user salt."""
    username = validate_username(username)
    filepath = SALT_DIR / f"{username}_salt"
    if filepath.exists():
        with filepath.open("rb") as f:
            return f.read()
    new_salt = os.urandom(16)
    with filepath.open("wb") as f:
        f.write(new_salt)
    return new_salt

def _get_encryption_key(password: str, salt: bytes) -> bytes:
    """Generate encryption key from password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    return b64encode(key)

def get_user_sets(username: str) -> dict:
    """Get list of saved memory/prompt sets for a user"""
    username = validate_username(username)
    user_sets_dir = SETS_DIR / username
    user_sets_dir.mkdir(parents=True, exist_ok=True)
    
    sets_file = user_sets_dir / "sets.json"
    if not sets_file.exists():
        with sets_file.open("w", encoding="utf-8") as f:
            json.dump({"default": {"created": time.time()}}, f)

    with sets_file.open("r", encoding="utf-8") as f:
        raw_sets = json.load(f) or {}

    sanitised_sets = {}
    changed = False
    for raw_name, meta in raw_sets.items():
        try:
            name = validate_set_name(raw_name)
        except ValueError:
            logger.warning("Dropping unsafe set name '%s' for user '%s'", raw_name, username)
            changed = True
            continue
        sanitised_sets[name] = meta
        if name != raw_name:
            changed = True

    if changed:
        with sets_file.open("w", encoding="utf-8") as f:
            json.dump(sanitised_sets, f, indent=2)

    return sanitised_sets


def load_user_memory(username: str, set_name: str = "default", password: str = None) -> str:
    username = validate_username(username)
    set_name = validate_set_name(set_name)
    # Check if user is logged in
    from flask import session
    if 'username' not in session or session['username'] != username:
        # Return temporary memory if available
        if username in TEMPORARY_STORAGE and 'memory' in TEMPORARY_STORAGE[username]:
            return TEMPORARY_STORAGE[username]['memory']
        return ""
    
    filepath = SETS_DIR / username / f"{set_name}_memory.txt"
    if not filepath.exists() or filepath.stat().st_size == 0:
        return ""
        
    sets = get_user_sets(username)
    if sets.get(set_name, {}).get("encrypted", False):
        # Skip decryption if file is empty
        if os.path.getsize(filepath) == 0:
            return ""
            
        # Require explicit password for decryption
        if not password:
            raise ValueError("Password required for decryption")
        salt = get_user_salt(username)
        key = _get_encryption_key(password, salt)
        f = Fernet(key)
        with filepath.open("rb") as file:
            encrypted_data = file.read()
        return f.decrypt(encrypted_data).decode()
    else:
        with filepath.open("r", encoding="utf-8") as f:
            return f.read()

def save_user_memory(username: str, memory_content: str, set_name: str = "default", password: str = None):
    logger.debug(f"Saving memory for set: {set_name}")
    
    # Check if user is logged in
    from flask import session
    username = validate_username(username)
    set_name = validate_set_name(set_name)

    if 'username' not in session or session['username'] != username:
        TEMPORARY_STORAGE[username]['memory'] = memory_content
        return
        
    user_sets_dir = SETS_DIR / username
    user_sets_dir.mkdir(parents=True, exist_ok=True)
    
    # Update sets.json
    sets = get_user_sets(username)
    sets[set_name] = {
        "created": time.time(),
        "encrypted": True
    }

    sets_file = user_sets_dir / "sets.json"
    with sets_file.open("w", encoding="utf-8") as f:
        json.dump(sets, f, indent=2)
    logger.debug(f"Updated sets.json for {username}/{set_name}")
    
    # Require explicit password for encryption
    if not password:
        raise ValueError("Password required for encryption")
    
    # Always encrypt using password
    salt = get_user_salt(username)
    key = _get_encryption_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(memory_content.encode())
    
    filepath = user_sets_dir / f"{set_name}_memory.txt"
    filepath.write_bytes(encrypted_data)
        
    logger.debug(f"Successfully saved encrypted memory for {username}/{set_name}")

def load_user_system_prompt(username: str, set_name: str = "default", password: str = None) -> str:
    username = validate_username(username)
    set_name = validate_set_name(set_name)
    # Check if user is logged in
    from flask import session
    if 'username' not in session or session['username'] != username:
        # Return temporary prompt if available
        if username in TEMPORARY_STORAGE and 'prompt' in TEMPORARY_STORAGE[username]:
            return TEMPORARY_STORAGE[username]['prompt']
        return Config.DEFAULT_SYSTEM_PROMPT
    
    filepath = SETS_DIR / username / f"{set_name}_prompt.txt"
    if not filepath.exists() or filepath.stat().st_size == 0:
        return Config.DEFAULT_SYSTEM_PROMPT

    try:
        sets = get_user_sets(username)
    except ValueError as exc:
        logger.error("Failed to load sets for user %s: %s", username, exc)
        return Config.DEFAULT_SYSTEM_PROMPT
    
    if sets.get(set_name, {}).get("encrypted", False):
        # Skip decryption if file is empty
        if os.path.getsize(filepath) == 0:
            return Config.DEFAULT_SYSTEM_PROMPT
            
        try:
            if not password:
                raise ValueError("Password required for decryption")
            
            salt = get_user_salt(username)
            key = _get_encryption_key(password, salt)
            f = Fernet(key)
            
            with filepath.open("rb") as file:
                encrypted_data = file.read()
                logger.debug(f"Read {len(encrypted_data)} bytes from {filepath}")
                
            try:
                decrypted = f.decrypt(encrypted_data).decode()
                logger.debug(f"Successfully decrypted {len(decrypted)} character prompt")
                return decrypted
            except Exception as e:
                logger.error(f"Decryption failed for {username}/{set_name}: {str(e)}")
                # Try decoding raw bytes instead of re-reading
                logger.debug("Attempting to decode raw bytes as fallback")
                return encrypted_data.decode('utf-8', errors='replace')
                    
        except Exception as e:
            logger.error(f"Error decrypting prompt for {username}/{set_name}: {str(e)}")
            return "You are a helpful AI assistant based on the Dolphin 3 8B model. Provide clear and concise answers to user queries."
    else:
        try:
            with filepath.open("r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading plaintext prompt for {username}/{set_name}: {str(e)}")
            return "You are a helpful AI assistant based on the Dolphin 3 8B model. Provide clear and concise answers to user queries."

def save_user_chat_history(username: str, full_history: list, set_name: str = "default", password: str = None):
    logger.debug(f"Saving chat history for set: {set_name}")
    """Save chat history for a user's set"""
    username = validate_username(username)
    set_name = validate_set_name(set_name)

    user_sets_dir = SETS_DIR / username
    user_sets_dir.mkdir(parents=True, exist_ok=True)
    
    # Update sets.json
    sets = get_user_sets(username)
    
    # Always mark as encrypted
    sets[set_name] = {
        "created": time.time(),
        "encrypted": True
    }
    
    sets_file = user_sets_dir / "sets.json"
    with sets_file.open("w", encoding='utf-8') as f:
        json.dump(sets, f, indent=2)
    logger.debug(f"Updated sets.json for {username}/{set_name}")
    
    if not password:
        raise ValueError("Password required for encryption")
    
    salt = get_user_salt(username)
    key = _get_encryption_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(json.dumps(full_history).encode())
    
    filepath = user_sets_dir / f"{set_name}_history.json"
    logger.debug(f"Writing history file to: {filepath}")
    filepath.write_bytes(encrypted_data)
    logger.debug(f"Successfully wrote {len(encrypted_data)} bytes to history file")
    
    logger.debug(f"Successfully saved encrypted chat history for user {username}, set {set_name}")

def load_user_chat_history(username: str, set_name: str = "default", password: str = None) -> list:
    """Load chat history for a user's set"""
    username = validate_username(username)
    set_name = validate_set_name(set_name)
    # Add check for logged-in status
    from flask import session
    if 'username' not in session or session['username'] != username:
        return []
    
    filepath = SETS_DIR / username / f"{set_name}_history.json"
    if not filepath.exists() or filepath.stat().st_size == 0:
        return []
        
    sets = get_user_sets(username)

    if sets.get(set_name, {}).get("encrypted", False):
        # Skip decryption if file is empty
        if os.path.getsize(filepath) == 0:
            return []
            
        try:
            if not password:
                raise ValueError("Password required for decryption")
            
            salt = get_user_salt(username)
            key = _get_encryption_key(password, salt)
            f = Fernet(key)
            
            with filepath.open("rb") as file:
                encrypted_data = file.read()
                
            try:
                return json.loads(f.decrypt(encrypted_data).decode())
            except Exception as e:
                logger.error(f"Decryption failed for {username}/{set_name}: {str(e)}")
                # Try reading as plaintext in case encryption flag was set incorrectly
                with filepath.open("r", encoding="utf-8") as f:
                    return json.load(f)
                    
        except Exception as e:
            logger.error(f"Error decrypting history for {username}/{set_name}: {str(e)}")
            return []
    else:
        try:
            with filepath.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading plaintext history for {username}/{set_name}: {str(e)}")
            return []

def save_user_system_prompt(username: str, system_prompt: str, set_name: str = "default", password: str = None):
    username = validate_username(username)
    set_name = validate_set_name(set_name)
    from flask import session
    if 'username' not in session or session['username'] != username:
        TEMPORARY_STORAGE[username]['prompt'] = system_prompt
        return
        
    user_sets_dir = SETS_DIR / username
    user_sets_dir.mkdir(parents=True, exist_ok=True)
    
    sets = get_user_sets(username)
    
    # Always mark as encrypted
    sets[set_name] = {
        "created": time.time(),
        "encrypted": True
    }
    
    sets_file = user_sets_dir / "sets.json"
    with sets_file.open("w", encoding='utf-8') as f:
        json.dump(sets, f, indent=2)
    
    if not password:
        raise ValueError("Password required for encryption")
    
    salt = get_user_salt(username)
    key = _get_encryption_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(system_prompt.encode())
    
    filepath = user_sets_dir / f"{set_name}_prompt.txt"
    with filepath.open("wb") as f:
        f.write(encrypted_data)
        
    logger.debug(f"Successfully saved encrypted prompt for {username}/{set_name}")

def create_new_set(username: str, set_name: str) -> bool:
    """Create a new empty set for a user"""
    username = validate_username(username)
    try:
        set_name = validate_set_name(set_name, allow_default=False)
    except ValueError:
        return False

    user_sets_dir = SETS_DIR / username
    user_sets_dir.mkdir(parents=True, exist_ok=True)
    
    sets = get_user_sets(username)
    
    if set_name in sets:
        return False
        
    sets[set_name] = {"created": time.time()}
    
    sets_file = user_sets_dir / "sets.json"
    with sets_file.open("w", encoding="utf-8") as f:
        json.dump(sets, f, indent=2)
    
    return True

def delete_set(username: str, set_name: str) -> bool:
    """Delete a set and its associated files"""
    username = validate_username(username)
    set_name = validate_set_name(set_name)

    if set_name == "default":
        return False
        
    user_sets_dir = SETS_DIR / username
    sets_file = user_sets_dir / "sets.json"
    
    if not sets_file.exists():
        return False
        
    with sets_file.open("r", encoding='utf-8') as f:
        sets = json.load(f)
    
    if set_name not in sets:
        return False
        
    # Remove from sets.json
    del sets[set_name]
    with sets_file.open("w", encoding='utf-8') as f:
        json.dump(sets, f, indent=2)
    
    # Delete associated files
    memory_file = user_sets_dir / f"{set_name}_memory.txt"
    prompt_file = user_sets_dir / f"{set_name}_prompt.txt"
    history_file = user_sets_dir / f"{set_name}_history.json"
    
    if memory_file.exists():
        memory_file.unlink()
    if prompt_file.exists():
        prompt_file.unlink()
    if history_file.exists():
        history_file.unlink()
    
    return True
