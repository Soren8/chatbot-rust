import os
import json
import time
import logging
from collections import defaultdict
from pathlib import Path
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
from typing import Dict
from base64 import b64encode, b64decode
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Temporary storage for non-logged-in users
TEMPORARY_STORAGE = defaultdict(dict)

# Initialize users file if it doesn't exist
if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, "w") as f:
        json.dump({}, f)

def load_users() -> Dict:
    with open(USERS_FILE, "r") as f:
        users = json.load(f)
    
    # Migrate old format to new format
    for username, data in users.items():
        if isinstance(data, str):  # Old format
            users[username] = {
                "password": data,
                "tier": "free"  # Explicit tier field
            }
        elif "tier" not in users[username]:  # New format migration
            users[username]["tier"] = "free"
    
    return users  # The 'tier' field will remain plaintext

def save_users(users: Dict):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

def get_user_tier(username: str) -> str:
    """Get the user's account tier"""
    users = load_users()
    return users.get(username, {}).get("tier", "free")

def set_user_tier(username: str, tier: str):
    """Update a user's account tier"""
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
    users = load_users()
    if username in users:
        return False

    # Store password hashed for security
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users[username] = {
        "password": hashed_password.decode('utf-8'),  # Hashed
        "tier": "free"  # Plaintext
    }
    save_users(users)
    return True

def validate_user(username: str, password: str) -> bool:
    """
    Validate a username and password against stored hashed credentials.
    """
    users = load_users()
    if username in users:
        stored_pass = users[username].get("password", "")
        return bcrypt.checkpw(password.encode('utf-8'), stored_pass.encode('utf-8'))
    return False

def get_user_salt(username: str) -> bytes:
    """Retrieve or generate a per-user salt."""
    filepath = SALT_DIR / f"{username}_salt"
    if filepath.exists():
        with filepath.open("rb") as f:
            return f.read()
    # Generate a new salt
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
    user_sets_dir = SETS_DIR / username
    user_sets_dir.mkdir(parents=True, exist_ok=True)
    
    sets_file = user_sets_dir / "sets.json"
    if not sets_file.exists():
        with sets_file.open("w") as f:
            json.dump({"default": {"created": time.time()}}, f)
    
    with sets_file.open("r") as f:
        return json.load(f)

def load_user_memory(username: str, set_name: str = "default") -> str:
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
        
    # Check if set is encrypted
    sets_file = SETS_DIR / username / "sets.json"
    with sets_file.open("r") as f:
        sets = json.load(f)
    
    if set_name in sets and sets[set_name].get("encrypted", False):
        # Skip decryption if file is empty
        if os.path.getsize(filepath) == 0:
            return ""
            
        # Get password from session to derive encryption key
        from flask import session
        if 'password' not in session:
            raise ValueError("Password not available for decryption")
        salt = get_user_salt(username)
        key = _get_encryption_key(session['password'], salt)
        f = Fernet(key)
        with open(filepath, "rb") as file:
            encrypted_data = file.read()
        return f.decrypt(encrypted_data).decode()
    else:
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()

def save_user_memory(username: str, memory_content: str, set_name: str = "default", password: str = None):
    logger.debug(f"Saving memory for set: {set_name}")
    max_size = 5000
    memory_content = memory_content[:max_size]
    
    # Check if user is logged in
    from flask import session
    if 'username' not in session or session['username'] != username:
        TEMPORARY_STORAGE[username]['memory'] = memory_content
        return
        
    user_sets_dir = Path(SETS_DIR) / username
    user_sets_dir.mkdir(parents=True, exist_ok=True)
    
    # Update sets.json
    sets_file = user_sets_dir / "sets.json"
    if sets_file.exists():
        with sets_file.open("r", encoding='utf-8') as f:
            sets = json.load(f)
    else:
        sets = {}
    
    # Always mark as encrypted
    sets[set_name] = {
        "created": time.time(),
        "encrypted": True
    }
    
    sets_file.write_text(json.dumps(sets), encoding='utf-8')
    logger.debug(f"Updated sets.json for {username}/{set_name}")
    
    # Get password from session if not provided
    if not password:
        from flask import session
        if 'password' not in session:
            raise ValueError("Password not available for encryption")
        password = session['password']
    
    # Always encrypt using password
    salt = get_user_salt(username)
    key = _get_encryption_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(memory_content.encode())
    
    filepath = user_sets_dir / f"{set_name}_memory.txt"
    filepath.write_bytes(encrypted_data)
        
    logger.debug(f"Successfully saved encrypted memory for {username}/{set_name}")

def load_user_system_prompt(username: str, set_name: str = "default", password: str = None) -> str:
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

    # Check if set is encrypted
    sets_file = SETS_DIR / username / "sets.json"
    try:
        with sets_file.open("r", encoding='utf-8') as f:
            sets = json.load(f)
    except Exception as e:
        logger.error(f"Error loading sets.json for {username}: {str(e)}")
        return Config.DEFAULT_SYSTEM_PROMPT
    
    if set_name in sets and sets[set_name].get("encrypted", False):
        # Skip decryption if file is empty
        if os.path.getsize(filepath) == 0:
            return Config.DEFAULT_SYSTEM_PROMPT
            
        try:
            if not password:
                # Try to get password from session if not provided
                from flask import session
                if 'password' not in session:
                    logger.error(f"Password not available for decryption for {username}")
                    return Config.DEFAULT_SYSTEM_PROMPT
                password = session['password']
            
            salt = get_user_salt(username)
            key = _get_encryption_key(password, salt)
            f = Fernet(key)
            
            with open(filepath, "rb") as file:
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
            with open(filepath, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading plaintext prompt for {username}/{set_name}: {str(e)}")
            return "You are a helpful AI assistant based on the Dolphin 3 8B model. Provide clear and concise answers to user queries."

def save_user_chat_history(username: str, full_history: list, set_name: str = "default", password: str = None):
    logger.debug(f"Saving chat history for set: {set_name}")
    """Save chat history for a user's set"""
    user_sets_dir = Path(SETS_DIR) / username
    user_sets_dir.mkdir(parents=True, exist_ok=True)
    
    # Update sets.json
    sets_file = user_sets_dir / "sets.json"
    if sets_file.exists():
        with sets_file.open("r", encoding='utf-8') as f:
            sets = json.load(f)
    else:
        sets = {}
    
    # Always mark as encrypted
    sets[set_name] = {
        "created": time.time(),
        "encrypted": True
    }
    
    sets_file.write_text(json.dumps(sets), encoding='utf-8')
    logger.debug(f"Updated sets.json for {username}/{set_name}")
    
    if not password:
        from flask import session
        if 'password' not in session:
            raise ValueError("Password not available for encryption")
        password = session['password']
    
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
    # Add check for logged-in status
    from flask import session
    if 'username' not in session or session['username'] != username:
        return []
    
    filepath = Path(SETS_DIR) / username / f"{set_name}_history.json"
    if not filepath.exists() or filepath.stat().st_size == 0:
        return []
        
    # Check if set is encrypted
    sets_file = Path(SETS_DIR) / username / "sets.json"
    try:
        with open(sets_file, "r") as f:
            sets = json.load(f)
    except Exception as e:
        logger.error(f"Error loading sets.json for {username}: {str(e)}")
        return []
    
    if set_name in sets and sets[set_name].get("encrypted", False):
        # Skip decryption if file is empty
        if os.path.getsize(filepath) == 0:
            return []
            
        try:
            if not password:
                # Try to get password from session if not provided
                from flask import session
                if 'password' not in session:
                    logger.error(f"Password not available for decryption for {username}")
                    return []
                password = session['password']
            
            salt = get_user_salt(username)
            key = _get_encryption_key(password, salt)
            f = Fernet(key)
            
            with open(filepath, "rb") as file:
                encrypted_data = file.read()
                
            try:
                return json.loads(f.decrypt(encrypted_data).decode())
            except Exception as e:
                logger.error(f"Decryption failed for {username}/{set_name}: {str(e)}")
                # Try reading as plaintext in case encryption flag was set incorrectly
                with open(filepath, "r", encoding="utf-8") as f:
                    return json.load(f)
                    
        except Exception as e:
            logger.error(f"Error decrypting history for {username}/{set_name}: {str(e)}")
            return []
    else:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading plaintext history for {username}/{set_name}: {str(e)}")
            return []

def save_user_system_prompt(username: str, system_prompt: str, set_name: str = "default", password: str = None):
    max_size = 3000
    system_prompt = system_prompt[:max_size]
    
    from flask import session
    if 'username' not in session or session['username'] != username:
        TEMPORARY_STORAGE[username]['prompt'] = system_prompt
        return
        
    user_sets_dir = SETS_DIR / username
    user_sets_dir.mkdir(parents=True, exist_ok=True)
    
    sets_file = user_sets_dir / "sets.json"
    if sets_file.exists():
        with sets_file.open("r", encoding='utf-8') as f:
            sets = json.load(f)
    else:
        sets = {}
    
    # Always mark as encrypted
    sets[set_name] = {
        "created": time.time(),
        "encrypted": True
    }
    
    with sets_file.open("w", encoding='utf-8') as f:
        json.dump(sets, f)
    
    if not password:
        from flask import session
        if 'password' not in session:
            raise ValueError("Password not available for encryption")
        password = session['password']
    
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
    if not set_name or set_name.isspace():
        return False
        
    user_sets_dir = SETS_DIR / username
    user_sets_dir.mkdir(parents=True, exist_ok=True)
    
    sets_file = user_sets_dir / "sets.json"
    if sets_file.exists():
        with sets_file.open("r", encoding='utf-8') as f:
            sets = json.load(f)
    else:
        sets = {}
    
    if set_name in sets:
        return False
        
    sets[set_name] = {"created": time.time()}
    
    with open(sets_file, "w") as f:
        json.dump(sets, f)
    
    return True

def delete_set(username: str, set_name: str) -> bool:
    """Delete a set and its associated files"""
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
        json.dump(sets, f)
    
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
