import os
import json
import time
import logging

logger = logging.getLogger(__name__)
import bcrypt
from typing import Dict
from base64 import b64encode, b64decode
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MEMORY_DIR = "data/memory"
SYSTEM_PROMPT_DIR = "data/system_prompts"
USERS_FILE = "data/users.json"
SETS_DIR = "data/user_sets"
SALT_DIR = "data/salts"

# Ensure necessary directories exist
os.makedirs("data", exist_ok=True)
os.makedirs(MEMORY_DIR, exist_ok=True)
os.makedirs(SYSTEM_PROMPT_DIR, exist_ok=True)
os.makedirs(SETS_DIR, exist_ok=True)
os.makedirs(SALT_DIR, exist_ok=True)

# Initialize users file if it doesn't exist
if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, "w") as f:
        json.dump({}, f)

def load_users() -> Dict[str, str]:
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users: Dict[str, str]):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f)

def create_user(username: str, password: str) -> bool:
    """
    Create a new user with a hashed password.
    """
    users = load_users()
    if username in users:
        return False

    # Generate a hashed password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users[username] = hashed_password.decode('utf-8')  # Store as a string

    save_users(users)
    return True

def validate_user(username: str, password: str) -> bool:
    """
    Validate a username and password against stored hashed credentials.
    """
    users = load_users()
    if username in users:
        stored_hashed_password = users[username].encode('utf-8')
        # Check if the provided password matches the stored hash
        return bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password)
    return False

def get_user_salt(username: str) -> bytes:
    """Retrieve or generate a per-user salt."""
    filepath = os.path.join(SALT_DIR, f"{username}_salt")
    if os.path.exists(filepath):
        with open(filepath, "rb") as f:
            return f.read()
    # Generate a new salt
    new_salt = os.urandom(16)
    with open(filepath, "wb") as f:
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
    user_sets_dir = os.path.join(SETS_DIR, username)
    os.makedirs(user_sets_dir, exist_ok=True)
    
    if not os.path.exists(os.path.join(user_sets_dir, "sets.json")):
        with open(os.path.join(user_sets_dir, "sets.json"), "w") as f:
            json.dump({"default": {"created": time.time()}}, f)
    
    with open(os.path.join(user_sets_dir, "sets.json"), "r") as f:
        return json.load(f)

def load_user_memory(username: str, set_name: str = "default") -> str:
    filepath = os.path.join(SETS_DIR, username, f"{set_name}_memory.txt")
    if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
        return ""
        
    # Check if set is encrypted
    sets_file = os.path.join(SETS_DIR, username, "sets.json")
    with open(sets_file, "r") as f:
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

def save_user_memory(username: str, memory_content: str, set_name: str = "default"):
    max_size = 5000  # Maximum allowed memory size in characters
    memory_content = memory_content[:max_size]
    
    # Ensure user directory exists
    user_sets_dir = os.path.join(SETS_DIR, username)
    os.makedirs(user_sets_dir, exist_ok=True)
    
    # Update sets.json
    sets_file = os.path.join(user_sets_dir, "sets.json")
    if os.path.exists(sets_file):
        with open(sets_file, "r") as f:
            sets = json.load(f)
    else:
        sets = {}
    
    sets[set_name] = {
        "created": time.time()
    }
    
    with open(sets_file, "w") as f:
        json.dump(sets, f)
    
    # Always encrypt
    from flask import session
    if 'password' not in session:
        raise ValueError("Password not available for encryption")
    salt = get_user_salt(username)
    key = _get_encryption_key(session['password'], salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(memory_content.encode())
    filepath = os.path.join(user_sets_dir, f"{set_name}_memory.txt")
    with open(filepath, "wb") as f:
        f.write(encrypted_data)
    logger.debug(f"Successfully saved encrypted memory for {username}/{set_name}")

def load_user_system_prompt(username: str, set_name: str = "default") -> str:
    filepath = os.path.join(SETS_DIR, username, f"{set_name}_prompt.txt")
    if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
        return "You are a helpful AI assistant based on the Dolphin 3 8B model. Provide clear and concise answers to user queries."

    # Check if set is encrypted
    sets_file = os.path.join(SETS_DIR, username, "sets.json")
    try:
        with open(sets_file, "r") as f:
            sets = json.load(f)
    except Exception as e:
        logger.error(f"Error loading sets.json for {username}: {str(e)}")
        return "You are a helpful AI assistant based on the Dolphin 3 8B model. Provide clear and concise answers to user queries."
    
    if set_name in sets and sets[set_name].get("encrypted", False):
        # Skip decryption if file is empty
        if os.path.getsize(filepath) == 0:
            return "You are a helpful AI assistant based on the Dolphin 3 8B model. Provide clear and concise answers to user queries."
            
        try:
            from flask import session
            if 'password' not in session:
                logger.error(f"Password not available for decryption for {username}")
                return "You are a helpful AI assistant based on the Dolphin 3 8B model. Provide clear and concise answers to user queries."
            
            salt = get_user_salt(username)
            key = _get_encryption_key(session['password'], salt)
            f = Fernet(key)
            
            with open(filepath, "rb") as file:
                encrypted_data = file.read()
                
            try:
                return f.decrypt(encrypted_data).decode()
            except Exception as e:
                logger.error(f"Decryption failed for {username}/{set_name}: {str(e)}")
                # Try reading as plaintext in case encryption flag was set incorrectly
                with open(filepath, "r", encoding="utf-8") as f:
                    return f.read()
                    
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

def save_user_chat_history(username: str, history: list, set_name: str = "default", password: str = None):
    """Save chat history for a user's set"""
    user_sets_dir = os.path.join(SETS_DIR, username)
    os.makedirs(user_sets_dir, exist_ok=True)
    logger.debug(f"Ensured user sets directory exists: {user_sets_dir}")
    
    # Update sets.json
    sets_file = os.path.join(user_sets_dir, "sets.json")
    if os.path.exists(sets_file):
        with open(sets_file, "r") as f:
            sets = json.load(f)
        logger.debug(f"Loaded existing sets.json for user {username}")
    else:
        sets = {}
        logger.debug(f"Creating new sets.json for user {username}")
    
    
    # Update set info
    sets[set_name] = {
        "created": time.time(),
        "encrypted": True  # Always encrypt
    }
    
    with open(sets_file, "w") as f:
        json.dump(sets, f)
    logger.debug(f"Updated sets.json for user {username} with set {set_name} and encryption status True")
    
    filepath = os.path.join(user_sets_dir, f"{set_name}_history.json")
    logger.debug(f"Saving chat history for user {username}, set {set_name} to file: {filepath}")
    
    try:
        try:
            if not password:
                logger.error(f"Password required for encryption")
                raise ValueError("Password required for encryption")
            
            salt = get_user_salt(username)
            key = _get_encryption_key(password, salt)
            f = Fernet(key)
            encrypted_data = f.encrypt(json.dumps(history).encode())
            with open(filepath, "wb") as f:
                f.write(encrypted_data)
            logger.debug(f"Successfully saved encrypted chat history for user {username}, set {set_name}")
            return
        except RuntimeError:  # Working outside of request context
            logger.error(f"Outside request context, cannot save encrypted data")
            raise ValueError("Cannot save encrypted data outside request context")
                
        # Save as plaintext if not encrypted
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(history, f)
        logger.debug(f"Successfully saved plaintext chat history for user {username}, set {set_name}")
    except Exception as e:
        logger.error(f"Failed to save chat history: {str(e)}", exc_info=True)
        raise

def load_user_chat_history(username: str, set_name: str = "default") -> list:
    """Load chat history for a user's set"""
    filepath = os.path.join(SETS_DIR, username, f"{set_name}_history.json")
    if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
        return []
        
    # Check if set is encrypted
    sets_file = os.path.join(SETS_DIR, username, "sets.json")
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
            from flask import session
            if 'password' not in session:
                logger.error(f"Password not available for decryption for {username}")
                return []
            
            salt = get_user_salt(username)
            key = _get_encryption_key(session['password'], salt)
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

def save_user_system_prompt(username: str, system_prompt: str, set_name: str = "default"):
    max_size = 3000  # Maximum allowed system prompt size in characters
    system_prompt = system_prompt[:max_size]
    
    # Ensure user directory exists
    user_sets_dir = os.path.join(SETS_DIR, username)
    os.makedirs(user_sets_dir, exist_ok=True)
    
    # Update sets.json
    sets_file = os.path.join(user_sets_dir, "sets.json")
    if os.path.exists(sets_file):
        with open(sets_file, "r") as f:
            sets = json.load(f)
    else:
        sets = {}
    
    sets[set_name] = {
        "created": time.time(),
        "encrypted": True  # Always mark as encrypted
    }
    
    with open(sets_file, "w") as f:
        json.dump(sets, f)
    
    # Always encrypt using session password
    from flask import session
    if 'password' not in session:
        raise ValueError("Password not available for encryption")
    
    salt = get_user_salt(username)
    key = _get_encryption_key(session['password'], salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(system_prompt.encode())
    
    filepath = os.path.join(user_sets_dir, f"{set_name}_prompt.txt")
    with open(filepath, "wb") as f:
        f.write(encrypted_data)
        
    logger.debug(f"Successfully saved encrypted prompt for {username}/{set_name}")

def create_new_set(username: str, set_name: str) -> bool:
    """Create a new empty set for a user"""
    if not set_name or set_name.isspace():
        return False
        
    user_sets_dir = os.path.join(SETS_DIR, username)
    os.makedirs(user_sets_dir, exist_ok=True)
    
    sets_file = os.path.join(user_sets_dir, "sets.json")
    if os.path.exists(sets_file):
        with open(sets_file, "r") as f:
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
        
    user_sets_dir = os.path.join(SETS_DIR, username)
    sets_file = os.path.join(user_sets_dir, "sets.json")
    
    if not os.path.exists(sets_file):
        return False
        
    with open(sets_file, "r") as f:
        sets = json.load(f)
    
    if set_name not in sets:
        return False
        
    # Remove from sets.json
    del sets[set_name]
    with open(sets_file, "w") as f:
        json.dump(sets, f)
    
    # Delete associated files
    memory_file = os.path.join(user_sets_dir, f"{set_name}_memory.txt")
    prompt_file = os.path.join(user_sets_dir, f"{set_name}_prompt.txt")
    history_file = os.path.join(user_sets_dir, f"{set_name}_history.json")
    
    if os.path.exists(memory_file):
        os.remove(memory_file)
    if os.path.exists(prompt_file):
        os.remove(prompt_file)
    if os.path.exists(history_file):
        os.remove(history_file)
    
    return True
