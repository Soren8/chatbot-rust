import os
import json
import time
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

# Ensure necessary directories exist
os.makedirs(MEMORY_DIR, exist_ok=True)
os.makedirs(SYSTEM_PROMPT_DIR, exist_ok=True)
os.makedirs(SETS_DIR, exist_ok=True)
os.makedirs("data", exist_ok=True)

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

def _get_encryption_key(password_hash: bytes) -> bytes:
    """Generate encryption key from password hash"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'static_salt',  # Using static salt since we're using the hash
        iterations=100000,
    )
    key = kdf.derive(password_hash)
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
    if not os.path.exists(filepath):
        return ""
        
    # Check if set is encrypted
    sets_file = os.path.join(SETS_DIR, username, "sets.json")
    with open(sets_file, "r") as f:
        sets = json.load(f)
    
    if set_name in sets and sets[set_name].get("encrypted", False):
        # Get user's password hash to derive encryption key
        with open(USERS_FILE, "r") as f:
            users = json.load(f)
        password_hash = users[username].encode('utf-8')
        key = _get_encryption_key(password_hash)
        f = Fernet(key)
        with open(filepath, "rb") as file:
            encrypted_data = file.read()
        return f.decrypt(encrypted_data).decode()
    else:
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()

def save_user_memory(username: str, memory_content: str, set_name: str = "default", encrypted: bool = False):
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
        "created": time.time(),
        "encrypted": encrypted
    }
    
    with open(sets_file, "w") as f:
        json.dump(sets, f)
    
    # Save memory content
    filepath = os.path.join(user_sets_dir, f"{set_name}_memory.txt")
    
    if encrypted:
        # Get user's password hash to derive encryption key
        with open(USERS_FILE, "r") as f:
            users = json.load(f)
        password_hash = users[username].encode('utf-8')
        key = _get_encryption_key(password_hash)
        f = Fernet(key)
        encrypted_data = f.encrypt(memory_content.encode())
        with open(filepath, "wb") as f:
            f.write(encrypted_data)
    else:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(memory_content)

def load_user_system_prompt(username: str, set_name: str = "default") -> str:
    filepath = os.path.join(SETS_DIR, username, f"{set_name}_prompt.txt")
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()
    # Default system prompt if none is saved
    return "You are a helpful AI assistant based on the Dolphin 3 8B model. Provide clear and concise answers to user queries."

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
    
    sets[set_name] = {"created": time.time()}
    
    with open(sets_file, "w") as f:
        json.dump(sets, f)
    
    # Save prompt content
    filepath = os.path.join(user_sets_dir, f"{set_name}_prompt.txt")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(system_prompt)

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
    
    if os.path.exists(memory_file):
        os.remove(memory_file)
    if os.path.exists(prompt_file):
        os.remove(prompt_file)
    
    return True
