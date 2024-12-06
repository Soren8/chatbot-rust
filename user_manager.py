import os
import json
import bcrypt
from typing import Dict

MEMORY_DIR = "data/memory"
SYSTEM_PROMPT_DIR = "data/system_prompts"
USERS_FILE = "data/users.json"

# Ensure necessary directories exist
os.makedirs(MEMORY_DIR, exist_ok=True)
os.makedirs(SYSTEM_PROMPT_DIR, exist_ok=True)
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

def load_user_memory(username: str) -> str:
    filepath = os.path.join(MEMORY_DIR, f"{username}.txt")
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()
    return ""

def save_user_memory(username: str, memory_content: str):
    max_size = 5000  # Maximum allowed memory size in characters
    memory_content = memory_content[:max_size]
    filepath = os.path.join(MEMORY_DIR, f"{username}.txt")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(memory_content)

def load_user_system_prompt(username: str) -> str:
    filepath = os.path.join(SYSTEM_PROMPT_DIR, f"{username}.txt")
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()
    # Default system prompt if none is saved
    return "You are a helpful AI assistant based on the Dolphin 3 8B model. Provide clear and concise answers to user queries."

def save_user_system_prompt(username: str, system_prompt: str):
    max_size = 3000  # Maximum allowed system prompt size in characters
    system_prompt = system_prompt[:max_size]
    filepath = os.path.join(SYSTEM_PROMPT_DIR, f"{username}.txt")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(system_prompt)
