import os
import json
import bcrypt
from typing import Dict

MEMORY_DIR = "data/memory"
os.makedirs(MEMORY_DIR, exist_ok=True)

USERS_FILE = "data/users.json"
os.makedirs("data", exist_ok=True)

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
    max_size = 5000
    memory_content = memory_content[:max_size]
    filepath = os.path.join(MEMORY_DIR, f"{username}.txt")
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(memory_content)
