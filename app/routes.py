import sys
import time
import logging
import threading
import os
import json
from collections import defaultdict

# Define SETS_DIR constant
SETS_DIR = "data/user_sets"
from flask import (
    Blueprint, request, jsonify, Response, session, redirect, 
    url_for, render_template, current_app
)

# Configure logging first
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

# Get logger for this module
logger = logging.getLogger(__name__)

MODEL_NAME = "dolphin3.1-8b"

from app.user_manager import (
    validate_user, create_user, load_user_memory, save_user_memory,
    load_user_system_prompt, save_user_system_prompt, get_user_sets,
    create_new_set, delete_set as delete_user_set,
    load_user_chat_history, save_user_chat_history
)
from app.chat_logic import generate_text_stream
from app.config import Config

logger = logging.getLogger(__name__)

bp = Blueprint("main", __name__)

# Basic in-memory sessions if not using flask.session
sessions = defaultdict(
    lambda: {
        "history": [],
        "system_prompt": "You are a helpful AI assistant based on the Dolphin 3 8B model. Provide clear and concise answers.",
        "last_used": time.time(),
        "memory": "",
        "system_prompt_saved": ""
    }
)

response_lock = threading.Lock()
requests_per_ip = {}
MAX_REQUESTS_PER_MINUTE = 60

def register_routes(app):
    # Store the config in the blueprint
    bp.config = app.config
    app.register_blueprint(bp)

@bp.before_app_request
def rate_limit():
    ip = request.remote_addr
    current_time = time.time()
    requests_per_ip.setdefault(ip, [])
    # Remove requests older than 60 seconds
    requests_per_ip[ip] = [t for t in requests_per_ip[ip] if t > current_time - 60]
    if len(requests_per_ip[ip]) >= MAX_REQUESTS_PER_MINUTE:
        return "Too many requests, please slow down.", 429
    requests_per_ip[ip].append(current_time)

def clean_old_sessions():
    current_time = time.time()
    for session_id in list(sessions.keys()):
        if current_time - sessions[session_id]["last_used"] > Config.SESSION_TIMEOUT:
            del sessions[session_id]

@bp.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            return "Username and password required.", 400
        if create_user(username, password):
            return redirect(url_for("main.login"))
        else:
            return "User already exists.", 400
    return render_template("signup.html")

@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if validate_user(username, password):
            session["username"] = username
            session["password"] = password  # Temporarily store for encryption
            # Load user memory and system prompt
            user_memory = load_user_memory(username)
            user_system_prompt = load_user_system_prompt(username)
            sessions[username]["memory"] = user_memory
            sessions[username]["system_prompt"] = user_system_prompt
            sessions[username]["system_prompt_saved"] = user_system_prompt
            return redirect(url_for("main.home"))
        else:
            return "Invalid credentials", 401
    return render_template("login.html")

@bp.route("/")
def home():
    logger.info("Serving home page")
    logged_in = ("username" in session)
    user_memory = ""
    user_system_prompt = ""
    if logged_in:
        username = session["username"]
        user_memory = sessions[username]["memory"]
        user_system_prompt = sessions[username]["system_prompt"]
    return render_template(
        "chat.html",
        logged_in=logged_in,
        user_memory=user_memory,
        user_system_prompt=user_system_prompt
    )

@bp.route("/logout") 
def logout():
    session.pop("username", None)
    session.pop("password", None)
    return redirect(url_for("main.home"))

@bp.route("/get_sets", methods=["GET"])
def get_sets():
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 403
    username = session["username"]
    sets = get_user_sets(username)
    return jsonify(sets)

@bp.route("/create_set", methods=["POST"])
def create_set():
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 403
    username = session["username"]
    set_name = request.json.get("set_name")
    if create_new_set(username, set_name):
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "error": "Set already exists or invalid name"})

@bp.route("/delete_set", methods=["POST"])
def delete_set():
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 403
    username = session["username"]
    set_name = request.json.get("set_name")
    if delete_user_set(username, set_name):
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "error": "Cannot delete set"})

@bp.route("/load_set", methods=["POST"])
def load_set():
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 403
    username = session["username"]
    set_name = request.json.get("set_name")
    password = session.get("password")  # Get the stored password
    
    logger.debug(f"Loading set '{set_name}' for user '{username}'")
    
    # Get encryption status from sets.json
    sets_file = os.path.join(SETS_DIR, username, "sets.json")
    encrypted = False
    if os.path.exists(sets_file):
        try:
            logger.debug(f"Reading sets file: {sets_file}")
            with open(sets_file, "r") as f:
                sets = json.load(f)
                logger.debug(f"Sets file contents: {sets}")
                if set_name in sets:
                    encrypted = sets[set_name].get("encrypted", False)
                    logger.debug(f"Set '{set_name}' encryption status: {encrypted}")
                else:
                    logger.debug(f"Set '{set_name}' not found in sets.json")
        except Exception as e:
            logger.error(f"Error reading sets.json: {str(e)}")
            logger.debug("Traceback:", exc_info=True)
    else:
        logger.debug(f"Sets file does not exist: {sets_file}")
    
    # Load data
    logger.debug("Loading memory...")
    memory = load_user_memory(username, set_name)
    logger.debug("Loading system prompt...")
    system_prompt = load_user_system_prompt(username, set_name, password if encrypted else None)
    logger.debug("Loading chat history...")
    history = load_user_chat_history(username, set_name, password if encrypted else None)
    
    # Update session with loaded data
    session_id = session.get("username")
    if session_id in sessions:
        logger.debug("Updating session data...")
        sessions[session_id]["memory"] = memory
        sessions[session_id]["system_prompt"] = system_prompt
        sessions[session_id]["history"] = history
        
    logger.debug(f"Returning data for set '{set_name}'")
    return jsonify({
        "memory": memory,
        "system_prompt": system_prompt,
        "history": history,
        "encrypted": encrypted
    })

@bp.route("/update_memory", methods=["POST"])
def update_memory():
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 403

    user_memory = request.json.get("memory", "")
    set_name = request.json.get("set_name", "default")
    encrypted = request.json.get("encrypted", False)
    username = session["username"]
    sessions[username]["memory"] = user_memory
    save_user_memory(username, user_memory, set_name, encrypted)
    return jsonify({"status": "success"})

@bp.route("/update_system_prompt", methods=["POST"])
def update_system_prompt():
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 403

    system_prompt = request.json.get("system_prompt", "")
    set_name = request.json.get("set_name", "default")
    encrypted = request.json.get("encrypted", False)
    username = session["username"]
    sessions[username]["system_prompt"] = system_prompt
    save_user_system_prompt(username, system_prompt, set_name, encrypted)
    return jsonify({"status": "success"})

@bp.route("/chat", methods=["POST"])
def chat():
    clean_old_sessions()

    user_message = request.json.get("message", "")
    new_system_prompt = request.json.get("system_prompt", None)

    session_id = session.get("username", "guest_" + request.remote_addr)
    user_session = sessions[session_id]
    user_session["last_used"] = time.time()

    logger.info(f"Received chat request. Session: {session_id}")

    if new_system_prompt is not None:
        logger.info("Updating system prompt")
        user_session["system_prompt"] = new_system_prompt
        if "username" in session:
            set_name = request.json.get("set_name", "default")
            encrypted = request.json.get("encrypted", False)
            save_user_system_prompt(session["username"], new_system_prompt, set_name, encrypted)

    # Update system prompt if it has changed
    current_system_prompt = user_session["system_prompt"]
    if new_system_prompt is not None and current_system_prompt != new_system_prompt:
        if "username" in session:
            set_name = request.json.get("set_name", "default")
            encrypted = request.json.get("encrypted", False)
            save_user_system_prompt(session["username"], new_system_prompt, set_name, encrypted)

    if response_lock.locked():
        return jsonify({"error": "A response is currently being generated. Please wait and try again."}), 429

    memory_text = user_session["memory"] if "username" in session else ""
    system_prompt = user_session["system_prompt"] if "username" in session else "You are a helpful AI assistant."

    # Get set_name and password before entering generator
    set_name = request.json.get("set_name", "default")
    encrypted = request.json.get("encrypted", False)
    password = session.get("password") if "username" in session else None

    def generate():
        with response_lock:
            stream = generate_text_stream(
                user_message,
                system_prompt,
                MODEL_NAME,
                user_session["history"],
                memory_text,
                bp.config
            )

            response_text = ""
            try:
                for chunk in stream:
                    response_text += chunk
                    yield chunk
            except Exception as e:
                logger.error(f"Error during streaming: {str(e)}")
                yield "\n[Error] An error occurred during response generation."

            user_session["history"].append((user_message, response_text))
            logger.info(f"Chat response generated. Length: {len(response_text)} characters")
            
            # Save history if user is logged in
            if session_id.startswith("guest_"):
                return
            try:
                if encrypted and not password:
                    raise ValueError("Password required for encryption")
                save_user_chat_history(session_id, user_session["history"], set_name, password if encrypted else None)
            except ValueError as e:
                logger.error(f"Failed to save chat history: {str(e)}")
                yield f"\n[Error] Failed to save chat history: {str(e)}"

    return Response(generate(), mimetype="text/plain")

@bp.route("/regenerate", methods=["POST"])
def regenerate():
    clean_old_sessions()

    user_message = request.json.get("message", "")
    system_prompt = request.json.get("system_prompt", "")

    session_id = session.get("username", "guest_" + request.remote_addr)
    user_session = sessions[session_id]
    user_session["last_used"] = time.time()

    logger.info(f"Received regenerate request. Session: {session_id}")

    # Remove the last response from history
    if user_session["history"] and user_session["history"][-1][0] == user_message:
        user_session["history"].pop()

    if response_lock.locked():
        return jsonify({"error": "A response is currently being generated. Please wait and try again."}), 429

    memory_text = user_session["memory"] if "username" in session else ""

    def generate():
        logger.info(f"Starting regeneration for session {session_id}")
        with response_lock:
            try:
                logger.info("Preparing to call LLM for regeneration")
                
                stream = generate_text_stream(
                    user_message,
                    system_prompt,
                    MODEL_NAME,
                    user_session["history"],
                    memory_text,
                    bp.config
                )
                logger.info("LLM stream initialized")

                response_text = ""
                chunk_count = 0
                empty_chunk_count = 0
                
                for chunk in stream:
                    chunk_count += 1
                    if chunk:
                        response_text += chunk
                        yield chunk
                    else:
                        empty_chunk_count += 1
                        # Removed debug log for empty chunks
                        continue

                logger.info(f"Stream complete: {chunk_count} chunks")
                
                if response_text.strip():
                    user_session["history"].append((user_message, response_text))
                    logger.info("Response added to history")
                else:
                    logger.warning("Generated empty response!")
            except Exception as e:
                logger.error(f"Error during regeneration: {str(e)}", exc_info=True)
                yield f"\n[Error] Failed to generate response: {str(e)}"

    return Response(generate(), mimetype="text/plain")

@bp.route("/reset_chat", methods=["POST"])
def reset_chat():
    session_id = session.get("username", "guest_" + request.remote_addr)
    if session_id in sessions:
        sessions[session_id]["history"] = []
        sessions[session_id]["system_prompt"] = (
            "You are a helpful AI assistant based on the Dolphin 3 8B model. "
            "Provide clear and concise answers to user queries."
        )
        if "username" in session:
            set_name = request.json.get("set_name", "default")
            save_user_system_prompt(
                session["username"],
                sessions[session_id]["system_prompt"],
                set_name
            )
            # Save empty chat history
            save_user_chat_history(session["username"], [], set_name)
            logger.info(f"Saved empty chat history for set '{set_name}'")
        logger.info(f"Chat history reset for session {session_id}")

    return jsonify({"status": "success", "message": "Chat history has been reset."})

@bp.route("/health")
def health_check():
    logger.info("Health check requested")
    return jsonify({"status": "healthy"}), 200
