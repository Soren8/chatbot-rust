import sys
import time
import logging
import threading
import os
import json
import re
from collections import defaultdict
from secrets import token_urlsafe
from werkzeug.serving import WSGIRequestHandler
WSGIRequestHandler.protocol_version = "HTTP/1.1"  # Enable keep-alive connections

# Define constants
STREAM_TIMEOUT = 300  # 5 minutes in seconds
from flask import (
    Blueprint, request, jsonify, Response, session, redirect, 
    url_for, render_template, current_app
)

# Get logger for this module
logger = logging.getLogger(__name__)

from app.tts import register_tts_routes
from app.user_manager import (
    validate_user, create_user, load_user_memory, save_user_memory,
    load_user_system_prompt, save_user_system_prompt, get_user_sets,
    create_new_set, delete_set as delete_user_set,
    load_user_chat_history, save_user_chat_history, get_user_tier,
    validate_set_name, validate_username
)
from app.chat_logic import generate_text_stream
from app.config import Config

logger = logging.getLogger(__name__)

bp = Blueprint("main", __name__)

# Basic in-memory sessions if not using flask.session
sessions = defaultdict(
    lambda: {
        "history": [],
        "system_prompt": Config.DEFAULT_SYSTEM_PROMPT,
        "last_used": time.time(),
        "memory": "",
        "system_prompt_saved": ""
    }
)

response_lock = threading.Lock()
requests_per_ip = {}
MAX_REQUESTS_PER_MINUTE = 60

# Helper utilities

def _get_session_id() -> str:
    """Return the canonical session identifier, allocating a guest ID if needed."""
    if "username" in session:
        return session["username"]

    guest_id = session.get("guest_id")
    if not guest_id:
        guest_id = token_urlsafe(16)
        session["guest_id"] = guest_id
    return f"guest_{guest_id}"

# Server-side store for sensitive per-user secrets (e.g., encryption password)
# Keyed by username; do NOT store plaintext passwords in client-side cookies.
USER_PASSWORDS = {}
PASSWORD_TTL_SECONDS = Config.SESSION_TIMEOUT
_password_cleanup_thread_started = False

def _set_user_password(username: str, password: str):
    USER_PASSWORDS[username] = {"password": password, "last_used": time.time()}

def _get_user_password(username: str):
    entry = USER_PASSWORDS.get(username)
    if not entry:
        return None
    now = time.time()
    if now - entry.get("last_used", 0) > PASSWORD_TTL_SECONDS:
        # Expired — remove and require re-auth
        try:
            del USER_PASSWORDS[username]
        except Exception:
            pass
        return None
    # Touch last used
    entry["last_used"] = now
    return entry.get("password")

def _cleanup_password_store():
    now = time.time()
    expired = [u for u, e in USER_PASSWORDS.items() if now - e.get("last_used", 0) > PASSWORD_TTL_SECONDS]
    for u in expired:
        try:
            del USER_PASSWORDS[u]
        except Exception:
            pass

def _password_cleanup_loop():
    interval = max(60, min(300, PASSWORD_TTL_SECONDS // 2 or 60))
    while True:
        try:
            _cleanup_password_store()
        except Exception:
            logging.getLogger(__name__).debug("Password cleanup loop error", exc_info=True)
        time.sleep(interval)

def start_password_cleanup_thread():
    global _password_cleanup_thread_started
    if _password_cleanup_thread_started:
        return
    t = threading.Thread(target=_password_cleanup_loop, name="password-cleanup", daemon=True)
    t.start()
    _password_cleanup_thread_started = True

def register_routes(app):
    # Store the config in the blueprint
    bp.config = app.config
    register_tts_routes(bp)
    app.register_blueprint(bp)
    # Start background password cleanup
    start_password_cleanup_thread()


def _is_model_allowed_for_user(provider_name: str, username: str) -> (bool, str):
    """Return (allowed, message) whether the current user may use provider_name.

    - If provider is not found, return (False, msg)
    - If provider tier is 'premium' and user is not premium, return (False, msg)
    - Otherwise return (True, "")
    """
    # Find provider config by provider_name
    provider = next((llm for llm in Config.LLM_PROVIDERS if llm.get("provider_name") == provider_name), None)
    if not provider:
        return False, "Requested model not found"

    model_tier = provider.get("tier", "free")
    # Treat unknown username as guest/free
    if not username:
        user_tier = "free"
    else:
        try:
            user_tier = get_user_tier(username)
        except Exception:
            user_tier = "free"

    if model_tier == "premium" and user_tier != "premium":
        return False, "This model requires a Premium account"

    return True, ""

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

def ensure_full_history_loaded(user_session):
    """Ensure complete history is loaded for logged-in users with empty session history"""
    if "username" in session and not user_session["history"]:
        set_name_temp = request.json.get("set_name", "default")
        password_temp = _get_user_password(session.get("username")) if "username" in session else None
        logger.debug(f"History is empty, reloading from disk. Set: {set_name_temp}")
        
        history = load_user_chat_history(session["username"], set_name_temp, password_temp)
        formatted_history = []
        for item in history:
            if isinstance(item, tuple) and len(item) == 2:
                formatted_history.append(item)
            elif isinstance(item, list) and len(item) == 2:
                formatted_history.append(tuple(item))
            else:
                logger.warning(f"Skipping invalid history item: {item}")
        
        user_session["history"] = formatted_history
        logger.debug(f"Reloaded {len(formatted_history)} history items from disk")

@bp.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            return "Username and password required.", 400
        try:
            if create_user(username, password):
                return redirect(url_for("main.login"))
        except ValueError as exc:
            logger.warning("Signup rejected invalid username '%s': %s", username, exc)
            return "Username may only include letters, numbers, '_' or '-'", 400
        return "User already exists.", 400
    return render_template("signup.html", sri=Config.CDN_SRI)

@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        try:
            if validate_user(username, password):
                session["username"] = username
                # Store encryption password server-side only
                _set_user_password(username, password)
                # Load user memory and system prompt
                user_memory = load_user_memory(username, "default", password)
                user_system_prompt = load_user_system_prompt(username, "default", password)
                sessions[username]["memory"] = user_memory
                sessions[username]["system_prompt"] = user_system_prompt
                sessions[username]["system_prompt_saved"] = user_system_prompt
                return redirect(url_for("main.home"))
        except ValueError as exc:
            logger.warning("Login rejected invalid username '%s': %s", username, exc)
            return "Invalid credentials", 401
        return "Invalid credentials", 401
    return render_template("login.html", sri=Config.CDN_SRI)

@bp.route("/")
def home():
    logger.debug("Serving home page")
    logged_in = ("username" in session)
    username = session.get("username")

    if logged_in:
        user_session = sessions[username]
        user_memory = user_session["memory"]
        user_system_prompt = user_session["system_prompt"]
    else:
        session_id = _get_session_id()
        user_session = sessions[session_id]
        user_memory = user_session["memory"]
        user_system_prompt = user_session["system_prompt"]

    # Determine user tier and filter available models for non-premium users
    user_tier = get_user_tier(username) if logged_in else "free"
    if user_tier != "premium":
        # Exclude premium-tier providers from the list shown to free users
        filtered_llms = [llm for llm in Config.LLM_PROVIDERS if llm.get("tier", "free") != "premium"]
    else:
        filtered_llms = Config.LLM_PROVIDERS

    # Sanitize provider metadata for frontend (no secrets or base URLs)
    available_llms = [
        {
            "provider_name": llm.get("provider_name", ""),
            "tier": llm.get("tier", "free"),
        }
        for llm in filtered_llms
    ]

    return render_template(
        "chat.html",
        logged_in=logged_in,
        user_tier=user_tier,
        available_llms=available_llms,
        default_system_prompt=Config.DEFAULT_SYSTEM_PROMPT,
        sri=Config.CDN_SRI
    )

@bp.after_app_request
def add_security_headers(response):
    try:
        csp = (
            "default-src 'self'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "connect-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self' https://cdn.jsdelivr.net data:; "
            "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
            "script-src 'self' https://code.jquery.com https://cdn.jsdelivr.net; "
            "media-src 'self' blob: data:"
        )
        response.headers.setdefault("Content-Security-Policy", csp)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
    except Exception:
        logging.getLogger(__name__).debug("Failed to set security headers", exc_info=True)
    return response

@bp.route("/logout") 
def logout():
    username = session.pop("username", None)
    if username:
        USER_PASSWORDS.pop(username, None)
    return redirect(url_for("main.home"))

@bp.route("/get_sets", methods=["GET"])
def get_sets():
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 403
    username = session["username"]
    try:
        sets = get_user_sets(username)
    except ValueError as exc:
        logger.warning("get_sets failed validation for user %s: %s", username, exc)
        return jsonify({"error": "invalid session"}), 400
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
    try:
        if delete_user_set(username, set_name):
            return jsonify({"status": "success"})
    except ValueError as exc:
        logger.warning("delete_set invalid request for user %s: %s", username, exc)
        return jsonify({"status": "error", "error": "invalid set name"}), 400
    return jsonify({"status": "error", "error": "Cannot delete set"})

@bp.route("/delete_message", methods=["POST"])
def delete_message():
    """
    Deletes a user/AI message pair from the in-memory session history.
    Expects JSON: { user_message: str, ai_message: str, set_name: str (optional) }
    Matching strategy:
      - Prefer exact match on both user and ai messages (trimmed).
      - If ai_message is not supplied/empty, match on user_message only (first occurrence).
    After removal, persist updated history to disk for logged-in users and return success.
    """
    logger.debug("delete_message called; raw json: %s", request.get_json())
    user_message = (request.json.get("user_message") or "").strip()
    ai_message = (request.json.get("ai_message") or "").strip()
    set_name_raw = request.json.get("set_name", "default")
    try:
        set_name = validate_set_name(set_name_raw)
    except ValueError as exc:
        logger.warning("delete_message received invalid set name '%s': %s", set_name_raw, exc)
        return jsonify({"status": "error", "error": "invalid set name"}), 400

    if not user_message:
        logger.debug("delete_message missing user_message in request")
        return jsonify({"status": "error", "error": "user_message is required"}), 400

    session_id = _get_session_id()
    logger.debug("Computed session_id=%s; session keys=%s; requester_ip=%s", session_id, list(session.keys()), request.remote_addr)

    if session_id not in sessions:
        logger.debug("Session id %s not found in sessions store", session_id)
        return jsonify({"status": "error", "error": "session not found"}), 404

    # Ensure we have the latest history loaded for logged-in users
    user_session = sessions[session_id]
    logger.debug("User session before deletion: last_used=%s history_len=%d system_prompt_saved=%s",
                 user_session.get("last_used"), len(user_session.get("history", [])), user_session.get("system_prompt_saved"))
    try:
        ensure_full_history_loaded(user_session)
    except Exception as e:
        logger.exception("ensure_full_history_loaded raised an exception")

    history = user_session.get("history", []) or []
    logger.debug("Current history length: %d; preview: %s", len(history), history[:5])

    # Try to find a matching history item.
    for idx, item in enumerate(list(history)):
        try:
            u, a = item
        except Exception:
            # skip malformed entries
            logger.debug("Skipping malformed history item at idx %d: %s", idx, item)
            continue

        u_text = (u or "").strip()
        a_text = (a or "").strip()

        logger.debug("Checking history idx=%d user_text(100)=%s ai_text(100)=%s", idx, u_text[:100], a_text[:100])

        # Match strategy: match on user_message only (ignore minor AI text mismatches)
        if u_text == user_message:
            logger.debug("Match found at history index %d", idx)
            # Remove matched pair
            history.pop(idx)
            sessions[session_id]["history"] = history
            logger.debug("Removed history index %d. New history length: %d", idx, len(history))

            # Persist change for logged-in users
            if "username" in session:
                username = session["username"]
                try:
                    safe_username = validate_username(username)
                except ValueError:
                    logger.error("Session username failed validation: %s", username)
                    return jsonify({"status": "error", "error": "invalid session"}), 400

                password_to_use = _get_user_password(safe_username)

                try:
                    logger.debug("Attempting to save_user_chat_history for user=%s set=%s history_len=%d", safe_username, set_name, len(history))
                    save_user_chat_history(safe_username, history, set_name, password_to_use)
                    logger.info("Deleted message pair and saved updated history for user '%s', set '%s'", safe_username, set_name)
                except ValueError as exc:
                    logger.warning("Failed to save history after delete due to invalid input for user '%s': %s", safe_username, exc)
                    return jsonify({"status": "error", "error": "invalid request"}), 400
                except Exception:
                    logger.exception("Failed to save history after delete for user '%s', set '%s'", safe_username, set_name)
            else:
                logger.debug("Not logged-in user; change persisted to in-memory session only")

            return jsonify({"status": "success"})

    logger.debug("No matching message pair found. user_message=%s ai_message=%s history_len=%d", user_message[:200], ai_message[:200], len(history))
    logger.debug("History contents for debugging: %s", history)
    return jsonify({"status": "error", "error": "message pair not found"}), 404

@bp.route("/load_set", methods=["POST"])
def load_set():
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 403
    username = session["username"]
    set_name_raw = request.json.get("set_name")

    try:
        safe_username = validate_username(username)
        set_name = validate_set_name(set_name_raw)
    except ValueError as exc:
        logger.warning("load_set validation failed for user=%s set=%s: %s", username, set_name_raw, exc)
        return jsonify({"error": "invalid request"}), 400

    password = _get_user_password(safe_username)  # Get the stored password
    
    logger.debug(f"Loading set '{set_name}' for user '{username}'")
    
    # Get encryption status from sets.json
    encrypted = False
    try:
        sets = get_user_sets(safe_username)
        encrypted = sets.get(set_name, {}).get("encrypted", False)
        logger.debug(f"Set '{set_name}' encryption status: {encrypted}")
    except Exception as exc:
        logger.error("Failed to read set metadata for user %s: %s", safe_username, exc)

    # If encrypted set and no ephemeral key available, require re-login
    if encrypted and not password:
        logger.error("Encrypted set requested but no in-memory password available")
        return jsonify({"error": "relogin required"}), 401

    # Load data
    logger.debug("Loading memory...")
    memory = load_user_memory(safe_username, set_name, password if encrypted else None)
    logger.debug("Loading system prompt...")
    system_prompt = load_user_system_prompt(safe_username, set_name, password if encrypted else None)
    logger.debug("Loading chat history...")
    history = load_user_chat_history(safe_username, set_name, password if encrypted else None)
    
    # Ensure history is in correct format (list of tuples)
    formatted_history = []
    for item in history:
        if isinstance(item, tuple) and len(item) == 2:
            formatted_history.append(item)
        elif isinstance(item, list) and len(item) == 2:
            formatted_history.append(tuple(item))
        else:
            logger.warning(f"Skipping invalid history item: {item}")
    
    # Update session with loaded data
    session_id = session.get("username")
    if session_id in sessions:
        logger.debug("Updating session data...")
        sessions[session_id]["memory"] = memory
        sessions[session_id]["system_prompt"] = system_prompt
        sessions[session_id]["history"] = formatted_history
        
    logger.debug(f"Returning data for set '{set_name}'")
    logger.debug(f"Loaded history: {len(formatted_history)} valid items")
    return jsonify({
        "memory": memory,
        "system_prompt": system_prompt,
        "history": formatted_history,
        "encrypted": encrypted
    })

@bp.route("/update_memory", methods=["POST"])
def update_memory():
    user_memory = request.json.get("memory", "")
    set_name_raw = request.json.get("set_name", "default")
    try:
        set_name = validate_set_name(set_name_raw)
    except ValueError as exc:
        logger.warning("update_memory invalid set name '%s': %s", set_name_raw, exc)
        return jsonify({"error": "invalid set name"}), 400
    encrypted = request.json.get("encrypted", False)

    if not user_memory:
        return jsonify({"error": "Memory content is required"}), 400

    if "username" in session:
        # Logged-in user - save to disk
        username = session["username"]
        password = _get_user_password(username)
        
        logger.debug(f"Updating memory for user {username}, set {set_name}. "
                    f"Memory length: {len(user_memory)}")
        
        sessions[username]["memory"] = user_memory
        try:
            save_user_memory(username, user_memory, set_name, password)
        except ValueError as exc:
            logger.warning("Failed to save memory for user %s: %s", username, exc)
            return jsonify({"error": "invalid request"}), 400
        
        logger.debug(f"Successfully updated memory for user {username}, set {set_name}")
        return jsonify({
            "status": "success",
            "message": "Memory saved to disk",
            "storage": "disk"
        })
    else:
        # Guest user - save to session memory and preserve it for first chat
        session_id = _get_session_id()
        sessions[session_id]["memory"] = user_memory
        sessions[session_id]["initialized"] = True

        logger.debug(f"Updated memory in session for guest user {session_id}")
        return jsonify({
            "status": "success",
            "message": "Memory saved to session memory",
            "storage": "session"
        })

@bp.route("/update_system_prompt", methods=["POST"])
def update_system_prompt():
    system_prompt = request.json.get("system_prompt", "")
    set_name_raw = request.json.get("set_name", "default")
    try:
        set_name = validate_set_name(set_name_raw)
    except ValueError as exc:
        logger.warning("update_system_prompt invalid set name '%s': %s", set_name_raw, exc)
        return jsonify({"error": "invalid set name"}), 400
    encrypted = request.json.get("encrypted", False)
    
    if not system_prompt:
        return jsonify({"error": "System prompt is required"}), 400

    if "username" in session:
        # Logged-in user - save to disk
        username = session["username"]
        password = _get_user_password(username)
        
        logger.debug(f"Updating system prompt for user {username}, set {set_name}. "
                    f"Prompt length: {len(system_prompt)}")
        
        sessions[username]["system_prompt"] = system_prompt
        try:
            save_user_system_prompt(username, system_prompt, set_name, password)
        except ValueError as exc:
            logger.warning("Failed to save system prompt for user %s: %s", username, exc)
            return jsonify({"error": "invalid request"}), 400
        
        logger.debug(f"Successfully updated system prompt for user {username}, set {set_name}")
        return jsonify({
            "status": "success",
            "message": "System prompt saved to disk",
            "storage": "disk"
        })
    else:
        # Guest user - save to session
        session_id = _get_session_id()
        sessions[session_id]["system_prompt"] = system_prompt
        
        logger.debug(f"Updated system prompt in session memory for guest user {session_id}")
        return jsonify({
            "status": "success", 
            "message": "System prompt saved to session memory",
            "storage": "session"
        })

@bp.route("/chat", methods=["POST"])
def chat():
    
    clean_old_sessions()

    user_message = request.json.get("message", "")
    new_system_prompt = request.json.get("system_prompt", None)
    set_name_raw = request.json.get("set_name", "default")
    try:
        set_name = validate_set_name(set_name_raw)
    except ValueError as exc:
        logger.warning("chat invalid set name '%s': %s", set_name_raw, exc)
        return jsonify({"error": "invalid set name"}), 400

    # Create consistent guest session ID without timestamp
    session_id = _get_session_id()
    user_session = sessions[session_id]
    user_session["last_used"] = time.time()

    # Initialize guest session if it doesn't exist
    if session_id.startswith("guest_") and not user_session.get("initialized", False):
        user_session.update({
            "history": [],
            "initialized": True
        })

    logger.info(f"Received chat request. Session: {session_id}")

    # Initialize guest session if it doesn't exist
    if session_id.startswith("guest_") and not user_session.get("initialized", False):
        user_session.update({
            "history": [],
            "system_prompt": Config.DEFAULT_SYSTEM_PROMPT,
            "initialized": True
        })

    # Ensure complete history is loaded for logged-in users with empty session history
    ensure_full_history_loaded(user_session)

    # Get password from server-side store - needed for encryption
    password = _get_user_password(session.get("username")) if "username" in session else None
    if not password and not session_id.startswith("guest_"):
        logger.error("No password available in session for logged-in user")
        return jsonify({"error": "Session expired or invalid. Please log in again."}), 401

    if new_system_prompt is not None:
        logger.info("Updating system prompt")
        user_session["system_prompt"] = new_system_prompt
        if "username" in session:
            # Always save encrypted; require ephemeral in-memory password
            password = _get_user_password(session["username"]) 
            try:
                save_user_system_prompt(session["username"], new_system_prompt, set_name, password)
            except ValueError as exc:
                logger.warning("chat failed to save system prompt for user %s: %s", session["username"], exc)
                return jsonify({"error": "invalid request"}), 400

    # Update system prompt if it has changed
    current_system_prompt = user_session["system_prompt"]
    if new_system_prompt is not None and current_system_prompt != new_system_prompt:
        if "username" in session:
            password = _get_user_password(session["username"]) 
            try:
                save_user_system_prompt(session["username"], new_system_prompt, set_name, password)
            except ValueError as exc:
                logger.warning("chat failed to persist updated system prompt for user %s: %s", session["username"], exc)
                return jsonify({"error": "invalid request"}), 400

    if response_lock.locked():
        return jsonify({"error": "A response is currently being generated. Please wait and try again."}), 429

    # Get memory text from the session regardless of login status
    memory_text = user_session.get("memory", "")
    system_prompt = user_session.get("system_prompt", Config.DEFAULT_SYSTEM_PROMPT)

    # Get set_name and password before entering generator
    encrypted = request.json.get("encrypted", False)
    password = _get_user_password(session.get("username")) if "username" in session else None

    # Get the selected model name from the request before entering the generator function
    selected_model = request.json.get("model_name", Config.DEFAULT_LLM["provider_name"])
    logger.debug(f"Using selected model: {selected_model}")

    # Validate model selection against user tier
    username = session.get("username") if "username" in session else None
    allowed, msg = _is_model_allowed_for_user(selected_model, username)
    if not allowed:
        logger.warning(f"Model selection not allowed for user {username}: {selected_model} - {msg}")
        return jsonify({"error": msg}), 403
    
    # Get current history from session
    current_history = user_session["history"]
    logger.debug(f"Using history for generation: {len(current_history)} items")
    
    def generate():
        with response_lock:
            logger.debug(
                "LLM Request Details:\n"
                f"Provider: {selected_model}\n"
                f"Type: {Config.DEFAULT_LLM['type']}\n"
                f"Model: {Config.DEFAULT_LLM['model_name']}\n"
                f"Context Size: {Config.DEFAULT_LLM.get('context_size', 'default')}\n"
                f"Base URL: {Config.DEFAULT_LLM.get('base_url', 'default')}\n"
                f"System Prompt: {system_prompt[:200]}...\n"
                f"Session History Length: {len(current_history)}\n"
                f"Memory Text Length: {len(memory_text)}"
            )
            
            # Pass full history to LLM but only use truncated version for generation
            stream = generate_text_stream(
                prompt=user_message,
                system_prompt=system_prompt,
                model_name=selected_model,
                full_history=current_history,  # Pass full history
                memory_text=memory_text
            )

            response_text = ""
            try:
                for chunk in stream:
                    response_text += chunk
                    # Encode the chunk to bytes before yielding
                    yield chunk.encode('utf-8')
            except Exception as e:
                logger.error(f"Error during streaming: {str(e)}")
                error_msg = "\n[Error] An error occurred during response generation."
                yield error_msg.encode('utf-8')

            
            # Remove thinking text from final response before storing in history
            clean_response = re.sub(r'<think>.*?</think>', '', response_text, flags=re.DOTALL)
            user_session["history"].append((user_message, clean_response))
            logger.info(f"Chat response generated. Length: {len(response_text)} characters")
            
            # Save full history to storage
            if session_id.startswith("guest_"):
                return
            try:
                save_user_chat_history(
                    session_id,
                    user_session["history"],
                    set_name,
                    password
                )
            except ValueError as e:
                logger.error(f"Failed to save chat history: {str(e)}")
                yield f"\n[Error] Failed to save chat history: {str(e)}"
            except Exception as e:
                logger.error(f"Unexpected error saving chat history: {str(e)}")
                yield f"\n[Error] Unexpected error saving chat history"

    return Response(
        generate(),
        mimetype="text/plain",
        headers={
            "X-Accel-Buffering": "no",  # Disable nginx buffering
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Transfer-Encoding": "chunked",
        },
        direct_passthrough=True
    )

@bp.route("/regenerate", methods=["POST"])
def regenerate():
    clean_old_sessions()

    user_message = request.json.get("message", "")
    system_prompt = request.json.get("system_prompt", "")
    set_name_raw = request.json.get("set_name", "default")
    try:
        set_name = validate_set_name(set_name_raw)
    except ValueError as exc:
        logger.warning("regenerate invalid set name '%s': %s", set_name_raw, exc)
        return jsonify({"error": "invalid set name"}), 400
    encrypted = request.json.get("encrypted", False)
    password = _get_user_password(session.get("username")) if "username" in session else None

    session_id = _get_session_id()
    user_session = sessions[session_id]
    user_session["last_used"] = time.time()

    # Ensure complete history is loaded for logged-in users
    ensure_full_history_loaded(user_session)

    logger.info(f"Received regenerate request. Session: {session_id}")

    # Allow regenerating a specific pair by index. If `pair_index` is provided,
    # remove that item so we can replace it. Otherwise fall back to removing
    # the last item if it matches the provided user_message (legacy behavior).
    pair_index = request.json.get("pair_index", None)
    insertion_index = None
    if pair_index is not None:
        try:
            pair_index = int(pair_index)
            if 0 <= pair_index < len(user_session.get("history", [])):
                logger.debug(f"Regenerate requested for index {pair_index}")
                user_session["history"].pop(pair_index)
                insertion_index = pair_index
            else:
                logger.debug(f"pair_index {pair_index} out of range; falling back to last-item behavior")
                pair_index = None
        except Exception:
            logger.exception("Invalid pair_index provided; falling back to last-item behavior")
            pair_index = None

    if pair_index is None:
        # Remove the last response from history if it matches the provided user_message
        if user_session["history"] and user_session["history"][-1][0] == user_message:
            user_session["history"].pop()
            insertion_index = len(user_session["history"])  # append position

    if response_lock.locked():
        return jsonify({"error": "A response is currently being generated. Please wait and try again."}), 429

    memory_text = user_session.get("memory", "")

    # Get the selected model name from the request before entering the generator function
    selected_model = request.json.get("model_name", Config.DEFAULT_LLM["provider_name"])
    logger.debug(f"Regenerating with selected model: {selected_model}")

    # Validate model selection against user tier
    username = session.get("username") if "username" in session else None
    allowed, msg = _is_model_allowed_for_user(selected_model, username)
    if not allowed:
        logger.warning(f"Regenerate request not allowed for user {username}: {selected_model} - {msg}")
        return jsonify({"error": msg}), 403
    
    # Capture logged-in state before entering generator context
    is_logged_in = "username" in session

    def generate():
        logger.info(f"Starting regeneration for session {session_id}")
        with response_lock:
            try:
                logger.info("Preparing to call LLM for regeneration")
                
                stream = generate_text_stream(
                    prompt=user_message,
                    system_prompt=system_prompt,
                    model_name=selected_model,  # Use the selected model
                    full_history=user_session["history"],
                    memory_text=memory_text
                )
                logger.info("LLM stream initialized")

                response_text = ""
                chunk_count = 0
                empty_chunk_count = 0
                
                for chunk in stream:
                    chunk_count += 1
                    if chunk:
                        response_text += chunk
                        # Encode the chunk to bytes before yielding
                        yield chunk.encode('utf-8')
                    else:
                        empty_chunk_count += 1
                        # Removed debug log for empty chunks
                        continue

                logger.info(f"Stream complete: {chunk_count} chunks")
                
                if response_text.strip():
                    # Remove thinking text from final response before storing in history
                    clean_response = re.sub(r'<think>.*?</think>', '', response_text, flags=re.DOTALL)
                    # If we determined an insertion_index earlier, insert there; otherwise append
                    try:
                        if insertion_index is not None:
                            user_session["history"].insert(insertion_index, (user_message, clean_response))
                        else:
                            user_session["history"].append((user_message, clean_response))
                        logger.info("Response added to history at index %s", insertion_index)
                    except Exception:
                        logger.exception("Failed to insert regenerated response into history; appending instead")
                        user_session["history"].append((user_message, clean_response))
                    
                    # Save history if user is logged in
                    if is_logged_in:
                        try:
                            save_user_chat_history(session_id, user_session["history"], set_name, password)
                            logger.info("Saved regenerated history to disk")
                        except ValueError as e:
                            logger.error(f"Failed to save chat history: {str(e)}")
                            yield f"\n[Error] Failed to save chat history: {str(e)}"
                        except Exception as e:
                            logger.error(f"Unexpected error saving chat history: {str(e)}")
                            yield f"\n[Error] Unexpected error saving chat history"
                else:
                    logger.warning("Generated empty response!")
            except Exception as e:
                logger.error(f"Error during regeneration: {str(e)}", exc_info=True)
                yield f"\n[Error] Failed to generate response: {str(e)}"

    return Response(
        generate(),
        mimetype="text/plain",
        headers={
            "X-Accel-Buffering": "no",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Transfer-Encoding": "chunked",
        },
        direct_passthrough=True
    )

@bp.route("/reset_chat", methods=["POST"])
def reset_chat():
    session_id = _get_session_id()
    if session_id not in sessions:
        return jsonify({"status": "error", "message": "Session not found"}), 404

    # Get set name from request
    set_name_raw = request.json.get("set_name", "default")
    try:
        set_name = validate_set_name(set_name_raw)
    except ValueError as exc:
        logger.warning("reset_chat invalid set name '%s': %s", set_name_raw, exc)
        return jsonify({"status": "error", "message": "invalid set name"}), 400
    
    # Reset history only
    sessions[session_id]["history"] = []
    
    # Save empty history if logged in
    if "username" in session:
        try:
            save_user_chat_history(
                session["username"],
                [],
                set_name,
                _get_user_password(session["username"]) if "username" in session else None
            )
            logger.info(f"Reset and saved empty chat history for set '{set_name}'")
        except ValueError as exc:
            logger.warning("reset_chat invalid input for user %s: %s", session["username"], exc)
            return jsonify({
                "status": "error",
                "message": "invalid request"
            }), 400
        except Exception as e:
            logger.error(f"Error saving empty history: {str(e)}")
            return jsonify({
                "status": "error",
                "message": f"Failed to save empty history: {str(e)}"
            }), 500
            
    return jsonify({
        "status": "success", 
        "message": "Chat history has been reset.",
        "set_name": set_name
    })

@bp.route("/health")
def health_check():
    logger.info("Health check requested")
    return jsonify({"status": "healthy"}), 200
