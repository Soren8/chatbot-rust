import sys
import time
import logging
import threading
import os
import json
import re
from collections import defaultdict
from werkzeug.serving import WSGIRequestHandler
WSGIRequestHandler.protocol_version = "HTTP/1.1"  # Enable keep-alive connections

# Define constants
SETS_DIR = "data/user_sets"
STREAM_TIMEOUT = 300  # 5 minutes in seconds
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

from app.tts import register_tts_routes
from app.user_manager import (
    validate_user, create_user, load_user_memory, save_user_memory,
    load_user_system_prompt, save_user_system_prompt, get_user_sets,
    create_new_set, delete_set as delete_user_set,
    load_user_chat_history, save_user_chat_history, get_user_tier
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
    register_tts_routes(bp)
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
        user_system_prompt=user_system_prompt,
        user_tier=get_user_tier(username) if logged_in else "free",
        available_llms=Config.LLM_PROVIDERS
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
    logger.debug(f"Loaded history: {len(history)} items")
    return jsonify({
        "memory": memory,
        "system_prompt": system_prompt,
        "history": history,
        "encrypted": encrypted
    })

@bp.route("/update_memory", methods=["POST"])
def update_memory():
    user_memory = request.json.get("memory", "")
    set_name = request.json.get("set_name", "default")
    encrypted = request.json.get("encrypted", False)

    if not user_memory:
        return jsonify({"error": "Memory content is required"}), 400

    if "username" in session:
        # Logged-in user - save to disk
        username = session["username"]
        password = session.get("password") if encrypted else None
        
        logger.debug(f"Updating memory for user {username}, set {set_name}. "
                    f"Memory length: {len(user_memory)}")
        
        sessions[username]["memory"] = user_memory
        save_user_memory(username, user_memory, set_name, password)
        
        logger.debug(f"Successfully updated memory for user {username}, set {set_name}")
        return jsonify({
            "status": "success",
            "message": "Memory saved to disk",
            "storage": "disk"
        })
    else:
        # Guest user - save to session
        session_id = f"guest_{request.remote_addr}"
        sessions[session_id]["memory"] = user_memory
        
        logger.debug(f"Updated memory in session for guest user {session_id}")
        return jsonify({
            "status": "success",
            "message": "Memory saved to session memory",
            "storage": "session"
        })

@bp.route("/update_system_prompt", methods=["POST"])
def update_system_prompt():
    system_prompt = request.json.get("system_prompt", "")
    set_name = request.json.get("set_name", "default")
    encrypted = request.json.get("encrypted", False)
    
    if not system_prompt:
        return jsonify({"error": "System prompt is required"}), 400

    if "username" in session:
        # Logged-in user - save to disk
        username = session["username"]
        password = session.get("password") if encrypted else None
        
        logger.debug(f"Updating system prompt for user {username}, set {set_name}. "
                    f"Prompt length: {len(system_prompt)}")
        
        sessions[username]["system_prompt"] = system_prompt
        save_user_system_prompt(username, system_prompt, set_name, password)
        
        logger.debug(f"Successfully updated system prompt for user {username}, set {set_name}")
        return jsonify({
            "status": "success",
            "message": "System prompt saved to disk",
            "storage": "disk"
        })
    else:
        # Guest user - save to session
        session_id = f"guest_{request.remote_addr}"
        sessions[session_id]["system_prompt"] = system_prompt
        
        logger.debug(f"Updated system prompt in session memory for guest user {session_id}")
        return jsonify({
            "status": "success", 
            "message": "System prompt saved to session memory",
            "storage": "session"
        })

@bp.route("/chat", methods=["POST"])
def chat():
    logger.debug(
        "Incoming chat request headers:\n"
        f"{json.dumps({k: v for k, v in request.headers.items()}, indent=2)}"
    )
    
    clean_old_sessions()

    user_message = request.json.get("message", "")
    new_system_prompt = request.json.get("system_prompt", None)

    # Create consistent guest session ID without timestamp
    session_id = session.get("username", f"guest_{request.remote_addr}")
    user_session = sessions[session_id]
    user_session["last_used"] = time.time()

    # Initialize guest session if it doesn't exist
    if session_id.startswith("guest_") and not user_session.get("initialized", False):
        user_session.update({
            "history": [],
            "system_prompt": "You are a helpful AI assistant.",
            "memory": "",
            "initialized": True
        })

    logger.info(f"Received chat request. Session: {session_id}")
    logger.debug(f"Current memory: {user_session.get('memory', '')[:50]}...")

    # Initialize guest session if it doesn't exist
    if session_id.startswith("guest_") and not user_session.get("initialized", False):
        user_session.update({
            "history": [],
            "system_prompt": "You are a helpful AI assistant.",
            "memory": "",
            "initialized": True
        })

    # Get password from session - needed for encryption
    password = session.get("password")
    if not password and not session_id.startswith("guest_"):
        logger.error("No password available in session for logged-in user")
        return jsonify({"error": "Session expired or invalid. Please log in again."}), 401

    if new_system_prompt is not None:
        logger.info("Updating system prompt")
        user_session["system_prompt"] = new_system_prompt
        if "username" in session:
            set_name = request.json.get("set_name", "default")
            encrypted = request.json.get("encrypted", False)
            password = session.get("password") if encrypted else None
            save_user_system_prompt(session["username"], new_system_prompt, set_name, password if encrypted else None)

    # Update system prompt if it has changed
    current_system_prompt = user_session["system_prompt"]
    if new_system_prompt is not None and current_system_prompt != new_system_prompt:
        if "username" in session:
            set_name = request.json.get("set_name", "default")
            encrypted = request.json.get("encrypted", False)
            password = session.get("password") if encrypted else None
            save_user_system_prompt(session["username"], new_system_prompt, set_name, password if encrypted else None)

    if response_lock.locked():
        return jsonify({"error": "A response is currently being generated. Please wait and try again."}), 429

    # Get memory text from the session regardless of login status
    memory_text = user_session.get("memory", "")
    system_prompt = user_session.get("system_prompt", "You are a helpful AI assistant.")

    # Get set_name and password before entering generator
    set_name = request.json.get("set_name", "default")
    encrypted = request.json.get("encrypted", False)
    password = session.get("password") if "username" in session else None

    # Get the selected model name from the request before entering the generator function
    selected_model = request.json.get("model_name", Config.DEFAULT_LLM["provider_name"])
    logger.debug(f"Using selected model: {selected_model}")
    
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
            
            stream = generate_text_stream(
                prompt=user_message,
                system_prompt=system_prompt,
                model_name=selected_model,  # Use the selected model
                session_history=current_history,
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

            logger.debug(
                "Full Response Analysis:\n"
                f"Total Characters: {len(response_text)}\n"
                "Response Preview:\n"
                f"{response_text[:500]}\n"
                "Response Metadata:\n"
                f"Memory Used: {len(memory_text)} chars\n"
                f"History Items: {len(user_session['history'])}"
            )
            
            # Remove thinking text from final response before storing in history
            clean_response = re.sub(r'<think>.*?</think>', '', response_text, flags=re.DOTALL)
            user_session["history"].append((user_message, clean_response))
            logger.info(f"Chat response generated. Length: {len(response_text)} characters")
            
            # Save history if user is logged in
            if session_id.startswith("guest_"):
                return
            try:
                # Always pass the password for encryption
                save_user_chat_history(session_id, user_session["history"], set_name, password)
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

    # Get the selected model name from the request before entering the generator function
    selected_model = request.json.get("model_name", Config.DEFAULT_LLM["provider_name"])
    logger.debug(f"Regenerating with selected model: {selected_model}")
    
    def generate():
        logger.info(f"Starting regeneration for session {session_id}")
        with response_lock:
            try:
                logger.info("Preparing to call LLM for regeneration")
                
                stream = generate_text_stream(
                    prompt=user_message,
                    system_prompt=system_prompt,
                    model_name=selected_model,  # Use the selected model
                    session_history=user_session["history"],
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
                    user_session["history"].append((user_message, response_text))
                    logger.info("Response added to history")
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
    session_id = session.get("username", "guest_" + request.remote_addr)
    if session_id not in sessions:
        return jsonify({"status": "error", "message": "Session not found"}), 404

    # Get set name from request
    set_name = request.json.get("set_name", "default")
    
    # Reset history only
    sessions[session_id]["history"] = []
    
    # Save empty history if logged in
    if "username" in session:
        try:
            save_user_chat_history(
                session["username"], 
                [],  # Empty history
                set_name,
                session.get("password")
            )
            logger.info(f"Reset and saved empty chat history for set '{set_name}'")
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
