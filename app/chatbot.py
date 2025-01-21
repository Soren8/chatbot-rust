import os
import sys
import json
import time
import logging
import threading
from collections import defaultdict
from flask import Flask, render_template, request, jsonify, Response, session, redirect, url_for
from dotenv import load_dotenv
from user_manager import (
    validate_user, create_user, load_user_memory, save_user_memory,
    load_user_system_prompt, save_user_system_prompt, get_user_sets,
    create_new_set, delete_set as delete_user_set, save_user_chat_history
)
from chat_logic import generate_text_stream

# Configure logging first, before any other imports or code
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

# Get logger for this module
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

# Ollama model name
MODEL_NAME = "dolphin3.1-8b"

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")  # Load secret key from environment variable

if not app.secret_key:
    logger.error("SECRET_KEY not set in environment variables.")
    sys.exit("SECRET_KEY not set in environment variables.")

sessions = defaultdict(
    lambda: {
        "history": [],
        "system_prompt": "You are a helpful AI assistant based on the Dolphin 3 8B model. Provide clear and concise answers to user queries.",
        "last_used": time.time(),
        "memory": "",
        "system_prompt_saved": ""
    }
)
SESSION_TIMEOUT = 3600  # 1 hour in seconds

response_lock = threading.Lock()

# Basic rate limiting (very naive, for demonstration)
requests_per_ip = {}
MAX_REQUESTS_PER_MINUTE = 60

@app.before_request
def rate_limit():
    ip = request.remote_addr
    current_time = time.time()
    requests_per_ip.setdefault(ip, [])
    # Clean up old requests
    requests_per_ip[ip] = [t for t in requests_per_ip[ip] if t > current_time - 60]
    if len(requests_per_ip[ip]) >= MAX_REQUESTS_PER_MINUTE:
        return "Too many requests, please slow down.", 429
    requests_per_ip[ip].append(current_time)

def clean_old_sessions():
    current_time = time.time()
    for session_id in list(sessions.keys()):
        if current_time - sessions[session_id]["last_used"] > SESSION_TIMEOUT:
            del sessions[session_id]

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            return "Username and password required.", 400
        if create_user(username, password):
            return redirect(url_for("login"))
        else:
            return "User already exists.", 400
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
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
            return redirect(url_for("home"))
        else:
            return "Invalid credentials", 401
    return render_template("login.html")

@app.route("/")
def home():
    logger.info("Serving home page")
    logged_in = ("username" in session)
    user_memory = ""
    user_system_prompt = ""
    if logged_in:
        username = session["username"]
        user_memory = sessions[username]["memory"]
        user_system_prompt = sessions[username]["system_prompt"]
    return render_template("chat.html", logged_in=logged_in, user_memory=user_memory, user_system_prompt=user_system_prompt)

@app.route("/logout") 
def logout():
    session.pop("username", None)
    session.pop("password", None)  # Clear cached password
    return redirect(url_for("home"))

@app.route("/get_sets", methods=["GET"])
def get_sets():
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 403
    username = session["username"]
    sets = get_user_sets(username)
    return jsonify(sets)

@app.route("/create_set", methods=["POST"])
def create_set():
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 403
    username = session["username"]
    set_name = request.json.get("set_name")
    if create_new_set(username, set_name):
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "error": "Set already exists or invalid name"})

@app.route("/delete_set", methods=["POST"])
def delete_set():
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 403
    username = session["username"]
    set_name = request.json.get("set_name")
    if delete_user_set(username, set_name):
        return jsonify({"status": "success"})
    return jsonify({"status": "error", "error": "Cannot delete set"})

@app.route("/load_set", methods=["POST"])
def load_set():
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 403
    username = session["username"]
    set_name = request.json.get("set_name")
    memory = load_user_memory(username, set_name)
    system_prompt = load_user_system_prompt(username, set_name)
    return jsonify({
        "memory": memory,
        "system_prompt": system_prompt
    })

@app.route("/update_memory", methods=["POST"])
def update_memory():
    user_memory = request.json.get("memory", "")
    set_name = request.json.get("set_name", "default")  # Get active set from request

    if not user_memory:
        return jsonify({"error": "Memory content is required"}), 400

    # Create consistent guest session ID
    session_id = session.get("username", f"guest_{request.remote_addr}")

    # Initialize session if it doesn't exist
    if session_id not in sessions:
        sessions[session_id] = {
            "history": [],
            "system_prompt": "You are a helpful AI assistant.",
            "memory": "",
            "last_used": time.time(),
            "initialized": True
        }

    # Update memory in session
    sessions[session_id]["memory"] = user_memory
    logger.debug(f"Updated memory for session {session_id}: {user_memory[:50]}...")

    # Save to disk for logged-in users
    if "username" in session:
        try:
            save_user_memory(session["username"], user_memory, set_name, session.get("password"))
            return jsonify({
                "status": "success",
                "message": f"Memory saved to disk in set {set_name}",
                "storage": "disk"
            })
        except Exception as e:
            logger.error(f"Error saving memory: {str(e)}")
            return jsonify({
                "status": "error",
                "message": f"Failed to save memory: {str(e)}"
            }), 500
    else:
        # Guest user - save to session
        return jsonify({
            "status": "success",
            "message": "Memory saved to session memory",
            "storage": "session"
        })

@app.route("/update_system_prompt", methods=["POST"])
def update_system_prompt():
    if "username" not in session:
        return jsonify({"error": "Not authenticated"}), 403

    system_prompt = request.json.get("system_prompt", "")
    set_name = request.json.get("set_name", "default")
    username = session["username"]
    sessions[username]["system_prompt"] = system_prompt
    encrypted = request.json.get("encrypted", False)
    save_user_system_prompt(username, system_prompt, set_name, True)  # Always encrypt
    return jsonify({"status": "success"})

@app.route("/chat", methods=["POST"])
def chat():
    clean_old_sessions()

    user_message = request.json.get("message", "")
    new_system_prompt = request.json.get("system_prompt", None)
    active_set = request.json.get("set_name", "default")  # Get active set from request
    active_set = request.json.get("set_name", "default")

    # Create a consistent guest session ID
    session_id = session.get("username", f"guest_{request.remote_addr}")
    
    # Initialize session if it doesn't exist
    if session_id not in sessions:
        sessions[session_id] = {
            "history": [],
            "system_prompt": "You are a helpful AI assistant.",
            "memory": "",
            "last_used": time.time()
        }
    
    user_session = sessions[session_id]
    user_session["last_used"] = time.time()

    # Log the current state for debugging
    logger.debug(f"Session {session_id} memory: {user_session.get('memory', '')[:50]}...")

    if new_system_prompt is not None:
        logger.info("Updating system prompt")
        user_session["system_prompt"] = new_system_prompt
        if "username" in session:
            save_user_system_prompt(
                session["username"], 
                new_system_prompt,
                active_set,
                request.json.get("encrypted", False)
            )

    if response_lock.locked():
        return jsonify(
            {
                "error": "A response is currently being generated. Please wait and try again."
            }
        ), 429

    # Get memory text from the session
    memory_text = user_session.get("memory", "")
    system_prompt = user_session.get("system_prompt", "You are a helpful AI assistant.")

    # Log what we're sending to the LLM
    logger.debug(f"Sending to LLM - Memory: {memory_text[:50]}...")

    def generate():
        with response_lock:
            stream = generate_text_stream(
                user_message,
                system_prompt,
                MODEL_NAME,
                user_session["history"],
                memory_text,
                app.config
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

            user_session["history"].append((user_message, response_text))
            logger.info(f"Chat response generated. Length: {len(response_text)} characters")
            
            if "username" in session:
                save_user_chat_history(
                    session["username"],
                    user_session["history"],
                    active_set,  # Pass the active set
                    True  # Always encrypt
                )

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

@app.route("/regenerate", methods=["POST"])
def regenerate():
    clean_old_sessions()

    user_message = request.json.get("message", "")
    system_prompt = request.json.get("system_prompt", "")
    active_set = request.json.get("set_name", "default")  # Get active set from request

    session_id = session.get("username", "guest_" + request.remote_addr)
    user_session = sessions[session_id]
    user_session["last_used"] = time.time()

    memory_text = user_session["memory"] if "username" in session else ""
    logger.info(f"Regenerate request - Session: {session_id[:8]}")

    # Remove the last response from history
    if user_session["history"] and user_session["history"][-1][0] == user_message:
        user_session["history"].pop()

    if response_lock.locked():
        return jsonify(
            {
                "error": "A response is currently being generated. Please wait and try again."
            }
        ), 429

    memory_text = user_session["memory"] if "username" in session else ""

    def generate():
        with response_lock:
            try:
                logger.debug(f"Starting regeneration with: message='{user_message[:50]}...', system_prompt='{system_prompt[:50]}...', memory='{memory_text[:50]}...'")
                
                stream = generate_text_stream(
                    user_message,
                    system_prompt,
                    MODEL_NAME,
                    user_session["history"],
                    memory_text,
                    app.config
                )

                response_text = ""
                for chunk in stream:
                    response_text += chunk
                    if not chunk.strip():
                        # Skip empty chunks
                        continue
                    # Encode the chunk to bytes before yielding
                    yield chunk.encode('utf-8')

                user_session["history"].append((user_message, response_text))
                logger.info(f"Regenerated response. Length: {len(response_text)} characters")
                
                # Save chat history to the active set if logged in
                if "username" in session:
                    save_user_chat_history(
                        session["username"],
                        user_session["history"],
                        active_set,  # Pass the active set
                        True  # Always encrypt
                    )
            except Exception as e:
                logger.error(f"Error during regeneration: {str(e)}", exc_info=True)
                logger.error(f"Regeneration failed: {str(e)}", exc_info=True)
                yield f"\n[Error] Failed to generate response: {str(e)}\n\n<div class='regenerate-container'><button class='regenerate-button' onclick='regenerateMessage(this)'>⟳</button></div>"

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

@app.route("/reset_chat", methods=["POST"])
def reset_chat():
    session_id = session.get("username", "guest_" + request.remote_addr)
    if session_id in sessions:
        sessions[session_id]["history"] = []
        sessions[session_id]["system_prompt"] = "You are a helpful AI assistant based on the Dolphin 3 8B model. Provide clear and concise answers to user queries."
        if "username" in session:
            save_user_system_prompt(session["username"], sessions[session_id]["system_prompt"])
        logger.info(f"Chat history has been reset for session {session_id[:8]}...")

    return jsonify({"status": "success", "message": "Chat history has been reset."})

@app.route("/health")
def health_check():
    logger.info("Health check requested")
    return jsonify({"status": "healthy"}), 200

if __name__ == "__main__":
    logger.info("Starting the Flask application")
    app.run(host="0.0.0.0", port=5000)
