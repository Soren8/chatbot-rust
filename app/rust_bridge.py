"""Helpers for routing requests from the Rust web server into the existing Flask app."""

from __future__ import annotations

import json
import os
import base64
import traceback

# If Python-side code raises, tests can inspect LAST_EXCEPTION to get the
# formatted traceback and fail deterministically. This is reset on each
# entry so tests can detect the most recent error.
LAST_EXCEPTION: Optional[str] = None
import threading
import inspect
import hmac
import time
from http.cookies import SimpleCookie
from typing import Dict, Iterable, Optional, Tuple

from flask import make_response, redirect, session, url_for, request, jsonify

from app import create_app
from app.routes import (
    _set_user_encryption_key,
    load_user_memory,
    load_user_system_prompt,
    sessions,
    USER_ENCRYPTION_KEYS,
    home,
    clean_old_sessions,
    _get_session_id,
    _get_user_encryption_key,
    _get_response_lock,
    _is_model_allowed_for_user,
    ensure_full_history_loaded,
    save_user_chat_history,
    save_user_system_prompt,
    Config,
    validate_set_name,
    logger,
)

_app_lock = threading.Lock()
_flask_app = None


def _get_app():
    global _flask_app
    if _flask_app is None:
        with _app_lock:
            if _flask_app is None:
                _flask_app = create_app()
    return _flask_app


def _set_cookie_on_client(client, host_header: Optional[str], morsel) -> None:
    """Set a cookie on the Flask test client across Werkzeug versions."""

    set_cookie = client.set_cookie
    params = inspect.signature(set_cookie).parameters
    accepts_kwargs = any(param.kind == inspect.Parameter.VAR_KEYWORD for param in params.values())

    def accepts(name: str) -> bool:
        return accepts_kwargs or name in params

    cookie_kwargs = {}

    domain = morsel["domain"]
    if domain and accepts("domain"):
        cookie_kwargs["domain"] = domain

    path = morsel["path"] or "/"
    if path and accepts("path"):
        cookie_kwargs["path"] = path

    if morsel["secure"] and accepts("secure"):
        cookie_kwargs["secure"] = True

    if morsel["httponly"] and accepts("httponly"):
        cookie_kwargs["httponly"] = True

    samesite = morsel["samesite"]
    if samesite and accepts("samesite"):
        cookie_kwargs["samesite"] = samesite

    max_age = morsel["max-age"]
    if max_age and accepts("max_age"):
        try:
            cookie_kwargs["max_age"] = int(max_age)
        except ValueError:
            # Ignore malformed max-age values; Flask/Werkzeug expect int.
            pass

    expires = morsel["expires"]
    if expires and accepts("expires"):
        cookie_kwargs["expires"] = expires

    value = morsel.value or ""
    host = (host_header or "localhost").split(":", 1)[0]

    parameters = list(params.keys())
    if parameters and parameters[0] == "server_name":
        set_cookie(host, morsel.key, value, **cookie_kwargs)
    else:
        set_cookie(morsel.key, value, **cookie_kwargs)


def _response_to_triplet(response):
    header_items_fn = response.headers.items
    header_params = inspect.signature(header_items_fn).parameters
    if "multi" in header_params:
        header_items = list(header_items_fn(multi=True))
    else:
        header_items = list(header_items_fn())
    return response.status_code, header_items, response.get_data()


def validate_csrf_token(cookie_header: Optional[str], submitted_token: Optional[str]) -> bool:
    """Return True if the submitted token matches the session CSRF token."""

    if not submitted_token:
        return False

    app = _get_app()
    headers = {}
    if cookie_header:
        headers["Cookie"] = cookie_header

    with app.test_request_context("/", method="POST", headers=headers):
        expected = session.get("csrf_token")

    if not expected:
        return False

    try:
        return hmac.compare_digest(submitted_token, expected)
    except TypeError:
        return submitted_token == expected


def finalize_login(
    cookie_header: Optional[str],
    username: str,
    encryption_key: bytes,
) -> Tuple[int, Iterable[Tuple[str, str]], bytes]:
    app = _get_app()

    headers = {}
    if cookie_header:
        headers["Cookie"] = cookie_header

    with app.test_request_context("/", method="POST", headers=headers or None):
        session["username"] = username
        key_bytes = encryption_key if isinstance(encryption_key, bytes) else encryption_key.encode("utf-8")
        _set_user_encryption_key(username, key_bytes)

        user_memory = load_user_memory(username, "default", encryption_key=key_bytes)
        user_system_prompt = load_user_system_prompt(
            username,
            "default",
            encryption_key=key_bytes,
        )

        sessions[username]["memory"] = user_memory
        sessions[username]["system_prompt"] = user_system_prompt
        sessions[username]["system_prompt_saved"] = user_system_prompt

        response = redirect(url_for("main.home"))
        app.session_interface.save_session(app, session, response)

        return _response_to_triplet(response)



def render_home(cookie_header: Optional[str] = None):
    app = _get_app()

    headers = {}
    if cookie_header:
        headers["Cookie"] = cookie_header

    with app.test_request_context("/", method="GET", headers=headers or None):
        response = make_response(home())
        app.session_interface.save_session(app, session, response)

        return _response_to_triplet(response)

def logout_user(cookie_header: Optional[str] = None):
    app = _get_app()

    headers = {}
    if cookie_header:
        headers["Cookie"] = cookie_header

    with app.test_request_context("/logout", method="GET", headers=headers or None):
        username = session.pop("username", None)
        if username:
            USER_ENCRYPTION_KEYS.pop(username, None)

        response = redirect(url_for("main.home"))
        app.session_interface.save_session(app, session, response)

        return _response_to_triplet(response)


def handle_request(
    method: str,
    path: str,
    *,
    query_string: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[bytes] = None,
    cookie_header: Optional[str] = None,
) -> Tuple[int, Iterable[Tuple[str, str]], bytes]:
    """Dispatch an HTTP request into Flask and return the raw response triplet."""

    app = _get_app()
    headers = headers or {}

    with app.test_client() as client:
        if cookie_header:
            parsed = SimpleCookie()
            parsed.load(cookie_header)
            host = headers.get("Host")
            for morsel in parsed.values():
                _set_cookie_on_client(client, host, morsel)

        response = client.open(
            path=path,
            method=method,
            query_string=query_string,
            headers=headers,
            data=body,
            follow_redirects=False,
        )

        # Ensure we can read the payload from streamed responses before
        # returning it to Rust. Werkzeug guards streaming responses with
        # direct_passthrough, so disable it prior to get_data().
        response.direct_passthrough = False

        status, header_items, body_bytes = _response_to_triplet(response)

        # The bridge collapses streamed responses into a single payload, so
        # drop chunked transfer-encoding metadata that would now be invalid.
        header_items = [
            (name, value)
            for name, value in header_items
            if name.lower() != "transfer-encoding"
        ]

        return status, header_items, body_bytes


def get_provider_config(provider_name: Optional[str] = None):
    target = provider_name or Config.DEFAULT_LLM.get("provider_name", "")
    for provider in Config.LLM_PROVIDERS:
        if provider.get("provider_name") == target:
            allowed = provider.get("allowed_providers", [])
            if isinstance(allowed, str):
                allowed = [allowed]
            payload = {
                "provider_name": provider.get("provider_name", ""),
                "type": provider.get("type", ""),
                "base_url": provider.get("base_url", ""),
                "api_key": provider.get("api_key"),
                "model_name": provider.get("model_name", ""),
                "context_size": provider.get("context_size"),
                "request_timeout": provider.get("request_timeout"),
                "allowed_providers": allowed or [],
                "test_chunks": provider.get("test_chunks"),
            }
            return json.dumps(payload)
    return None


def _build_error_response(status_code: int, payload: Dict[str, str]):
    response = jsonify(payload)
    response.status_code = status_code
    return _response_to_triplet(response)


def chat_prepare(
    cookie_header: Optional[str],
    payload: Dict[str, object],
):
    global LAST_EXCEPTION
    LAST_EXCEPTION = None
    app = _get_app()

    headers = {}
    if cookie_header:
        headers["Cookie"] = cookie_header

    try:
        with app.test_request_context(
            "/chat",
            method="POST",
            headers=headers or None,
            json=payload,
        ):
            clean_old_sessions()

            user_message = (payload.get("message") or "").strip()
            if not user_message:
                return {
                    "ok": False,
                    "response": _build_error_response(400, {"error": "message is required"}),
                }

            new_system_prompt = payload.get("system_prompt")
        set_name_raw = payload.get("set_name", "default") or "default"
        try:
            set_name = validate_set_name(set_name_raw)
        except ValueError as exc:
            logger.warning("chat invalid set name '%s': %s", set_name_raw, exc)
            return {
                "ok": False,
                "response": _build_error_response(400, {"error": "invalid set name"}),
            }

        session_id = _get_session_id()
        user_session = sessions[session_id]
        user_session["last_used"] = time.time()

        if session_id.startswith("guest_") and not user_session.get("initialized", False):
            user_session.update(
                {
                    "history": [],
                    "system_prompt": Config.DEFAULT_SYSTEM_PROMPT,
                    "initialized": True,
                }
            )

        logger.info("Received chat request. Session: %s", session_id)

        ensure_full_history_loaded(user_session)

        session_username = session.get("username") if "username" in session else None
        encryption_key = _get_user_encryption_key(session_username) if session_username else None
        if not encryption_key and not session_id.startswith("guest_"):
            logger.error("No password available in session for logged-in user")
            return {
                "ok": False,
                "response": _build_error_response(
                    401,
                    {"error": "Session expired or invalid. Please log in again."},
                ),
            }

        if new_system_prompt is not None:
            logger.info("Updating system prompt")
            user_session["system_prompt"] = new_system_prompt
            if session_username:
                current_key = _get_user_encryption_key(session_username)
                try:
                    save_user_system_prompt(
                        session_username,
                        new_system_prompt,
                        set_name,
                        encryption_key=current_key,
                    )
                except ValueError as exc:
                    logger.warning(
                        "chat failed to save system prompt for user %s: %s",
                        session_username,
                        exc,
                    )
                    return {
                        "ok": False,
                        "response": _build_error_response(400, {"error": "invalid request"}),
                    }

        current_system_prompt = user_session.get("system_prompt", Config.DEFAULT_SYSTEM_PROMPT)
        if new_system_prompt is not None and current_system_prompt != new_system_prompt and session_username:
            current_key = _get_user_encryption_key(session_username)
            try:
                save_user_system_prompt(
                    session_username,
                    new_system_prompt,
                    set_name,
                    encryption_key=current_key,
                )
            except ValueError as exc:
                logger.warning(
                    "chat failed to persist updated system prompt for user %s: %s",
                    session_username,
                    exc,
                )
                return {
                    "ok": False,
                    "response": _build_error_response(400, {"error": "invalid request"}),
                }

        session_lock = _get_response_lock(session_id)
        lock_acquired = False
        if session_lock.locked():
            return {
                "ok": False,
                "response": _build_error_response(
                    429,
                    {"error": "A response is currently being generated. Please wait and try again."},
                ),
            }
        if session_lock.acquire(blocking=False):
            lock_acquired = True
        else:
            return {
                "ok": False,
                "response": _build_error_response(
                    429,
                    {"error": "A response is currently being generated. Please wait and try again."},
                ),
            }

        try:
            memory_text = user_session.get("memory", "")
            system_prompt = user_session.get("system_prompt", Config.DEFAULT_SYSTEM_PROMPT)
            encrypted = bool(payload.get("encrypted", False))
            selected_model = payload.get("model_name") or Config.DEFAULT_LLM["provider_name"]

            allowed, msg = _is_model_allowed_for_user(selected_model, session_username)
            if not allowed:
                logger.warning(
                    "Model selection not allowed for user %s: %s - %s",
                    session_username,
                    selected_model,
                    msg,
                )
                if lock_acquired:
                    session_lock.release()
                return {
                    "ok": False,
                    "response": _build_error_response(403, {"error": msg}),
                }

            provider_config_raw = next(
                (
                    llm
                    for llm in Config.LLM_PROVIDERS
                    if llm.get("provider_name") == selected_model
                ),
                None,
            )
            if not provider_config_raw:
                logger.warning("Requested model not found: %s", selected_model)
                if lock_acquired:
                    session_lock.release()
                return {
                    "ok": False,
                    "response": _build_error_response(
                        400,
                        {"error": "requested model not found"},
                    ),
                }

            provider_config = dict(provider_config_raw)
            # Normalize `allowed_providers` so it's always a list. YAML may
            # contain a single string; other code (and Rust's deserializer)
            # expects a sequence. Mirror the logic used in `get_provider_config`.
            allowed = provider_config.get("allowed_providers", [])
            if isinstance(allowed, str):
                provider_config["allowed_providers"] = [allowed]

            # Ensure `test_chunks` is a list when present and valid JSON.
            # Some configs may set this as a JSON string; try to coerce if
            # necessary.
            tc = provider_config.get("test_chunks")
            if isinstance(tc, str):
                try:
                    provider_config["test_chunks"] = json.loads(tc)
                except Exception:
                    # leave as-is; downstream code will ignore invalid values
                    pass

            history_serialisable = []
            for item in user_session.get("history", []):
                if not isinstance(item, (tuple, list)) or len(item) != 2:
                    continue
                user_part = (item[0] or "") if item[0] is not None else ""
                assistant_part = (item[1] or "") if item[1] is not None else ""
                history_serialisable.append([user_part, assistant_part])

            context = {
                "session_id": session_id,
                "username": session_username,
                "set_name": set_name,
                "memory_text": memory_text,
                "system_prompt": system_prompt,
                "history": history_serialisable,
                "encrypted": encrypted,
                "model_name": selected_model,
                "provider_config": provider_config,
            }

            updated_key = _get_user_encryption_key(session_username) if session_username else None
            if updated_key:
                context["encryption_key"] = base64.b64encode(updated_key).decode("ascii")

            test_chunks = os.getenv("CHATBOT_TEST_OPENAI_CHUNKS")
            if test_chunks:
                try:
                    context["test_chunks"] = json.loads(test_chunks)
                except json.JSONDecodeError:
                    logger.warning("Invalid CHATBOT_TEST_OPENAI_CHUNKS payload; ignoring")

            return {"ok": True, "context": json.dumps(context)}
        except Exception:
            # capture the full traceback for test introspection and re-raise
            LAST_EXCEPTION = traceback.format_exc()
            logger.exception("chat_prepare raised unexpected error; releasing lock")
            session_lock.release()
            raise
    except Exception:
        # Ensure LAST_EXCEPTION is set for unexpected outer exceptions
        if LAST_EXCEPTION is None:
            LAST_EXCEPTION = traceback.format_exc()
        raise


def chat_finalize(
    cookie_header: Optional[str],
    session_id: str,
    set_name: str,
    user_message: str,
    assistant_response: str,
    encryption_key: Optional[bytes] = None,
):
    app = _get_app()

    headers = {}
    if cookie_header:
        headers["Cookie"] = cookie_header

    extras: list[str] = []

    with app.test_request_context(
        "/chat",
        method="POST",
        headers=headers or None,
    ):
        try:
            user_session = sessions.get(session_id)
            if user_session is None:
                logger.debug("Session %s missing during finalize", session_id)
                return extras

            history = user_session.setdefault("history", [])
            history.append((user_message, assistant_response))
            logger.info("Chat response generated. Length: %d characters", len(assistant_response))

            if not session_id.startswith("guest_"):
                try:
                    save_user_chat_history(
                        session_id,
                        history,
                        set_name,
                        encryption_key=encryption_key,
                    )
                except ValueError as exc:
                    logger.error("Failed to save chat history: %s", exc)
                    extras.append(f"\n[Error] Failed to save chat history: {exc}")
                except Exception as exc:
                    logger.error("Unexpected error saving chat history: %s", exc)
                    extras.append("\n[Error] Unexpected error saving chat history")
        finally:
            lock = _get_response_lock(session_id)
            if lock.locked():
                lock.release()

    return extras


def chat_release_lock(session_id: str):
    lock = _get_response_lock(session_id)
    if lock.locked():
        lock.release()
