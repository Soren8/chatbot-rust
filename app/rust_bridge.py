"""Helpers for routing requests from the Rust web server into the existing Flask app."""

from __future__ import annotations

import threading
import inspect
import hmac
from http.cookies import SimpleCookie
from typing import Dict, Iterable, Optional, Tuple

from flask import make_response, redirect, session, url_for

from app import create_app
from app.routes import (
    _set_user_encryption_key,
    load_user_memory,
    load_user_system_prompt,
    sessions,
    USER_ENCRYPTION_KEYS,
    home,
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

        header_items_fn = response.headers.items
        header_params = inspect.signature(header_items_fn).parameters
        if "multi" in header_params:
            header_items = list(header_items_fn(multi=True))
        else:
            header_items = list(header_items_fn())

        return response.status_code, header_items, response.get_data()



def render_home(cookie_header: Optional[str] = None):
    app = _get_app()

    headers = {}
    if cookie_header:
        headers["Cookie"] = cookie_header

    with app.test_request_context("/", method="GET", headers=headers or None):
        response = make_response(home())
        app.session_interface.save_session(app, session, response)

        header_items_fn = response.headers.items
        header_params = inspect.signature(header_items_fn).parameters
        if "multi" in header_params:
            header_items = list(header_items_fn(multi=True))
        else:
            header_items = list(header_items_fn())

        return response.status_code, header_items, response.get_data()

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

        header_items_fn = response.headers.items
        header_params = inspect.signature(header_items_fn).parameters
        if "multi" in header_params:
            header_items = list(header_items_fn(multi=True))
        else:
            header_items = list(header_items_fn())

        return response.status_code, header_items, response.get_data()


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

        header_items_fn = response.headers.items
        header_params = inspect.signature(header_items_fn).parameters
        if "multi" in header_params:
            header_items = list(header_items_fn(multi=True))
        else:
            header_items = list(header_items_fn())
        return response.status_code, header_items, response.get_data()
