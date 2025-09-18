"""Helpers for routing requests from the Rust web server into the existing Flask app."""

from __future__ import annotations

import threading
from http.cookies import SimpleCookie
from typing import Dict, Iterable, Optional, Tuple

from app import create_app

_app_lock = threading.Lock()
_flask_app = None


def _get_app():
    global _flask_app
    if _flask_app is None:
        with _app_lock:
            if _flask_app is None:
                _flask_app = create_app()
    return _flask_app


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
            for morsel in parsed.values():
                client.set_cookie(
                    server_name=headers.get("Host", "localhost"),
                    key=morsel.key,
                    value=morsel.value,
                )

        response = client.open(
            path=path,
            method=method,
            query_string=query_string,
            headers=headers,
            data=body,
            follow_redirects=False,
        )

        header_items = list(response.headers.items(multi=True))
        return response.status_code, header_items, response.get_data()
