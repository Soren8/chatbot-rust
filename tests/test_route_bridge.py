import urllib.parse

import pytest

from app import rust_bridge


def _call_bridge(method: str, path: str, *, headers=None, body=None, query=None):
    status, header_items, payload = rust_bridge.handle_request(
        method,
        path,
        headers=headers,
        body=body,
        query_string=query,
    )
    header_map = {}
    for name, value in header_items:
        header_map.setdefault(name.lower(), value)
    return status, header_map, payload


@pytest.mark.parametrize(
    "path, expected_status, content_check",
    [
        ("/", 200, b"<!DOCTYPE html"),
        ("/signup", 200, b"csrf_token"),
        ("/login", 200, b"csrf_token"),
        ("/health", 200, b"\"healthy\""),
    ],
)
def test_bridge_get_routes(client, path, expected_status, content_check):
    flask_response = client.get(path)
    status, headers, payload = _call_bridge("GET", path)

    assert status == expected_status == flask_response.status_code
    assert content_check in payload
    assert headers.get("content-type") == flask_response.headers.get("Content-Type")


@pytest.mark.parametrize(
    "path, form_data, expected_status",
    [
        ("/login", {"username": "ghost", "password": "invalid"}, 400),
        ("/signup", {"username": "", "password": ""}, 400),
    ],
)
def test_bridge_post_forms(client, path, form_data, expected_status):
    encoded = urllib.parse.urlencode(form_data).encode()
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    status, _, _ = _call_bridge(
        "POST",
        path,
        headers=headers,
        body=encoded,
    )

    flask_status = client.post(path, data=form_data).status_code

    assert status == expected_status == flask_status
