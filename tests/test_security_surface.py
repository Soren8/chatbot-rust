import re
import json


def extract_app_data(html: str):
    # Extract JSON from the <template id="app-data" type="application/json"> ... </template>
    m = re.search(r'<template\s+id="app-data"[^>]*>(.*?)</template>', html, re.DOTALL | re.IGNORECASE)
    assert m, "app-data template not found in HTML"
    payload = m.group(1).strip()
    return json.loads(payload)


def assert_no_secrets(html: str):
    forbidden = [
        "api_key",
        "API_KEY",
        "OPENAI",
        "OPENROUTER",
        "Authorization",
        "Bearer ",
        "base_url",
    ]
    lowered = html.lower()
    for token in forbidden:
        assert token.lower() not in lowered, f"Found potential secret token in HTML: {token}"


def test_homepage_has_sanitized_models_and_no_secrets(client):
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8", errors="ignore")

    # Assert no obvious secrets appear in HTML
    assert_no_secrets(html)

    # Validate the app-data JSON shape
    data = extract_app_data(html)
    assert isinstance(data.get("availableModels", []), list)
    for entry in data.get("availableModels", []):
        # Only non-sensitive fields should be present
        assert set(entry.keys()) <= {"provider_name", "tier"}, f"Unexpected fields in availableModels: {entry.keys()}"


def test_auth_pages_have_no_secrets(client):
    for path in ("/login", "/signup"):
        resp = client.get(path)
        assert resp.status_code == 200
        html = resp.data.decode("utf-8", errors="ignore")
        assert_no_secrets(html)
