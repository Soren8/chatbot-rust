def test_dotfiles_not_served(client):
    for path in ("/.env", "/.config.yml"):
        resp = client.get(path)
        assert resp.status_code in (404, 403), f"{path} should not be served (status was {resp.status_code})"


def test_static_traversal_blocked(client):
    # Attempt basic traversal into project root via static path
    for path in ("/static/../.env", "/static/../.config.yml", "/static/%2e%2e/.env"):
        resp = client.get(path)
        assert resp.status_code in (404, 403), f"Traversal path {path} should be blocked (status was {resp.status_code})"

