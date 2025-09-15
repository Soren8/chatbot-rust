import os
import pytest


# Ensure a non-default secret key for app init in tests
os.environ.setdefault("SECRET_KEY", "test_secret_key_for_security_tests")


@pytest.fixture(scope="session")
def app():
    from app import create_app
    application = create_app()

    # Push an application context for the test session
    ctx = application.app_context()
    ctx.push()
    try:
        yield application
    finally:
        ctx.pop()


@pytest.fixture()
def client(app):
    return app.test_client()

