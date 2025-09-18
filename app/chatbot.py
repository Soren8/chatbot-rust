"""Legacy Flask entry point.

This module now delegates to ``create_app`` from :mod:`app`. Running
``python -m app.chatbot`` will start the same application that Flask or
Gunicorn use, without the insecure session password caching that the old
implementation performed.
"""

from app import create_app

app = create_app()

if __name__ == "__main__":  # pragma: no cover
    app.run()
