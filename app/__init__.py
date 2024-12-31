from flask import Flask
from app.config import Config
from app.routes import register_routes

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Register all application routes
    register_routes(app)

    return app
