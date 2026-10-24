
from flask import Flask, jsonify
from flask_login import (
    LoginManager,
    login_required,
    current_user
)
from flask_wtf.csrf import CSRFProtect
from config import Config
from app.models import db, User

login_manager = LoginManager()
csrf = CSRFProtect()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    login_manager.login_view = "auth.login"

    @login_manager.user_loader
    def load_user(user_id):
        try:
            return db.session.get(User, int(user_id))
        except (ValueError, TypeError):
            return None

    from app.routes.auth import auth_bp
    app.register_blueprint(auth_bp, url_prefix="/auth")

    @app.route("/")
    def home():
        return "TrustVault authentication service"

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return jsonify({
            "message": "Welcome to TrustVault",
            "email": current_user.email,
            "role": current_user.role
        })

    return app
