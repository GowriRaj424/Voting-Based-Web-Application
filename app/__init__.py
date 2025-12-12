from flask import Flask, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_wtf import CSRFProtect
from datetime import timedelta

# Initialize instances
db = SQLAlchemy()
migrate = Migrate()
csrf = CSRFProtect()   # CSRF protection enabled


def create_app():
    app = Flask(__name__)


    # Secret Key for Sessions + CSRF
    app.config['SECRET_KEY'] = 'REPLACE_WITH_A_SECURE_RANDOM_KEY'

    # Database
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///polls.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Session Security
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SECURE'] = False   # set True if using HTTPS
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)   # Enable CSRF globally

    # Login Manager
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'routes.login'
    login_manager.session_protection = "strong"  # Helps prevent session hijacking

    from app.models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from app.routes import bp as routes_bp
    app.register_blueprint(routes_bp)

    return app 