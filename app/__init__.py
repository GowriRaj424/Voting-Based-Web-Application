from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate

# Initialize the database and migration objects
db = SQLAlchemy()
migrate = Migrate()

# Initialize the Flask application
def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///polls.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'your_secret_key'

    # Initialize the app with the db, migrate, and login_manager
    db.init_app(app)
    migrate.init_app(app, db)
    
    # Initialize Login Manager
    login_manager = LoginManager(app)
    login_manager.login_view = 'routes.login'  # specify the login route for unauthenticated users

    # Import routes and register blueprint
    from app.routes import bp as routes_bp
    app.register_blueprint(routes_bp)

    # Set the user loader function
    from app.models import User
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    return app
