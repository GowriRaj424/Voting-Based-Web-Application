from app import create_app, db
from app.models import User
from werkzeug.security import generate_password_hash

# Create an instance of the Flask application
app = create_app()

with app.app_context():
    # Create an admin user with email
    admin = User(
        ssn="123-45-6789",
        email="admin@example.com",  # Provide a default email
        password=generate_password_hash("adminpassword", method="scrypt"),  # Use 'scrypt'
        is_admin=True,
    )
    db.session.add(admin)
    db.session.commit()
    print("Admin user created successfully!")
