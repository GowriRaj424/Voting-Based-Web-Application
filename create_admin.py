from app import create_app, db
from app.models import User
from werkzeug.security import generate_password_hash

# Create Flask app instance
app = create_app()

with app.app_context():
    # ---- ADMIN CREDENTIALS (DEMO PURPOSES ONLY) ----
    ADMIN_SSN = "123-45-6789"
    ADMIN_EMAIL = "admin@example.com"
    ADMIN_PASSWORD = "Admin@889966"

    # Normalize inputs
    ADMIN_SSN = ADMIN_SSN.strip()
    ADMIN_EMAIL = ADMIN_EMAIL.lower().strip()

    # Check if admin already exists
    existing_admin = User.query.filter_by(email=ADMIN_EMAIL).first()

    if existing_admin:
        print("Admin user already exists. No action taken.")
    else:
        admin_user = User(
            ssn=ADMIN_SSN,
            email=ADMIN_EMAIL,
            password=generate_password_hash(
                ADMIN_PASSWORD,
                method="pbkdf2:sha256",   # ✅ SAME METHOD USED ACROSS APP
                salt_length=16            # extra hardening
            ),
            is_admin=True,
            active=True
        )

        db.session.add(admin_user)
        db.session.commit()

        print("Admin user created successfully.")
