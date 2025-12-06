from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import re
from datetime import datetime

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ssn = db.Column(db.String(11), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    active = db.Column(db.Boolean, default=True)
    votes = db.relationship('Vote', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.email}>'

    # Password Hashing 
    def set_password(self, plaintext_password):
        """
        Hashes and stores the password securely.
        """
        self.password = generate_password_hash(plaintext_password)

    def check_password(self, password):
        """
        Verifies the given password against the stored hash.
        """
        return check_password_hash(self.password, password)

    # Role Helper for RBAC 
    def is_admin_user(self):
        """
        Returns True if the user is an admin.
        """
        return self.is_admin

    # Validation for User Fields
    def validate_email(self):
        """
        Validates format of email.
        """
        if "@" not in self.email or "." not in self.email:
            raise ValueError("Invalid email format")

    def validate_ssn(self):
        """
        Ensures SSN is exactly 11 characters (format XXX-XX-XXXX).
        """
        pattern = r"^\d{3}-\d{2}-\d{4}$"
        if not re.match(pattern, self.ssn):
            raise ValueError("Invalid SSN format")

    def validate_password_strength(self, password):
        """
        Ensures password meets minimum strength requirements.
        """
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")


class Poll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(10), nullable=False)

    user = db.relationship('User', backref=db.backref('polls', lazy=True))
    options = db.relationship('Option', cascade='all, delete-orphan', backref='poll', lazy=True)
    votes = db.relationship('Vote', cascade='all, delete-orphan', backref='poll', lazy=True)

    # Validation for Poll 
    def validate_status(self):
        """
        Restrict status to valid values only.
        """
        allowed = ["draft", "active", "closed"]
        if self.status not in allowed:
            raise ValueError("Invalid status value")

    def validate_dates(self):
        """
        Ensures start_date < end_date.
        """
        if self.start_date >= self.end_date:
            raise ValueError("Start date must be before end date")


class Option(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    option = db.Column(db.String(200), nullable=False)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    votes = db.relationship('Vote', cascade='all, delete-orphan', backref='option', lazy=True)

    def sanitize_option(self):
        """
        Basic XSS protection by stripping HTML tags.
        """
        self.option = re.sub(r'<.*?>', '', self.option)

    def validate_option_length(self):
        """
        Enforces the maximum allowed length.
        """
        if len(self.option) > 200:
            raise ValueError("Option text too long")


class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    option_id = db.Column(db.Integer, db.ForeignKey('option.id'), nullable=False)

    def validate_unique_vote(self):
        """
        Prevent a user from voting twice in the same poll.
        """
        exists = Vote.query.filter_by(user_id=self.user_id, poll_id=self.poll_id).first()
        if exists:
            raise ValueError("User has already voted in this poll")
