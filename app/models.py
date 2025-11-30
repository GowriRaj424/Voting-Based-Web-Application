# app/models.py

from app import db
from flask_login import UserMixin

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ssn = db.Column(db.String(11), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    active = db.Column(db.Boolean, default=True)
    votes = db.relationship('Vote', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.email}>'  # Changed from username to email for better clarity

# Poll model
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

# Option model
class Option(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    option = db.Column(db.String(200), nullable=False)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    votes = db.relationship('Vote', cascade='all, delete-orphan', backref='option', lazy=True)

# Vote model
class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    option_id = db.Column(db.Integer, db.ForeignKey('option.id'), nullable=False)
