from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_migrate import Migrate  # Import Migrate

# Initialize Flask application
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///polls.db'  # SQLite URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'  # Session management key

# Initialize database and migration objects
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Initialize Flask-Migrate with the app and db

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Define models (User, Poll, Option, Vote) and migrations here

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Add an admin flag

class Poll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(10), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('polls', lazy=True))
    
    # Add cascade deletion here
    options = db.relationship('Option', backref='poll', cascade='all, delete-orphan')

    def __repr__(self):
        return f'<Poll {self.title}>'


class Option(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    option = db.Column(db.String(100), nullable=False)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    poll = db.relationship('Poll', backref=db.backref('options', lazy=True))

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    option_id = db.Column(db.Integer, db.ForeignKey('option.id'), nullable=False)

# User login manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Home Route (Dashboard)
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        polls = Poll.query.all()  # Admin sees all polls
        flash('Admin Login successfully!', 'success')
        return render_template('admin_dashboard.html', polls=polls)
    else:
        polls = Poll.query.filter_by(status='active').all()  # Regular users see only active polls

    print(f"Polls fetched for {current_user.username}: {polls}")  # Debugging line to check polls

    return render_template('dashboard.html', polls=polls)


# Create Poll Route (Handles form to create a new poll)
@app.route('/create_poll', methods=['GET', 'POST'])
@login_required
def create_poll():
    if not current_user.is_admin:  # Only admins can create polls
        flash('You do not have permission to create polls!', 'danger')
        return redirect(url_for('routes.dashboard'))  # Redirect non-admins to the dashboard
    if request.method == 'POST':
        poll_title = request.form.get('title')
        start_date_str = request.form.get('start_date')
        end_date_str = request.form.get('end_date')
        status = request.form.get('status')
        options = request.form.get('options').split(',')  # Get options from the form and split by comma

        # Convert the string dates to datetime objects
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d')

        # Create a new Poll object for the current user (admin)
        new_poll = Poll(title=poll_title, start_date=start_date, end_date=end_date, status=status, user_id=current_user.id)

        # Add the new poll to the database
        db.session.add(new_poll)
        db.session.commit()  # Commit to get the poll's ID

        # Add options to the new poll
        for option_text in options:
            option_text = option_text.strip()  # Remove extra spaces
            if option_text:  # Ensure we don't add empty options
                new_option = Option(poll_id=new_poll.id, option=option_text)
                db.session.add(new_option)

        db.session.commit()  # Commit the options

        flash('Poll created successfully!', 'success')
        return redirect(url_for('routes.admin_dashboard'))  # Redirect admin to the admin dashboard

    return render_template('create_poll.html')  # Show the form to create a poll

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:  # Ensure only admins access this route
        flash('Access denied. Admins only!', 'danger')
        return redirect(url_for('routes.dashboard'))

    # Fetch all polls and their vote results
    polls = Poll.query.all()

    poll_results = []
    for poll in polls:
        # Calculate the results for each option in the poll
        results = db.session.query(
            Option.option, db.func.count(Vote.id)
        ).join(Vote, Option.id == Vote.option_id, isouter=True).filter(
            Option.poll_id == poll.id
        ).group_by(Option.id).all()

        poll_results.append({
            'poll': poll,
            'results': results
        })

    return render_template('admin_dashboard.html', poll_results=poll_results)

# Additional routes for user registration, login, voting, etc. ...

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
