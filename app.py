from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_migrate import Migrate

# Initialize the Flask application
app = Flask(__name__)



# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///polls.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'  # Set a secret key for session management

# Initialize the database and migration objects
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Initialize Flask-Migrate with the app and db

login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Specify the login route for unauthenticated users

# Define models for User, Poll, Option, and Vote
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Add is_admin column for admin users

    def __repr__(self):
        return f'<User {self.username}>'

class Poll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(10), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('polls', lazy=True))

    def __repr__(self):
        return f'<Poll {self.title}>'

class Option(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    option = db.Column(db.String(200), nullable=False)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    poll = db.relationship('Poll', backref=db.backref('options', lazy=True))

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    option_id = db.Column(db.Integer, db.ForeignKey('option.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('votes', lazy=True))
    poll = db.relationship('Poll', backref=db.backref('votes', lazy=True))
    option = db.relationship('Option', backref=db.backref('votes', lazy=True))

# Initialize the database tables before the first request
@app.before_request
def create_tables():
    db.create_all()

# User login manager
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Home Route (index)
@app.route('/')
def index():
    return render_template('index.html')  # Make sure you have index.html in your templates folder

# Dashboard Route (User Home after login)

@app.route('/dashboard')
@login_required
def dashboard():
    # Fetch polls for the logged-in user (admin can view all polls, regular users view active polls)
    if current_user.is_admin:
        polls = Poll.query.all()  # Admin can see all polls
    else:
        polls = Poll.query.filter_by(status='active').all()  # Regular users see only active polls
    
    return render_template('dashboard.html', polls=polls)

# Create Poll Route (Handles form to create a new poll)

@app.route('/create_poll', methods=['GET', 'POST'])
@login_required
def create_poll():
    if not current_user.is_admin:  # Only admins can create polls
        flash('You do not have permission to create polls!', 'danger')
        return redirect(url_for('routes.dashboard'))

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
        return redirect(url_for('routes.admin_dashboard'))

    return render_template('create_poll.html')

# Edit Poll Route
@app.route('/edit_poll/<int:poll_id>', methods=['GET', 'POST'])
@login_required
def edit_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    if not current_user.is_admin or poll.user_id != current_user.id:  # Only admin or owner can edit
        flash('You do not have permission to edit this poll!', 'danger')
        return redirect(url_for('routes.dashboard'))

    if request.method == 'POST':
        poll.title = request.form.get('title')
        start_date_str = request.form.get('start_date')
        end_date_str = request.form.get('end_date')
        poll.status = request.form.get('status')

        poll.start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
        poll.end_date = datetime.strptime(end_date_str, '%Y-%m-%d')

        db.session.commit()

        flash('Poll updated successfully!', 'success')
        return redirect(url_for('routes.admin_dashboard'))

    return render_template('edit_poll.html', poll=poll)

# Delete Poll Route
@app.route('/delete_poll/<int:poll_id>', methods=['GET', 'POST'])
@login_required
def delete_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    if not current_user.is_admin or poll.user_id != current_user.id:  # Only admin or owner can delete
        flash('You do not have permission to delete this poll!', 'danger')
        return redirect(url_for('routes.dashboard'))

    db.session.delete(poll)
    db.session.commit()

    flash('Poll deleted successfully!', 'success')
    return redirect(url_for('routes.admin_dashboard'))

# Sign Up Route (User Registration)
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # Hash the password using pbkdf2:sha256
        hashed_password = generate_password_hash(password, method='sha256')

        # Check if the email already exists
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists!', 'danger')
            return redirect(url_for('routes.signup'))

        # Create a new user
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('routes.login'))

    return render_template('signup.html')

# Login Route (User Authentication)
@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Fetch user from database
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')

            # Redirect based on admin status
            if user.is_admin:
                return redirect(url_for('routes.admin_dashboard'))
            else:
                return redirect(url_for('routes.dashboard'))
        else:
            flash('Invalid login credentials', 'danger')

    return render_template('login.html')

# Logout Route (User Logout)
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('routes.login'))

# Poll Voting Route
@app.route('/vote/<int:poll_id>', methods=['GET', 'POST'])
@login_required
def vote(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    options = Option.query.filter_by(poll_id=poll.id).all()

    if request.method == 'POST':
        # Ensure the 'option' field is selected
        option_id = request.form.get('option')

        if not option_id:
            flash('Please select an option to vote!', 'danger')
            return redirect(url_for('vote', poll_id=poll.id))  # Redirect back to poll if option not selected

        # Check if the user has already voted in this poll
        existing_vote = Vote.query.filter_by(user_id=current_user.id, poll_id=poll.id).first()

        if existing_vote:
            flash('You have already voted in this poll!', 'danger')
            return redirect(url_for('routes.dashboard'))  # Redirect to dashboard if user has voted already

        # Add new vote to the database
        new_vote = Vote(user_id=current_user.id, poll_id=poll.id, option_id=option_id)
        db.session.add(new_vote)
        db.session.commit()
        flash('Your vote has been cast successfully!', 'success')

        return redirect(url_for('routes.dashboard'))  # Redirect to dashboard after voting

    return render_template('poll.html', poll=poll, options=options)

# Poll Results Route
@app.route('/results/<int:poll_id>')
@login_required
def results(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    results = db.session.query(Option.option, db.func.count(Vote.id)).join(Vote).filter(Vote.poll_id == poll.id).group_by(Option.id).all()
    return render_template('results.html', poll=poll, results=results)

# Admin Dashboard with Poll Results and Analytics
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.is_admin:
        polls = Poll.query.all()  # Admin views all polls
        return render_template('admin_dashboard.html', polls=polls)
    else:
        return redirect(url_for('routes.user_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)

