from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from app.models import User, Poll, Option, Vote
from datetime import datetime
from flask import render_template
from .models import Poll, Option, Vote
from datetime import datetime
from flask import render_template, abort
from .models import Poll, Option, Vote, User  # Ensure models are imported
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash

# Define the blueprint
bp = Blueprint('routes', __name__)

# Home Route (Dashboard)
@bp.route('/')
def home():
    return render_template('index.html')

@bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        ssn = request.form.get('ssn')  # Collect SSN instead of username
        email = request.form.get('email')
        password = request.form.get('password')

        # Hash the password using scrypt
        hashed_password = generate_password_hash(password, method='scrypt')

        try:
            # Create and commit a new user with SSN
            new_user = User(ssn=ssn, email=email, password=hashed_password, active=True)
            db.session.add(new_user)
            db.session.commit()

            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('routes.login'))

        except IntegrityError as e:
            db.session.rollback()

            if 'UNIQUE constraint failed: user.ssn' in str(e):
                flash('The SSN is already registered. Please use a different SSN.', 'danger')
            elif 'UNIQUE constraint failed: user.email' in str(e):
                flash('The email is already registered. Please use a different email.', 'danger')
            else:
                flash('An unexpected error occurred. Please try again.', 'danger')

            return redirect(url_for('routes.signup'))

    return render_template('signup.html')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ssn = request.form.get('ssn')  # Collect SSN from the login form
        password = request.form.get('password')

        # Query the user by SSN
        user = User.query.filter_by(ssn=ssn).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')

            # Redirect based on user type
            if user.is_admin:
                return redirect(url_for('routes.admin_dashboard'))
            else:
                return redirect(url_for('routes.user_dashboard'))
        else:
            flash('Invalid SSN or password. Please try again.', 'danger')

    return render_template('login.html')

# Logout Route (User Logout)
@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('routes.login'))

# Poll Creation Route (Admin only)
@bp.route('/create_poll', methods=['GET', 'POST'])
@login_required
def create_poll():
    if not current_user.is_admin:  # Only admins can create polls
        flash('You do not have permission to create polls!', 'danger')
        return redirect(url_for('routes.user_dashboard'))

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

@bp.route('/user_dashboard', endpoint='user_dashboard')
@login_required
def user_dashboard():
    """
    This is the dashboard for regular users.
    Users can see both active polls and completed polls (with results).
    """
    if current_user.is_admin:
        # If admin accesses this page, redirect them to the admin dashboard
        return redirect(url_for('routes.admin_dashboard'))
    
    # Show active polls and completed polls
    active_polls = Poll.query.filter_by(status='active').all()
    completed_polls = Poll.query.filter_by(status='closed').all()
    
    # Fetch user's total votes count
    user_votes_count = len(current_user.votes) if current_user.votes else 0

    return render_template('dashboard.html', active_polls=active_polls, completed_polls=completed_polls, user_votes_count=user_votes_count)

@bp.route('/admin_dashboard', endpoint='admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.is_admin:
        polls = Poll.query.all()
        total_polls = Poll.query.count()
        active_polls = Poll.query.filter_by(status='active').count()
        total_users = User.query.count()
        total_candidates = 0  # Replace this with the actual query for candidates
        return render_template('admin_dashboard.html', 
                               polls=polls, 
                               total_polls=total_polls, 
                               active_polls=active_polls, 
                               total_users=total_users, 
                               total_candidates=total_candidates)
    else:
        return redirect(url_for('routes.user_dashboard'))

@bp.route('/delete_poll/<int:poll_id>', methods=['GET', 'POST'])
@login_required
def delete_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    if not current_user.is_admin or poll.user_id != current_user.id:
        flash('You do not have permission to delete this poll!', 'danger')
        return redirect(url_for('routes.user_dashboard'))

    db.session.delete(poll)  # This will now cascade and delete related options and votes
    db.session.commit()

    flash('Poll deleted successfully!', 'success')
    return redirect(url_for('routes.admin_dashboard'))


# Poll Voting Route
@bp.route('/vote/<int:poll_id>', methods=['GET', 'POST'])
@login_required
def vote(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    options = Option.query.filter_by(poll_id=poll.id).all()

    if request.method == 'POST':
        option_id = request.form.get('option')
        existing_vote = Vote.query.filter_by(user_id=current_user.id, poll_id=poll.id).first()

        if existing_vote:
            flash('You have already voted in this poll!', 'danger')
            return redirect(url_for('routes.user_dashboard'))

        new_vote = Vote(user_id=current_user.id, poll_id=poll.id, option_id=option_id)
        db.session.add(new_vote)
        db.session.commit()

        flash('Your vote has been cast successfully!', 'success')
        return redirect(url_for('routes.user_dashboard'))

    return render_template('vote.html', poll=poll, options=options)


@bp.route('/results/<int:poll_id>')
@login_required
def results(poll_id):
    try:
        # Get poll, if not found return 404
        poll = Poll.query.get_or_404(poll_id)

        # Check if the poll is closed
        if poll.status != 'closed':
            # If user is not admin, redirect to the dashboard or show a message
            if not current_user.is_admin:
                return redirect(url_for('routes.user_dashboard'))  # Or show an appropriate message

        # Get total votes for this poll
        total_votes = Vote.query.filter_by(poll_id=poll_id).count()

        # Get active users (ensure 'active' column exists in User model)
        try:
            active_users = User.query.filter_by(active=True).count()
        except Exception as e:
            print(f"User 'active' attribute not found. Error: {e}")
            active_users = 0  # Default to 0

        # Get vote counts for each option
        results = (
            db.session.query(Option.option, db.func.count(Vote.id).label('vote_count'))
            .join(Vote, Vote.option_id == Option.id)
            .filter(Vote.poll_id == poll_id)
            .group_by(Option.option)
            .all()
        )

        # Handle no votes case
        if not results:
            winning_candidate = "No Votes"
            winning_votes = 0
        else:
            # Sort results by votes in descending order
            results.sort(key=lambda x: x[1], reverse=True)
            winning_candidate = results[0][0]  # Candidate with most votes
            winning_votes = results[0][1]  # Number of votes for the winner

        # Detailed table data for the results
        detailed_results = []
        
        for option, vote_count in results:
            detailed_results.append({
                'candidate_name': option,
                'live_votes': vote_count, 
                'total_votes': vote_count, 
                'poll_end_time': poll.end_date if isinstance(poll.end_date, datetime) else datetime.strptime(poll.end_date, '%Y-%m-%d')
            })

        # Prepare chart data for Echarts
        chart_data = [{"name": option, "value": vote_count} for option, vote_count in results]

        # Render the results.html page
        return render_template(
            'results.html', 
            poll=poll, 
            total_votes=total_votes, 
            active_users=active_users, 
            winning_votes=winning_votes, 
            winning_candidate=winning_candidate, 
            results=detailed_results, 
            chart_data=chart_data
        )

    except SQLAlchemyError as e:
        print(f"SQLAlchemy Error: {str(e)}")
        return "Database Error. Please check the server logs.", 500

    except Exception as e:
        print(f"General Error: {str(e)}")
        return "Something went wrong. Please check the server logs.", 500


@bp.route('/edit_poll/<int:poll_id>', methods=['GET', 'POST'])
@login_required
def edit_poll(poll_id):
    """
    Edit an existing poll. Only accessible to admins.
    """
    # Check if the user is an admin
    if not current_user.is_admin:
        flash('You do not have permission to edit polls.', 'danger')
        return redirect(url_for('routes.user_dashboard'))

    # Fetch the poll from the database
    poll = Poll.query.get_or_404(poll_id)

    if request.method == 'POST':
        try:
            # Get data from the form
            poll.title = request.form.get('title')
            poll.start_date = datetime.strptime(request.form.get('start_date'), '%Y-%m-%d')
            poll.end_date = datetime.strptime(request.form.get('end_date'), '%Y-%m-%d')
            poll.status = request.form.get('status')

            # Ensure the end date is after the start date
            if poll.start_date >= poll.end_date:
                flash('End date must be after the start date.', 'danger')
                return render_template('edit_poll.html', poll=poll)

            # Commit changes to the database
            db.session.commit()

            flash('Poll updated successfully!', 'success')
            return redirect(url_for('routes.admin_dashboard'))

        except Exception as e:
            print(f"Error updating poll: {e}")
            flash('An error occurred while updating the poll.', 'danger')
            return redirect(url_for('routes.edit_poll', poll_id=poll.id))

    # Render the edit form
    return render_template('edit_poll.html', poll=poll)

