from flask import Blueprint, render_template, request, redirect, url_for, flash, abort
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from datetime import datetime
from app import db
from app.models import User, Poll, Option, Vote
import re

bp = Blueprint('routes', __name__)

def admin_required(func):
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for('routes.user_dashboard'))
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

def validate_form_csrf():
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        abort(403)


def sanitize_text(value):
    return re.sub(r'<.*?>', '', value).strip()

def validate_email(email):
    return "@" in email and "." in email

def validate_ssn(ssn):
    return re.match(r"^\d{3}-\d{2}-\d{4}$", ssn)


@bp.route('/')
def home():
    return render_template('index.html')


@bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        ssn = request.form.get('ssn')
        email = request.form.get('email')
        password = request.form.get('password')

        # -------- VALIDATION --------
        if not validate_ssn(ssn):
            flash("Invalid SSN format.", "danger")
            return redirect(url_for('routes.signup'))

        if not validate_email(email):
            flash("Invalid email format.", "danger")
            return redirect(url_for('routes.signup'))

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return redirect(url_for('routes.signup'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        try:
            new_user = User(
                ssn=ssn,
                email=email,
                password=hashed_password,
                active=True
            )
            db.session.add(new_user)
            db.session.commit()
            flash("Account created successfully!", "success")
            return redirect(url_for('routes.login'))

        except IntegrityError as e:
            db.session.rollback()
            if "user.ssn" in str(e):
                flash("SSN already registered.", "danger")
            elif "user.email" in str(e):
                flash("Email already registered.", "danger")
            else:
                flash("Unexpected error occurred.", "danger")
            return redirect(url_for('routes.signup'))

    return render_template('signup.html')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ssn = request.form.get('ssn')
        password = request.form.get('password')

        user = User.query.filter_by(ssn=ssn).first()

        if user and check_password_hash(user.password, password):
            login_user(user)

            # Regenerate session ID on login
            session.permanent = True

            flash("Login successful!", "success")
            return redirect(url_for('routes.admin_dashboard' if user.is_admin else 'routes.user_dashboard'))

        flash("Invalid SSN or password.", "danger")

    return render_template('login.html')


@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('routes.login'))


@bp.route('/create_poll', methods=['GET', 'POST'])
@login_required
@admin_required
def create_poll():
    if request.method == 'POST':
        title = sanitize_text(request.form.get('title'))
        status = request.form.get('status')
        options_raw = request.form.get('options').split(',')

        start_date = datetime.strptime(request.form.get('start_date'), '%Y-%m-%d')
        end_date = datetime.strptime(request.form.get('end_date'), '%Y-%m-%d')

        if start_date >= end_date:
            flash("Start date must be before end date.", "danger")
            return redirect(url_for('routes.create_poll'))

        if status not in ['draft', 'active', 'closed']:
            flash("Invalid poll status.", "danger")
            return redirect(url_for('routes.create_poll'))

        try:
            new_poll = Poll(
                title=title,
                start_date=start_date,
                end_date=end_date,
                status=status,
                user_id=current_user.id
            )
            db.session.add(new_poll)
            db.session.commit()

            # Add sanitized poll options
            for opt in options_raw:
                clean_opt = sanitize_text(opt)
                if clean_opt and len(clean_opt) <= 200:
                    db.session.add(Option(option=clean_opt, poll_id=new_poll.id))

            db.session.commit()

            flash("Poll created successfully!", "success")
            return redirect(url_for('routes.admin_dashboard'))

        except SQLAlchemyError:
            db.session.rollback()
            flash("Database error creating poll.", "danger")

    return render_template('create_poll.html')


@bp.route('/user_dashboard')
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('routes.admin_dashboard'))

    active_polls = Poll.query.filter_by(status='active').all()
    completed_polls = Poll.query.filter_by(status='closed').all()
    user_votes_count = len(current_user.votes)

    return render_template(
        'dashboard.html',
        active_polls=active_polls,
        completed_polls=completed_polls,
        user_votes_count=user_votes_count
    )


@bp.route('/admin_dashboard')
@login_required
@admin_required
def admin_dashboard():
    polls = Poll.query.all()
    summary = {
        "total_polls": Poll.query.count(),
        "active_polls": Poll.query.filter_by(status='active').count(),
        "total_users": User.query.count(),
    }
    return render_template('admin_dashboard.html', polls=polls, summary=summary)


@bp.route('/delete_poll/<int:poll_id>')
@login_required
@admin_required
def delete_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)

    if poll.user_id != current_user.id:
        flash("You cannot delete this poll.", "danger")
        return redirect(url_for('routes.admin_dashboard'))

    db.session.delete(poll)
    db.session.commit()

    flash("Poll deleted successfully.", "success")
    return redirect(url_for('routes.admin_dashboard'))


@bp.route('/vote/<int:poll_id>', methods=['GET', 'POST'])
@login_required
def vote(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    options = Option.query.filter_by(poll_id=poll.id).all()

    if request.method == 'POST':
        option_id = request.form.get('option')

        # Prevent duplicate voting
        if Vote.query.filter_by(user_id=current_user.id, poll_id=poll.id).first():
            flash("You already voted.", "danger")
            return redirect(url_for('routes.user_dashboard'))

        new_vote = Vote(
            user_id=current_user.id,
            poll_id=poll.id,
            option_id=option_id
        )

        db.session.add(new_vote)
        db.session.commit()

        flash("Vote submitted!", "success")
        return redirect(url_for('routes.user_dashboard'))

    return render_template('vote.html', poll=poll, options=options)


@bp.route('/results/<int:poll_id>')
@login_required
def results(poll_id):
    poll = Poll.query.get_or_404(poll_id)

    if poll.status != "closed" and not current_user.is_admin:
        return redirect(url_for('routes.user_dashboard'))

    total_votes = Vote.query.filter_by(poll_id=poll_id).count()
    active_users = User.query.filter_by(active=True).count()

    results = (
        db.session.query(Option.option, db.func.count(Vote.id))
        .join(Vote, Vote.option_id == Option.id)
        .filter(Vote.poll_id == poll_id)
        .group_by(Option.option)
        .all()
    )

    chart_data = [{"name": opt, "value": count} for opt, count in results]

    return render_template(
        "results.html",
        poll=poll,
        results=results,
        total_votes=total_votes,
        active_users=active_users,
        chart_data=chart_data
    )
