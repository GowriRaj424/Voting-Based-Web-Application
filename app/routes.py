from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, session
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from datetime import datetime
import re
from functools import wraps

from app import db
from app.models import User, Poll, Option, Vote

bp = Blueprint('routes', __name__)

# ADMIN DECORATOR
def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)   # Unauthorized

        if not current_user.is_admin:
            abort(403)   # Forbidden

        return func(*args, **kwargs)
    return wrapper

# HELPERS
def sanitize_text(value):
    return re.sub(r'<.*?>', '', value).strip()

def validate_email(email):
    return "@" in email and "." in email

def validate_ssn(ssn):
    if not ssn:
        return False
    ssn = ssn.strip()
    return bool(re.fullmatch(r"\d{3}-\d{2}-\d{4}", ssn))


# HOME
@bp.route('/')
def home():
    return render_template('index.html')

# SIGNUP
@bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        ssn = request.form.get('ssn')
        email = request.form.get('email')
        password = request.form.get('password')

        if not validate_ssn(ssn):
            flash("Invalid SSN format.", "danger")
            return redirect(url_for('routes.signup'))

        if not validate_email(email):
            flash("Invalid email format.", "danger")
            return redirect(url_for('routes.signup'))

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return redirect(url_for('routes.signup'))

        hashed_password = generate_password_hash(password)

        try:
            user = User(
                ssn=ssn,
                email=email,
                password=hashed_password,
                active=True
            )
            db.session.add(user)
            db.session.commit()
            flash("Account created successfully.", "success")
            return redirect(url_for('routes.login'))

        except IntegrityError:
            db.session.rollback()
            flash("SSN or Email already exists.", "danger")

    return render_template('signup.html')


# LOGIN
@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ssn = request.form.get('ssn')
        password = request.form.get('password')

        user = User.query.filter_by(ssn=ssn).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            session.permanent = True

            flash("Login successful.", "success")
            return redirect(
                url_for('routes.admin_dashboard' if user.is_admin else 'routes.user_dashboard')
            )

        flash("Invalid SSN or password.", "danger")

    return render_template('login.html')


# LOGOUT
@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for('routes.login'))


# USER DASHBOARD
@bp.route('/user_dashboard')
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('routes.admin_dashboard'))

    active_polls = Poll.query.filter_by(status='active').all()
    completed_polls = Poll.query.filter_by(status='closed').all()

    return render_template(
        'dashboard.html',
        active_polls=active_polls,
        completed_polls=completed_polls,
        user_votes_count=len(current_user.votes)
    )

# ADMIN DASHBOARD
@bp.route('/admin_dashboard')
@login_required
@admin_required
def admin_dashboard():
    polls = Poll.query.all()

    return render_template(
        'admin_dashboard.html',
        polls=polls,
        total_polls=Poll.query.count(),
        active_polls=Poll.query.filter_by(status='active').count(),
        total_users=User.query.count()
    )


# CREATE POLL
@bp.route("/create_poll", methods=["GET", "POST"])
@login_required
@admin_required
def create_poll():

    if request.method == "GET":
        return render_template("create_poll.html")

    # POST logic
    title = request.form.get("title", "").strip()
    start_date = request.form.get("start_date")
    end_date = request.form.get("end_date")
    status = request.form.get("status")
    options_raw = request.form.get("options", "")

    options_list = [opt.strip() for opt in options_raw.split(",") if opt.strip()]

    poll = Poll(
        user_id=current_user.id,
        title=title,
        start_date=datetime.strptime(start_date, "%Y-%m-%d"),
        end_date=datetime.strptime(end_date, "%Y-%m-%d"),
        status=status
    )

    db.session.add(poll)
    db.session.commit()

    for opt_text in options_list:
        option = Option(option=opt_text, poll_id=poll.id)
        db.session.add(option)

    db.session.commit()
    flash("Poll created successfully", "success")

    return redirect(url_for("routes.admin_dashboard"))

# EDIT POLL
@bp.route('/edit_poll/<int:poll_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)

    if poll.user_id != current_user.id:
        abort(403)

    if request.method == 'POST':
        poll.title = sanitize_text(request.form.get('title'))
        poll.status = request.form.get('status')
        poll.start_date = datetime.strptime(request.form.get('start_date'), '%Y-%m-%d')
        poll.end_date = datetime.strptime(request.form.get('end_date'), '%Y-%m-%d')

        db.session.commit()
        flash("Poll updated.", "success")
        return redirect(url_for('routes.admin_dashboard'))

    return render_template('edit_poll.html', poll=poll)


# DELETE POLL (POST ONLY)
@bp.route('/delete_poll/<int:poll_id>', methods=['POST'])
@login_required
@admin_required
def delete_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)

    if poll.user_id != current_user.id:
        abort(403)

    db.session.delete(poll)
    db.session.commit()
    flash("Poll deleted.", "success")
    return redirect(url_for('routes.admin_dashboard'))


# VOTE
@bp.route('/vote/<int:poll_id>', methods=['GET', 'POST'])
@login_required
def vote(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    options = Option.query.filter_by(poll_id=poll.id).all()

    if request.method == 'POST':
        if Vote.query.filter_by(user_id=current_user.id, poll_id=poll.id).first():
            flash("You already voted.", "danger")
            return redirect(url_for('routes.user_dashboard'))

        vote = Vote(
            user_id=current_user.id,
            poll_id=poll.id,
            option_id=request.form.get('option')
        )
        db.session.add(vote)
        db.session.commit()
        flash("Vote submitted.", "success")
        return redirect(url_for('routes.user_dashboard'))

    return render_template('vote.html', poll=poll, options=options)


# RESULTS
@bp.route('/results/<int:poll_id>')
@login_required
def results(poll_id):
    poll = Poll.query.get_or_404(poll_id)

    if poll.status != 'closed' and not current_user.is_admin:
        return redirect(url_for('routes.user_dashboard'))

    results = (
        db.session.query(Option.option, db.func.count(Vote.id))
        .join(Vote)
        .filter(Vote.poll_id == poll.id)
        .group_by(Option.option)
        .all()
    )

    return render_template(
        'results.html',
        poll=poll,
        results=results,
        total_votes=len(poll.votes),
        active_users=User.query.filter_by(active=True).count(),
        chart_data=[{"name": o, "value": c} for o, c in results]
    )