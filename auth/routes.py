from functools import wraps
from flask import render_template, request, redirect, url_for, session, flash, jsonify
from auth import auth_bp
from database import db
from database.models import User
from config import logger

def login_required(f):
    """Decorator to require session authentication for protected routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            if request.is_json or request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required", "authenticated": False}), 401
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username_or_email = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username_or_email or not password:
            flash("Username/email and password are required.", "danger")
            return render_template("login.html")

        # Query user by username or email
        user = User.query.filter(
            (User.username == username_or_email) | (User.email == username_or_email)
        ).first()

        if user and user.check_password(password):
            session.clear()
            session["user_id"] = user.id
            session["username"] = user.username
            session["email"] = user.email
            session.permanent = True
            logger.info(f"Successful login for user '{user.username}' from {request.remote_addr}")
            flash(f"Welcome back, {user.username}!", "success")

            next_url = request.args.get("next")
            if next_url and next_url.startswith("/"):
                return redirect(next_url)
            return redirect(url_for("dashboard.index"))
        else:
            logger.warning(f"Failed login attempt for identifier '{username_or_email}' from {request.remote_addr}")
            flash("Invalid credentials. Please verify username and password.", "danger")

    return render_template("login.html")


@auth_bp.route("/logout")
def logout():
    username = session.get("username", "Unknown")
    session.clear()
    logger.info(f"User '{username}' logged out.")
    flash("You have been successfully logged out.", "info")
    return redirect(url_for("auth.login"))
