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


@auth_bp.route("/signup", methods=["GET", "POST"])
def signup():
    if "user_id" in session:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # --- Validation ---
        if not username or not email or not password or not confirm_password:
            flash("All fields are required.", "danger")
            return render_template("signup.html", username=username, email=email)

        if len(username) < 3 or len(username) > 64:
            flash("Username must be between 3 and 64 characters.", "danger")
            return render_template("signup.html", username=username, email=email)

        if "@" not in email or "." not in email.split("@")[-1]:
            flash("Please enter a valid email address.", "danger")
            return render_template("signup.html", username=username, email=email)

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return render_template("signup.html", username=username, email=email)

        if not any(c.isupper() for c in password) or not any(c.islower() for c in password) or not any(c.isdigit() for c in password):
            flash("Password must contain at least one uppercase letter, one lowercase letter, and one digit.", "danger")
            return render_template("signup.html", username=username, email=email)

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("signup.html", username=username, email=email)

        # Check for existing user
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()

        if existing_user:
            if existing_user.username == username:
                flash("Username is already taken.", "danger")
            else:
                flash("An account with this email already exists.", "danger")
            return render_template("signup.html", username=username, email=email)

        # Create new user
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        logger.info(f"New user '{username}' registered from {request.remote_addr}")

        # Auto-login the new user
        session.clear()
        session["user_id"] = new_user.id
        session["username"] = new_user.username
        session["email"] = new_user.email
        session.permanent = True

        flash(f"Welcome to PortZen, {new_user.username}! Your account has been created.", "success")
        return redirect(url_for("dashboard.index"))

    return render_template("signup.html")


@auth_bp.route("/logout")
def logout():
    username = session.get("username", "Unknown")
    session.clear()
    logger.info(f"User '{username}' logged out.")
    flash("You have been successfully logged out.", "info")
    return redirect(url_for("auth.login"))
