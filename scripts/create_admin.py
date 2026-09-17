import sys
import argparse
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from database import db
from database.models import User
from config import logger

def create_admin(username="admin", email="admin@portzen.local", password="admin123"):
    app = create_app()
    with app.app_context():
        user = User.query.filter((User.username == username) | (User.email == email)).first()
        if user:
            user.username = username
            user.email = email
            user.set_password(password)
            db.session.commit()
            logger.info(f"Updated password for existing administrator '{username}'")
            print(f"User '{username}' updated successfully.")
        else:
            user = User(
                username=username,
                email=email,
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            logger.info(f"Created default administrator '{username}' (email: {email})")
            print(f"User '{username}' created successfully.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create or update administrator user for PortZen")
    parser.add_argument("--username", default="admin", help="Admin username")
    parser.add_argument("--email", default="admin@portzen.local", help="Admin email")
    parser.add_argument("--password", default="admin123", help="Admin password")
    args = parser.parse_args()

    create_admin(args.username, args.email, args.password)
