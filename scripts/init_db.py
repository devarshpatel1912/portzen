import sys
import platform
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from database import db
from database.models import Host, MonitoringConfig
from config import logger

def init_database():
    app = create_app()
    with app.app_context():
        logger.info("Creating database tables...")
        db.create_all()

        # Seed initial local host if none exists
        local_host = Host.query.filter_by(is_local=True).first()
        if not local_host:
            os_name = f"{platform.system()} {platform.release()}"
            local_host = Host(
                name="Local Machine",
                ip_address="127.0.0.1",
                operating_system=os_name,
                description=f"Authorized local monitoring target on {platform.node()}",
                is_local=True,
            )
            db.session.add(local_host)
            db.session.flush()

            # Initialize monitoring config
            config = MonitoringConfig(
                host_id=local_host.id,
                enabled=False,
                interval_seconds=60,
                auto_start=False,
            )
            db.session.add(config)
            db.session.commit()
            logger.info(f"Initialized default local host: {local_host.name} (ID: {local_host.id})")
        else:
            logger.info(f"Local host already exists: {local_host.name} (ID: {local_host.id})")

        print("Database initialized successfully.")

if __name__ == "__main__":
    init_database()
