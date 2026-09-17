import os
import logging
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

# Ensure logs directory exists
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)
LOG_FILE = LOGS_DIR / "portzen.log"

class Config:
    """Application base configuration."""
    SECRET_KEY = os.environ.get("SECRET_KEY", "portzen-dev-secret-key-cybersec-2026")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'portzen.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = 86400  # 24 hours
    
    # Monitoring Defaults
    PORT = int(os.environ.get("PORT", 5100))
    DEFAULT_SCAN_INTERVAL = 60  # seconds
    SUPPORTED_INTERVALS = [10, 30, 60, 300, 900, 1800]
    
    # Logging Configuration
    LOG_FILE_PATH = str(LOG_FILE)
    LOG_LEVEL = os.environ.get("PORTZEN_LOG_LEVEL", os.environ.get("PORTWATCH_LOG_LEVEL", "INFO")).upper()


def setup_logger():
    """Configure PortZen system logger."""
    logger = logging.getLogger("portzen")
    if not logger.handlers:
        logger.setLevel(getattr(logging, Config.LOG_LEVEL, logging.INFO))
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        
        # File handler
        file_handler = logging.FileHandler(Config.LOG_FILE_PATH, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
    return logger

logger = setup_logger()
