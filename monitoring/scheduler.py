"""Monitoring Scheduler Module
Provides a thread-safe background service that runs continuous periodic port scans
for all hosts with monitoring enabled.
"""

import threading
import time
from datetime import datetime, timezone, timedelta
from config import logger

class BackgroundScheduler:
    def __init__(self):
        self._thread = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._app = None
        self._is_running = False

    def init_app(self, app):
        """Bind Flask app instance to scheduler."""
        self._app = app

    def start(self):
        """Start the background monitoring loop."""
        with self._lock:
            if self._is_running:
                logger.debug("Background scheduler already running.")
                return

            self._stop_event.clear()
            self._is_running = True
            self._thread = threading.Thread(target=self._run_loop, name="PortZenScheduler", daemon=True)
            self._thread.start()
            logger.info("Background monitoring scheduler thread started.")

    def stop(self):
        """Gracefully signal scheduler thread to terminate."""
        def can_log():
            try:
                for h in logger.handlers:
                    if hasattr(h, "stream") and getattr(h.stream, "closed", False):
                        return False
                return True
            except Exception:
                return False

        with self._lock:
            if not self._is_running:
                return
            if can_log():
                try:
                    logger.info("Stopping background monitoring scheduler...")
                except Exception:
                    pass
            self._stop_event.set()
            self._is_running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
            if can_log():
                try:
                    logger.info("Background monitoring scheduler stopped.")
                except Exception:
                    pass

    def _run_loop(self):
        """Scheduler worker loop."""
        while not self._stop_event.is_set():
            try:
                if self._app:
                    with self._app.app_context():
                        self._check_and_scan_hosts()
            except Exception as e:
                logger.error(f"Error in scheduler execution cycle: {e}", exc_info=True)

            # Sleep in short increments to allow rapid shutdown response
            for _ in range(5):
                if self._stop_event.is_set():
                    break
                time.sleep(1)

    def _check_and_scan_hosts(self):
        """Check all hosts that have monitoring enabled and need a scan."""
        from database import db
        from database.models import Host, MonitoringConfig
        from monitoring.monitor import execute_host_scan

        now = datetime.now(timezone.utc)
        active_configs = MonitoringConfig.query.filter_by(enabled=True).all()

        for config in active_configs:
            # If next_scan is due or not set yet
            due = False
            if config.next_scan is None:
                due = True
            else:
                # Handle naive vs aware datetime if needed
                next_scan_time = config.next_scan
                if next_scan_time.tzinfo is None:
                    next_scan_time = next_scan_time.replace(tzinfo=timezone.utc)
                if now >= next_scan_time:
                    due = True

            if due:
                host = db.session.get(Host, config.host_id)
                if host:
                    try:
                        logger.info(f"Scheduled periodic scan triggered for host '{host.name}' (ID: {host.id}).")
                        execute_host_scan(host.id)
                    except Exception as err:
                        logger.error(f"Scheduled scan failed for host '{host.name}': {err}")
                        # Push next scan forward anyway to prevent rapid loop failure
                        config.next_scan = now + timedelta(seconds=config.interval_seconds or 60)
                        db.session.commit()


scheduler = BackgroundScheduler()

def start_host_monitoring(host_id: int, interval_seconds: int = None) -> bool:
    """Enable continuous monitoring for a specific host."""
    from database import db
    from database.models import MonitoringConfig
    from monitoring.monitor import execute_host_scan

    config = MonitoringConfig.query.filter_by(host_id=host_id).first()
    if not config:
        config = MonitoringConfig(host_id=host_id)
        db.session.add(config)

    config.enabled = True
    if interval_seconds:
        config.interval_seconds = interval_seconds

    now = datetime.now(timezone.utc)
    config.last_scan = now
    config.next_scan = now + timedelta(seconds=config.interval_seconds)
    db.session.commit()

    # Trigger an immediate scan run upon starting monitoring
    try:
        execute_host_scan(host_id)
    except Exception as e:
        logger.warning(f"Immediate scan on start monitoring encountered error: {e}")

    logger.info(f"Monitoring enabled for Host ID {host_id} (Interval: {config.interval_seconds}s)")
    return True


def stop_host_monitoring(host_id: int) -> bool:
    """Disable continuous monitoring for a specific host."""
    from database import db
    from database.models import MonitoringConfig

    config = MonitoringConfig.query.filter_by(host_id=host_id).first()
    if config:
        config.enabled = False
        config.next_scan = None
        db.session.commit()
        logger.info(f"Monitoring disabled for Host ID {host_id}")
        return True
    return False
