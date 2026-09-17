from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from database import db

def utc_now():
    """Return current UTC datetime with timezone awareness."""
    return datetime.now(timezone.utc)

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Host(db.Model):
    __tablename__ = "hosts"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    ip_address = db.Column(db.String(64), nullable=False)
    operating_system = db.Column(db.String(64), nullable=True)
    description = db.Column(db.Text, nullable=True)
    is_local = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=utc_now)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now)

    # Relationships
    snapshots = db.relationship("PortSnapshot", backref="host", cascade="all, delete-orphan", lazy="dynamic")
    baseline_ports = db.relationship("BaselinePort", backref="host", cascade="all, delete-orphan", lazy="dynamic")
    events = db.relationship("PortEvent", backref="host", cascade="all, delete-orphan", lazy="dynamic")
    alerts = db.relationship("Alert", backref="host", cascade="all, delete-orphan", lazy="dynamic")
    monitoring_config = db.relationship("MonitoringConfig", backref="host", uselist=False, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "ip_address": self.ip_address,
            "operating_system": self.operating_system,
            "description": self.description,
            "is_local": self.is_local,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "is_monitoring": self.monitoring_config.enabled if self.monitoring_config else False,
            "interval_seconds": self.monitoring_config.interval_seconds if self.monitoring_config else 60,
        }


class BaselinePort(db.Model):
    __tablename__ = "baseline_ports"

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("hosts.id"), nullable=False, index=True)
    port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(8), nullable=False, default="TCP")
    service = db.Column(db.String(64), nullable=True)
    process_name = db.Column(db.String(128), nullable=True)
    local_address = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now)

    __table_args__ = (
        db.UniqueConstraint("host_id", "port", "protocol", name="uq_host_port_proto_baseline"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "host_id": self.host_id,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service or "Unknown",
            "process_name": self.process_name or "Unknown",
            "local_address": self.local_address or "*",
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class PortSnapshot(db.Model):
    __tablename__ = "port_snapshots"

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("hosts.id"), nullable=False, index=True)
    port = db.Column(db.Integer, nullable=False, index=True)
    protocol = db.Column(db.String(8), nullable=False, default="TCP")
    local_address = db.Column(db.String(64), nullable=False, default="0.0.0.0")
    state = db.Column(db.String(32), nullable=False, default="LISTEN")
    process_name = db.Column(db.String(128), nullable=True)
    pid = db.Column(db.Integer, nullable=True)
    service = db.Column(db.String(64), nullable=True)
    risk_level = db.Column(db.String(16), nullable=True, default="LOW")
    timestamp = db.Column(db.DateTime, default=utc_now, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "host_id": self.host_id,
            "port": self.port,
            "protocol": self.protocol,
            "local_address": self.local_address,
            "state": self.state,
            "process_name": self.process_name or "Unknown",
            "pid": self.pid,
            "service": self.service or "Unknown",
            "risk_level": self.risk_level or "LOW",
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


class PortEvent(db.Model):
    __tablename__ = "port_events"

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("hosts.id"), nullable=False, index=True)
    port = db.Column(db.Integer, nullable=False, index=True)
    protocol = db.Column(db.String(8), nullable=False, default="TCP")
    event_type = db.Column(db.String(32), nullable=False, index=True)  # NEW_PORT, PORT_CLOSED, PROCESS_CHANGED, STATE_CHANGED, NO_CHANGE
    previous_state = db.Column(db.String(32), nullable=True)
    current_state = db.Column(db.String(32), nullable=True)
    process_name = db.Column(db.String(128), nullable=True)
    pid = db.Column(db.Integer, nullable=True)
    service = db.Column(db.String(64), nullable=True)
    risk_level = db.Column(db.String(16), nullable=False, default="LOW")
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=utc_now, index=True)

    # One-to-one or one-to-many relationship to Alert
    alert = db.relationship("Alert", backref="event", uselist=False, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "host_id": self.host_id,
            "host_name": self.host.name if self.host else "Unknown",
            "port": self.port,
            "protocol": self.protocol,
            "event_type": self.event_type,
            "previous_state": self.previous_state,
            "current_state": self.current_state,
            "process_name": self.process_name or "Unknown",
            "pid": self.pid,
            "service": self.service or "Unknown",
            "risk_level": self.risk_level,
            "details": self.details,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("hosts.id"), nullable=False, index=True)
    event_id = db.Column(db.Integer, db.ForeignKey("port_events.id"), nullable=True, index=True)
    port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(8), nullable=False, default="TCP")
    risk = db.Column(db.String(16), nullable=False, default="MEDIUM")  # LOW, MEDIUM, HIGH
    score = db.Column(db.Integer, nullable=False, default=50)
    reason = db.Column(db.Text, nullable=False)
    recommendation = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(32), nullable=False, default="OPEN", index=True)  # OPEN, ACKNOWLEDGED, RESOLVED, IGNORED
    process_name = db.Column(db.String(128), nullable=True)
    pid = db.Column(db.Integer, nullable=True)
    service = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now, index=True)
    resolved_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "host_id": self.host_id,
            "host_name": self.host.name if self.host else "Unknown",
            "event_id": self.event_id,
            "port": self.port,
            "protocol": self.protocol,
            "risk": self.risk,
            "score": self.score,
            "reason": self.reason,
            "recommendation": self.recommendation,
            "status": self.status,
            "process_name": self.process_name or "Unknown",
            "pid": self.pid,
            "service": self.service or "Unknown",
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }


class MonitoringConfig(db.Model):
    __tablename__ = "monitoring_configs"

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("hosts.id"), unique=True, nullable=False)
    enabled = db.Column(db.Boolean, default=False)
    interval_seconds = db.Column(db.Integer, default=60)
    auto_start = db.Column(db.Boolean, default=False)
    last_scan = db.Column(db.DateTime, nullable=True)
    next_scan = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now)

    def to_dict(self):
        return {
            "id": self.id,
            "host_id": self.host_id,
            "enabled": self.enabled,
            "interval_seconds": self.interval_seconds,
            "auto_start": self.auto_start,
            "last_scan": self.last_scan.isoformat() if self.last_scan else None,
            "next_scan": self.next_scan.isoformat() if self.next_scan else None,
        }
