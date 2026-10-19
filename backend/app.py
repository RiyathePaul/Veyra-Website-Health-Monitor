import os
import ssl
import socket
import smtplib
from email.message import EmailMessage
from datetime import datetime, timezone, timedelta

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import hashlib
import re


# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================

BASE_DIR = os.path.abspath(
    os.path.dirname(os.path.dirname(__file__))
)

load_dotenv(
    os.path.join(BASE_DIR, ".env")
)


# ============================================================
# EMAIL SETTINGS
# ============================================================

MAIL_SERVER = os.getenv(
    "MAIL_SERVER",
    "smtp.gmail.com"
)

MAIL_PORT = int(
    os.getenv(
        "MAIL_PORT",
        "587"
    )
)

MAIL_USERNAME = os.getenv(
    "MAIL_USERNAME"
)

MAIL_PASSWORD = os.getenv(
    "MAIL_PASSWORD"
)

MAIL_RECIPIENT = os.getenv(
    "MAIL_RECIPIENT"
)


# ============================================================
# APP SETUP
# ============================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("VEYRA_SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
CORS(app, supports_credentials=True, origins=["http://127.0.0.1:5500", "http://localhost:5500"])

DB_PATH = os.path.join(
    BASE_DIR,
    "website_health.db"
)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///" + DB_PATH.replace("\\", "/")
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

scheduler = BackgroundScheduler()


# ============================================================
# DATABASE MODELS
# ============================================================

class HealthCheck(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    url = db.Column(
        db.String(500),
        nullable=False
    )

    status = db.Column(
        db.String(50)
    )

    http_status = db.Column(
        db.Integer
    )

    response_time_ms = db.Column(
        db.Float
    )

    ssl_valid = db.Column(
        db.Boolean
    )

    ssl_expiry = db.Column(
        db.DateTime
    )

    ssl_days_remaining = db.Column(
        db.Integer
    )

    ssl_error = db.Column(
        db.Text
    )

    checked_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )


class MonitoredWebsite(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    url = db.Column(
        db.String(500),
        unique=True,
        nullable=False
    )

    status = db.Column(
        db.String(50)
    )

    http_status = db.Column(
        db.Integer
    )

    response_time_ms = db.Column(
        db.Float
    )

    ssl_valid = db.Column(
        db.Boolean
    )

    ssl_expiry = db.Column(
        db.DateTime
    )

    ssl_days_remaining = db.Column(
        db.Integer
    )

    checked_at = db.Column(
        db.DateTime
    )

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )


class Incident(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    url = db.Column(
        db.String(500),
        nullable=False
    )

    incident_type = db.Column(
        db.String(100)
    )

    status = db.Column(
        db.String(50)
    )

    message = db.Column(
        db.Text
    )

    started_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    resolved_at = db.Column(
        db.DateTime
    )


class AppSetting(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    key = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    value = db.Column(
        db.String(500),
        nullable=False
    )


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class EmailOTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    code_hash = db.Column(db.String(64), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts = db.Column(db.Integer, default=0, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)


class WebsiteSubscription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    website_id = db.Column(db.Integer, db.ForeignKey("monitored_website.id"), nullable=False, index=True)
    notify_down = db.Column(db.Boolean, default=True, nullable=False)
    notify_recovery = db.Column(db.Boolean, default=True, nullable=False)
    __table_args__ = (db.UniqueConstraint("user_id", "website_id", name="uq_user_website_subscription"),)


# ============================================================
# DEFAULT SETTINGS
# ============================================================

DEFAULT_SETTINGS = {
    "monitoring_enabled": "true",
    "monitoring_interval_minutes": "5",
    "max_retries": "2"
}


def get_setting(key):

    setting = AppSetting.query.filter_by(
        key=key
    ).first()

    if setting:
        return setting.value

    default_value = DEFAULT_SETTINGS.get(key)

    if default_value is not None:

        setting = AppSetting(
            key=key,
            value=default_value
        )

        db.session.add(setting)
        db.session.commit()

        return default_value

    return None


def set_setting(key, value):

    setting = AppSetting.query.filter_by(
        key=key
    ).first()

    if setting:

        setting.value = str(value)

    else:

        setting = AppSetting(
            key=key,
            value=str(value)
        )

        db.session.add(setting)

    db.session.commit()


def get_monitoring_enabled():

    return (
        get_setting("monitoring_enabled")
        == "true"
    )


def get_monitoring_interval():

    try:

        value = int(
            get_setting(
                "monitoring_interval_minutes"
            )
        )

        return max(1, value)

    except Exception:

        return 5


def get_max_retries():

    try:

        value = int(
            get_setting("max_retries")
        )

        return max(0, value)

    except Exception:

        return 2


# ============================================================
# EMAIL ALERT FUNCTION
# ============================================================

def send_email_alert(
    subject,
    message
):

    recipient_setting = AppSetting.query.filter_by(key="alert_email").first()
    recipient = recipient_setting.value if recipient_setting and recipient_setting.value else MAIL_RECIPIENT
    enabled_setting = AppSetting.query.filter_by(key="email_alerts_enabled").first()
    if enabled_setting and enabled_setting.value.lower() == "false":
        return False
    if not MAIL_USERNAME or not MAIL_PASSWORD or not recipient:
        print("[EMAIL] Email settings are missing. Alert was not sent.")
        return False

    try:

        email = EmailMessage()

        email["From"] = MAIL_USERNAME

        email["To"] = recipient

        email["Subject"] = subject

        email.set_content(message)

        with smtplib.SMTP(
            MAIL_SERVER,
            MAIL_PORT,
            timeout=20
        ) as server:

            server.starttls()

            server.login(
                MAIL_USERNAME,
                MAIL_PASSWORD
            )

            server.send_message(email)

        print(
            f"[EMAIL] Alert sent to {recipient}"
        )

        return True

    except Exception as error:

        print(
            f"[EMAIL ERROR] {error}"
        )

        return False


def send_email_to(recipient, subject, message):
    if not MAIL_USERNAME or not MAIL_PASSWORD or not recipient:
        print("[EMAIL] SMTP credentials or recipient missing; email skipped.")
        return False
    try:
        email = EmailMessage()
        email["From"] = MAIL_USERNAME
        email["To"] = recipient
        email["Subject"] = subject
        email.set_content(message)
        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=20) as server:
            server.starttls()
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.send_message(email)
        print(f"[EMAIL] Sent to {recipient}")
        return True
    except Exception as error:
        print(f"[EMAIL ERROR] {error}")
        return False


def notify_subscribers(url, event, result, reason=""):
    website = MonitoredWebsite.query.filter_by(url=url).first()
    if not website:
        return
    for sub in WebsiteSubscription.query.filter_by(website_id=website.id).all():
        user = db.session.get(User, sub.user_id)
        if not user or not user.email_verified:
            continue
        if event == "DOWN" and not sub.notify_down:
            continue
        if event == "UP" and not sub.notify_recovery:
            continue
        if event == "DOWN":
            subject = f"Veyra alert: {url} is DOWN"
            body = (f"Veyra Website Health Monitor\n\nWebsite: {url}\nStatus: DOWN\n"
                    f"HTTP status: {result.get('http_status')}\nResponse time: {result.get('response_time_ms')} ms\n"
                    f"Reason: {reason or 'Confirmed health check failure'}\n\n"
                    "You receive this because you subscribed to alerts for this website.")
        else:
            subject = f"Veyra recovery: {url} is UP"
            body = (f"Veyra Website Health Monitor\n\nWebsite: {url}\nStatus: UP\n"
                    f"HTTP status: {result.get('http_status')}\nResponse time: {result.get('response_time_ms')} ms\n\n"
                    "The website has recovered. You receive this because you subscribed to its alerts.")
        send_email_to(user.email, subject, body)


def current_user():
    user_id = session.get("user_id")
    return db.session.get(User, user_id) if user_id else None


# ============================================================
# URL HELPERS
# ============================================================

def normalize_url(url):

    url = url.strip()

    if not url.startswith(
        ("http://", "https://")
    ):

        url = "https://" + url

    return url.rstrip("/")


# ============================================================
# SSL CHECK
# ============================================================

def check_ssl_certificate(url):

    if not url.startswith("https://"):

        return {
            "ssl_valid": None,
            "ssl_expiry": None,
            "ssl_days_remaining": None,
            "ssl_error": ""
        }

    try:

        hostname = (
            url
            .split("://", 1)[1]
            .split("/", 1)[0]
        )

        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, 443),
            timeout=10
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as secure_socket:

                certificate = (
                    secure_socket.getpeercert()
                )

        expiry_text = certificate.get(
            "notAfter"
        )

        if not expiry_text:

            return {
                "ssl_valid": True,
                "ssl_expiry": None,
                "ssl_days_remaining": None,
                "ssl_error": ""
            }

        expiry = datetime.strptime(
            expiry_text,
            "%b %d %H:%M:%S %Y %Z"
        ).replace(
            tzinfo=timezone.utc
        )

        now = datetime.now(timezone.utc)

        days_remaining = (
            expiry - now
        ).days

        return {
            "ssl_valid": days_remaining >= 0,
            "ssl_expiry": expiry,
            "ssl_days_remaining": days_remaining,
            "ssl_error": ""
        }

    except Exception as error:

        return {
            "ssl_valid": False,
            "ssl_expiry": None,
            "ssl_days_remaining": None,
            "ssl_error": str(error)
        }


# ============================================================
# HEALTH CHECK
# ============================================================

def perform_health_check(url):

    url = normalize_url(url)

    start = datetime.now(timezone.utc)

    try:

        response = requests.get(
            url,
            timeout=15,
            allow_redirects=True
        )

        end = datetime.now(timezone.utc)

        response_time = (
            end - start
        ).total_seconds() * 1000

        ssl_data = check_ssl_certificate(
            response.url
        )

        if 200 <= response.status_code < 400:

            status = "UP"

        else:

            status = "DOWN"

        return {
            "url": url,
            "status": status,
            "http_status": response.status_code,
            "response_time_ms": round(
                response_time,
                2
            ),
            **ssl_data
        }

    except requests.RequestException as error:

        end = datetime.now(timezone.utc)

        response_time = (
            end - start
        ).total_seconds() * 1000

        return {
            "url": url,
            "status": "DOWN",
            "http_status": None,
            "response_time_ms": round(
                response_time,
                2
            ),
            "ssl_valid": None,
            "ssl_expiry": None,
            "ssl_days_remaining": None,
            "ssl_error": str(error)
        }

    except Exception as error:

        return {
            "url": url,
            "status": "DOWN",
            "http_status": None,
            "response_time_ms": None,
            "ssl_valid": None,
            "ssl_expiry": None,
            "ssl_days_remaining": None,
            "ssl_error": str(error)
        }


# ============================================================
# RETRY LOGIC
# ============================================================

def perform_health_check_with_retry(url):

    max_retries = get_max_retries()

    total_attempts = max_retries + 1

    last_result = None

    for attempt in range(total_attempts):

        result = perform_health_check(url)

        last_result = result

        if result["status"] == "UP":

            return result

    return last_result


# ============================================================
# SAVE HEALTH RESULT
# ============================================================

def save_health_result(result):

    checked_at = datetime.now(timezone.utc)

    health = HealthCheck(
        url=result["url"],
        status=result["status"],
        http_status=result["http_status"],
        response_time_ms=result["response_time_ms"],
        ssl_valid=result["ssl_valid"],
        ssl_expiry=result["ssl_expiry"],
        ssl_days_remaining=result[
            "ssl_days_remaining"
        ],
        ssl_error=result.get(
            "ssl_error",
            ""
        ),
        checked_at=checked_at
    )

    db.session.add(health)

    website = MonitoredWebsite.query.filter_by(
        url=result["url"]
    ).first()

    if website:

        website.status = result["status"]

        website.http_status = (
            result["http_status"]
        )

        website.response_time_ms = (
            result["response_time_ms"]
        )

        website.ssl_valid = (
            result["ssl_valid"]
        )

        website.ssl_expiry = (
            result["ssl_expiry"]
        )

        website.ssl_days_remaining = (
            result["ssl_days_remaining"]
        )

        website.checked_at = checked_at

    db.session.commit()

    return health


# ============================================================
# INCIDENT HANDLING + EMAIL ALERTS
# ============================================================

def handle_incident(result):
    """Track incident transitions and notify users subscribed to the website."""
    url = result.get("url")
    status = result.get("status")
    if not url:
        print("[INCIDENT ERROR] Health-check result has no URL.")
        return

    open_incident = Incident.query.filter_by(url=url, status="OPEN").first()

    if status == "DOWN":
        if open_incident:
            print(f"[INCIDENT] {url} remains DOWN; duplicate alert skipped.")
            return

        error_message = result.get("ssl_error") or ""
        if result.get("http_status") is not None:
            incident_message = f"Website returned HTTP {result['http_status']}."
        elif error_message:
            incident_message = f"Website check failed: {error_message}"
        else:
            incident_message = "Website failed the confirmed health check."

        incident = Incident(
            url=url,
            incident_type="WEBSITE_DOWN",
            status="OPEN",
            message=incident_message,
            started_at=datetime.now(timezone.utc),
        )
        db.session.add(incident)
        db.session.commit()
        print(f"[INCIDENT] {url} -> OPEN")
        # Send to verified users who subscribed to this website, not the fixed admin address.
        notify_subscribers(url, "DOWN", result, incident_message)

    elif status == "UP" and open_incident:
        open_incident.status = "RESOLVED"
        open_incident.resolved_at = datetime.now(timezone.utc)
        open_incident.message = "Website recovered and is responding again."
        db.session.commit()
        print(f"[INCIDENT] {url} -> RESOLVED")
        notify_subscribers(url, "UP", result)


# ============================================================
# AUTOMATIC MONITORING
# ============================================================

def monitor_all_websites():

    with app.app_context():

        if not get_monitoring_enabled():

            print(
                "[MONITOR] Automatic monitoring "
                "is disabled"
            )

            return

        websites = MonitoredWebsite.query.all()

        print(
            f"[MONITOR] Checking "
            f"{len(websites)} website(s)"
        )

        for website in websites:

            result = (
                perform_health_check_with_retry(
                    website.url
                )
            )

            save_health_result(result)

            handle_incident(result)

            print(
                f"[CHECK] "
                f"{website.url} -> "
                f"{result['status']}"
            )


# ============================================================
# SCHEDULER CONTROL
# ============================================================

def configure_scheduler():

    interval = get_monitoring_interval()

    existing_job = scheduler.get_job(
        "website_monitor"
    )

    if existing_job:

        scheduler.remove_job(
            "website_monitor"
        )

    if get_monitoring_enabled():

        scheduler.add_job(
            monitor_all_websites,
            "interval",
            minutes=interval,
            id="website_monitor",
            replace_existing=True
        )

        print(
            f"[SCHEDULER] Monitoring enabled "
            f"every {interval} minute(s)"
        )

    else:

        print(
            "[SCHEDULER] Monitoring disabled"
        )


# ============================================================
# API — HEALTH CHECK
# ============================================================

@app.route(
    "/api/health-check",
    methods=["POST"]
)
def health_check():

    data = request.get_json(
        silent=True
    ) or {}

    url = data.get("url")

    if not url:

        return jsonify({
            "error": "URL is required"
        }), 400

    url = normalize_url(url)

    result = perform_health_check_with_retry(
        url
    )

    health = save_health_result(
        result
    )

    handle_incident(result)

    return jsonify({
        "id": health.id,
        **result
    })


# ============================================================
# API — HEALTH HISTORY
# ============================================================

@app.route(
    "/api/health-history",
    methods=["GET"]
)
def health_history():

    history = HealthCheck.query.order_by(
        HealthCheck.checked_at.desc()
    ).all()

    return jsonify([

        {
            "id": item.id,
            "url": item.url,
            "status": item.status,
            "http_status": item.http_status,
            "response_time_ms": (
                item.response_time_ms
            ),
            "ssl_valid": item.ssl_valid,
            "ssl_expiry": (
                item.ssl_expiry.isoformat()
                if item.ssl_expiry
                else None
            ),
            "ssl_days_remaining": (
                item.ssl_days_remaining
            ),
            "ssl_error": item.ssl_error,
            "checked_at": (
                item.checked_at.isoformat()
                if item.checked_at
                else None
            )
        }

        for item in history
    ])


# ============================================================
# API — WEBSITES
# ============================================================

@app.route(
    "/api/websites",
    methods=["GET"]
)
def get_websites():

    websites = MonitoredWebsite.query.order_by(
        MonitoredWebsite.created_at.desc()
    ).all()

    return jsonify([

        {
            "id": item.id,
            "url": item.url,
            "status": item.status,
            "http_status": item.http_status,
            "response_time_ms": (
                item.response_time_ms
            ),
            "ssl_valid": item.ssl_valid,
            "ssl_expiry": (
                item.ssl_expiry.isoformat()
                if item.ssl_expiry
                else None
            ),
            "ssl_days_remaining": (
                item.ssl_days_remaining
            ),
            "checked_at": (
                item.checked_at.isoformat()
                if item.checked_at
                else None
            ),
            "created_at": (
                item.created_at.isoformat()
                if item.created_at
                else None
            )
        }

        for item in websites
    ])


@app.route(
    "/api/websites",
    methods=["POST"]
)
def add_website():

    data = request.get_json(
        silent=True
    ) or {}

    url = data.get("url")

    if not url:

        return jsonify({
            "error": "URL is required"
        }), 400

    url = normalize_url(url)

    existing = MonitoredWebsite.query.filter_by(
        url=url
    ).first()

    if existing:

        return jsonify({
            "error": "Website already exists"
        }), 400

    website = MonitoredWebsite(
        url=url
    )

    db.session.add(website)
    db.session.commit()

    # If a user is logged in, subscribe them to alerts for the website they added.
    user = current_user()
    if user and user.email_verified:
        subscription = WebsiteSubscription.query.filter_by(
            user_id=user.id,
            website_id=website.id
        ).first()
        if not subscription:
            db.session.add(WebsiteSubscription(
                user_id=user.id,
                website_id=website.id,
                notify_down=True,
                notify_recovery=True
            ))
            db.session.commit()

    return jsonify({
        "message": "Website added",
        "id": website.id,
        "url": website.url
    }), 201


@app.route(
    "/api/websites/<int:website_id>",
    methods=["DELETE"]
)
def delete_website(website_id):

    website = MonitoredWebsite.query.get(
        website_id
    )

    if not website:

        return jsonify({
            "error": "Website not found"
        }), 404

    db.session.delete(website)

    db.session.commit()

    return jsonify({
        "message": "Website deleted"
    })


# ============================================================
# API — INCIDENTS
# ============================================================

@app.route(
    "/api/incidents",
    methods=["GET"]
)
def get_incidents():

    incidents = Incident.query.order_by(
        Incident.started_at.desc()
    ).all()

    return jsonify([

        {
            "id": item.id,
            "url": item.url,
            "incident_type": item.incident_type,
            "status": item.status,
            "message": item.message,
            "started_at": (
                item.started_at.isoformat()
                if item.started_at
                else None
            ),
            "resolved_at": (
                item.resolved_at.isoformat()
                if item.resolved_at
                else None
            )
        }

        for item in incidents
    ])


# ============================================================
# API — SYSTEM STATUS
# ============================================================

@app.route(
    "/api/system-status",
    methods=["GET"]
)
def system_status():

    try:

        db.session.execute(
            db.text("SELECT 1")
        )

        database_status = "UP"

    except Exception:

        database_status = "DOWN"

    website_count = (
        MonitoredWebsite.query.count()
    )

    open_incidents = (
        Incident.query.filter_by(
            status="OPEN"
        ).count()
    )

    return jsonify({

        "backend": "UP",

        "database": database_status,

        "database_connected": (
            database_status == "UP"
        ),

        "monitored_websites":
            website_count,

        "open_incidents":
            open_incidents,

        "timestamp":
            datetime.now(
                timezone.utc
            ).isoformat()
    })


# ============================================================
# API — MONITORING STATUS
# ============================================================

@app.route(
    "/api/monitoring/status",
    methods=["GET"]
)
def monitoring_status():

    return jsonify({

        "monitored_websites":
            MonitoredWebsite.query.count(),

        "monitoring_interval_minutes":
            get_monitoring_interval(),

        "scheduler_running":
            scheduler.running
            and get_monitoring_enabled(),

        "monitoring_enabled":
            get_monitoring_enabled(),

        "max_retries":
            get_max_retries(),

        "timestamp":
            datetime.now(
                timezone.utc
            ).isoformat()
    })


# ============================================================
# API — SETTINGS GET
# ============================================================

@app.route(
    "/api/settings",
    methods=["GET"]
)
def get_settings_api():

    return jsonify({

        "monitoring_enabled":
            get_monitoring_enabled(),

        "monitoring_interval_minutes":
            get_monitoring_interval(),

        "max_retries":
            get_max_retries(),
        "alert_email": get_setting("alert_email") or MAIL_RECIPIENT or "",
        "email_alerts_enabled": (get_setting("email_alerts_enabled") or "true").lower() == "true"
    })


# ============================================================
# API — SETTINGS UPDATE
# ============================================================

@app.route(
    "/api/settings",
    methods=["PUT"]
)
def update_settings():

    data = request.get_json(
        silent=True
    ) or {}

    if "monitoring_enabled" in data:

        enabled = data[
            "monitoring_enabled"
        ]

        if not isinstance(
            enabled,
            bool
        ):

            return jsonify({
                "error":
                    "monitoring_enabled must be true or false"
            }), 400

        set_setting(
            "monitoring_enabled",
            str(enabled).lower()
        )

    if "monitoring_interval_minutes" in data:

        try:

            interval = int(
                data[
                    "monitoring_interval_minutes"
                ]
            )

        except (
            TypeError,
            ValueError
        ):

            return jsonify({
                "error":
                    "Monitoring interval must be a number"
            }), 400

        if interval < 1 or interval > 1440:

            return jsonify({
                "error":
                    "Monitoring interval must be between 1 and 1440 minutes"
            }), 400

        set_setting(
            "monitoring_interval_minutes",
            interval
        )

    if "max_retries" in data:

        try:

            retries = int(
                data["max_retries"]
            )

        except (
            TypeError,
            ValueError
        ):

            return jsonify({
                "error":
                    "Retry attempts must be a number"
            }), 400

        if retries < 0 or retries > 10:

            return jsonify({
                "error":
                    "Retry attempts must be between 0 and 10"
            }), 400

        set_setting(
            "max_retries",
            retries
        )

    if "alert_email" in data:
        alert_email = str(data.get("alert_email") or "").strip()
        if alert_email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", alert_email):
            return jsonify({"error": "Enter a valid alert email address."}), 400
        set_setting("alert_email", alert_email)

    if "email_alerts_enabled" in data:
        set_setting("email_alerts_enabled", str(bool(data["email_alerts_enabled"])).lower())

    configure_scheduler()

    return jsonify({

        "message":
            "Settings updated successfully",

        "monitoring_enabled":
            get_monitoring_enabled(),

        "monitoring_interval_minutes":
            get_monitoring_interval(),

        "max_retries":
            get_max_retries(),
        "alert_email": get_setting("alert_email") or MAIL_RECIPIENT or "",
        "email_alerts_enabled": (get_setting("email_alerts_enabled") or "true").lower() == "true",

        "scheduler_running":
            scheduler.running
            and get_monitoring_enabled()
    })


# ============================================================
# API — ACCOUNT, EMAIL OTP AND SUBSCRIPTIONS
# ============================================================

def otp_digest(code):
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


@app.route("/api/auth/register", methods=["POST"])
def register_user():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    if not name or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return jsonify({"error": "Enter your name and a valid email address."}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "An account with this email already exists. Try logging in."}), 409
    user = User(name=name, email=email, password_hash=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()
    code = f"{secrets.randbelow(1000000):06d}"
    otp = EmailOTP(user_id=user.id, code_hash=otp_digest(code),
                   expires_at=datetime.now(timezone.utc) + timedelta(minutes=10))
    db.session.add(otp)
    db.session.commit()
    sent = send_email_to(email, "Your Veyra email verification code", f"Hi {name},\n\nYour Veyra verification code is {code}.\nIt expires in 10 minutes. If you did not create this account, you can ignore this email.")
    if not sent:
        return jsonify({"message": "Account created, but the verification email could not be sent. Check SMTP settings and ask to resend the code.", "email": email, "email_sent": False}), 503
    return jsonify({"message": "Verification code sent. Check your email.", "email": email, "email_sent": True}), 201


@app.route("/api/auth/resend-otp", methods=["POST"])
def resend_otp():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    user = User.query.filter_by(email=email).first()
    if not user or user.email_verified:
        return jsonify({"message": "If the account needs verification, a new code will be sent."})
    code = f"{secrets.randbelow(1000000):06d}"
    db.session.add(EmailOTP(user_id=user.id, code_hash=otp_digest(code), expires_at=datetime.now(timezone.utc) + timedelta(minutes=10)))
    db.session.commit()
    sent = send_email_to(email, "Your new Veyra verification code", f"Your Veyra verification code is {code}. It expires in 10 minutes.")
    if not sent:
        return jsonify({"error": "Email could not be sent. Check SMTP settings."}), 503
    return jsonify({"message": "A new verification code has been sent."})


@app.route("/api/auth/verify", methods=["POST"])
def verify_otp():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    code = str(data.get("code", "")).strip()
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "Account not found."}), 404
    if user.email_verified:
        return jsonify({"message": "Email is already verified. You can log in."})
    now = datetime.now(timezone.utc)
    otp = EmailOTP.query.filter_by(user_id=user.id, used=False).order_by(EmailOTP.id.desc()).first()
    if not otp or otp.expires_at.replace(tzinfo=timezone.utc) < now or otp.attempts >= 5:
        return jsonify({"error": "Code expired or attempt limit reached. Request a new code."}), 400
    otp.attempts += 1
    if not secrets.compare_digest(otp.code_hash, otp_digest(code)):
        db.session.commit()
        return jsonify({"error": "Incorrect verification code."}), 400
    otp.used = True
    user.email_verified = True
    db.session.commit()
    return jsonify({"message": "Email verified. You can now log in."})


@app.route("/api/auth/login", methods=["POST"])
def login_user():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "Incorrect email or password."}), 401
    if not user.email_verified:
        return jsonify({"error": "Verify your email before logging in."}), 403
    session.clear()
    session["user_id"] = user.id
    return jsonify({"message": "Logged in successfully.", "user": {"id": user.id, "name": user.name, "email": user.email}})


@app.route("/api/auth/me", methods=["GET"])
def auth_me():
    user = current_user()
    if not user:
        return jsonify({"user": None})
    return jsonify({"user": {"id": user.id, "name": user.name, "email": user.email}})


@app.route("/api/auth/logout", methods=["POST"])
def logout_user():
    session.clear()
    return jsonify({"message": "Logged out."})


@app.route("/api/subscriptions", methods=["GET"])
def list_subscriptions():
    user = current_user()
    if not user:
        return jsonify({"error": "Log in to manage subscriptions."}), 401
    rows = WebsiteSubscription.query.filter_by(user_id=user.id).all()
    return jsonify([{"id": x.id, "website_id": x.website_id,
                     "url": db.session.get(MonitoredWebsite, x.website_id).url if db.session.get(MonitoredWebsite, x.website_id) else None,
                     "notify_down": x.notify_down, "notify_recovery": x.notify_recovery} for x in rows])


@app.route("/api/subscriptions", methods=["POST"])
def create_subscription():
    user = current_user()
    if not user:
        return jsonify({"error": "Log in to subscribe to alerts."}), 401
    data = request.get_json(silent=True) or {}
    try:
        website_id = int(data.get("website_id"))
    except (TypeError, ValueError):
        return jsonify({"error": "Choose a website."}), 400
    website = db.session.get(MonitoredWebsite, website_id)
    if not website:
        return jsonify({"error": "Website not found."}), 404
    sub = WebsiteSubscription.query.filter_by(user_id=user.id, website_id=website_id).first()
    if not sub:
        sub = WebsiteSubscription(user_id=user.id, website_id=website_id)
        db.session.add(sub)
    sub.notify_down = bool(data.get("notify_down", True))
    sub.notify_recovery = bool(data.get("notify_recovery", True))
    db.session.commit()
    return jsonify({"message": "Website alert subscription saved.", "website_id": website_id})


@app.route("/api/subscriptions/<int:subscription_id>", methods=["DELETE"])
def delete_subscription(subscription_id):
    user = current_user()
    if not user:
        return jsonify({"error": "Log in to manage subscriptions."}), 401
    sub = WebsiteSubscription.query.filter_by(id=subscription_id, user_id=user.id).first()
    if not sub:
        return jsonify({"error": "Subscription not found."}), 404
    db.session.delete(sub)
    db.session.commit()
    return jsonify({"message": "Unsubscribed from website alerts."})


@app.route("/api/test-email", methods=["POST"])
def test_email_api():
    data = request.get_json(silent=True) or {}
    recipient = str(data.get("recipient") or get_setting("alert_email") or MAIL_RECIPIENT or "").strip()
    if not recipient:
        return jsonify({"error": "Set an alert recipient in Settings first."}), 400
    ok = send_email_to(recipient, "Veyra test email", "This is a test email from Veyra Website Health Monitor. If you received it, email delivery is working.")
    if not ok:
        return jsonify({"error": "Test email failed. Check MAIL_USERNAME, MAIL_PASSWORD and SMTP settings in .env."}), 500
    return jsonify({"message": f"Test email sent to {recipient}."})


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    return jsonify({
        "message":
            "Veyra Website Health Monitoring API",
        "status":
            "running"
    })


# ============================================================
# DATABASE + SCHEDULER STARTUP
# ============================================================

with app.app_context():

    db.create_all()

    for key, value in DEFAULT_SETTINGS.items():

        get_setting(key)

    configure_scheduler()

    if not scheduler.running:

        scheduler.start()

    monitoring_state = (
        "ON"
        if get_monitoring_enabled()
        else "OFF"
    )

    monitoring_interval = (
        get_monitoring_interval()
    )

    retry_count = (
        get_max_retries()
    )


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    print("")
    print("========================================")
    print(" Veyra Website Health Monitor")
    print("========================================")
    print(
        " Monitoring:",
        monitoring_state
    )
    print(
        " Interval:",
        monitoring_interval,
        "minute(s)"
    )
    print(
        " Retries:",
        retry_count
    )
    print("========================================")
    print("")

    app.run(
        debug=True,
        use_reloader=False
    )