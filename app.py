import os
from datetime import timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort,
)
from flask_wtf.csrf import CSRFProtect, CSRFError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import io
import json
import zipfile
from datetime import datetime, timezone

import click

from database import init_db, get_db
from security.crypto import encrypt, decrypt_str, KeyNotConfiguredError
from security.signatures import (
    sign_bytes, verify_bytes,
    SigningKeyNotFoundError, VerificationKeyNotFoundError,
)
from security.shortage_prediction import predict_shortage_risks

app = Flask(__name__)
csrf = CSRFProtect()

# ---------------------------------------------------------------------------
# Configuration — read from environment; safe defaults for local development
# ---------------------------------------------------------------------------
app.secret_key = os.environ.get("SECRET_KEY") or __import__("secrets").token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    TESTING=os.environ.get("TESTING", "false").lower() == "true",
    WTF_CSRF_ENABLED=os.environ.get("WTF_CSRF_ENABLED", "true").lower() != "false",
    WTF_CSRF_TIME_LIMIT=3600,
)
csrf.init_app(app)

# Per-username brute-force lockout constants
LOCKOUT_MAX_ATTEMPTS    = 5
LOCKOUT_WINDOW_MINUTES  = 15

# Per-IP login rate-limit constants
# Uses the existing login_attempts table (ip_address column).
# X-Forwarded-For is intentionally ignored — only request.remote_addr is
# trusted to prevent header-spoofing bypasses.
IP_RATE_LIMIT_ATTEMPTS  = 20   # distinct login POSTs from one IP
IP_RATE_LIMIT_WINDOW_MINUTES = 15

# Input length limits (characters, server-side)
MAX_USERNAME_LEN = 64
MAX_PASSWORD_LEN = 256
MAX_FULL_NAME_LEN = 120
MAX_CONTACT_LEN   = 40
MAX_ORGAN_LEN     = 60
MAX_SEARCH_LEN    = 100

ALLOWED_ROLES = ("doctor", "staff")

# Sentinel stored in the DB when a nullable field was blank at registration time.
# Distinguishes "user left it empty" from a decryption failure.
_EMPTY_SENTINEL = ""


# ---------------------------------------------------------------------------
# Security HTTP headers
# ---------------------------------------------------------------------------

@app.after_request
def set_security_headers(response):
    """
    Apply security headers to every response.
    CSP allows Bootstrap and Bootstrap Icons from jsDelivr CDN (used in
    base.html), the project's own static files, and inline styles that
    Bootstrap injects at runtime.  No eval or object sources are permitted.
    """
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    return response


@app.errorhandler(CSRFError)
def handle_csrf_error(exc):
    """Return a clear 400 when a CSRF token is missing or invalid."""
    return render_template("csrf_error.html", reason=exc.description), 400


# ---------------------------------------------------------------------------
# Brute-force / account-lockout helpers
# ---------------------------------------------------------------------------

def _count_recent_failures(db, username: str) -> int:
    """Count failed login attempts for *username* within the lockout window."""
    row = db.execute(
        "SELECT COUNT(*) FROM login_attempts"
        " WHERE username = ?"
        " AND attempted_at >= datetime('now', ?)",
        (username, f"-{LOCKOUT_WINDOW_MINUTES} minutes"),
    ).fetchone()
    return row[0]


def _count_recent_ip_attempts(db, ip: str) -> int:
    """Count login attempts from *ip* within the IP rate-limit window.
    Only request.remote_addr is used — X-Forwarded-For is never trusted."""
    if not ip:
        return 0
    row = db.execute(
        "SELECT COUNT(*) FROM login_attempts"
        " WHERE ip_address = ?"
        " AND attempted_at >= datetime('now', ?)",
        (ip, f"-{IP_RATE_LIMIT_WINDOW_MINUTES} minutes"),
    ).fetchone()
    return row[0]


def _record_failure(db, username: str, ip: str | None) -> None:
    """Insert one failed-attempt row. Never stores passwords or secrets."""
    db.execute(
        "INSERT INTO login_attempts (username, ip_address) VALUES (?, ?)",
        (username, ip),
    )
    db.commit()


def _clear_failures(db, username: str) -> None:
    """Remove all attempt rows for *username* after a successful login."""
    db.execute("DELETE FROM login_attempts WHERE username = ?", (username,))
    db.commit()


# ---------------------------------------------------------------------------
# Encryption helpers
# ---------------------------------------------------------------------------

def _encrypt_field(value: str | None) -> str | None:
    """Encrypt a non-empty string field. Returns None for blank/None input."""
    if not value:
        return None
    return encrypt(value)


def _decrypt_field(token: str | None, fallback: str = "[encrypted]") -> str:
    """
    Decrypt a stored token. Returns *fallback* if the token is None/empty.
    Raises KeyNotConfiguredError upward — callers must handle it.
    """
    if not token:
        return ""
    return decrypt_str(token)


def decrypt_donor(row) -> dict:
    """
    Return a plain dict with sensitive fields decrypted.
    Raises KeyNotConfiguredError if DS_AES_KEY is not set.
    Non-sensitive fields (blood_group, donation_type, status, etc.) are
    passed through unchanged.
    """
    return {
        "id":                 row["id"],
        "full_name":          _decrypt_field(row["full_name"]),
        "blood_group":        row["blood_group"],
        "contact":            _decrypt_field(row["contact"]) if row["contact"] else "",
        "donation_type":      row["donation_type"],
        "organ_type":         _decrypt_field(row["organ_type"]) if row["organ_type"] else "",
        "status":             row["status"],
        "registered_by":      row["registered_by"],
        "registered_by_name": row["registered_by_name"] if "registered_by_name" in row.keys() else "",
        "created_at":         row["created_at"],
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log_event(event_type, description=None, user_id=None):
    """Write to audit_events. Never log passwords, keys, or plaintext PII."""
    uid = user_id if user_id is not None else session.get("user_id")
    db = get_db()
    db.execute(
        "INSERT INTO audit_events (event_type, description, user_id, ip_address)"
        " VALUES (?, ?, ?, ?)",
        (event_type, description, uid, request.remote_addr),
    )
    db.commit()
    db.close()


def get_current_user():
    if "user_id" not in session:
        return None
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    db.close()
    return user


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def roles_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if session.get("role") not in roles:
                flash("You do not have permission to access that page.", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return decorated
    return decorator


# ---------------------------------------------------------------------------
# Routes — public
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    db = get_db()
    donor_count = db.execute("SELECT COUNT(*) FROM donors").fetchone()[0]
    user_count  = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    db.close()
    return render_template("index.html", user=get_current_user(),
                           donor_count=donor_count, user_count=user_count)


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "warning")
            return render_template("login.html", user=None)

        # Enforce input length limits before any DB work.
        if len(username) > MAX_USERNAME_LEN or len(password) > MAX_PASSWORD_LEN:
            flash("Invalid username or password.", "danger")
            return render_template("login.html", user=None)

        db = get_db()
        ip = request.remote_addr

        # Per-IP rate limit — checked before per-username lockout.
        # Uses only remote_addr; X-Forwarded-For is never trusted.
        ip_attempts = _count_recent_ip_attempts(db, ip)
        if ip_attempts >= IP_RATE_LIMIT_ATTEMPTS:
            _record_failure(db, username, ip)
            log_event("LOGIN_IP_BLOCKED",
                      f"Login blocked — IP rate limit reached ({ip_attempts} attempts)")
            db.close()
            flash("Invalid username or password.", "danger")
            return render_template("login.html", user=None)

        # Check per-username lockout window BEFORE touching the password hash.
        # We check by username so an attacker cannot enumerate accounts
        # by observing different error messages.
        recent_failures = _count_recent_failures(db, username)
        if recent_failures >= LOCKOUT_MAX_ATTEMPTS:
            _record_failure(db, username, request.remote_addr)
            log_event("LOGIN_LOCKED",
                      f"Login blocked — account locked after {recent_failures} failures")
            db.close()
            flash("Invalid username or password.", "danger")
            return render_template("login.html", user=None)

        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and check_password_hash(user["password"], password):
            _clear_failures(db, username)
            db.close()
            session.permanent = True
            session["user_id"] = user["id"]
            session["role"]    = user["role"]
            log_event("LOGIN", f"Successful login for '{username}'", user_id=user["id"])
            return redirect(url_for("dashboard"))

        # Failed attempt — record it, then respond generically.
        _record_failure(db, username, ip)
        new_count = _count_recent_failures(db, username)
        if new_count >= LOCKOUT_MAX_ATTEMPTS:
            log_event("LOGIN_LOCKED",
                      f"Account locked after {new_count} failed attempts for '{username}'")
        else:
            log_event("LOGIN_FAILED",
                      f"Failed login attempt for username '{username}'")
        db.close()
        flash("Invalid username or password.", "danger")

    return render_template("login.html", user=None)


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")
        role     = request.form.get("role", "")

        errors = []
        if not username:
            errors.append("Username is required.")
        elif len(username) < 3:
            errors.append("Username must be at least 3 characters.")
        elif len(username) > MAX_USERNAME_LEN:
            errors.append(f"Username must be at most {MAX_USERNAME_LEN} characters.")
        if not password:
            errors.append("Password is required.")
        elif len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        elif len(password) > MAX_PASSWORD_LEN:
            errors.append(f"Password must be at most {MAX_PASSWORD_LEN} characters.")
        if password != confirm:
            errors.append("Passwords do not match.")
        if role not in ALLOWED_ROLES:
            errors.append("Invalid role selected.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("register.html", user=None,
                                   allowed_roles=ALLOWED_ROLES, form=request.form)

        db = get_db()
        existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            db.close()
            flash("That username is already taken. Please choose another.", "danger")
            return render_template("register.html", user=None,
                                   allowed_roles=ALLOWED_ROLES, form=request.form)

        db.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), role),
        )
        db.commit()
        new_user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        db.close()

        log_event("REGISTER", f"New account registered: '{username}' as {role}",
                  user_id=new_user["id"])
        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", user=None,
                           allowed_roles=ALLOWED_ROLES, form={})


@app.route("/logout")
@login_required
def logout():
    username = get_current_user()["username"]
    log_event("LOGOUT", f"'{username}' logged out")
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Routes — authenticated
# ---------------------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    donor_count   = db.execute("SELECT COUNT(*) FROM donors").fetchone()[0]
    staff_count   = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    bb_count      = db.execute("SELECT COUNT(*) FROM blood_banks").fetchone()[0]
    alert_count   = db.execute(
        "SELECT COUNT(*) FROM network_alerts WHERE status='new'"
    ).fetchone()[0]
    blood_inv     = db.execute(
        "SELECT * FROM blood_inventory ORDER BY blood_group"
    ).fetchall()
    recent_demand = {row["blood_group"]: row["demand"] for row in db.execute(
        "SELECT blood_group, SUM(quantity) AS demand FROM doctor_requests "
        "WHERE request_type='blood' AND status IN ('Pending','Approved','Fulfilled') "
        "AND created_at >= datetime('now','-30 days') GROUP BY blood_group"
    ).fetchall()}
    shortage_prediction = predict_shortage_risks(blood_inv, recent_demand)
    recent_events = db.execute(
        "SELECT ae.*, u.username FROM audit_events ae"
        " LEFT JOIN users u ON ae.user_id = u.id"
        " ORDER BY ae.timestamp DESC LIMIT 10"
    ).fetchall()
    db.close()
    return render_template(
        "dashboard.html",
        user=get_current_user(),
        donor_count=donor_count,
        staff_count=staff_count,
        bb_count=bb_count,
        alert_count=alert_count,
        blood_inv=blood_inv,
        shortage_prediction=shortage_prediction,
        recent_events=recent_events,
    )


@app.route("/donors")
@login_required
def donors():
    q_name   = request.args.get("name",   "").strip()[:MAX_SEARCH_LEN]
    q_blood  = request.args.get("blood",  "").strip()
    q_type   = request.args.get("dtype",  "").strip()
    q_status = request.args.get("status", "").strip()
    try:
        from security.crypto import _load_key
        _load_key()
        db = get_db()
        # blood_group, donation_type, status are plaintext — filterable in SQL.
        # full_name is encrypted — name search is done in Python after decryption.
        conditions, params = [], []
        if q_blood:
            conditions.append("d.blood_group = ?")
            params.append(q_blood)
        if q_type:
            conditions.append("d.donation_type = ?")
            params.append(q_type)
        if q_status:
            conditions.append("d.status = ?")
            params.append(q_status)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        rows = db.execute(
            f"SELECT d.*, u.username AS registered_by_name"
            f" FROM donors d LEFT JOIN users u ON d.registered_by = u.id"
            f" {where} ORDER BY d.created_at DESC",
            params,
        ).fetchall()
        db.close()
        decrypted = [decrypt_donor(r) for r in rows]
        if q_name:
            q_lower = q_name.lower()
            decrypted = [d for d in decrypted if q_lower in d["full_name"].lower()]
    except KeyNotConfiguredError:
        flash(
            "Donor records cannot be displayed: DS_AES_KEY is not configured. "
            "Set the environment variable and restart the application.",
            "danger",
        )
        decrypted = []
        q_name = q_blood = q_type = q_status = ""
    return render_template(
        "donors.html",
        user=get_current_user(),
        donors=decrypted,
        q_name=q_name,
        q_blood=q_blood,
        q_type=q_type,
        q_status=q_status,
        blood_groups=["A+","A-","B+","B-","AB+","AB-","O+","O-"],
    )


@app.route("/donors/<int:donor_id>")
@login_required
def donor_detail(donor_id):
    """View a single donor's decrypted details."""
    try:
        from security.crypto import _load_key
        _load_key()
        db = get_db()
        row = db.execute(
            "SELECT d.*, u.username AS registered_by_name"
            " FROM donors d LEFT JOIN users u ON d.registered_by = u.id"
            " WHERE d.id = ?",
            (donor_id,),
        ).fetchone()
        db.close()
        if row is None:
            abort(404)
        donor = decrypt_donor(row)
    except KeyNotConfiguredError:
        flash("DS_AES_KEY is not configured — cannot decrypt donor record.", "danger")
        return redirect(url_for("donors"))
    return render_template("donor_detail.html", user=get_current_user(), donor=donor)


@app.route("/donors/<int:donor_id>/edit", methods=["GET", "POST"])
@login_required
@roles_required("admin", "staff")
def edit_donor(donor_id):
    """Edit a donor record. Sensitive fields are re-encrypted on save."""
    try:
        from security.crypto import _load_key
        _load_key()
        db = get_db()
        row = db.execute("SELECT * FROM donors WHERE id = ?", (donor_id,)).fetchone()
        if row is None:
            db.close()
            abort(404)
        donor = decrypt_donor(row)
    except KeyNotConfiguredError:
        flash("DS_AES_KEY is not configured — cannot edit donor record.", "danger")
        return redirect(url_for("donors"))

    if request.method == "POST":
        full_name     = request.form.get("full_name", "").strip()
        blood_group   = request.form.get("blood_group", "")
        donation_type = request.form.get("donation_type", "")
        organ_type    = request.form.get("organ_type", "").strip() or None
        contact       = request.form.get("contact", "").strip() or None
        status        = request.form.get("status", "active")

        errors = []
        if not full_name:
            errors.append("Full name is required.")
        elif len(full_name) > MAX_FULL_NAME_LEN:
            errors.append(f"Full name must be at most {MAX_FULL_NAME_LEN} characters.")
        if contact and len(contact) > MAX_CONTACT_LEN:
            errors.append(f"Contact must be at most {MAX_CONTACT_LEN} characters.")
        if organ_type and len(organ_type) > MAX_ORGAN_LEN:
            errors.append(f"Organ type must be at most {MAX_ORGAN_LEN} characters.")
        if status not in ("active", "inactive"):
            errors.append("Invalid status.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("edit_donor.html", user=get_current_user(), donor=donor)

        try:
            enc_name    = encrypt(full_name)
            enc_contact = _encrypt_field(contact)
            enc_organ   = _encrypt_field(organ_type)
        except KeyNotConfiguredError:
            flash("DS_AES_KEY is not configured — cannot save changes.", "danger")
            return render_template("edit_donor.html", user=get_current_user(), donor=donor)

        old_type  = row["donation_type"]
        old_blood = row["blood_group"]

        db.execute(
            "UPDATE donors SET full_name=?, blood_group=?, contact=?,"
            " donation_type=?, organ_type=?, status=? WHERE id=?",
            (enc_name, blood_group, enc_contact, donation_type, enc_organ, status, donor_id),
        )
        # Adjust inventory if blood donation type or blood group changed.
        if old_type == "blood" and (donation_type != "blood" or blood_group != old_blood):
            db.execute(
                "UPDATE blood_inventory SET units = MAX(0, units - 1),"
                " updated_at = datetime('now') WHERE blood_group = ?",
                (old_blood,),
            )
        if donation_type == "blood" and (old_type != "blood" or blood_group != old_blood):
            db.execute(
                "UPDATE blood_inventory SET units = units + 1,"
                " updated_at = datetime('now') WHERE blood_group = ?",
                (blood_group,),
            )
        db.commit()
        db.close()
        log_event("EDIT_DONOR", f"Donor ID {donor_id} updated ({donation_type}, {blood_group})")
        flash("Donor record updated successfully.", "success")
        return redirect(url_for("donor_detail", donor_id=donor_id))

    db.close()
    return render_template("edit_donor.html", user=get_current_user(), donor=donor)


@app.route("/donors/<int:donor_id>/delete", methods=["POST"])
@login_required
@roles_required("admin")
def delete_donor(donor_id):
    """Permanently delete a donor record. Admin only."""
    db = get_db()
    row = db.execute("SELECT * FROM donors WHERE id = ?", (donor_id,)).fetchone()
    if row is None:
        db.close()
        abort(404)
    # Adjust inventory if this was a blood donor.
    if row["donation_type"] == "blood":
        db.execute(
            "UPDATE blood_inventory SET units = MAX(0, units - 1),"
            " updated_at = datetime('now') WHERE blood_group = ?",
            (row["blood_group"],),
        )
    db.execute("DELETE FROM donors WHERE id = ?", (donor_id,))
    db.commit()
    db.close()
    log_event("DELETE_DONOR", f"Donor ID {donor_id} deleted")
    flash(f"Donor #{donor_id} has been deleted.", "success")
    return redirect(url_for("donors"))


@app.route("/donors/add", methods=["GET", "POST"])
@login_required
@roles_required("admin", "staff")
def add_donor():
    if request.method == "POST":
        full_name     = request.form.get("full_name", "").strip()
        blood_group   = request.form.get("blood_group", "")
        donation_type = request.form.get("donation_type", "")
        organ_type    = request.form.get("organ_type", "").strip() or None
        contact       = request.form.get("contact", "").strip() or None

        if not full_name:
            flash("Full name is required.", "danger")
            return render_template("add_donor.html", user=get_current_user())
        if len(full_name) > MAX_FULL_NAME_LEN:
            flash(f"Full name must be at most {MAX_FULL_NAME_LEN} characters.", "danger")
            return render_template("add_donor.html", user=get_current_user())
        if contact and len(contact) > MAX_CONTACT_LEN:
            flash(f"Contact must be at most {MAX_CONTACT_LEN} characters.", "danger")
            return render_template("add_donor.html", user=get_current_user())
        if organ_type and len(organ_type) > MAX_ORGAN_LEN:
            flash(f"Organ type must be at most {MAX_ORGAN_LEN} characters.", "danger")
            return render_template("add_donor.html", user=get_current_user())

        # Encrypt sensitive fields before any DB write.
        # If the key is missing, abort immediately — never store plaintext.
        try:
            enc_name    = encrypt(full_name)
            enc_contact = _encrypt_field(contact)
            enc_organ   = _encrypt_field(organ_type)
        except KeyNotConfiguredError:
            flash(
                "Donor could not be registered: DS_AES_KEY is not configured. "
                "Set the environment variable and restart the application.",
                "danger",
            )
            log_event("ADD_DONOR_FAILED", "Encryption key not configured — donor not saved")
            return render_template("add_donor.html", user=get_current_user())

        db = get_db()
        db.execute(
            "INSERT INTO donors"
            " (full_name, blood_group, contact, donation_type, organ_type, registered_by)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (enc_name, blood_group, enc_contact, donation_type, enc_organ, session["user_id"]),
        )
        if donation_type == "blood":
            db.execute(
                "UPDATE blood_inventory SET units = units + 1,"
                " updated_at = datetime('now') WHERE blood_group = ?",
                (blood_group,),
            )
        db.commit()
        # Log donor ID and blood group only — never log the plaintext name.
        new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        db.close()
        log_event("ADD_DONOR", f"Donor ID {new_id} ({donation_type}, {blood_group}) registered")
        flash("Donor registered successfully.", "success")
        return redirect(url_for("donors"))

    return render_template("add_donor.html", user=get_current_user())


# ---------------------------------------------------------------------------
# Routes — Blood Inventory
# ---------------------------------------------------------------------------

@app.route("/requests", methods=["GET", "POST"])
@login_required
def doctor_requests():
    user = get_current_user()
    is_doctor = user["role"] == "doctor"
    if request.method == "POST":
        if not is_doctor:
            abort(403)
        kind = request.form.get("request_type", "").strip().lower()
        blood = request.form.get("blood_group", "").strip()
        organ = request.form.get("organ_type", "").strip()
        location = request.form.get("location", "").strip()
        urgency = request.form.get("urgency", "").strip().lower()
        details = request.form.get("details", "").strip()
        errors = []
        if kind not in ("blood", "organ"):
            errors.append("Choose blood or organ.")
        if kind == "blood" and blood not in ("A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"):
            errors.append("Choose a valid blood group.")
        if kind == "organ" and (not organ or len(organ) > MAX_ORGAN_LEN):
            errors.append("Organ type is required and must be at most 60 characters.")
        try:
            quantity = int(request.form.get("quantity", ""))
            if not 1 <= quantity <= 9999:
                raise ValueError
        except ValueError:
            quantity = 0
            errors.append("Quantity must be between 1 and 9999.")
        if not location or len(location) > 120:
            errors.append("Location is required and must be at most 120 characters.")
        if urgency not in ("routine", "urgent", "emergency"):
            errors.append("Choose a valid urgency.")
        if not details or len(details) > 1000:
            errors.append("Details are required and must be at most 1000 characters.")
        for error in errors:
            flash(error, "danger")
        if not errors:
            db = get_db()
            cur = db.execute(
                "INSERT INTO doctor_requests(doctor_id,request_type,blood_group,organ_type,quantity,location,urgency,details) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (user["id"], kind, blood if kind == "blood" else None,
                 organ if kind == "organ" else None, quantity, location, urgency, details),
            )
            db.commit()
            rid = cur.lastrowid
            db.close()
            requested_resource = blood if kind == "blood" else organ
            log_event("DOCTOR_REQUEST_CREATED",
                      f"Doctor request #{rid} created: {kind} {requested_resource}, {quantity} units",
                      user_id=user["id"])
            flash("Your request was submitted.", "success")
            return redirect(url_for("doctor_requests"))
    db = get_db()
    if is_doctor:
        rows = db.execute("SELECT r.*,i.units AS available_units FROM doctor_requests r "
                          "LEFT JOIN blood_inventory i ON i.blood_group=r.blood_group "
                          "WHERE r.doctor_id=? ORDER BY r.created_at DESC,r.id DESC", (user["id"],)).fetchall()
    elif user["role"] in ("admin", "staff"):
        rows = db.execute("SELECT r.*,u.username doctor_name,i.units AS available_units FROM doctor_requests r "
                          "JOIN users u ON u.id=r.doctor_id LEFT JOIN blood_inventory i ON i.blood_group=r.blood_group "
                          "ORDER BY CASE r.status WHEN 'Pending' THEN 0 ELSE 1 END,r.created_at DESC,r.id DESC").fetchall()
    else:
        db.close()
        abort(403)
    db.close()
    return render_template("doctor_requests.html", user=user, requests=rows, is_doctor=is_doctor)


@app.route("/requests/<int:request_id>/status", methods=["POST"])
@login_required
@roles_required("admin", "staff")
def update_doctor_request(request_id):
    status = request.form.get("status", "").strip()
    response = request.form.get("response", "").strip()
    if status not in ("Pending", "Approved", "Rejected", "Fulfilled") or len(response) > 1000:
        flash("Invalid request status or response length.", "danger")
        return redirect(url_for("doctor_requests"))
    db = get_db()
    old = db.execute("SELECT status,request_type,transferred_units FROM doctor_requests WHERE id=?", (request_id,)).fetchone()
    if not old:
        db.close()
        abort(404)
    if old["transferred_units"] is not None or old["status"] == "Fulfilled":
        db.close()
        flash("Completed requests cannot be changed.", "danger")
        return redirect(url_for("doctor_requests"))
    if old["request_type"] == "blood" and status == "Fulfilled":
        db.close()
        flash("Confirm the blood transfer using the Complete Transfer action.", "warning")
        return redirect(url_for("doctor_requests"))
    db.execute("UPDATE doctor_requests SET status=?,response=?,updated_at=datetime('now'),processed_by=? WHERE id=?",
               (status, response or None, session["user_id"], request_id))
    db.commit()
    db.close()
    log_event("DOCTOR_REQUEST_STATUS", f"Doctor request #{request_id}: {old['status']} -> {status}")
    flash("Request status updated.", "success")
    return redirect(url_for("doctor_requests"))


@app.route("/requests/<int:request_id>/complete-transfer", methods=["POST"])
@login_required
@roles_required("admin", "staff")
def complete_blood_transfer(request_id):
    db = get_db()
    try:
        # Acquire SQLite's write reservation before reading status or stock.
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT id,request_type,blood_group,quantity,status,transferred_units "
                         "FROM doctor_requests WHERE id=?", (request_id,)).fetchone()
        if not row:
            db.rollback()
            abort(404)
        if row["request_type"] != "blood" or row["status"] != "Approved" or row["transferred_units"] is not None:
            db.rollback()
            flash("Only approved, incomplete blood requests can be transferred.", "danger")
            return redirect(url_for("doctor_requests"))
        stock = db.execute("SELECT units FROM blood_inventory WHERE blood_group=?", (row["blood_group"],)).fetchone()
        if not stock or stock["units"] < row["quantity"]:
            db.rollback()
            flash("Insufficient inventory to complete this transfer.", "danger")
            return redirect(url_for("doctor_requests"))
        before = stock["units"]
        changed = db.execute(
            "UPDATE blood_inventory SET units=units-?,updated_at=datetime('now') "
            "WHERE blood_group=? AND units>=?",
            (row["quantity"], row["blood_group"], row["quantity"]),
        ).rowcount
        if changed != 1:
            db.rollback()
            flash("Insufficient inventory to complete this transfer.", "danger")
            return redirect(url_for("doctor_requests"))
        changed = db.execute(
            "UPDATE doctor_requests SET status='Fulfilled',response=COALESCE(response,'Transfer completed'), "
            "updated_at=datetime('now'),processed_by=?,transferred_units=?,transfer_completed_at=datetime('now') "
            "WHERE id=? AND status='Approved' AND transferred_units IS NULL",
            (session["user_id"], row["quantity"], request_id),
        ).rowcount
        if changed != 1:
            db.rollback()
            flash("This request has already changed and was not transferred.", "danger")
            return redirect(url_for("doctor_requests"))
        after = before - row["quantity"]
        description = (f"Blood transfer completed for request #{request_id}; {row['blood_group']}, "
                       f"{row['quantity']} units; inventory {before}->{after}; status Approved->Fulfilled")
        db.execute("INSERT INTO audit_events(event_type,description,user_id,ip_address) VALUES(?,?,?,?)",
                   ("BLOOD_TRANSFER_COMPLETED", description, session["user_id"], request.remote_addr))
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    flash(f"Transfer completed: {row['quantity']} {row['blood_group']} units. Remaining stock: {after}.", "success")
    return redirect(url_for("doctor_requests"))


@app.route("/inventory")
@login_required
def inventory():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM blood_inventory ORDER BY blood_group"
    ).fetchall()
    recent_demand = {row["blood_group"]: row["demand"] for row in db.execute(
        "SELECT blood_group,SUM(quantity) AS demand FROM doctor_requests "
        "WHERE request_type='blood' AND status IN ('Pending','Approved','Fulfilled') "
        "AND created_at >= datetime('now','-30 days') GROUP BY blood_group"
    ).fetchall()}
    shortage_prediction = predict_shortage_risks(rows, recent_demand)
    db.close()
    return render_template("inventory.html", user=get_current_user(), inventory=rows,
                           shortage_prediction=shortage_prediction)


@app.route("/inventory/update", methods=["POST"])
@login_required
@roles_required("admin", "staff")
def inventory_update():
    """Set the unit count for a blood group directly."""
    blood_group = request.form.get("blood_group", "")
    try:
        units = int(request.form.get("units", ""))
    except (ValueError, TypeError):
        flash("Units must be a whole number.", "danger")
        return redirect(url_for("inventory"))
    if units < 0:
        flash("Units cannot be negative.", "danger")
        return redirect(url_for("inventory"))
    valid_groups = {"A+","A-","B+","B-","AB+","AB-","O+","O-"}
    if blood_group not in valid_groups:
        flash("Invalid blood group.", "danger")
        return redirect(url_for("inventory"))
    db = get_db()
    db.execute(
        "UPDATE blood_inventory SET units=?, updated_at=datetime('now')"
        " WHERE blood_group=?",
        (units, blood_group),
    )
    db.commit()
    db.close()
    log_event("INVENTORY_UPDATE", f"Blood group {blood_group} set to {units} units")
    flash(f"{blood_group} inventory updated to {units} units.", "success")
    return redirect(url_for("inventory"))


@app.route("/audit")
@login_required
@roles_required("admin")
def audit_log():
    db = get_db()
    events = db.execute(
        "SELECT ae.*, u.username FROM audit_events ae"
        " LEFT JOIN users u ON ae.user_id = u.id"
        " ORDER BY ae.timestamp DESC LIMIT 200"
    ).fetchall()
    db.close()
    return render_template("audit.html", user=get_current_user(), events=events)


@app.route("/audit/export")
@login_required
@roles_required("admin")
def audit_export():
    """
    Export a signed security audit report as a ZIP archive containing:
      report.json  — audit metadata (no passwords, keys, or decrypted PII)
      report.sig   — detached RSA-PSS/SHA-256 signature over the exact
                     report.json bytes

    The report is tamper-evident: any modification to report.json after
    export will cause signature verification to fail.
    """
    db = get_db()
    events = db.execute(
        "SELECT ae.id, ae.event_type, ae.description, ae.ip_address,"
        " ae.timestamp, u.username"
        " FROM audit_events ae"
        " LEFT JOIN users u ON ae.user_id = u.id"
        " ORDER BY ae.timestamp DESC LIMIT 500"
    ).fetchall()
    donor_count = db.execute("SELECT COUNT(*) FROM donors").fetchone()[0]
    user_count  = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    db.close()

    report = {
        "report_type":    "DonorShield Security Audit Report",
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "generated_by":   get_current_user()["username"],
        "summary": {
            "total_donors": donor_count,
            "total_users":  user_count,
            "event_count":  len(events),
        },
        # Audit events contain only metadata — no decrypted donor PII,
        # no passwords, no session secrets, no AES or RSA key material.
        "events": [
            {
                "id":          e["id"],
                "timestamp":   e["timestamp"],
                "event_type":  e["event_type"],
                "description": e["description"],
                "username":    e["username"],
                "ip_address":  e["ip_address"],
            }
            for e in events
        ],
    }

    report_bytes = json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")

    try:
        signature = sign_bytes(report_bytes)
    except SigningKeyNotFoundError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("audit_log"))

    log_event("AUDIT_EXPORT", f"Signed audit report exported ({len(events)} events)")

    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    zip_filename  = f"audit_report_{timestamp_str}.zip"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("report.json", report_bytes)
        zf.writestr("report.sig",  signature)
    buf.seek(0)

    from flask import send_file
    return send_file(
        buf,
        mimetype="application/zip",
        as_attachment=True,
        download_name=zip_filename,
    )


# ---------------------------------------------------------------------------
# Routes — Security summary (admin only)
# ---------------------------------------------------------------------------

@app.route("/security")
@login_required
@roles_required("admin")
def security_dashboard():
    """
    Admin-only security summary: recent failed logins, lockout events,
    and current accounts with active lockout windows.
    IP addresses are shown only to admins; never exposed to other roles.
    """
    db = get_db()

    # Recent failed / locked events from audit log
    security_events = db.execute(
        "SELECT ae.*, u.username AS actor"
        " FROM audit_events ae"
        " LEFT JOIN users u ON ae.user_id = u.id"
        " WHERE ae.event_type IN ('LOGIN_FAILED', 'LOGIN_LOCKED')"
        " ORDER BY ae.timestamp DESC LIMIT 100"
    ).fetchall()

    # Accounts currently within a lockout window
    locked_accounts = db.execute(
        "SELECT username, COUNT(*) AS attempts,"
        " MAX(attempted_at) AS last_attempt"
        " FROM login_attempts"
        " WHERE attempted_at >= datetime('now', ?)"
        " GROUP BY username"
        " HAVING COUNT(*) >= ?"
        " ORDER BY last_attempt DESC",
        (f"-{LOCKOUT_WINDOW_MINUTES} minutes", LOCKOUT_MAX_ATTEMPTS),
    ).fetchall()

    # Summary counts
    total_failures_24h = db.execute(
        "SELECT COUNT(*) FROM audit_events"
        " WHERE event_type IN ('LOGIN_FAILED', 'LOGIN_LOCKED')"
        " AND timestamp >= datetime('now', '-24 hours')"
    ).fetchone()[0]

    db.close()
    return render_template(
        "security.html",
        user=get_current_user(),
        security_events=security_events,
        locked_accounts=locked_accounts,
        total_failures_24h=total_failures_24h,
        lockout_max=LOCKOUT_MAX_ATTEMPTS,
        lockout_window=LOCKOUT_WINDOW_MINUTES,
    )


# ---------------------------------------------------------------------------
# Routes — Network monitoring (admin only)
# ---------------------------------------------------------------------------

ALLOWED_PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB — matches network_monitor limit

MONITOR_PAGE_SIZE = 20


@app.route("/monitor")
@login_required
@roles_required("admin")
def monitor():
    """
    Admin-only network alert dashboard.
    Shows alerts from offline PCAP analysis with severity/status filters
    and pagination.  IP addresses are visible only to admins.
    """
    db = get_db()

    q_severity = request.args.get("severity", "").strip()
    q_status   = request.args.get("status", "").strip()
    q_rule     = request.args.get("rule", "").strip()
    q_source   = request.args.get("source", "").strip()
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1

    conditions, params = [], []
    if q_severity:
        conditions.append("severity = ?")
        params.append(q_severity)
    if q_status:
        conditions.append("status = ?")
        params.append(q_status)
    if q_rule:
        conditions.append("rule_id = ?")
        params.append(q_rule)
    if q_source:
        conditions.append("source = ?")
        params.append(q_source)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    total = db.execute(
        f"SELECT COUNT(*) FROM network_alerts {where}", params
    ).fetchone()[0]

    offset = (page - 1) * MONITOR_PAGE_SIZE
    alerts = db.execute(
        f"SELECT * FROM network_alerts {where}"
        f" ORDER BY detected_at DESC LIMIT ? OFFSET ?",
        params + [MONITOR_PAGE_SIZE, offset],
    ).fetchall()

    summary = db.execute(
        "SELECT severity, COUNT(*) AS cnt FROM network_alerts GROUP BY severity"
    ).fetchall()
    new_count = db.execute(
        "SELECT COUNT(*) FROM network_alerts WHERE status='new'"
    ).fetchone()[0]

    db.close()

    total_pages = max(1, (total + MONITOR_PAGE_SIZE - 1) // MONITOR_PAGE_SIZE)
    return render_template(
        "monitor.html",
        user=get_current_user(),
        alerts=alerts,
        total=total,
        page=page,
        total_pages=total_pages,
        summary=summary,
        new_count=new_count,
        q_severity=q_severity,
        q_status=q_status,
        q_rule=q_rule,
        q_source=q_source,
    )


@app.route("/monitor/upload", methods=["GET", "POST"])
@login_required
@roles_required("admin")
def monitor_upload():
    """
    Admin-only PCAP upload and analysis page.
    Supports two analysis engines:
      - scapy  (built-in rules, always available)
      - snort  (Snort 2.9, requires DS_SNORT_PATH or default install path)
    No live capture is performed.
    """
    if request.method == "POST":
        save   = request.form.get("save_alerts") == "1"
        engine = request.form.get("engine", "scapy")  # 'scapy' or 'snort'
        if engine not in ("scapy", "snort", "tshark"):
            engine = "scapy"

        f = request.files.get("pcap_file")
        if not f or not f.filename:
            flash("No file selected.", "warning")
            return render_template("monitor_upload.html", user=get_current_user())

        filename = secure_filename(f.filename)
        ext = os.path.splitext(filename)[1].lower()
        if ext not in ALLOWED_PCAP_EXTENSIONS:
            flash(f"Unsupported file type '{ext}'. Upload a .pcap, .pcapng, or .cap file.", "danger")
            return render_template("monitor_upload.html", user=get_current_user())

        data = f.read(MAX_UPLOAD_BYTES + 1)
        if len(data) > MAX_UPLOAD_BYTES:
            flash("File exceeds the 50 MB limit.", "danger")
            return render_template("monitor_upload.html", user=get_current_user())
        if len(data) == 0:
            flash("Uploaded file is empty.", "danger")
            return render_template("monitor_upload.html", user=get_current_user())

        import tempfile
        with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name

        try:
            if engine == "snort":
                from security.snort_runner import (
                    run_snort_on_pcap, SnortNotFoundError, SnortRunError,
                )
                from security.network_monitor import save_alerts
                try:
                    snort_result = run_snort_on_pcap(tmp_path, source_name=filename)
                except SnortNotFoundError as exc:
                    flash(f"Snort not found: {exc}", "danger")
                    return render_template("monitor_upload.html", user=get_current_user())
                except SnortRunError as exc:
                    flash(f"Snort error: {exc}", "danger")
                    return render_template("monitor_upload.html", user=get_current_user())

                alerts_saved = 0
                if save:
                    db = get_db()
                    try:
                        alerts_saved = save_alerts(snort_result["alerts"], db, source="snort")
                    finally:
                        db.close()
                    log_event(
                        "SNORT_UPLOAD",
                        f"Snort analysis of '{filename}': "
                        f"{len(snort_result['alerts'])} alerts, {alerts_saved} saved",
                    )
                    flash(
                        f"Snort analysis complete: {len(snort_result['alerts'])} alert(s) found, "
                        f"{alerts_saved} saved.",
                        "success" if alerts_saved > 0 else "info",
                    )
                    return redirect(url_for("monitor"))
                else:
                    flash(
                        f"Snort analysis complete (not saved): "
                        f"{len(snort_result['alerts'])} alert(s) found.",
                        "info",
                    )
                    return render_template(
                        "monitor_upload.html",
                        user=get_current_user(),
                        result=snort_result,
                        filename=filename,
                        engine="snort",
                    )
            elif engine == "tshark":
                from security.snort_runner import (
                    run_tshark_on_pcap,
                    TsharkNotFoundError,
                    TsharkRunError,
                )
                try:
                    result = run_tshark_on_pcap(tmp_path, source_name=filename)
                except (TsharkNotFoundError, TsharkRunError) as exc:
                    flash(f"TShark analysis error: {exc}", "danger")
                    return render_template(
                        "monitor_upload.html", user=get_current_user()
                    )
                flash("TShark capture summary complete; no alerts saved.", "info")
                return render_template(
                    "monitor_upload.html",
                    user=get_current_user(),
                    result=result,
                    filename=filename,
                    engine="tshark",
                )
            else:
                # Scapy engine
                from security.network_monitor import analyse_pcap_file, PcapValidationError
                db = get_db() if save else None
                try:
                    result = analyse_pcap_file(tmp_path, db=db, source_name=filename)
                except PcapValidationError as exc:
                    flash(f"PCAP validation error: {exc}", "danger")
                    return render_template("monitor_upload.html", user=get_current_user())
                except Exception as exc:
                    flash(f"Error reading PCAP file: {exc}", "danger")
                    return render_template("monitor_upload.html", user=get_current_user())
                finally:
                    if db is not None:
                        db.close()

                if save:
                    log_event(
                        "PCAP_UPLOAD",
                        f"Scapy analysis of '{filename}': {result['packets_read']} packets, "
                        f"{result['alerts_saved']} alerts saved",
                    )
                    flash(
                        f"Scapy analysis complete: {result['packets_read']} packets read, "
                        f"{len(result['alerts'])} alert(s) found, "
                        f"{result['alerts_saved']} saved.",
                        "success" if result["alerts_saved"] > 0 else "info",
                    )
                    return redirect(url_for("monitor"))
                else:
                    flash(
                        f"Scapy analysis complete (not saved): {result['packets_read']} packets read, "
                        f"{len(result['alerts'])} alert(s) found.",
                        "info",
                    )
                    return render_template(
                        "monitor_upload.html",
                        user=get_current_user(),
                        result=result,
                        filename=filename,
                        engine="scapy",
                    )
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass  # Windows: file may still be held by scapy/snort briefly

    return render_template("monitor_upload.html", user=get_current_user())


@app.route("/monitor/<int:alert_id>/review", methods=["POST"])
@login_required
@roles_required("admin")
def monitor_review(alert_id):
    """Mark a network alert as reviewed."""
    db = get_db()
    alert = db.execute(
        "SELECT id FROM network_alerts WHERE id = ?", (alert_id,)
    ).fetchone()
    if alert is None:
        db.close()
        abort(404)
    db.execute(
        "UPDATE network_alerts SET status='reviewed' WHERE id = ?", (alert_id,)
    )
    db.commit()
    db.close()
    log_event("ALERT_REVIEWED", f"Network alert {alert_id} marked as reviewed")
    flash(f"Alert #{alert_id} marked as reviewed.", "success")
    return redirect(request.referrer or url_for("monitor"))


# ---------------------------------------------------------------------------
# Routes — Blood Bank Directory
# ---------------------------------------------------------------------------

PAGE_SIZE = 25


@app.route("/bloodbanks")
@login_required
def bloodbanks():
    db = get_db()

    # Filter params — truncated to MAX_SEARCH_LEN to prevent oversized LIKE queries.
    q_state    = request.args.get("state",    "").strip()[:MAX_SEARCH_LEN]
    q_district = request.args.get("district", "").strip()[:MAX_SEARCH_LEN]
    q_city     = request.args.get("city",     "").strip()[:MAX_SEARCH_LEN]
    q_name     = request.args.get("name",     "").strip()[:MAX_SEARCH_LEN]
    q_category = request.args.get("category", "").strip()[:MAX_SEARCH_LEN]
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1

    conditions, params = [], []
    if q_state:
        conditions.append("LOWER(state) LIKE ?")
        params.append(f"%{q_state.lower()}%")
    if q_district:
        conditions.append("LOWER(district) LIKE ?")
        params.append(f"%{q_district.lower()}%")
    if q_city:
        conditions.append("LOWER(city) LIKE ?")
        params.append(f"%{q_city.lower()}%")
    if q_name:
        conditions.append("LOWER(name) LIKE ?")
        params.append(f"%{q_name.lower()}%")
    if q_category:
        conditions.append("LOWER(category) = ?")
        params.append(q_category.lower())

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    total = db.execute(
        f"SELECT COUNT(*) FROM blood_banks {where}", params
    ).fetchone()[0]

    offset = (page - 1) * PAGE_SIZE
    rows = db.execute(
        f"SELECT * FROM blood_banks {where} ORDER BY state, district, name"
        f" LIMIT ? OFFSET ?",
        params + [PAGE_SIZE, offset],
    ).fetchall()

    states     = [r[0] for r in db.execute(
        "SELECT DISTINCT state FROM blood_banks ORDER BY state").fetchall()]
    categories = [r[0] for r in db.execute(
        "SELECT DISTINCT category FROM blood_banks WHERE category != '' ORDER BY category"
    ).fetchall()]

    db.close()

    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    return render_template(
        "bloodbanks.html",
        user=get_current_user(),
        banks=rows,
        total=total,
        page=page,
        total_pages=total_pages,
        states=states,
        categories=categories,
        q_state=q_state,
        q_district=q_district,
        q_city=q_city,
        q_name=q_name,
        q_category=q_category,
    )


@app.route("/bloodbanks/<int:bank_id>")
@login_required
def bloodbank_detail(bank_id):
    db = get_db()
    bank = db.execute("SELECT * FROM blood_banks WHERE id = ?", (bank_id,)).fetchone()
    db.close()
    if bank is None:
        abort(404)
    return render_template("bloodbank_detail.html", user=get_current_user(), bank=bank)


# ---------------------------------------------------------------------------
# CLI — offline PCAP analysis (Scapy)
# ---------------------------------------------------------------------------

@app.cli.command("analyze-pcap")
@click.argument("pcap_path")
@click.option("--save", is_flag=True, default=False,
              help="Persist alerts to the database.")
def analyze_pcap(pcap_path, save):
    """
    Analyse a PCAP file using built-in Scapy detection rules.

    Usage: flask analyze-pcap <path/to/file.pcap> [--save]

    Offline analysis only.  No live traffic is captured.
    Only analyse traffic you own or have explicit permission to capture.
    """
    from security.network_monitor import analyse_pcap_file, PcapValidationError

    db = get_db() if save else None
    try:
        result = analyse_pcap_file(pcap_path, db=db)
    except PcapValidationError as exc:
        print(f"ERROR: {exc}")
        return
    except Exception as exc:
        print(f"ERROR reading PCAP: {exc}")
        return
    finally:
        if db is not None:
            db.close()

    print(f"\n[SCAPY OFFLINE ANALYSIS] {result['pcap_file']}")
    print(f"  Packets read : {result['packets_read']}"
          + (" (truncated at limit)" if result['truncated'] else ""))
    print(f"  Alerts found : {len(result['alerts'])}")
    if save:
        print(f"  Alerts saved : {result['alerts_saved']}")

    if result["alerts"]:
        print()
        for a in result["alerts"]:
            print(f"  [{a.severity.upper():6}] {a.rule_id}: {a.reason}")
    else:
        print("  No suspicious patterns detected.")


# ---------------------------------------------------------------------------
# CLI — offline PCAP analysis (Snort 2.9)
# ---------------------------------------------------------------------------

@app.cli.command("snort-analyze")
@click.argument("pcap_path")
@click.option("--save", is_flag=True, default=False,
              help="Persist Snort alerts to the database.")
def snort_analyze(pcap_path, save):
    """
    Analyse a PCAP file using Snort 2.9 with DonorShield rules.

    Usage: flask snort-analyze <path/to/file.pcap> [--save]

    Requires Snort 2.9 installed at C:\\Users\\Admin\\Snort\\bin\\snort.exe
    or DS_SNORT_PATH set in the environment.  Offline analysis only.
    Only analyse traffic you own or have explicit permission to capture.
    """
    from security.snort_runner import run_snort_on_pcap, SnortNotFoundError, SnortRunError
    from security.network_monitor import save_alerts

    if not os.path.isfile(pcap_path):
        print(f"ERROR: File not found: {pcap_path}")
        return

    try:
        result = run_snort_on_pcap(pcap_path)
    except SnortNotFoundError as exc:
        print(f"ERROR: {exc}")
        return
    except SnortRunError as exc:
        print(f"ERROR: {exc}")
        return
    except Exception as exc:
        print(f"ERROR running Snort: {exc}")
        return

    print(f"\n[SNORT OFFLINE ANALYSIS] {result['pcap_file']}")
    print(f"  Snort path   : {result['snort_path']}")
    print(f"  Alerts found : {len(result['alerts'])}")

    saved = 0
    if save and result["alerts"]:
        db = get_db()
        try:
            saved = save_alerts(result["alerts"], db, source="snort")
        finally:
            db.close()
        print(f"  Alerts saved : {saved}")

    if result["alerts"]:
        print()
        for a in result["alerts"]:
            print(f"  [{a.severity.upper():6}] {a.rule_id}: {a.reason}")
    else:
        print("  No Snort alerts generated.")
        if result["raw_output"].strip():
            print("  Snort output:")
            for line in result["raw_output"].strip().splitlines()[:10]:
                print(f"    {line}")


# ---------------------------------------------------------------------------
# CLI — key management and report verification
# ---------------------------------------------------------------------------

@app.cli.command("generate-keys")
def generate_keys():
    """
    Generate an RSA-2048 key pair and save to keys/private.pem and
    keys/public.pem.  Run once before using the audit export feature.

    IMPORTANT: Add keys/private.pem to .gitignore.  Never commit it.
    """
    from security.signatures import (
        generate_key_pair, save_private_key, save_public_key,
        get_private_key_path, get_public_key_path,
    )
    priv_path = get_private_key_path()
    pub_path  = get_public_key_path()

    if os.path.exists(priv_path):
        confirm = input(f"Private key already exists at '{priv_path}'. Overwrite? [y/N] ")
        if confirm.strip().lower() != "y":
            print("Aborted.")
            return

    private_key, public_key = generate_key_pair()
    save_private_key(private_key, priv_path)
    save_public_key(public_key, pub_path)
    print(f"Private key saved to: {priv_path}")
    print(f"Public key saved to:  {pub_path}")
    print("Keep private.pem secret. Never commit it to version control.")


@app.cli.command("verify-report")
@click.argument("zip_path")
def verify_report(zip_path):
    """
    Verify the RSA-PSS signature of an exported audit report ZIP.

    Usage: flask verify-report <path/to/audit_report_*.zip>

    Reads report.json and report.sig from the ZIP and verifies the signature
    using the public key at DS_RSA_PUBLIC_KEY_PATH (or keys/public.pem).
    Only the public key is required — the private key is not needed.
    """
    from security.signatures import verify_bytes, load_public_key, VerificationKeyNotFoundError

    if not os.path.isfile(zip_path):
        print(f"ERROR: File not found: {zip_path}")
        return

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            report_bytes = zf.read("report.json")
            signature    = zf.read("report.sig")
    except (KeyError, zipfile.BadZipFile) as exc:
        print(f"ERROR: Could not read ZIP archive: {exc}")
        return

    try:
        public_key = load_public_key()
    except VerificationKeyNotFoundError as exc:
        print(f"ERROR: {exc}")
        return

    if verify_bytes(report_bytes, signature, public_key):
        print("VALID — signature verified. The report has not been modified.")
    else:
        print("INVALID — signature verification failed. The report may have been tampered with.")


# ---------------------------------------------------------------------------
# CLI — create first admin (not available through public registration)
# ---------------------------------------------------------------------------

@app.cli.command("create-admin")
def create_admin():
    """Create an admin user. Run: flask create-admin"""
    import getpass
    username = input("Admin username: ").strip()
    if not username:
        print("Username cannot be empty.")
        return
    password = getpass.getpass("Password (min 8 chars): ")
    if len(password) < 8:
        print("Password too short.")
        return
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), "admin"),
        )
        db.commit()
        print(f"Admin user '{username}' created successfully.")
    except Exception as exc:
        print(f"Error: {exc}")
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
