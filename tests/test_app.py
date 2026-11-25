"""
DonorShield - Stage 1 automated tests.
Run with:  .venv/Scripts/pytest tests/ -v
"""
import os
import tempfile
import pytest
from werkzeug.security import generate_password_hash, check_password_hash


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def app():
    """Create a Flask test app backed by a temporary SQLite database."""
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.environ["DB_PATH"] = db_path
    os.environ["TESTING"] = "true"
    # Stage 3: donor routes encrypt/decrypt with this key during tests.
    # 64-char hex = 32 bytes. Never used outside the test suite.
    os.environ["DS_AES_KEY"] = "ab" * 32

    # Import after setting env so DB_PATH is picked up by database.py
    import importlib
    import database
    import app as app_module
    importlib.reload(database)
    importlib.reload(app_module)

    database.init_db()
    app_module.app.config.update(
        TESTING=True,
        SECRET_KEY="test-secret",
        WTF_CSRF_ENABLED=False,
    )

    yield app_module.app

    os.close(db_fd)
    os.unlink(db_path)
    del os.environ["DB_PATH"]
    del os.environ["TESTING"]
    del os.environ["DS_AES_KEY"]


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def seeded_user(app):
    """Insert a staff user directly into the test DB and return credentials."""
    from database import get_db
    username, password, role = "teststaff", "Password1!", "staff"
    db = get_db()
    db.execute(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        (username, generate_password_hash(password), role),
    )
    db.commit()
    db.close()
    return {"username": username, "password": password, "role": role}


@pytest.fixture()
def logged_in_client(client, seeded_user):
    """Return a test client that is already logged in as the seeded staff user."""
    client.post("/login", data={
        "username": seeded_user["username"],
        "password": seeded_user["password"],
    }, follow_redirects=True)
    return client


# ---------------------------------------------------------------------------
# 1. Database initialisation
# ---------------------------------------------------------------------------

class TestDatabaseInit:
    def test_all_tables_created(self, app):
        from database import get_db
        db = get_db()
        tables = {r["name"] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        db.close()
        assert {"users", "donors", "blood_inventory", "audit_events"}.issubset(tables)

    def test_blood_inventory_seeded(self, app):
        from database import get_db
        db = get_db()
        rows = db.execute("SELECT blood_group FROM blood_inventory").fetchall()
        db.close()
        groups = {r["blood_group"] for r in rows}
        assert groups == {"A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"}


# ---------------------------------------------------------------------------
# 2. Password hashing
# ---------------------------------------------------------------------------

class TestPasswordHashing:
    def test_hash_is_not_plaintext(self):
        h = generate_password_hash("MySecret99")
        assert h != "MySecret99"

    def test_correct_password_verifies(self):
        h = generate_password_hash("MySecret99")
        assert check_password_hash(h, "MySecret99")

    def test_wrong_password_fails(self):
        h = generate_password_hash("MySecret99")
        assert not check_password_hash(h, "WrongPass")

    def test_stored_password_is_hashed(self, app, seeded_user):
        from database import get_db
        db = get_db()
        row = db.execute(
            "SELECT password FROM users WHERE username = ?",
            (seeded_user["username"],),
        ).fetchone()
        db.close()
        assert row["password"] != seeded_user["password"]
        # Werkzeug 3.x uses scrypt by default on Python 3.13; pbkdf2 on older builds.
        assert row["password"].startswith(("scrypt:", "pbkdf2:"))


# ---------------------------------------------------------------------------
# 3. Registration
# ---------------------------------------------------------------------------

class TestRegistration:
    def test_successful_registration(self, client):
        rv = client.post("/register", data={
            "username": "newstaff",
            "password": "SecurePass1",
            "confirm_password": "SecurePass1",
            "role": "staff",
        }, follow_redirects=True)
        assert rv.status_code == 200
        assert b"Account created" in rv.data

    def test_duplicate_username_rejected(self, client, seeded_user):
        rv = client.post("/register", data={
            "username": seeded_user["username"],
            "password": "SecurePass1",
            "confirm_password": "SecurePass1",
            "role": "staff",
        }, follow_redirects=True)
        assert b"already taken" in rv.data

    def test_password_mismatch_rejected(self, client):
        rv = client.post("/register", data={
            "username": "anotheruser",
            "password": "SecurePass1",
            "confirm_password": "DifferentPass1",
            "role": "staff",
        }, follow_redirects=True)
        assert b"do not match" in rv.data

    def test_short_password_rejected(self, client):
        rv = client.post("/register", data={
            "username": "shortpwuser",
            "password": "abc",
            "confirm_password": "abc",
            "role": "staff",
        }, follow_redirects=True)
        assert b"8 characters" in rv.data

    def test_admin_role_blocked(self, client):
        rv = client.post("/register", data={
            "username": "hacker",
            "password": "SecurePass1",
            "confirm_password": "SecurePass1",
            "role": "admin",
        }, follow_redirects=True)
        assert b"Invalid role" in rv.data

    def test_short_username_rejected(self, client):
        rv = client.post("/register", data={
            "username": "ab",
            "password": "SecurePass1",
            "confirm_password": "SecurePass1",
            "role": "staff",
        }, follow_redirects=True)
        assert b"3 characters" in rv.data


# ---------------------------------------------------------------------------
# 4. Login / Logout
# ---------------------------------------------------------------------------

class TestLogin:
    def test_valid_login_redirects_to_dashboard(self, client, seeded_user):
        rv = client.post("/login", data={
            "username": seeded_user["username"],
            "password": seeded_user["password"],
        }, follow_redirects=True)
        assert rv.status_code == 200
        assert b"Dashboard" in rv.data

    def test_wrong_password_rejected(self, client, seeded_user):
        rv = client.post("/login", data={
            "username": seeded_user["username"],
            "password": "WrongPassword",
        }, follow_redirects=True)
        assert b"Invalid username or password" in rv.data

    def test_unknown_user_rejected(self, client):
        rv = client.post("/login", data={
            "username": "nobody",
            "password": "Password1!",
        }, follow_redirects=True)
        assert b"Invalid username or password" in rv.data

    def test_empty_fields_rejected(self, client):
        rv = client.post("/login", data={
            "username": "",
            "password": "",
        }, follow_redirects=True)
        assert b"required" in rv.data

    def test_logout_clears_session(self, logged_in_client):
        rv = logged_in_client.get("/logout", follow_redirects=True)
        assert b"logged out" in rv.data
        rv2 = logged_in_client.get("/dashboard", follow_redirects=True)
        assert b"log in" in rv2.data.lower()


# ---------------------------------------------------------------------------
# 5. Protected routes
# ---------------------------------------------------------------------------

class TestProtectedRoutes:
    def test_dashboard_requires_login(self, client):
        rv = client.get("/dashboard", follow_redirects=True)
        assert b"log in" in rv.data.lower()

    def test_donors_requires_login(self, client):
        rv = client.get("/donors", follow_redirects=True)
        assert b"log in" in rv.data.lower()

    def test_audit_log_requires_login(self, client):
        rv = client.get("/audit", follow_redirects=True)
        assert b"log in" in rv.data.lower()

    def test_audit_log_blocked_for_staff(self, logged_in_client):
        rv = logged_in_client.get("/audit", follow_redirects=True)
        assert b"permission" in rv.data.lower()

    def test_add_donor_blocked_for_doctor(self, app, client):
        from database import get_db
        db = get_db()
        db.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("dr_test", generate_password_hash("Password1!"), "doctor"),
        )
        db.commit()
        db.close()
        client.post("/login", data={"username": "dr_test", "password": "Password1!"})
        rv = client.get("/donors/add", follow_redirects=True)
        assert b"permission" in rv.data.lower()

    def test_authenticated_user_reaches_dashboard(self, logged_in_client):
        rv = logged_in_client.get("/dashboard")
        assert rv.status_code == 200
        assert b"Dashboard" in rv.data


# ---------------------------------------------------------------------------
# 6. Audit logging
# ---------------------------------------------------------------------------

class TestAuditLogging:
    def test_login_event_recorded(self, client, seeded_user):
        from database import get_db
        client.post("/login", data={
            "username": seeded_user["username"],
            "password": seeded_user["password"],
        })
        db = get_db()
        event = db.execute(
            "SELECT * FROM audit_events WHERE event_type = 'LOGIN' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        db.close()
        assert event is not None
        assert seeded_user["username"] in event["description"]
        assert seeded_user["password"] not in (event["description"] or "")

    def test_failed_login_event_recorded(self, client, seeded_user):
        from database import get_db
        client.post("/login", data={
            "username": seeded_user["username"],
            "password": "BadPassword",
        })
        db = get_db()
        event = db.execute(
            "SELECT * FROM audit_events WHERE event_type = 'LOGIN_FAILED' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        db.close()
        assert event is not None

    def test_register_event_recorded(self, client):
        from database import get_db
        client.post("/register", data={
            "username": "audituser",
            "password": "SecurePass1",
            "confirm_password": "SecurePass1",
            "role": "doctor",
        })
        db = get_db()
        event = db.execute(
            "SELECT * FROM audit_events WHERE event_type = 'REGISTER' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        db.close()
        assert event is not None
        assert "audituser" in event["description"]
