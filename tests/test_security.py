"""
DonorShield - Stage 7 security tests.
Covers: brute-force lockout, time-window expiry, security HTTP headers,
        CSRF rejection/acceptance, and admin security dashboard access.
Run with:  .venv/Scripts/pytest tests/ -v
"""
import os
import tempfile
import pytest
from werkzeug.security import generate_password_hash

TEST_AES_KEY = "ab" * 32


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def app(monkeypatch):
    """Isolated app + temp DB with CSRF enabled (default) and AES key set."""
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    monkeypatch.setenv("DB_PATH", db_path)
    monkeypatch.setenv("TESTING", "true")
    monkeypatch.setenv("DS_AES_KEY", TEST_AES_KEY)
    # Leave WTF_CSRF_ENABLED unset so it defaults to "true" inside app.py
    monkeypatch.delenv("WTF_CSRF_ENABLED", raising=False)

    import importlib
    import database
    import app as app_module
    importlib.reload(database)
    importlib.reload(app_module)

    database.init_db()
    app_module.app.config.update(
        TESTING=True,
        SECRET_KEY="sec-test-secret",
    )
    # Do NOT set WTF_CSRF_ENABLED=False here — we want CSRF active for most tests

    yield app_module.app

    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture()
def app_no_csrf(monkeypatch):
    """Isolated app with CSRF disabled — for tests that need to POST freely."""
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    monkeypatch.setenv("DB_PATH", db_path)
    monkeypatch.setenv("TESTING", "true")
    monkeypatch.setenv("DS_AES_KEY", TEST_AES_KEY)
    monkeypatch.setenv("WTF_CSRF_ENABLED", "false")

    import importlib
    import database
    import app as app_module
    importlib.reload(database)
    importlib.reload(app_module)

    database.init_db()
    app_module.app.config.update(
        TESTING=True,
        SECRET_KEY="sec-nocsrf-secret",
        WTF_CSRF_ENABLED=False,
    )

    yield app_module.app

    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def client_no_csrf(app_no_csrf):
    return app_no_csrf.test_client()


def _seed_user(app, username="victim", password="Password1!", role="staff"):
    from database import get_db
    db = get_db()
    db.execute(
        "INSERT INTO users (username, password, role) VALUES (?,?,?)",
        (username, generate_password_hash(password), role),
    )
    db.commit()
    db.close()
    return {"username": username, "password": password}


def _seed_admin(app, username="admin1", password="AdminPass1!"):
    return _seed_user(app, username=username, password=password, role="admin")


def _login_no_csrf(client, username, password):
    """Login using the no-CSRF client."""
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


def _get_csrf_token(client):
    """Fetch the login page and extract the CSRF token from the hidden input."""
    rv = client.get("/login")
    html = rv.data.decode()
    # Find: <input type="hidden" name="csrf_token" value="TOKEN" />
    marker = 'name="csrf_token" value="'
    idx = html.find(marker)
    assert idx != -1, "CSRF token input not found in login page"
    start = idx + len(marker)
    end = html.index('"', start)
    return html[start:end]


# ---------------------------------------------------------------------------
# 1. Login_attempts table exists
# ---------------------------------------------------------------------------

class TestLoginAttemptsSchema:
    def test_login_attempts_table_exists(self, app_no_csrf):
        from database import get_db
        db = get_db()
        tables = {r[0] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        db.close()
        assert "login_attempts" in tables

    def test_schema_version_7_recorded(self, app_no_csrf):
        from database import get_db
        db = get_db()
        versions = {r[0] for r in db.execute(
            "SELECT version FROM schema_version"
        ).fetchall()}
        db.close()
        assert 7 in versions


# ---------------------------------------------------------------------------
# 2. Brute-force lockout — threshold and window
# ---------------------------------------------------------------------------

class TestBruteForce:
    def _fail_login(self, client, username, n=1):
        for _ in range(n):
            client.post("/login", data={
                "username": username, "password": "WrongPass!",
            }, follow_redirects=True)

    def test_single_failure_does_not_lock(self, app_no_csrf, client_no_csrf):
        _seed_user(app_no_csrf)
        self._fail_login(client_no_csrf, "victim", 1)
        # Should still be able to log in with correct password
        rv = _login_no_csrf(client_no_csrf, "victim", "Password1!")
        assert b"Dashboard" in rv.data

    def test_four_failures_do_not_lock(self, app_no_csrf, client_no_csrf):
        _seed_user(app_no_csrf)
        self._fail_login(client_no_csrf, "victim", 4)
        rv = _login_no_csrf(client_no_csrf, "victim", "Password1!")
        assert b"Dashboard" in rv.data

    def test_five_failures_trigger_lockout(self, app_no_csrf, client_no_csrf):
        _seed_user(app_no_csrf)
        self._fail_login(client_no_csrf, "victim", 5)
        # 6th attempt (correct password) must still be blocked
        rv = _login_no_csrf(client_no_csrf, "victim", "Password1!")
        assert b"Invalid username or password" in rv.data
        assert b"Dashboard" not in rv.data

    def test_lockout_message_is_generic(self, app_no_csrf, client_no_csrf):
        """Locked accounts must not reveal they are locked."""
        _seed_user(app_no_csrf)
        self._fail_login(client_no_csrf, "victim", 5)
        rv = _login_no_csrf(client_no_csrf, "victim", "Password1!")
        assert b"locked" not in rv.data.lower()
        assert b"Invalid username or password" in rv.data

    def test_nonexistent_account_also_locked_generically(self, app_no_csrf, client_no_csrf):
        """Attacking a non-existent username should not reveal it doesn't exist."""
        self._fail_login(client_no_csrf, "ghost", 5)
        rv = _login_no_csrf(client_no_csrf, "ghost", "AnyPass1!")
        assert b"Invalid username or password" in rv.data
        assert b"does not exist" not in rv.data.lower()

    def test_successful_login_clears_failure_count(self, app_no_csrf, client_no_csrf):
        _seed_user(app_no_csrf)
        self._fail_login(client_no_csrf, "victim", 3)
        # Successful login clears the slate
        _login_no_csrf(client_no_csrf, "victim", "Password1!")
        client_no_csrf.get("/logout")
        # Now 3 more failures should NOT lock (counter was cleared)
        self._fail_login(client_no_csrf, "victim", 3)
        rv = _login_no_csrf(client_no_csrf, "victim", "Password1!")
        assert b"Dashboard" in rv.data

    def test_lockout_event_recorded_in_audit_log(self, app_no_csrf, client_no_csrf):
        _seed_user(app_no_csrf)
        self._fail_login(client_no_csrf, "victim", 5)
        _login_no_csrf(client_no_csrf, "victim", "Password1!")
        from database import get_db
        db = get_db()
        event = db.execute(
            "SELECT * FROM audit_events WHERE event_type = 'LOGIN_LOCKED'"
            " ORDER BY id DESC LIMIT 1"
        ).fetchone()
        db.close()
        assert event is not None

    def test_failure_rows_recorded_in_login_attempts(self, app_no_csrf, client_no_csrf):
        _seed_user(app_no_csrf)
        self._fail_login(client_no_csrf, "victim", 3)
        from database import get_db
        db = get_db()
        count = db.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE username = 'victim'"
        ).fetchone()[0]
        db.close()
        assert count == 3

    def test_successful_login_deletes_attempt_rows(self, app_no_csrf, client_no_csrf):
        _seed_user(app_no_csrf)
        self._fail_login(client_no_csrf, "victim", 3)
        _login_no_csrf(client_no_csrf, "victim", "Password1!")
        from database import get_db
        db = get_db()
        count = db.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE username = 'victim'"
        ).fetchone()[0]
        db.close()
        assert count == 0

    def test_passwords_not_stored_in_login_attempts(self, app_no_csrf, client_no_csrf):
        _seed_user(app_no_csrf)
        self._fail_login(client_no_csrf, "victim", 2)
        from database import get_db
        db = get_db()
        rows = db.execute("SELECT * FROM login_attempts").fetchall()
        db.close()
        for row in rows:
            row_str = " ".join(str(v) for v in row)
            assert "WrongPass" not in row_str
            assert "Password1" not in row_str


# ---------------------------------------------------------------------------
# 3. Lockout window expiry (using direct DB manipulation)
# ---------------------------------------------------------------------------

class TestLockoutWindowExpiry:
    def test_expired_attempts_do_not_count(self, app_no_csrf, client_no_csrf):
        """Attempts older than the window must not contribute to lockout."""
        _seed_user(app_no_csrf)
        from database import get_db
        db = get_db()
        # Insert 5 attempts with timestamps 20 minutes in the past
        for _ in range(5):
            db.execute(
                "INSERT INTO login_attempts (username, ip_address, attempted_at)"
                " VALUES (?, ?, datetime('now', '-20 minutes'))",
                ("victim", "127.0.0.1"),
            )
        db.commit()
        db.close()
        # Login with correct password must succeed — old attempts are outside window
        rv = _login_no_csrf(client_no_csrf, "victim", "Password1!")
        assert b"Dashboard" in rv.data

    def test_mix_of_old_and_new_attempts(self, app_no_csrf, client_no_csrf):
        """Only recent attempts count; old ones are ignored."""
        _seed_user(app_no_csrf)
        from database import get_db
        db = get_db()
        # 4 old attempts (outside window)
        for _ in range(4):
            db.execute(
                "INSERT INTO login_attempts (username, ip_address, attempted_at)"
                " VALUES (?, ?, datetime('now', '-20 minutes'))",
                ("victim", "127.0.0.1"),
            )
        db.commit()
        db.close()
        # 4 new failures — total recent = 4, should NOT lock
        for _ in range(4):
            client_no_csrf.post("/login", data={
                "username": "victim", "password": "WrongPass!",
            })
        rv = _login_no_csrf(client_no_csrf, "victim", "Password1!")
        assert b"Dashboard" in rv.data


# ---------------------------------------------------------------------------
# 4. Security HTTP headers
# ---------------------------------------------------------------------------

class TestSecurityHeaders:
    def _get_headers(self, client):
        rv = client.get("/")
        return rv.headers

    def test_x_frame_options_deny(self, client_no_csrf):
        h = self._get_headers(client_no_csrf)
        assert h.get("X-Frame-Options") == "DENY"

    def test_x_content_type_options_nosniff(self, client_no_csrf):
        h = self._get_headers(client_no_csrf)
        assert h.get("X-Content-Type-Options") == "nosniff"

    def test_referrer_policy_set(self, client_no_csrf):
        h = self._get_headers(client_no_csrf)
        assert "Referrer-Policy" in h
        assert h["Referrer-Policy"] != ""

    def test_permissions_policy_set(self, client_no_csrf):
        h = self._get_headers(client_no_csrf)
        assert "Permissions-Policy" in h

    def test_csp_present(self, client_no_csrf):
        h = self._get_headers(client_no_csrf)
        assert "Content-Security-Policy" in h

    def test_csp_blocks_object_src(self, client_no_csrf):
        csp = self._get_headers(client_no_csrf).get("Content-Security-Policy", "")
        assert "object-src 'none'" in csp

    def test_csp_restricts_default_src(self, client_no_csrf):
        csp = self._get_headers(client_no_csrf).get("Content-Security-Policy", "")
        assert "default-src 'self'" in csp

    def test_csp_allows_jsdelivr_scripts(self, client_no_csrf):
        """Bootstrap JS is loaded from jsDelivr — must be in script-src."""
        csp = self._get_headers(client_no_csrf).get("Content-Security-Policy", "")
        assert "https://cdn.jsdelivr.net" in csp

    def test_headers_present_on_authenticated_route(self, app_no_csrf, client_no_csrf):
        _seed_user(app_no_csrf)
        _login_no_csrf(client_no_csrf, "victim", "Password1!")
        rv = client_no_csrf.get("/dashboard")
        assert rv.headers.get("X-Frame-Options") == "DENY"
        assert "Content-Security-Policy" in rv.headers

    def test_headers_present_on_404(self, client_no_csrf):
        rv = client_no_csrf.get("/nonexistent-route-xyz")
        assert rv.headers.get("X-Content-Type-Options") == "nosniff"


# ---------------------------------------------------------------------------
# 5. CSRF protection
# ---------------------------------------------------------------------------

class TestCSRFProtection:
    def test_post_without_csrf_token_rejected(self, client):
        """POST to login without a CSRF token must return 400."""
        rv = client.post("/login", data={
            "username": "anyone", "password": "Password1!",
        })
        assert rv.status_code == 400

    def test_post_with_invalid_csrf_token_rejected(self, client):
        rv = client.post("/login", data={
            "username": "anyone",
            "password": "Password1!",
            "csrf_token": "invalid-token-value",
        })
        assert rv.status_code == 400

    def test_csrf_error_page_rendered(self, client):
        rv = client.post("/login", data={
            "username": "anyone", "password": "Password1!",
        })
        assert rv.status_code == 400
        assert b"validation" in rv.data.lower() or b"security" in rv.data.lower()

    def test_valid_csrf_token_allows_login(self, app, client):
        _seed_user(app)
        token = _get_csrf_token(client)
        rv = client.post("/login", data={
            "username": "victim",
            "password": "Password1!",
            "csrf_token": token,
        }, follow_redirects=True)
        assert b"Dashboard" in rv.data

    def test_valid_csrf_token_allows_registration(self, app, client):
        rv = client.get("/register")
        html = rv.data.decode()
        marker = 'name="csrf_token" value="'
        idx = html.find(marker)
        assert idx != -1
        start = idx + len(marker)
        token = html[start:html.index('"', start)]

        rv2 = client.post("/register", data={
            "username": "newuser",
            "password": "SecurePass1!",
            "confirm_password": "SecurePass1!",
            "role": "staff",
            "csrf_token": token,
        }, follow_redirects=True)
        assert b"Account created" in rv2.data

    def test_register_without_csrf_rejected(self, client):
        rv = client.post("/register", data={
            "username": "hacker",
            "password": "SecurePass1!",
            "confirm_password": "SecurePass1!",
            "role": "staff",
        })
        assert rv.status_code == 400

    def test_add_donor_without_csrf_rejected(self, app, client):
        """POST to /donors/add without CSRF token must be rejected."""
        _seed_user(app)
        token = _get_csrf_token(client)
        client.post("/login", data={
            "username": "victim", "password": "Password1!", "csrf_token": token,
        }, follow_redirects=True)
        rv = client.post("/donors/add", data={
            "full_name": "Test Donor",
            "blood_group": "A+",
            "donation_type": "blood",
        })
        assert rv.status_code == 400

    def test_get_requests_do_not_require_csrf(self, client):
        """GET requests must never be blocked by CSRF protection."""
        rv = client.get("/login")
        assert rv.status_code == 200
        rv2 = client.get("/register")
        assert rv2.status_code == 200

    def test_csrf_token_present_in_login_form(self, client):
        rv = client.get("/login")
        assert b'name="csrf_token"' in rv.data

    def test_csrf_token_present_in_register_form(self, client):
        rv = client.get("/register")
        assert b'name="csrf_token"' in rv.data


# ---------------------------------------------------------------------------
# 6. Admin security dashboard access control
# ---------------------------------------------------------------------------

class TestSecurityDashboardAccess:
    def test_unauthenticated_redirected(self, client_no_csrf):
        rv = client_no_csrf.get("/security", follow_redirects=True)
        assert b"log in" in rv.data.lower()

    def test_staff_cannot_access_security_dashboard(self, app_no_csrf, client_no_csrf):
        _seed_user(app_no_csrf, role="staff")
        _login_no_csrf(client_no_csrf, "victim", "Password1!")
        rv = client_no_csrf.get("/security", follow_redirects=True)
        assert b"permission" in rv.data.lower()

    def test_doctor_cannot_access_security_dashboard(self, app_no_csrf, client_no_csrf):
        _seed_user(app_no_csrf, role="doctor")
        _login_no_csrf(client_no_csrf, "victim", "Password1!")
        rv = client_no_csrf.get("/security", follow_redirects=True)
        assert b"permission" in rv.data.lower()

    def test_admin_can_access_security_dashboard(self, app_no_csrf, client_no_csrf):
        _seed_admin(app_no_csrf)
        _login_no_csrf(client_no_csrf, "admin1", "AdminPass1!")
        rv = client_no_csrf.get("/security")
        assert rv.status_code == 200
        assert b"Security Dashboard" in rv.data

    def test_security_dashboard_shows_failed_login_events(self, app_no_csrf, client_no_csrf):
        _seed_user(app_no_csrf)
        _seed_admin(app_no_csrf)
        # Generate some failures
        for _ in range(3):
            client_no_csrf.post("/login", data={
                "username": "victim", "password": "WrongPass!",
            })
        _login_no_csrf(client_no_csrf, "admin1", "AdminPass1!")
        rv = client_no_csrf.get("/security")
        assert b"LOGIN_FAILED" in rv.data

    def test_security_dashboard_shows_locked_account(self, app_no_csrf, client_no_csrf):
        _seed_user(app_no_csrf)
        _seed_admin(app_no_csrf)
        # Trigger lockout
        for _ in range(5):
            client_no_csrf.post("/login", data={
                "username": "victim", "password": "WrongPass!",
            })
        _login_no_csrf(client_no_csrf, "admin1", "AdminPass1!")
        rv = client_no_csrf.get("/security")
        assert b"victim" in rv.data

    def test_security_dashboard_shows_24h_failure_count(self, app_no_csrf, client_no_csrf):
        _seed_admin(app_no_csrf)
        _login_no_csrf(client_no_csrf, "admin1", "AdminPass1!")
        rv = client_no_csrf.get("/security")
        assert b"Failed Logins" in rv.data

    def test_security_page_not_accessible_via_nav_for_staff(self, app_no_csrf, client_no_csrf):
        """The /security URL must return 403-equivalent for staff, not just hide the link."""
        _seed_user(app_no_csrf, role="staff")
        _login_no_csrf(client_no_csrf, "victim", "Password1!")
        rv = client_no_csrf.get("/security", follow_redirects=False)
        # roles_required redirects to dashboard — not 200
        assert rv.status_code in (302, 403)
