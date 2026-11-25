"""
DonorShield - Stage 9 security-hardening tests.
Covers: per-IP login rate limiting, input length validation on login /
        register / add_donor / bloodbank search, and audit logging of
        IP-block events.
Run with:  .venv/Scripts/pytest tests/ -v
"""
import os
import tempfile
import pytest
from werkzeug.security import generate_password_hash

TEST_AES_KEY = "ab" * 32


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def app(monkeypatch):
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
        SECRET_KEY="hardening-test",
        WTF_CSRF_ENABLED=False,
    )
    yield app_module.app

    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture()
def client(app):
    return app.test_client()


def _seed_user(app, username="victim", password="Password1!", role="staff"):
    from database import get_db
    db = get_db()
    db.execute(
        "INSERT INTO users (username, password, role) VALUES (?,?,?)",
        (username, generate_password_hash(password), role),
    )
    db.commit()
    db.close()


def _seed_admin(app, username="admin1", password="AdminPass1!"):
    _seed_user(app, username=username, password=password, role="admin")


def _login(client, username, password):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


def _insert_ip_attempts(app, ip, n, minutes_ago=0):
    """Directly insert n login_attempts rows for a given IP."""
    from database import get_db
    db = get_db()
    ts_expr = f"datetime('now', '-{minutes_ago} minutes')" if minutes_ago else "datetime('now')"
    for _ in range(n):
        db.execute(
            f"INSERT INTO login_attempts (username, ip_address, attempted_at)"
            f" VALUES (?, ?, {ts_expr})",
            ("someuser", ip),
        )
    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# 1. Per-IP rate limiting
# ---------------------------------------------------------------------------

class TestIPRateLimit:
    """
    The test client uses 127.0.0.1 as remote_addr.
    IP_RATE_LIMIT_ATTEMPTS = 20 (configurable in app.py).
    We seed rows directly to avoid running 20 real HTTP requests.
    """

    def test_below_ip_threshold_allows_login(self, app, client):
        _seed_user(app)
        # 19 prior attempts from this IP — still under threshold
        _insert_ip_attempts(app, "127.0.0.1", 19)
        rv = _login(client, "victim", "Password1!")
        assert b"Dashboard" in rv.data

    def test_at_ip_threshold_blocks_login(self, app, client):
        _seed_user(app)
        # 20 prior attempts — at threshold, next attempt is blocked
        _insert_ip_attempts(app, "127.0.0.1", 20)
        rv = _login(client, "victim", "Password1!")
        assert b"Invalid username or password" in rv.data
        assert b"Dashboard" not in rv.data

    def test_ip_block_message_is_generic(self, app, client):
        """Blocked IP must not reveal it is rate-limited."""
        _seed_user(app)
        _insert_ip_attempts(app, "127.0.0.1", 20)
        rv = _login(client, "victim", "Password1!")
        assert b"rate" not in rv.data.lower()
        assert b"blocked" not in rv.data.lower()
        assert b"Invalid username or password" in rv.data

    def test_ip_block_logged_in_audit(self, app, client):
        _seed_user(app)
        _insert_ip_attempts(app, "127.0.0.1", 20)
        _login(client, "victim", "Password1!")
        from database import get_db
        db = get_db()
        event = db.execute(
            "SELECT * FROM audit_events WHERE event_type='LOGIN_IP_BLOCKED'"
            " ORDER BY id DESC LIMIT 1"
        ).fetchone()
        db.close()
        assert event is not None

    def test_ip_block_does_not_store_password(self, app, client):
        _seed_user(app)
        _insert_ip_attempts(app, "127.0.0.1", 20)
        _login(client, "victim", "Password1!")
        from database import get_db
        db = get_db()
        rows = db.execute("SELECT * FROM login_attempts").fetchall()
        db.close()
        for row in rows:
            assert "Password1" not in " ".join(str(v) for v in row)

    def test_expired_ip_attempts_do_not_count(self, app, client):
        _seed_user(app)
        # 20 attempts older than the window (20 minutes ago, window is 15)
        _insert_ip_attempts(app, "127.0.0.1", 20, minutes_ago=20)
        rv = _login(client, "victim", "Password1!")
        assert b"Dashboard" in rv.data

    def test_mix_old_and_new_ip_attempts(self, app, client):
        _seed_user(app)
        # 19 old (expired) + 10 new = 10 recent, under threshold
        _insert_ip_attempts(app, "127.0.0.1", 19, minutes_ago=20)
        _insert_ip_attempts(app, "127.0.0.1", 10)
        rv = _login(client, "victim", "Password1!")
        assert b"Dashboard" in rv.data

    def test_different_ip_not_affected(self, app, client):
        """Attempts from a different IP must not block 127.0.0.1."""
        _seed_user(app)
        _insert_ip_attempts(app, "10.0.0.1", 20)
        rv = _login(client, "victim", "Password1!")
        assert b"Dashboard" in rv.data

    def test_schema_version_9_present(self, app):
        from database import get_db
        db = get_db()
        versions = {r[0] for r in db.execute(
            "SELECT version FROM schema_version"
        ).fetchall()}
        db.close()
        assert 9 in versions

    def test_ip_index_exists(self, app):
        from database import get_db
        db = get_db()
        indexes = {r[0] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()}
        db.close()
        assert "idx_la_ip" in indexes


# ---------------------------------------------------------------------------
# 2. Login input length limits
# ---------------------------------------------------------------------------

class TestLoginInputLimits:
    def test_oversized_username_rejected(self, app, client):
        rv = _login(client, "a" * 65, "Password1!")
        assert b"Invalid username or password" in rv.data
        assert b"Dashboard" not in rv.data

    def test_oversized_password_rejected(self, app, client):
        _seed_user(app)
        rv = _login(client, "victim", "x" * 257)
        assert b"Invalid username or password" in rv.data
        assert b"Dashboard" not in rv.data

    def test_max_length_username_accepted(self, app, client):
        """A username exactly at the limit must not be rejected by length alone."""
        long_name = "a" * 64
        _seed_user(app, username=long_name)
        rv = _login(client, long_name, "Password1!")
        assert b"Dashboard" in rv.data

    def test_max_length_password_accepted(self, app, client):
        pw = "A1!" + "x" * 253  # 256 chars total
        _seed_user(app, username="pwtest", password=pw)
        rv = _login(client, "pwtest", pw)
        assert b"Dashboard" in rv.data


# ---------------------------------------------------------------------------
# 3. Registration input length limits
# ---------------------------------------------------------------------------

class TestRegistrationInputLimits:
    def test_oversized_username_rejected(self, app, client):
        rv = client.post("/register", data={
            "username": "a" * 65,
            "password": "SecurePass1!",
            "confirm_password": "SecurePass1!",
            "role": "staff",
        }, follow_redirects=True)
        assert b"at most 64" in rv.data

    def test_oversized_password_rejected(self, app, client):
        rv = client.post("/register", data={
            "username": "validuser",
            "password": "x" * 257,
            "confirm_password": "x" * 257,
            "role": "staff",
        }, follow_redirects=True)
        assert b"at most 256" in rv.data

    def test_valid_max_length_username_accepted(self, app, client):
        rv = client.post("/register", data={
            "username": "a" * 64,
            "password": "SecurePass1!",
            "confirm_password": "SecurePass1!",
            "role": "staff",
        }, follow_redirects=True)
        assert b"Account created" in rv.data

    def test_existing_short_validations_still_work(self, app, client):
        """Existing min-length checks must not be broken."""
        rv = client.post("/register", data={
            "username": "ab",
            "password": "SecurePass1!",
            "confirm_password": "SecurePass1!",
            "role": "staff",
        }, follow_redirects=True)
        assert b"3 characters" in rv.data


# ---------------------------------------------------------------------------
# 4. Add-donor input length limits
# ---------------------------------------------------------------------------

class TestDonorInputLimits:
    def _login_as_staff(self, app, client):
        _seed_user(app, username="staff1", password="Password1!", role="staff")
        _login(client, "staff1", "Password1!")

    def test_oversized_full_name_rejected(self, app, client):
        self._login_as_staff(app, client)
        rv = client.post("/donors/add", data={
            "full_name": "A" * 121,
            "blood_group": "A+",
            "donation_type": "blood",
        }, follow_redirects=True)
        assert b"at most 120" in rv.data

    def test_oversized_contact_rejected(self, app, client):
        self._login_as_staff(app, client)
        rv = client.post("/donors/add", data={
            "full_name": "Valid Name",
            "blood_group": "A+",
            "donation_type": "blood",
            "contact": "9" * 41,
        }, follow_redirects=True)
        assert b"at most 40" in rv.data

    def test_oversized_organ_type_rejected(self, app, client):
        self._login_as_staff(app, client)
        rv = client.post("/donors/add", data={
            "full_name": "Valid Name",
            "blood_group": "A+",
            "donation_type": "organ",
            "organ_type": "k" * 61,
        }, follow_redirects=True)
        assert b"at most 60" in rv.data

    def test_valid_donor_still_accepted(self, app, client):
        self._login_as_staff(app, client)
        rv = client.post("/donors/add", data={
            "full_name": "Jane Doe",
            "blood_group": "O+",
            "donation_type": "blood",
        }, follow_redirects=True)
        assert b"registered successfully" in rv.data


# ---------------------------------------------------------------------------
# 5. Blood bank search input length limits
# ---------------------------------------------------------------------------

class TestBloodBankSearchLimits:
    def _login_as_staff(self, app, client):
        _seed_user(app, username="staff2", password="Password1!", role="staff")
        _login(client, "staff2", "Password1!")

    def test_oversized_search_truncated_not_errored(self, app, client):
        """A search term longer than MAX_SEARCH_LEN must not cause a 500."""
        self._login_as_staff(app, client)
        long_query = "x" * 200
        rv = client.get(f"/bloodbanks?name={long_query}")
        assert rv.status_code == 200

    def test_normal_search_still_works(self, app, client):
        self._login_as_staff(app, client)
        rv = client.get("/bloodbanks?state=Maharashtra")
        assert rv.status_code == 200
