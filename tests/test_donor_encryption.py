"""
DonorShield - Stage 3 donor encryption integration tests.
Run with:  .venv/Scripts/pytest tests/ -v
"""
import os
import tempfile

import pytest
from werkzeug.security import generate_password_hash

TEST_KEY = "cd" * 32   # 64-char hex = 32 bytes, synthetic test key only


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def app(monkeypatch):
    """
    Isolated Flask app + temp DB with DS_AES_KEY set.
    Each test gets a fresh database and a known encryption key.
    """
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    monkeypatch.setenv("DB_PATH", db_path)
    monkeypatch.setenv("TESTING", "true")
    monkeypatch.setenv("DS_AES_KEY", TEST_KEY)

    import importlib
    import database
    import app as app_module
    importlib.reload(database)
    importlib.reload(app_module)

    database.init_db()
    app_module.app.config.update(
        TESTING=True,
        SECRET_KEY="stage3-test-secret",
        WTF_CSRF_ENABLED=False,
    )

    yield app_module.app

    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture()
def app_no_key(monkeypatch):
    """Isolated Flask app with DS_AES_KEY deliberately absent."""
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    monkeypatch.setenv("DB_PATH", db_path)
    monkeypatch.setenv("TESTING", "true")
    monkeypatch.delenv("DS_AES_KEY", raising=False)

    import importlib
    import database
    import app as app_module
    importlib.reload(database)
    importlib.reload(app_module)

    database.init_db()
    app_module.app.config.update(
        TESTING=True,
        SECRET_KEY="stage3-nokey-secret",
        WTF_CSRF_ENABLED=False,
    )

    yield app_module.app

    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def client_no_key(app_no_key):
    return app_no_key.test_client()


def _seed_staff(app, username="staffuser", password="Password1!"):
    from database import get_db
    db = get_db()
    db.execute(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        (username, generate_password_hash(password), "staff"),
    )
    db.commit()
    db.close()
    return {"username": username, "password": password}


def _seed_doctor(app, username="docuser", password="Password1!"):
    from database import get_db
    db = get_db()
    db.execute(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        (username, generate_password_hash(password), "doctor"),
    )
    db.commit()
    db.close()
    return {"username": username, "password": password}


def _login(client, creds):
    client.post("/login", data=creds, follow_redirects=True)


def _add_donor_via_form(client, name="Priya Sharma", blood_group="B+",
                        donation_type="blood", contact="9876500001", organ_type=""):
    return client.post("/donors/add", data={
        "full_name":     name,
        "blood_group":   blood_group,
        "donation_type": donation_type,
        "organ_type":    organ_type,
        "contact":       contact,
    }, follow_redirects=True)


# ---------------------------------------------------------------------------
# 1. Plaintext is never stored in the database
# ---------------------------------------------------------------------------

class TestPlaintextNotStored:
    def test_full_name_not_stored_in_plaintext(self, app, client):
        creds = _seed_staff(app)
        _login(client, creds)
        _add_donor_via_form(client, name="Ravi Kumar")

        from database import get_db
        db = get_db()
        row = db.execute("SELECT full_name FROM donors ORDER BY id DESC LIMIT 1").fetchone()
        db.close()

        raw = row["full_name"]
        assert raw != "Ravi Kumar", "full_name stored as plaintext"
        assert raw.startswith("v1:"), f"Expected AES-GCM token, got: {raw[:40]}"

    def test_contact_not_stored_in_plaintext(self, app, client):
        creds = _seed_staff(app)
        _login(client, creds)
        _add_donor_via_form(client, contact="9123456789")

        from database import get_db
        db = get_db()
        row = db.execute("SELECT contact FROM donors ORDER BY id DESC LIMIT 1").fetchone()
        db.close()

        raw = row["contact"]
        assert raw != "9123456789", "contact stored as plaintext"
        assert raw.startswith("v1:")

    def test_organ_type_not_stored_in_plaintext(self, app, client):
        creds = _seed_staff(app)
        _login(client, creds)
        _add_donor_via_form(client, donation_type="organ", organ_type="Kidney", contact="")

        from database import get_db
        db = get_db()
        row = db.execute("SELECT organ_type FROM donors ORDER BY id DESC LIMIT 1").fetchone()
        db.close()

        raw = row["organ_type"]
        assert raw != "Kidney", "organ_type stored as plaintext"
        assert raw.startswith("v1:")

    def test_blood_group_stored_in_plaintext(self, app, client):
        """blood_group must remain plaintext for inventory filtering."""
        creds = _seed_staff(app)
        _login(client, creds)
        _add_donor_via_form(client, blood_group="AB+")

        from database import get_db
        db = get_db()
        row = db.execute("SELECT blood_group FROM donors ORDER BY id DESC LIMIT 1").fetchone()
        db.close()

        assert row["blood_group"] == "AB+", "blood_group should not be encrypted"

    def test_donation_type_stored_in_plaintext(self, app, client):
        """donation_type must remain plaintext for operational filtering."""
        creds = _seed_staff(app)
        _login(client, creds)
        _add_donor_via_form(client, donation_type="blood")

        from database import get_db
        db = get_db()
        row = db.execute("SELECT donation_type FROM donors ORDER BY id DESC LIMIT 1").fetchone()
        db.close()

        assert row["donation_type"] == "blood"

    def test_null_contact_stored_as_null(self, app, client):
        """A blank contact field should be stored as NULL, not an empty token."""
        creds = _seed_staff(app)
        _login(client, creds)
        _add_donor_via_form(client, contact="")

        from database import get_db
        db = get_db()
        row = db.execute("SELECT contact FROM donors ORDER BY id DESC LIMIT 1").fetchone()
        db.close()

        assert row["contact"] is None


# ---------------------------------------------------------------------------
# 2. Authorized users see decrypted data
# ---------------------------------------------------------------------------

class TestDecryptionOnRead:
    def test_staff_sees_decrypted_name_in_list(self, app, client):
        creds = _seed_staff(app)
        _login(client, creds)
        _add_donor_via_form(client, name="Ananya Iyer")

        rv = client.get("/donors")
        assert rv.status_code == 200
        assert b"Ananya Iyer" in rv.data

    def test_staff_sees_decrypted_contact_in_list(self, app, client):
        creds = _seed_staff(app)
        _login(client, creds)
        _add_donor_via_form(client, contact="9000011111")

        rv = client.get("/donors")
        assert b"9000011111" in rv.data

    def test_doctor_sees_decrypted_name_in_list(self, app, client):
        _seed_staff(app, username="s1")
        doc = _seed_doctor(app)
        # Staff registers the donor.
        _login(client, {"username": "s1", "password": "Password1!"})
        _add_donor_via_form(client, name="Vikram Nair")
        client.get("/logout")
        # Doctor views the list.
        _login(client, doc)
        rv = client.get("/donors")
        assert b"Vikram Nair" in rv.data

    def test_ciphertext_not_visible_in_response(self, app, client):
        """The raw v1: token must never appear in the rendered HTML."""
        creds = _seed_staff(app)
        _login(client, creds)
        _add_donor_via_form(client, name="Meera Pillai")

        rv = client.get("/donors")
        assert b"v1:" not in rv.data

    def test_multiple_donors_all_decrypted(self, app, client):
        creds = _seed_staff(app)
        _login(client, creds)
        names = ["Donor Alpha", "Donor Beta", "Donor Gamma"]
        for n in names:
            _add_donor_via_form(client, name=n)

        rv = client.get("/donors")
        for n in names:
            assert n.encode() in rv.data


# ---------------------------------------------------------------------------
# 3. Missing key — safe abort, no plaintext stored
# ---------------------------------------------------------------------------

class TestMissingKeyHandling:
    def test_add_donor_fails_gracefully_without_key(self, app_no_key, client_no_key):
        """POST to /donors/add must flash an error and store nothing."""
        from database import get_db
        db = get_db()
        db.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("staffnokey", generate_password_hash("Password1!"), "staff"),
        )
        db.commit()
        db.close()

        client_no_key.post("/login",
                           data={"username": "staffnokey", "password": "Password1!"},
                           follow_redirects=True)

        rv = client_no_key.post("/donors/add", data={
            "full_name":     "Should Not Be Saved",
            "blood_group":   "O+",
            "donation_type": "blood",
            "contact":       "9999999999",
            "organ_type":    "",
        }, follow_redirects=True)

        assert rv.status_code == 200
        assert b"DS_AES_KEY" in rv.data or b"not configured" in rv.data.lower()

        db = get_db()
        count = db.execute("SELECT COUNT(*) FROM donors").fetchone()[0]
        db.close()
        assert count == 0, "Donor row was written despite missing encryption key"

    def test_donor_list_shows_error_without_key(self, app_no_key, client_no_key):
        """GET /donors must show an error message, not crash or expose ciphertext."""
        from database import get_db
        db = get_db()
        db.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("staffnokey2", generate_password_hash("Password1!"), "staff"),
        )
        db.commit()
        db.close()

        client_no_key.post("/login",
                           data={"username": "staffnokey2", "password": "Password1!"},
                           follow_redirects=True)

        rv = client_no_key.get("/donors", follow_redirects=True)
        assert rv.status_code == 200
        assert b"DS_AES_KEY" in rv.data or b"not configured" in rv.data.lower()


# ---------------------------------------------------------------------------
# 4. Role access control on donor routes
# ---------------------------------------------------------------------------

class TestDonorRoleAccess:
    def test_unauthenticated_cannot_view_donors(self, client):
        rv = client.get("/donors", follow_redirects=True)
        assert b"log in" in rv.data.lower()

    def test_unauthenticated_cannot_add_donor(self, client):
        rv = client.get("/donors/add", follow_redirects=True)
        assert b"log in" in rv.data.lower()

    def test_doctor_cannot_access_add_donor_form(self, app, client):
        doc = _seed_doctor(app)
        _login(client, doc)
        rv = client.get("/donors/add", follow_redirects=True)
        assert b"permission" in rv.data.lower()

    def test_doctor_cannot_post_add_donor(self, app, client):
        doc = _seed_doctor(app)
        _login(client, doc)
        rv = client.post("/donors/add", data={
            "full_name":     "Unauthorized Donor",
            "blood_group":   "A+",
            "donation_type": "blood",
        }, follow_redirects=True)
        assert b"permission" in rv.data.lower()

        from database import get_db
        db = get_db()
        count = db.execute("SELECT COUNT(*) FROM donors").fetchone()[0]
        db.close()
        assert count == 0

    def test_staff_can_add_and_view_donor(self, app, client):
        creds = _seed_staff(app)
        _login(client, creds)
        rv = _add_donor_via_form(client, name="Suresh Babu")
        assert b"registered successfully" in rv.data

        rv2 = client.get("/donors")
        assert b"Suresh Babu" in rv2.data


# ---------------------------------------------------------------------------
# 5. Audit log does not contain plaintext PII
# ---------------------------------------------------------------------------

class TestAuditLogPrivacy:
    def test_audit_log_does_not_contain_donor_name(self, app, client):
        creds = _seed_staff(app)
        _login(client, creds)
        _add_donor_via_form(client, name="Confidential Name")

        from database import get_db
        db = get_db()
        events = db.execute(
            "SELECT description FROM audit_events WHERE event_type = 'ADD_DONOR'"
        ).fetchall()
        db.close()

        for e in events:
            desc = e["description"] or ""
            assert "Confidential Name" not in desc, \
                f"Plaintext donor name found in audit log: {desc}"

    def test_audit_log_contains_donor_id_and_blood_group(self, app, client):
        creds = _seed_staff(app)
        _login(client, creds)
        _add_donor_via_form(client, name="Test Donor", blood_group="O-")

        from database import get_db
        db = get_db()
        event = db.execute(
            "SELECT description FROM audit_events WHERE event_type = 'ADD_DONOR'"
            " ORDER BY id DESC LIMIT 1"
        ).fetchone()
        db.close()

        desc = event["description"] or ""
        assert "O-" in desc
        assert "Donor ID" in desc
