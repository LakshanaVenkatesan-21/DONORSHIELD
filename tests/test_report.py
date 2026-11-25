"""
DonorShield - Stage 4 audit report export integration tests.
Run with:  .venv/Scripts/pytest tests/ -v
"""
import io
import json
import os
import tempfile
import zipfile

import pytest
from werkzeug.security import generate_password_hash

TEST_AES_KEY = "ef" * 32   # 64-char hex, synthetic test key only


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def key_dir(tmp_path):
    """Generate a real RSA key pair in a temp directory for each test."""
    from security.signatures import generate_key_pair, save_private_key, save_public_key
    priv_path = str(tmp_path / "private.pem")
    pub_path  = str(tmp_path / "public.pem")
    priv, pub = generate_key_pair()
    save_private_key(priv, priv_path)
    save_public_key(pub, pub_path)
    return {"private": priv_path, "public": pub_path, "priv_obj": priv, "pub_obj": pub}


@pytest.fixture()
def app(monkeypatch, key_dir):
    """Isolated Flask app with temp DB, AES key, and RSA key paths configured."""
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    monkeypatch.setenv("DB_PATH", db_path)
    monkeypatch.setenv("TESTING", "true")
    monkeypatch.setenv("DS_AES_KEY", TEST_AES_KEY)
    monkeypatch.setenv("DS_RSA_PRIVATE_KEY_PATH", key_dir["private"])
    monkeypatch.setenv("DS_RSA_PUBLIC_KEY_PATH",  key_dir["public"])

    import importlib
    import database
    import app as app_module
    importlib.reload(database)
    importlib.reload(app_module)

    database.init_db()
    app_module.app.config.update(
        TESTING=True,
        SECRET_KEY="stage4-test-secret",
        WTF_CSRF_ENABLED=False,
    )

    yield app_module.app

    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture()
def app_no_keys(monkeypatch):
    """Isolated Flask app with no RSA keys configured."""
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    monkeypatch.setenv("DB_PATH", db_path)
    monkeypatch.setenv("TESTING", "true")
    monkeypatch.setenv("DS_AES_KEY", TEST_AES_KEY)
    monkeypatch.setenv("DS_RSA_PRIVATE_KEY_PATH", "/nonexistent/private.pem")
    monkeypatch.setenv("DS_RSA_PUBLIC_KEY_PATH",  "/nonexistent/public.pem")

    import importlib
    import database
    import app as app_module
    importlib.reload(database)
    importlib.reload(app_module)

    database.init_db()
    app_module.app.config.update(
        TESTING=True,
        SECRET_KEY="stage4-nokeys-secret",
        WTF_CSRF_ENABLED=False,
    )

    yield app_module.app

    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def client_no_keys(app_no_keys):
    return app_no_keys.test_client()


def _seed_admin(app, username="adminuser", password="AdminPass1!"):
    from database import get_db
    db = get_db()
    db.execute(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        (username, generate_password_hash(password), "admin"),
    )
    db.commit()
    db.close()
    return {"username": username, "password": password}


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


def _export_zip(client):
    """Return the ZIP bytes from /audit/export."""
    rv = client.get("/audit/export")
    assert rv.status_code == 200
    assert rv.content_type == "application/zip"
    return rv.data


def _parse_zip(zip_bytes):
    """Return (report_dict, report_bytes, signature_bytes) from a ZIP."""
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        report_bytes = zf.read("report.json")
        sig_bytes    = zf.read("report.sig")
    return json.loads(report_bytes.decode("utf-8")), report_bytes, sig_bytes


# ---------------------------------------------------------------------------
# 1. Role access control
# ---------------------------------------------------------------------------

class TestExportRoleAccess:
    def test_unauthenticated_redirected(self, client):
        rv = client.get("/audit/export", follow_redirects=True)
        assert b"log in" in rv.data.lower()

    def test_staff_cannot_export(self, app, client):
        creds = _seed_staff(app)
        _login(client, creds)
        rv = client.get("/audit/export", follow_redirects=True)
        assert b"permission" in rv.data.lower()

    def test_doctor_cannot_export(self, app, client):
        creds = _seed_doctor(app)
        _login(client, creds)
        rv = client.get("/audit/export", follow_redirects=True)
        assert b"permission" in rv.data.lower()

    def test_admin_can_export(self, app, client):
        creds = _seed_admin(app)
        _login(client, creds)
        rv = client.get("/audit/export")
        assert rv.status_code == 200
        assert rv.content_type == "application/zip"


# ---------------------------------------------------------------------------
# 2. ZIP archive structure
# ---------------------------------------------------------------------------

class TestZipStructure:
    def test_zip_contains_report_json(self, app, client):
        creds = _seed_admin(app)
        _login(client, creds)
        zip_bytes = _export_zip(client)
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            assert "report.json" in zf.namelist()

    def test_zip_contains_report_sig(self, app, client):
        creds = _seed_admin(app)
        _login(client, creds)
        zip_bytes = _export_zip(client)
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            assert "report.sig" in zf.namelist()

    def test_sig_is_non_empty_bytes(self, app, client):
        creds = _seed_admin(app)
        _login(client, creds)
        zip_bytes = _export_zip(client)
        _, _, sig = _parse_zip(zip_bytes)
        assert len(sig) > 0

    def test_download_name_contains_timestamp(self, app, client):
        creds = _seed_admin(app)
        _login(client, creds)
        rv = client.get("/audit/export")
        cd = rv.headers.get("Content-Disposition", "")
        assert "audit_report_" in cd
        assert ".zip" in cd


# ---------------------------------------------------------------------------
# 3. Report JSON content and privacy
# ---------------------------------------------------------------------------

class TestReportContent:
    def test_report_has_required_top_level_keys(self, app, client):
        creds = _seed_admin(app)
        _login(client, creds)
        report, _, _ = _parse_zip(_export_zip(client))
        for key in ("report_type", "generated_at", "generated_by", "summary", "events"):
            assert key in report, f"Missing key: {key}"

    def test_summary_has_counts(self, app, client):
        creds = _seed_admin(app)
        _login(client, creds)
        report, _, _ = _parse_zip(_export_zip(client))
        assert "total_donors" in report["summary"]
        assert "total_users"  in report["summary"]
        assert "event_count"  in report["summary"]

    def test_events_list_is_present(self, app, client):
        creds = _seed_admin(app)
        _login(client, creds)
        report, _, _ = _parse_zip(_export_zip(client))
        assert isinstance(report["events"], list)

    def test_report_does_not_contain_passwords(self, app, client):
        creds = _seed_admin(app)
        _login(client, creds)
        _, report_bytes, _ = _parse_zip(_export_zip(client))
        assert b"password" not in report_bytes.lower()

    def test_report_does_not_contain_aes_key(self, app, client):
        creds = _seed_admin(app)
        _login(client, creds)
        _, report_bytes, _ = _parse_zip(_export_zip(client))
        assert TEST_AES_KEY.encode() not in report_bytes

    def test_report_does_not_contain_v1_tokens(self, app, client):
        """No AES-GCM ciphertext tokens should appear in the report."""
        creds = _seed_admin(app)
        _login(client, creds)
        _, report_bytes, _ = _parse_zip(_export_zip(client))
        assert b"v1:" not in report_bytes

    def test_event_count_matches_events_list(self, app, client):
        creds = _seed_admin(app)
        _login(client, creds)
        report, _, _ = _parse_zip(_export_zip(client))
        assert report["summary"]["event_count"] == len(report["events"])

    def test_generated_by_is_exporting_admin(self, app, client):
        creds = _seed_admin(app, username="reportadmin")
        _login(client, creds)
        report, _, _ = _parse_zip(_export_zip(client))
        assert report["generated_by"] == "reportadmin"


# ---------------------------------------------------------------------------
# 4. Signature is valid and verifiable with the public key
# ---------------------------------------------------------------------------

class TestSignatureValid:
    def test_signature_verifies_with_public_key(self, app, client, key_dir):
        from security.signatures import verify_bytes, load_public_key
        creds = _seed_admin(app)
        _login(client, creds)
        _, report_bytes, sig = _parse_zip(_export_zip(client))
        pub = load_public_key(key_dir["public"])
        assert verify_bytes(report_bytes, sig, pub) is True

    def test_modified_report_fails_verification(self, app, client, key_dir):
        from security.signatures import verify_bytes, load_public_key
        creds = _seed_admin(app)
        _login(client, creds)
        _, report_bytes, sig = _parse_zip(_export_zip(client))
        pub = load_public_key(key_dir["public"])
        tampered = report_bytes + b"\n# tampered"
        assert verify_bytes(tampered, sig, pub) is False

    def test_wrong_public_key_fails_verification(self, app, client):
        from security.signatures import verify_bytes, generate_key_pair
        creds = _seed_admin(app)
        _login(client, creds)
        _, report_bytes, sig = _parse_zip(_export_zip(client))
        _, wrong_pub = generate_key_pair()
        assert verify_bytes(report_bytes, sig, wrong_pub) is False

    def test_corrupted_signature_fails_verification(self, app, client, key_dir):
        from security.signatures import verify_bytes, load_public_key
        creds = _seed_admin(app)
        _login(client, creds)
        _, report_bytes, sig = _parse_zip(_export_zip(client))
        pub = load_public_key(key_dir["public"])
        bad_sig = bytearray(sig)
        bad_sig[0] ^= 0xFF
        assert verify_bytes(report_bytes, bytes(bad_sig), pub) is False

    def test_export_event_recorded_in_audit_log(self, app, client):
        from database import get_db
        creds = _seed_admin(app)
        _login(client, creds)
        _export_zip(client)
        db = get_db()
        event = db.execute(
            "SELECT * FROM audit_events WHERE event_type = 'AUDIT_EXPORT'"
            " ORDER BY id DESC LIMIT 1"
        ).fetchone()
        db.close()
        assert event is not None


# ---------------------------------------------------------------------------
# 5. Missing signing key handled gracefully
# ---------------------------------------------------------------------------

class TestMissingSigningKey:
    def test_export_without_private_key_redirects_with_error(
        self, app_no_keys, client_no_keys
    ):
        from database import get_db
        db = get_db()
        db.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("adminnokey", generate_password_hash("AdminPass1!"), "admin"),
        )
        db.commit()
        db.close()

        client_no_keys.post(
            "/login",
            data={"username": "adminnokey", "password": "AdminPass1!"},
            follow_redirects=True,
        )
        rv = client_no_keys.get("/audit/export", follow_redirects=True)
        assert rv.status_code == 200
        # Must show an error, not crash or return a ZIP.
        assert rv.content_type.startswith("text/html")
        assert b"generate-keys" in rv.data or b"not found" in rv.data.lower()
