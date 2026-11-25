"""
DonorShield - Feature completeness tests.
Covers: donor view/edit/delete, donor search, inventory management,
        PCAP upload workflow, dashboard alert count, navigation links.
Run with:  .venv/Scripts/pytest tests/ -v
"""
import os
import struct
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
        SECRET_KEY="features-test",
        WTF_CSRF_ENABLED=False,
    )
    yield app_module.app

    # Close all SQLite connections before unlinking on Windows.
    import sqlite3
    try:
        conn = sqlite3.connect(db_path)
        conn.close()
    except Exception:
        pass
    os.close(db_fd)
    try:
        os.unlink(db_path)
    except PermissionError:
        pass  # Windows: file still locked; temp dir cleanup will handle it


@pytest.fixture()
def client(app):
    return app.test_client()


def _seed(app, username, password="Password1!", role="staff"):
    from database import get_db
    db = get_db()
    db.execute(
        "INSERT INTO users (username, password, role) VALUES (?,?,?)",
        (username, generate_password_hash(password), role),
    )
    db.commit()
    db.close()
    return {"username": username, "password": password}


def _login(client, creds):
    client.post("/login", data=creds, follow_redirects=True)


def _add_donor(client, name="Test Donor", blood="A+", dtype="blood",
               contact="9000000001", organ=""):
    return client.post("/donors/add", data={
        "full_name": name, "blood_group": blood,
        "donation_type": dtype, "contact": contact, "organ_type": organ,
    }, follow_redirects=True)


def _get_donor_id(app):
    from database import get_db
    db = get_db()
    row = db.execute("SELECT id FROM donors ORDER BY id DESC LIMIT 1").fetchone()
    db.close()
    return row["id"] if row else None


# ---------------------------------------------------------------------------
# 1. Donor detail view
# ---------------------------------------------------------------------------

class TestDonorDetail:
    def test_staff_can_view_donor_detail(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        _add_donor(client, name="Detail Test")
        did = _get_donor_id(app)
        rv = client.get(f"/donors/{did}")
        assert rv.status_code == 200
        assert b"Detail Test" in rv.data

    def test_doctor_can_view_donor_detail(self, app, client):
        _seed(app, "s1", role="staff")
        _seed(app, "doc1", role="doctor")
        _login(client, {"username": "s1", "password": "Password1!"})
        _add_donor(client, name="Doctor View Test")
        did = _get_donor_id(app)
        client.get("/logout")
        _login(client, {"username": "doc1", "password": "Password1!"})
        rv = client.get(f"/donors/{did}")
        assert rv.status_code == 200
        assert b"Doctor View Test" in rv.data

    def test_nonexistent_donor_returns_404(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        rv = client.get("/donors/999999")
        assert rv.status_code == 404

    def test_unauthenticated_redirected(self, client):
        rv = client.get("/donors/1", follow_redirects=True)
        assert b"log in" in rv.data.lower()

    def test_detail_shows_blood_group(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        _add_donor(client, blood="O-")
        did = _get_donor_id(app)
        rv = client.get(f"/donors/{did}")
        assert b"O-" in rv.data

    def test_detail_shows_edit_button_for_staff(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        _add_donor(client)
        did = _get_donor_id(app)
        rv = client.get(f"/donors/{did}")
        assert b"Edit" in rv.data

    def test_detail_hides_delete_for_staff(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        _add_donor(client)
        did = _get_donor_id(app)
        rv = client.get(f"/donors/{did}")
        assert b"delete_donor" not in rv.data.lower()

    def test_detail_shows_delete_for_admin(self, app, client):
        _seed(app, "adm1", role="admin")
        _login(client, {"username": "adm1", "password": "Password1!"})
        _add_donor(client)
        did = _get_donor_id(app)
        rv = client.get(f"/donors/{did}")
        assert b"Delete" in rv.data


# ---------------------------------------------------------------------------
# 2. Donor edit
# ---------------------------------------------------------------------------

class TestDonorEdit:
    def test_staff_can_edit_donor(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        _add_donor(client, name="Original Name")
        did = _get_donor_id(app)
        rv = client.post(f"/donors/{did}/edit", data={
            "full_name": "Updated Name", "blood_group": "B+",
            "donation_type": "blood", "contact": "", "organ_type": "", "status": "active",
        }, follow_redirects=True)
        assert b"updated successfully" in rv.data
        assert b"Updated Name" in rv.data

    def test_edit_form_loads_with_existing_data(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        _add_donor(client, name="Prefill Test")
        did = _get_donor_id(app)
        rv = client.get(f"/donors/{did}/edit")
        assert rv.status_code == 200
        assert b"Prefill Test" in rv.data

    def test_doctor_cannot_edit_donor(self, app, client):
        _seed(app, "s1", role="staff")
        _seed(app, "doc1", role="doctor")
        _login(client, {"username": "s1", "password": "Password1!"})
        _add_donor(client)
        did = _get_donor_id(app)
        client.get("/logout")
        _login(client, {"username": "doc1", "password": "Password1!"})
        rv = client.post(f"/donors/{did}/edit", data={
            "full_name": "Hacked", "blood_group": "A+",
            "donation_type": "blood", "status": "active",
        }, follow_redirects=True)
        assert b"permission" in rv.data.lower()

    def test_edit_empty_name_rejected(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        _add_donor(client, name="Valid Name")
        did = _get_donor_id(app)
        rv = client.post(f"/donors/{did}/edit", data={
            "full_name": "", "blood_group": "A+",
            "donation_type": "blood", "status": "active",
        }, follow_redirects=True)
        assert b"required" in rv.data.lower()

    def test_edit_logs_audit_event(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        _add_donor(client)
        did = _get_donor_id(app)
        client.post(f"/donors/{did}/edit", data={
            "full_name": "Audit Edit", "blood_group": "A+",
            "donation_type": "blood", "status": "active",
        }, follow_redirects=True)
        from database import get_db
        db = get_db()
        event = db.execute(
            "SELECT * FROM audit_events WHERE event_type='EDIT_DONOR' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        db.close()
        assert event is not None

    def test_edit_status_change_persists(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        _add_donor(client)
        did = _get_donor_id(app)
        client.post(f"/donors/{did}/edit", data={
            "full_name": "Status Test", "blood_group": "A+",
            "donation_type": "blood", "status": "inactive",
        }, follow_redirects=True)
        from database import get_db
        db = get_db()
        row = db.execute("SELECT status FROM donors WHERE id=?", (did,)).fetchone()
        db.close()
        assert row["status"] == "inactive"

    def test_edit_nonexistent_donor_returns_404(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        rv = client.get("/donors/999999/edit")
        assert rv.status_code == 404


# ---------------------------------------------------------------------------
# 3. Donor delete
# ---------------------------------------------------------------------------

class TestDonorDelete:
    def test_admin_can_delete_donor(self, app, client):
        _seed(app, "adm1", role="admin")
        _login(client, {"username": "adm1", "password": "Password1!"})
        _add_donor(client)
        did = _get_donor_id(app)
        rv = client.post(f"/donors/{did}/delete", follow_redirects=True)
        assert b"deleted" in rv.data.lower()
        from database import get_db
        db = get_db()
        row = db.execute("SELECT id FROM donors WHERE id=?", (did,)).fetchone()
        db.close()
        assert row is None

    def test_staff_cannot_delete_donor(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        _add_donor(client)
        did = _get_donor_id(app)
        rv = client.post(f"/donors/{did}/delete", follow_redirects=True)
        assert b"permission" in rv.data.lower()
        from database import get_db
        db = get_db()
        row = db.execute("SELECT id FROM donors WHERE id=?", (did,)).fetchone()
        db.close()
        assert row is not None

    def test_delete_nonexistent_returns_404(self, app, client):
        _seed(app, "adm1", role="admin")
        _login(client, {"username": "adm1", "password": "Password1!"})
        rv = client.post("/donors/999999/delete")
        assert rv.status_code == 404

    def test_delete_logs_audit_event(self, app, client):
        _seed(app, "adm1", role="admin")
        _login(client, {"username": "adm1", "password": "Password1!"})
        _add_donor(client)
        did = _get_donor_id(app)
        client.post(f"/donors/{did}/delete", follow_redirects=True)
        from database import get_db
        db = get_db()
        event = db.execute(
            "SELECT * FROM audit_events WHERE event_type='DELETE_DONOR' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        db.close()
        assert event is not None

    def test_delete_blood_donor_decrements_inventory(self, app, client):
        _seed(app, "adm1", role="admin")
        _login(client, {"username": "adm1", "password": "Password1!"})
        _add_donor(client, blood="A+", dtype="blood")
        did = _get_donor_id(app)
        from database import get_db
        db = get_db()
        before = db.execute(
            "SELECT units FROM blood_inventory WHERE blood_group='A+'"
        ).fetchone()["units"]
        db.close()
        client.post(f"/donors/{did}/delete", follow_redirects=True)
        db = get_db()
        after = db.execute(
            "SELECT units FROM blood_inventory WHERE blood_group='A+'"
        ).fetchone()["units"]
        db.close()
        assert after == before - 1


# ---------------------------------------------------------------------------
# 4. Donor search / filter
# ---------------------------------------------------------------------------

class TestDonorSearch:
    def test_name_search_returns_matching_donor(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        _add_donor(client, name="Unique Searchable Name")
        _add_donor(client, name="Other Person")
        rv = client.get("/donors?name=Unique+Searchable")
        assert b"Unique Searchable Name" in rv.data
        assert b"Other Person" not in rv.data

    def test_blood_group_filter(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        _add_donor(client, name="AB Donor", blood="AB+")
        _add_donor(client, name="O Donor", blood="O+")
        rv = client.get("/donors?blood=AB%2B")
        assert b"AB Donor" in rv.data
        assert b"O Donor" not in rv.data

    def test_donation_type_filter(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        _add_donor(client, name="Blood Donor", dtype="blood")
        _add_donor(client, name="Organ Donor", dtype="organ", organ="Kidney")
        rv = client.get("/donors?dtype=organ")
        assert b"Organ Donor" in rv.data
        assert b"Blood Donor" not in rv.data

    def test_no_results_shows_empty_state(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        rv = client.get("/donors?name=zzznomatch")
        assert b"No donors" in rv.data

    def test_clear_filter_shows_all(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        _add_donor(client, name="Alpha")
        _add_donor(client, name="Beta")
        rv = client.get("/donors")
        assert b"Alpha" in rv.data
        assert b"Beta" in rv.data


# ---------------------------------------------------------------------------
# 5. Blood inventory management
# ---------------------------------------------------------------------------

class TestInventory:
    def test_inventory_page_loads(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        rv = client.get("/inventory")
        assert rv.status_code == 200
        assert b"Blood Inventory" in rv.data

    def test_inventory_shows_all_blood_groups(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        rv = client.get("/inventory")
        for bg in [b"A+", b"A-", b"B+", b"B-", b"AB+", b"AB-", b"O+", b"O-"]:
            assert bg in rv.data

    def test_staff_can_update_inventory(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        rv = client.post("/inventory/update", data={
            "blood_group": "B+", "units": "15",
        }, follow_redirects=True)
        assert b"updated" in rv.data.lower()
        from database import get_db
        db = get_db()
        row = db.execute(
            "SELECT units FROM blood_inventory WHERE blood_group='B+'"
        ).fetchone()
        db.close()
        assert row["units"] == 15

    def test_doctor_cannot_update_inventory(self, app, client):
        _seed(app, "doc1", role="doctor")
        _login(client, {"username": "doc1", "password": "Password1!"})
        rv = client.post("/inventory/update", data={
            "blood_group": "A+", "units": "99",
        }, follow_redirects=True)
        assert b"permission" in rv.data.lower()

    def test_negative_units_rejected(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        rv = client.post("/inventory/update", data={
            "blood_group": "A+", "units": "-5",
        }, follow_redirects=True)
        assert b"negative" in rv.data.lower()

    def test_invalid_blood_group_rejected(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        rv = client.post("/inventory/update", data={
            "blood_group": "Z+", "units": "10",
        }, follow_redirects=True)
        assert b"Invalid" in rv.data

    def test_non_numeric_units_rejected(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        rv = client.post("/inventory/update", data={
            "blood_group": "A+", "units": "abc",
        }, follow_redirects=True)
        assert b"whole number" in rv.data

    def test_inventory_update_logs_audit_event(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        client.post("/inventory/update", data={
            "blood_group": "O+", "units": "7",
        }, follow_redirects=True)
        from database import get_db
        db = get_db()
        event = db.execute(
            "SELECT * FROM audit_events WHERE event_type='INVENTORY_UPDATE'"
            " ORDER BY id DESC LIMIT 1"
        ).fetchone()
        db.close()
        assert event is not None

    def test_unauthenticated_redirected_from_inventory(self, client):
        rv = client.get("/inventory", follow_redirects=True)
        assert b"log in" in rv.data.lower()

    def test_inventory_update_requires_login(self, client):
        rv = client.post("/inventory/update", data={
            "blood_group": "A+", "units": "5",
        }, follow_redirects=True)
        assert b"log in" in rv.data.lower()


# ---------------------------------------------------------------------------
# 6. Dashboard alert count
# ---------------------------------------------------------------------------

class TestDashboardAlertCount:
    def test_dashboard_shows_alert_count_for_admin(self, app, client):
        _seed(app, "adm1", role="admin")
        _login(client, {"username": "adm1", "password": "Password1!"})
        from database import get_db
        db = get_db()
        db.execute(
            "INSERT INTO network_alerts (rule_id, severity, src_ip, reason, status, source_file)"
            " VALUES ('RULE_SYN_SCAN','high','1.2.3.4','test','new','f.pcap')"
        )
        db.commit()
        db.close()
        rv = client.get("/dashboard")
        assert b"Unreviewed Alerts" in rv.data

    def test_dashboard_alert_count_is_real(self, app, client):
        _seed(app, "adm1", role="admin")
        _login(client, {"username": "adm1", "password": "Password1!"})
        from database import get_db
        db = get_db()
        for i in range(3):
            db.execute(
                "INSERT INTO network_alerts (rule_id, severity, src_ip, reason, status, source_file)"
                " VALUES ('RULE_SYN_SCAN','high','1.2.3.4','test','new','f.pcap')"
            )
        db.commit()
        db.close()
        rv = client.get("/dashboard")
        assert b"3" in rv.data

    def test_dashboard_no_alert_section_for_staff(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        rv = client.get("/dashboard")
        assert b"Unreviewed Alerts" not in rv.data


# ---------------------------------------------------------------------------
# 7. PCAP upload route access control
# ---------------------------------------------------------------------------

class TestPcapUploadAccess:
    def test_unauthenticated_redirected(self, client):
        rv = client.get("/monitor/upload", follow_redirects=True)
        assert b"log in" in rv.data.lower()

    def test_staff_cannot_access_upload(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        rv = client.get("/monitor/upload", follow_redirects=True)
        assert b"permission" in rv.data.lower()

    def test_doctor_cannot_access_upload(self, app, client):
        _seed(app, "doc1", role="doctor")
        _login(client, {"username": "doc1", "password": "Password1!"})
        rv = client.get("/monitor/upload", follow_redirects=True)
        assert b"permission" in rv.data.lower()

    def test_admin_can_access_upload_page(self, app, client):
        _seed(app, "adm1", role="admin")
        _login(client, {"username": "adm1", "password": "Password1!"})
        rv = client.get("/monitor/upload")
        assert rv.status_code == 200
        assert b"Upload" in rv.data

    def test_upload_page_shows_offline_disclaimer(self, app, client):
        _seed(app, "adm1", role="admin")
        _login(client, {"username": "adm1", "password": "Password1!"})
        rv = client.get("/monitor/upload")
        assert b"Offline" in rv.data or b"offline" in rv.data

    def test_upload_no_file_flashes_warning(self, app, client):
        _seed(app, "adm1", role="admin")
        _login(client, {"username": "adm1", "password": "Password1!"})
        rv = client.post("/monitor/upload", data={}, follow_redirects=True)
        assert b"No file" in rv.data

    def test_upload_wrong_extension_rejected(self, app, client):
        _seed(app, "adm1", role="admin")
        _login(client, {"username": "adm1", "password": "Password1!"})
        rv = client.post("/monitor/upload", data={
            "pcap_file": (io.BytesIO(b"data"), "capture.txt"),
        }, content_type="multipart/form-data", follow_redirects=True)
        assert b"Unsupported" in rv.data

    def test_upload_valid_pcap_runs_analysis(self, app, client):
        _seed(app, "adm1", role="admin")
        _login(client, {"username": "adm1", "password": "Password1!"})
        pcap_bytes = _make_minimal_pcap()
        rv = client.post("/monitor/upload", data={
            "pcap_file": (io.BytesIO(pcap_bytes), "test.pcap"),
        }, content_type="multipart/form-data", follow_redirects=True)
        assert rv.status_code == 200
        assert b"Analysis complete" in rv.data or b"Packets read" in rv.data

    def test_upload_with_save_persists_alerts(self, app, client):
        _seed(app, "adm1", role="admin")
        _login(client, {"username": "adm1", "password": "Password1!"})
        # Build a PCAP that triggers RULE_SYN_SCAN (15+ distinct ports)
        pcap_bytes = _make_syn_scan_pcap()
        rv = client.post("/monitor/upload", data={
            "pcap_file": (io.BytesIO(pcap_bytes), "scan.pcap"),
            "save_alerts": "1",
        }, content_type="multipart/form-data", follow_redirects=True)
        assert rv.status_code == 200
        from database import get_db
        db = get_db()
        count = db.execute("SELECT COUNT(*) FROM network_alerts").fetchone()[0]
        db.close()
        assert count >= 1

    def test_upload_save_logs_audit_event(self, app, client):
        _seed(app, "adm1", role="admin")
        _login(client, {"username": "adm1", "password": "Password1!"})
        pcap_bytes = _make_minimal_pcap()
        client.post("/monitor/upload", data={
            "pcap_file": (io.BytesIO(pcap_bytes), "audit.pcap"),
            "save_alerts": "1",
        }, content_type="multipart/form-data", follow_redirects=True)
        from database import get_db
        db = get_db()
        event = db.execute(
            "SELECT * FROM audit_events WHERE event_type='PCAP_UPLOAD'"
            " ORDER BY id DESC LIMIT 1"
        ).fetchone()
        db.close()
        assert event is not None


# ---------------------------------------------------------------------------
# 8. Navigation links
# ---------------------------------------------------------------------------

class TestNavigation:
    def test_inventory_link_in_nav_for_staff(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        rv = client.get("/dashboard")
        assert b"inventory" in rv.data.lower()

    def test_network_dropdown_in_nav_for_admin(self, app, client):
        _seed(app, "adm1", role="admin")
        _login(client, {"username": "adm1", "password": "Password1!"})
        rv = client.get("/dashboard")
        assert b"monitor" in rv.data.lower()
        assert b"upload" in rv.data.lower()

    def test_network_nav_not_shown_for_staff(self, app, client):
        _seed(app, "s1")
        _login(client, {"username": "s1", "password": "Password1!"})
        rv = client.get("/dashboard")
        assert b"monitor_upload" not in rv.data


# ---------------------------------------------------------------------------
# PCAP builder helpers
# ---------------------------------------------------------------------------

import io


def _make_minimal_pcap() -> bytes:
    """One-packet PCAP — enough to test parsing without triggering alerts."""
    buf = io.BytesIO()
    # Global header
    buf.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    # One Ethernet/IP/TCP SYN frame
    frame = _eth_ip_tcp("1.2.3.4", "5.6.7.8", 80, 0x02)
    buf.write(struct.pack("<IIII", 0, 0, len(frame), len(frame)))
    buf.write(frame)
    return buf.getvalue()


def _make_syn_scan_pcap() -> bytes:
    """PCAP with SYN packets to 20 distinct ports — triggers RULE_SYN_SCAN."""
    import socket
    buf = io.BytesIO()
    buf.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for port in range(1, 21):
        frame = _eth_ip_tcp("10.0.0.1", "192.168.1.1", port, 0x02)
        ts = port  # spread over 20 seconds — within 60s window
        buf.write(struct.pack("<IIII", ts, 0, len(frame), len(frame)))
        buf.write(frame)
    return buf.getvalue()


def _eth_ip_tcp(src_ip: str, dst_ip: str, dport: int, flags: int) -> bytes:
    import socket
    eth = b"\xff\xff\xff\xff\xff\xff" + b"\x00" * 6 + b"\x08\x00"
    tcp = struct.pack("!HHIIBBHHH",
                      12345, dport, 0, 0, (5 << 4), flags, 1024, 0, 0)
    total = 20 + len(tcp)
    ip = struct.pack("!BBHHHBBH4s4s",
                     0x45, 0, total, 0, 0, 64, 6, 0,
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    return eth + ip + tcp
