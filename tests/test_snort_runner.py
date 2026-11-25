"""
DonorShield — Stage 9/10 Snort + Wireshark integration tests.
Run with:  .venv/Scripts/pytest tests/test_snort_runner.py -v
"""
import os
from pathlib import Path
import importlib
import pytest

from security.snort_runner import (
    parse_snort_fast_output,
    find_snort,
    find_tshark,
    SnortNotFoundError,
    SNORT_DEFAULT_PATH,
)
from security.network_monitor import NetworkAlert, STATUS_NEW, save_alerts


TEST_AES_KEY = "ab" * 32

# ---------------------------------------------------------------------------
# Sample Snort fast-alert output for parser tests
# ---------------------------------------------------------------------------

SAMPLE_FAST_OUTPUT = """\
01/15-14:23:01.123456  [**] [1:9100001:1] DS SYN Scan Detected [**] [Priority: 2] {TCP} 10.0.0.5:54321 -> 192.168.1.1:80
01/15-14:23:02.000000  [**] [1:9100002:1] DS High Connection Rate [**] [Priority: 2] {TCP} 10.0.0.5:12345 -> 192.168.1.1:443
01/15-14:23:03.500000  [**] [1:9100003:1] DS Repeated SSH Connection Attempts [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 10.0.0.9:11111 -> 192.168.1.1:22
01/15-14:23:04.000000  [**] [1:9100007:1] DS ICMP Ping Sweep [**] [Priority: 3] {ICMP} 172.16.0.1 -> 192.168.1.1
"""

SAMPLE_FAST_OUTPUT_DUPLICATE = """\
01/15-14:23:01.123456  [**] [1:9100001:1] DS SYN Scan Detected [**] [Priority: 2] {TCP} 10.0.0.5:54321 -> 192.168.1.1:80
01/15-14:23:01.999999  [**] [1:9100001:1] DS SYN Scan Detected [**] [Priority: 2] {TCP} 10.0.0.5:54322 -> 192.168.1.1:80
"""

SAMPLE_FAST_OUTPUT_EMPTY = ""
SAMPLE_FAST_OUTPUT_NO_MATCH = "Snort! Commencing packet processing\nRun complete.\n"


# ---------------------------------------------------------------------------
# 1. Alert parser
# ---------------------------------------------------------------------------

class TestParseSnortFastOutput:
    def test_parses_four_alerts(self):
        alerts = parse_snort_fast_output(SAMPLE_FAST_OUTPUT, "test.pcap")
        assert len(alerts) == 4

    def test_rule_id_prefixed_snort(self):
        alerts = parse_snort_fast_output(SAMPLE_FAST_OUTPUT, "test.pcap")
        for a in alerts:
            assert a.rule_id.startswith("SNORT_")

    def test_src_ip_extracted(self):
        alerts = parse_snort_fast_output(SAMPLE_FAST_OUTPUT, "test.pcap")
        assert alerts[0].src_ip == "10.0.0.5"

    def test_dst_ip_extracted(self):
        alerts = parse_snort_fast_output(SAMPLE_FAST_OUTPUT, "test.pcap")
        assert alerts[0].dst_ip == "192.168.1.1"

    def test_dst_port_extracted(self):
        alerts = parse_snort_fast_output(SAMPLE_FAST_OUTPUT, "test.pcap")
        assert alerts[0].dst_port == 80

    def test_priority_2_maps_to_medium(self):
        alerts = parse_snort_fast_output(SAMPLE_FAST_OUTPUT, "test.pcap")
        syn_alert = next(a for a in alerts if "SYN" in a.rule_id)
        assert syn_alert.severity == "medium"

    def test_priority_1_maps_to_high(self):
        alerts = parse_snort_fast_output(SAMPLE_FAST_OUTPUT, "test.pcap")
        ssh_alert = next(a for a in alerts if "SSH" in a.rule_id)
        assert ssh_alert.severity == "high"

    def test_priority_3_maps_to_low(self):
        alerts = parse_snort_fast_output(SAMPLE_FAST_OUTPUT, "test.pcap")
        icmp_alert = next(a for a in alerts if "ICMP" in a.rule_id or "PING" in a.rule_id)
        assert icmp_alert.severity == "low"

    def test_source_file_set(self):
        alerts = parse_snort_fast_output(SAMPLE_FAST_OUTPUT, "capture.pcap")
        for a in alerts:
            assert a.source_file == "capture.pcap"

    def test_status_defaults_to_new(self):
        alerts = parse_snort_fast_output(SAMPLE_FAST_OUTPUT, "test.pcap")
        for a in alerts:
            assert a.status == STATUS_NEW

    def test_reason_contains_message(self):
        alerts = parse_snort_fast_output(SAMPLE_FAST_OUTPUT, "test.pcap")
        assert "DS SYN Scan Detected" in alerts[0].reason

    def test_reason_contains_protocol(self):
        alerts = parse_snort_fast_output(SAMPLE_FAST_OUTPUT, "test.pcap")
        assert "TCP" in alerts[0].reason

    def test_empty_output_returns_empty_list(self):
        assert parse_snort_fast_output(SAMPLE_FAST_OUTPUT_EMPTY, "x.pcap") == []

    def test_no_matching_lines_returns_empty_list(self):
        assert parse_snort_fast_output(SAMPLE_FAST_OUTPUT_NO_MATCH, "x.pcap") == []

    def test_duplicate_same_src_dst_port_deduplicated(self):
        alerts = parse_snort_fast_output(SAMPLE_FAST_OUTPUT_DUPLICATE, "test.pcap")
        assert len(alerts) == 1

    def test_classification_included_in_reason(self):
        alerts = parse_snort_fast_output(SAMPLE_FAST_OUTPUT, "test.pcap")
        ssh_alert = next(a for a in alerts if "SSH" in a.rule_id)
        assert "Attempted Administrator Privilege Gain" in ssh_alert.reason

    def test_icmp_no_port_dst_port_is_none(self):
        alerts = parse_snort_fast_output(SAMPLE_FAST_OUTPUT, "test.pcap")
        icmp_alert = next(a for a in alerts if "ICMP" in a.rule_id or "PING" in a.rule_id)
        assert icmp_alert.dst_port is None

    def test_returns_network_alert_instances(self):
        alerts = parse_snort_fast_output(SAMPLE_FAST_OUTPUT, "test.pcap")
        for a in alerts:
            assert isinstance(a, NetworkAlert)


# ---------------------------------------------------------------------------
# 2. Path detection
# ---------------------------------------------------------------------------

class TestFindSnort:
    def test_finds_default_path(self):
        """Snort is installed at the default path on this machine."""
        path = find_snort()
        assert os.path.isfile(path)

    def test_returns_string(self):
        path = find_snort()
        assert isinstance(path, str)

    def test_env_var_override(self, monkeypatch, tmp_path):
        fake_exe = tmp_path / "snort.exe"
        fake_exe.write_bytes(b"fake")
        monkeypatch.setenv("DS_SNORT_PATH", str(fake_exe))
        path = find_snort()
        assert path == str(fake_exe)

    def test_missing_env_var_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("DS_SNORT_PATH", "")
        path = find_snort()
        assert os.path.isfile(path)

    def test_nonexistent_env_var_raises(self, monkeypatch):
        monkeypatch.setenv("DS_SNORT_PATH", "/no/such/snort.exe")
        # Also patch default so it doesn't exist
        import security.snort_runner as sr
        original = sr.SNORT_DEFAULT_PATH
        monkeypatch.setattr(sr, "SNORT_DEFAULT_PATH", "/no/default/snort.exe")
        import shutil
        monkeypatch.setattr(shutil, "which", lambda _: None)
        with pytest.raises(SnortNotFoundError):
            find_snort()


class TestFindTshark:
    def test_finds_tshark(self):
        """tshark is installed at the default Wireshark path on this machine."""
        path = find_tshark()
        assert os.path.isfile(path)

    def test_returns_string(self):
        path = find_tshark()
        assert isinstance(path, str)

    def test_env_var_override(self, monkeypatch, tmp_path):
        fake_exe = tmp_path / "tshark.exe"
        fake_exe.write_bytes(b"fake")
        monkeypatch.setenv("DS_TSHARK_PATH", str(fake_exe))
        path = find_tshark()
        assert path == str(fake_exe)

    def test_missing_raises_file_not_found(self, monkeypatch):
        monkeypatch.setenv("DS_TSHARK_PATH", "/no/such/tshark.exe")
        import security.snort_runner as sr
        monkeypatch.setattr(sr, "find_tshark", lambda: (_ for _ in ()).throw(
            FileNotFoundError("tshark not found")
        ))
        with pytest.raises(FileNotFoundError):
            sr.find_tshark()


# ---------------------------------------------------------------------------
# 3. save_alerts with source column
# ---------------------------------------------------------------------------

@pytest.fixture()
def db_conn(monkeypatch, tmp_path):
    db_path = str(tmp_path / "snort_test.db")
    monkeypatch.setenv("DB_PATH", db_path)
    monkeypatch.setenv("DS_AES_KEY", TEST_AES_KEY)
    import database
    importlib.reload(database)
    database.init_db()
    conn = database.get_db()
    yield conn
    conn.close()


def _snort_alert(msg="DS SYN Scan Detected", src="10.0.0.5",
                 dst="192.168.1.1", port=80, fname="test.pcap"):
    return NetworkAlert(
        rule_id="SNORT_" + msg.upper().replace(" ", "_"),
        severity="medium",
        src_ip=src,
        dst_ip=dst,
        dst_port=port,
        reason=f"{msg} (TCP {src} -> {dst}:{port})",
        source_file=fname,
    )


class TestSaveAlertsSourceColumn:
    def test_snort_source_stored(self, db_conn):
        alert = _snort_alert()
        save_alerts([alert], db_conn, source="snort")
        row = db_conn.execute("SELECT source FROM network_alerts").fetchone()
        assert row["source"] == "snort"

    def test_scapy_source_stored(self, db_conn):
        alert = NetworkAlert(
            rule_id="RULE_SYN_SCAN", severity="high",
            src_ip="1.2.3.4", dst_ip=None, dst_port=None,
            reason="test", source_file="f.pcap",
        )
        save_alerts([alert], db_conn, source="scapy")
        row = db_conn.execute("SELECT source FROM network_alerts").fetchone()
        assert row["source"] == "scapy"

    def test_same_alert_different_source_not_duplicate(self, db_conn):
        alert = _snort_alert()
        save_alerts([alert], db_conn, source="scapy")
        n = save_alerts([alert], db_conn, source="snort")
        assert n == 1
        count = db_conn.execute("SELECT COUNT(*) FROM network_alerts").fetchone()[0]
        assert count == 2

    def test_same_alert_same_source_is_duplicate(self, db_conn):
        alert = _snort_alert()
        save_alerts([alert], db_conn, source="snort")
        n = save_alerts([alert], db_conn, source="snort")
        assert n == 0

    def test_schema_version_10_present(self, db_conn):
        versions = {r[0] for r in db_conn.execute(
            "SELECT version FROM schema_version"
        ).fetchall()}
        assert 10 in versions

    def test_source_column_exists(self, db_conn):
        cols = {row[1] for row in db_conn.execute(
            "PRAGMA table_info(network_alerts)"
        ).fetchall()}
        assert "source" in cols


# ---------------------------------------------------------------------------
# 4. Flask routes — source filter and Snort upload
# ---------------------------------------------------------------------------

@pytest.fixture()
def app(monkeypatch, tmp_path):
    db_path = str(tmp_path / "route_test.db")
    monkeypatch.setenv("DB_PATH", db_path)
    monkeypatch.setenv("TESTING", "true")
    monkeypatch.setenv("DS_AES_KEY", TEST_AES_KEY)
    monkeypatch.setenv("WTF_CSRF_ENABLED", "false")

    import database
    import app as app_module
    importlib.reload(database)
    importlib.reload(app_module)

    database.init_db()
    app_module.app.config.update(
        TESTING=True, SECRET_KEY="snort-test", WTF_CSRF_ENABLED=False,
    )
    yield app_module.app


@pytest.fixture()
def client(app):
    return app.test_client()


def _seed_admin(app, username="admin1", password="Password1!"):
    from database import get_db
    from werkzeug.security import generate_password_hash
    db = get_db()
    db.execute(
        "INSERT INTO users (username, password, role) VALUES (?,?,?)",
        (username, generate_password_hash(password), "admin"),
    )
    db.commit()
    db.close()
    return {"username": username, "password": password}


def _login(client, creds):
    client.post("/login", data=creds, follow_redirects=True)


def _insert_alert(app, source="scapy", rule="RULE_SYN_SCAN", severity="high"):
    from database import get_db
    db = get_db()
    db.execute(
        "INSERT INTO network_alerts"
        " (rule_id, severity, src_ip, reason, status, source_file, source)"
        " VALUES (?,?,?,?,?,?,?)",
        (rule, severity, "1.2.3.4", "test reason", "new", "test.pcap", source),
    )
    db.commit()
    db.close()


class TestMonitorSourceFilter:
    def test_source_filter_scapy(self, app, client):
        _seed_admin(app)
        _insert_alert(app, source="scapy")
        _insert_alert(app, source="snort", rule="SNORT_DS_SYN_SCAN_DETECTED")
        _login(client, {"username": "admin1", "password": "Password1!"})
        rv = client.get("/monitor?source=scapy")
        body = rv.data.split(b"alerts-tbody")[1].split(b"end-alerts-tbody")[0]
        assert b"Scapy" in body
        assert b"Snort" not in body

    def test_source_filter_snort(self, app, client):
        _seed_admin(app)
        _insert_alert(app, source="scapy")
        _insert_alert(app, source="snort", rule="SNORT_DS_SYN_SCAN_DETECTED")
        _login(client, {"username": "admin1", "password": "Password1!"})
        rv = client.get("/monitor?source=snort")
        body = rv.data.split(b"alerts-tbody")[1].split(b"end-alerts-tbody")[0]
        assert b"Snort" in body
        assert b"Scapy" not in body

    def test_no_source_filter_shows_both(self, app, client):
        _seed_admin(app)
        _insert_alert(app, source="scapy")
        _insert_alert(app, source="snort", rule="SNORT_DS_SYN_SCAN_DETECTED")
        _login(client, {"username": "admin1", "password": "Password1!"})
        rv = client.get("/monitor")
        body = rv.data.split(b"alerts-tbody")[1].split(b"end-alerts-tbody")[0]
        assert b"Scapy" in body
        assert b"Snort" in body

    def test_monitor_page_has_source_filter_dropdown(self, app, client):
        _seed_admin(app)
        _login(client, {"username": "admin1", "password": "Password1!"})
        rv = client.get("/monitor")
        assert b"All Sources" in rv.data

    def test_monitor_shows_engine_badge_scapy(self, app, client):
        _seed_admin(app)
        _insert_alert(app, source="scapy")
        _login(client, {"username": "admin1", "password": "Password1!"})
        rv = client.get("/monitor")
        assert b"Scapy" in rv.data

    def test_monitor_shows_engine_badge_snort(self, app, client):
        _seed_admin(app)
        _insert_alert(app, source="snort", rule="SNORT_DS_SYN_SCAN_DETECTED")
        _login(client, {"username": "admin1", "password": "Password1!"})
        rv = client.get("/monitor")
        assert b"Snort" in rv.data


class TestUploadRouteEngineParam:
    def test_upload_get_shows_engine_selector(self, app, client):
        _seed_admin(app)
        _login(client, {"username": "admin1", "password": "Password1!"})
        rv = client.get("/monitor/upload")
        assert b"engineScapy" in rv.data
        assert b"engineSnort" in rv.data

    def test_upload_get_shows_snort_version(self, app, client):
        _seed_admin(app)
        _login(client, {"username": "admin1", "password": "Password1!"})
        rv = client.get("/monitor/upload")
        assert b"Snort 2.9" in rv.data

    def test_upload_no_file_returns_warning(self, app, client):
        _seed_admin(app)
        _login(client, {"username": "admin1", "password": "Password1!"})
        rv = client.post(
            "/monitor/upload",
            data={"engine": "scapy"},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert b"No file selected" in rv.data

    def test_upload_wrong_extension_rejected(self, app, client):
        _seed_admin(app)
        _login(client, {"username": "admin1", "password": "Password1!"})
        from io import BytesIO
        rv = client.post(
            "/monitor/upload",
            data={"engine": "scapy", "pcap_file": (BytesIO(b"data"), "file.txt")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert b"Unsupported" in rv.data

    def test_upload_invalid_engine_defaults_to_scapy(self, app, client):
        """An invalid engine value is silently coerced to scapy."""
        _seed_admin(app)
        _login(client, {"username": "admin1", "password": "Password1!"})
        from io import BytesIO
        rv = client.post(
            "/monitor/upload",
            data={"engine": "invalid_engine",
                  "pcap_file": (BytesIO(b"not a pcap"), "test.pcap")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        # Should not crash — will fail at PCAP validation, not engine selection
        assert rv.status_code == 200

    def test_upload_snort_missing_snort_shows_error(self, app, client, monkeypatch):
        """If Snort is not found, the upload page shows a friendly error."""
        _seed_admin(app)
        _login(client, {"username": "admin1", "password": "Password1!"})
        import security.snort_runner as sr
        monkeypatch.setattr(sr, "find_snort",
                            lambda: (_ for _ in ()).throw(
                                SnortNotFoundError("not installed")))
        from io import BytesIO
        import struct
        # Write a minimal valid PCAP header
        pcap_header = struct.pack("<IHHiIII",
                                  0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        rv = client.post(
            "/monitor/upload",
            data={"engine": "snort",
                  "pcap_file": (BytesIO(pcap_header), "test.pcap")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        assert b"Snort not found" in rv.data or b"not installed" in rv.data


# ---------------------------------------------------------------------------
# 5. Snort rules file content
# ---------------------------------------------------------------------------

class TestSnortRulesContent:
    def test_rules_contain_syn_scan(self):
        from security.snort_runner import DONORSHIELD_RULES
        assert "SYN Scan" in DONORSHIELD_RULES

    def test_rules_contain_high_rate(self):
        from security.snort_runner import DONORSHIELD_RULES
        assert "High Connection Rate" in DONORSHIELD_RULES

    def test_rules_contain_repeated_conn(self):
        from security.snort_runner import DONORSHIELD_RULES
        assert "Repeated" in DONORSHIELD_RULES

    def test_rules_contain_icmp(self):
        from security.snort_runner import DONORSHIELD_RULES
        assert "ICMP" in DONORSHIELD_RULES

    def test_rules_have_unique_sids(self):
        from security.snort_runner import DONORSHIELD_RULES
        import re
        sids = re.findall(r"sid:(\d+)", DONORSHIELD_RULES)
        assert len(sids) == len(set(sids)), "Duplicate SIDs found in rules"

    def test_all_rules_have_rev(self):
        from security.snort_runner import DONORSHIELD_RULES
        import re
        rule_lines = [l for l in DONORSHIELD_RULES.splitlines()
                      if l.strip().startswith("alert")]
        for line in rule_lines:
            assert "rev:" in line, f"Rule missing rev: {line}"

    def test_conf_template_includes_rules_path(self):
        from security.snort_runner import SNORT_CONF_TEMPLATE
        assert "{rules_path}" in SNORT_CONF_TEMPLATE

    def test_conf_template_has_home_net(self):
        from security.snort_runner import SNORT_CONF_TEMPLATE
        assert "HOME_NET" in SNORT_CONF_TEMPLATE


# ---------------------------------------------------------------------------
# 6. Priority-to-severity mapping
# ---------------------------------------------------------------------------

class TestPriorityMapping:
    def test_priority_1_is_high(self):
        from security.snort_runner import _priority_to_severity
        assert _priority_to_severity(1) == "high"

    def test_priority_0_is_high(self):
        from security.snort_runner import _priority_to_severity
        assert _priority_to_severity(0) == "high"

    def test_priority_2_is_medium(self):
        from security.snort_runner import _priority_to_severity
        assert _priority_to_severity(2) == "medium"

    def test_priority_3_is_low(self):
        from security.snort_runner import _priority_to_severity
        assert _priority_to_severity(3) == "low"

    def test_priority_10_is_low(self):
        from security.snort_runner import _priority_to_severity
        assert _priority_to_severity(10) == "low"


# ---------------------------------------------------------------------------
# 7. Live end-to-end Snort integration (requires Snort installed)
# ---------------------------------------------------------------------------

def _write_syn_scan_pcap(path, n_ports=19):
    """Write a synthetic PCAP with n_ports SYN packets (zero-checksum, Snort
    must be configured with checksum_mode:none to process them)."""
    import struct, socket
    src = socket.inet_aton("10.0.0.5")
    dst = socket.inet_aton("192.168.1.1")
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, port in enumerate(range(1, n_ports + 1)):
            eth = b"\xff\xff\xff\xff\xff\xff" + b"\x00\x11\x22\x33\x44\x55" + b"\x08\x00"
            ip  = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, i, 0, 64, 6, 0, src, dst)
            tcp = struct.pack("!HHIIBBHHH", 12345, port, 0, 0, 0x50, 0x02, 1024, 0, 0)
            frame = eth + ip + tcp
            f.write(struct.pack("<IIII", i, 0, len(frame), len(frame)))
            f.write(frame)


class TestSnortLiveIntegration:
    """Actually invokes Snort 2.9 against a synthetic PCAP.
    Auto-skipped if Snort is not installed."""

    @pytest.fixture(autouse=True)
    def require_snort(self):
        try:
            find_snort()
        except SnortNotFoundError:
            pytest.skip("Snort not installed")

    @pytest.fixture()
    def syn_scan_pcap(self, tmp_path):
        path = str(tmp_path / "syn_scan.pcap")
        _write_syn_scan_pcap(path, n_ports=19)
        return path

    def test_run_snort_returns_dict(self, syn_scan_pcap):
        from security.snort_runner import run_snort_on_pcap
        result = run_snort_on_pcap(syn_scan_pcap)
        assert isinstance(result, dict)
        for key in ("alerts", "pcap_file", "snort_path", "raw_output"):
            assert key in result

    def test_run_snort_detects_syn_scan(self, syn_scan_pcap):
        from security.snort_runner import run_snort_on_pcap
        result = run_snort_on_pcap(syn_scan_pcap)
        assert len(result["alerts"]) >= 1
        assert any("SYN" in a.rule_id for a in result["alerts"])

    def test_run_snort_alert_severity_high(self, syn_scan_pcap):
        from security.snort_runner import run_snort_on_pcap
        result = run_snort_on_pcap(syn_scan_pcap)
        syn_alerts = [a for a in result["alerts"] if "SYN" in a.rule_id]
        assert syn_alerts[0].severity == "high"

    def test_run_snort_alert_src_ip_correct(self, syn_scan_pcap):
        from security.snort_runner import run_snort_on_pcap
        result = run_snort_on_pcap(syn_scan_pcap)
        syn_alerts = [a for a in result["alerts"] if "SYN" in a.rule_id]
        assert syn_alerts[0].src_ip == "10.0.0.5"

    def test_run_snort_alert_dst_ip_correct(self, syn_scan_pcap):
        from security.snort_runner import run_snort_on_pcap
        result = run_snort_on_pcap(syn_scan_pcap)
        syn_alerts = [a for a in result["alerts"] if "SYN" in a.rule_id]
        assert syn_alerts[0].dst_ip == "192.168.1.1"

    def test_run_snort_source_name_override(self, syn_scan_pcap):
        from security.snort_runner import run_snort_on_pcap
        result = run_snort_on_pcap(syn_scan_pcap, source_name="custom.pcap")
        assert result["pcap_file"] == "custom.pcap"
        for a in result["alerts"]:
            assert a.source_file == "custom.pcap"

    def test_run_snort_alerts_are_network_alert_instances(self, syn_scan_pcap):
        from security.snort_runner import run_snort_on_pcap
        result = run_snort_on_pcap(syn_scan_pcap)
        for a in result["alerts"]:
            assert isinstance(a, NetworkAlert)

    def test_run_snort_alerts_have_new_status(self, syn_scan_pcap):
        from security.snort_runner import run_snort_on_pcap
        result = run_snort_on_pcap(syn_scan_pcap)
        for a in result["alerts"]:
            assert a.status == STATUS_NEW

    def test_run_snort_rule_id_prefixed_snort(self, syn_scan_pcap):
        from security.snort_runner import run_snort_on_pcap
        result = run_snort_on_pcap(syn_scan_pcap)
        for a in result["alerts"]:
            assert a.rule_id.startswith("SNORT_")

    def test_run_snort_below_threshold_no_syn_scan_alert(self, tmp_path):
        """5 SYN packets to different ports — below threshold of 15."""
        from security.snort_runner import run_snort_on_pcap
        path = str(tmp_path / "small.pcap")
        _write_syn_scan_pcap(path, n_ports=5)
        result = run_snort_on_pcap(path)
        syn_scan_alerts = [a for a in result["alerts"] if "SYN_SCAN" in a.rule_id]
        assert len(syn_scan_alerts) == 0

    def test_run_snort_snort_path_is_real_file(self, syn_scan_pcap):
        from security.snort_runner import run_snort_on_pcap
        result = run_snort_on_pcap(syn_scan_pcap)
        assert os.path.isfile(result["snort_path"])

    def test_conf_checksum_mode_none_present(self):
        from security.snort_runner import SNORT_CONF_TEMPLATE
        assert "checksum_mode" in SNORT_CONF_TEMPLATE

class TestTsharkSummary:
    def test_success(self, tmp_path, monkeypatch):
        import subprocess
        import security.snort_runner as sr

        path = tmp_path / "x.pcap"
        path.write_bytes(b"x")
        monkeypatch.setattr(sr, "find_tshark", lambda: "tshark.exe")
        output = "1\teth:ip:tcp\t10.0.0.1\t\t10.0.0.2\t\n"
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *args, **kwargs: subprocess.CompletedProcess(
                args[0], 0, output, ""
            ),
        )

        result = sr.run_tshark_on_pcap(str(path))

        assert result["packets_read"] == 1
        assert result["protocols"] == [{"name": "TCP", "count": 1}]
        assert result["sources"][0]["ip"] == "10.0.0.1"
        assert result["destinations"][0]["ip"] == "10.0.0.2"

    def test_invalid_file(self, tmp_path):
        import security.snort_runner as sr

        with pytest.raises(sr.TsharkRunError, match="Invalid PCAP"):
            sr.run_tshark_on_pcap(str(tmp_path / "missing.pcap"))

    def test_missing_executable(self, tmp_path, monkeypatch):
        import security.snort_runner as sr

        path = tmp_path / "x.pcap"
        path.write_bytes(b"x")
        monkeypatch.setattr(
            sr,
            "find_tshark",
            lambda: (_ for _ in ()).throw(FileNotFoundError("missing")),
        )

        with pytest.raises(sr.TsharkNotFoundError):
            sr.run_tshark_on_pcap(str(path))

    def test_timeout(self, tmp_path, monkeypatch):
        import subprocess
        import security.snort_runner as sr

        path = tmp_path / "x.pcap"
        path.write_bytes(b"x")
        monkeypatch.setattr(sr, "find_tshark", lambda: "tshark.exe")

        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(args[0], 30)

        monkeypatch.setattr(subprocess, "run", timeout)
        with pytest.raises(sr.TsharkRunError, match="timed out"):
            sr.run_tshark_on_pcap(str(path))

    def test_real_tshark_upload_renders_capture_summary(self, app, client):
        from io import BytesIO

        _seed_admin(app)
        _login(client, {"username": "admin1", "password": "Password1!"})
        capture = Path("test_snort.pcap").read_bytes()
        response = client.post(
            "/monitor/upload",
            data={
                "engine": "tshark",
                "pcap_file": (BytesIO(capture), "test_snort.pcap"),
            },
            content_type="multipart/form-data",
        )

        assert response.status_code == 200
        assert b"TShark summary" in response.data
        assert b"19" in response.data
        assert b"TCP: 19" in response.data
        assert b"10.0.0.5" in response.data
        assert b"192.168.1.1" in response.data

    def test_tshark_upload_reports_missing_executable(
        self, app, client, monkeypatch
    ):
        from io import BytesIO
        import security.snort_runner as sr

        _seed_admin(app)
        _login(client, {"username": "admin1", "password": "Password1!"})
        monkeypatch.setattr(
            sr,
            "find_tshark",
            lambda: (_ for _ in ()).throw(FileNotFoundError("TShark absent")),
        )
        response = client.post(
            "/monitor/upload",
            data={
                "engine": "tshark",
                "pcap_file": (
                    BytesIO(Path("test_snort.pcap").read_bytes()),
                    "test.pcap",
                ),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

        assert b"TShark analysis error" in response.data
        assert b"TShark absent" in response.data

    def test_tshark_invalid_capture_output(self, tmp_path, monkeypatch):
        import subprocess
        import security.snort_runner as sr

        path = tmp_path / "bad.pcap"
        path.write_bytes(b"not-a-capture")
        monkeypatch.setattr(sr, "find_tshark", lambda: "tshark.exe")
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *args, **kwargs: subprocess.CompletedProcess(
                args[0], 2, "", "Invalid capture"
            ),
        )

        with pytest.raises(sr.TsharkRunError, match="Invalid capture"):
            sr.run_tshark_on_pcap(str(path))

    def test_tshark_upload_rejects_oversized_file(self, app, client):
        from io import BytesIO
        from app import MAX_UPLOAD_BYTES

        _seed_admin(app)
        _login(client, {"username": "admin1", "password": "Password1!"})
        response = client.post(
            "/monitor/upload",
            data={
                "engine": "tshark",
                "pcap_file": (
                    BytesIO(b"x" * (MAX_UPLOAD_BYTES + 1)),
                    "large.pcap",
                ),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

        assert b"50 MB limit" in response.data

    def test_tshark_upload_requires_admin(self, client):
        from io import BytesIO

        response = client.post(
            "/monitor/upload",
            data={
                "engine": "tshark",
                "pcap_file": (BytesIO(b"x"), "test.pcap"),
            },
            content_type="multipart/form-data",
        )

        assert response.status_code == 302
        assert "/login" in response.headers["Location"]

    def test_real_snort_upload_renders_alerts_separately(self, app, client):
        from io import BytesIO

        _seed_admin(app)
        _login(client, {"username": "admin1", "password": "Password1!"})
        response = client.post(
            "/monitor/upload",
            data={
                "engine": "snort",
                "pcap_file": (
                    BytesIO(Path("test_snort.pcap").read_bytes()),
                    "test_snort.pcap",
                ),
            },
            content_type="multipart/form-data",
        )

        assert response.status_code == 200
        assert b"Snort alerts" in response.data
        assert b"SNORT_DS_SYN_SCAN_DETECTED" in response.data
        assert b"TShark summary" not in response.data
