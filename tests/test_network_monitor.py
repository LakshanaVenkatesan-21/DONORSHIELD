"""
DonorShield - Stage 8 network monitoring tests (part 1: detection engine).
Run with:  .venv/Scripts/pytest tests/ -v
"""
import os
import tempfile
import struct
import pytest

from security.network_monitor import (
    DetectionEngine, NetworkAlert,
    RULE_SYN_SCAN, RULE_HIGH_RATE, RULE_REPEATED_CONN,
    SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW,
    STATUS_NEW, STATUS_REVIEWED,
    PcapValidationError, validate_pcap_path,
    save_alerts, MAX_PCAP_SIZE_BYTES,
)


# ---------------------------------------------------------------------------
# Packet builder helpers
# ---------------------------------------------------------------------------

def _pkt(src="1.2.3.4", dst="5.6.7.8", dport=80,
         proto="TCP", flags="S", ts=0.0):
    return {
        "src_ip": src, "dst_ip": dst, "dst_port": dport,
        "proto": proto, "flags": flags, "timestamp_float": ts,
    }


def _syn(src="1.2.3.4", dst="5.6.7.8", dport=80, ts=0.0):
    return _pkt(src=src, dst=dst, dport=dport, proto="TCP", flags="S", ts=ts)


def _udp(src="1.2.3.4", dst="5.6.7.8", dport=53, ts=0.0):
    return _pkt(src=src, dst=dst, dport=dport, proto="UDP", flags="", ts=ts)


# ---------------------------------------------------------------------------
# 1. SYN scan rule
# ---------------------------------------------------------------------------

class TestSynScanRule:
    def _engine(self, threshold=5, window=60):
        return DetectionEngine(syn_scan_port_threshold=threshold,
                               syn_scan_window=window)

    def test_below_threshold_no_alert(self):
        engine = self._engine(threshold=5)
        pkts = [_syn(dport=p, ts=float(p)) for p in range(1, 5)]
        alerts = engine.analyse(pkts)
        syn_alerts = [a for a in alerts if a.rule_id == RULE_SYN_SCAN]
        assert len(syn_alerts) == 0

    def test_at_threshold_triggers_alert(self):
        engine = self._engine(threshold=5)
        pkts = [_syn(dport=p, ts=float(p)) for p in range(1, 6)]
        alerts = engine.analyse(pkts)
        syn_alerts = [a for a in alerts if a.rule_id == RULE_SYN_SCAN]
        assert len(syn_alerts) == 1

    def test_above_threshold_still_one_alert_per_source(self):
        engine = self._engine(threshold=5)
        pkts = [_syn(dport=p, ts=float(p)) for p in range(1, 20)]
        alerts = engine.analyse(pkts)
        syn_alerts = [a for a in alerts if a.rule_id == RULE_SYN_SCAN]
        assert len(syn_alerts) == 1

    def test_alert_severity_is_high(self):
        engine = self._engine(threshold=3)
        pkts = [_syn(dport=p, ts=float(p)) for p in range(1, 5)]
        alerts = engine.analyse(pkts)
        syn_alerts = [a for a in alerts if a.rule_id == RULE_SYN_SCAN]
        assert syn_alerts[0].severity == SEVERITY_HIGH

    def test_alert_src_ip_correct(self):
        engine = self._engine(threshold=3)
        pkts = [_syn(src="10.0.0.1", dport=p, ts=float(p)) for p in range(1, 5)]
        alerts = engine.analyse(pkts)
        syn_alerts = [a for a in alerts if a.rule_id == RULE_SYN_SCAN]
        assert syn_alerts[0].src_ip == "10.0.0.1"

    def test_two_sources_each_get_own_alert(self):
        engine = self._engine(threshold=3)
        pkts  = [_syn(src="10.0.0.1", dport=p, ts=float(p)) for p in range(1, 5)]
        pkts += [_syn(src="10.0.0.2", dport=p, ts=float(p)) for p in range(1, 5)]
        alerts = engine.analyse(pkts)
        syn_alerts = [a for a in alerts if a.rule_id == RULE_SYN_SCAN]
        srcs = {a.src_ip for a in syn_alerts}
        assert srcs == {"10.0.0.1", "10.0.0.2"}

    def test_outside_time_window_no_alert(self):
        engine = self._engine(threshold=3, window=10)
        # Spread 4 SYNs over 60 seconds — outside 10s window
        pkts = [_syn(dport=p, ts=float(p * 20)) for p in range(1, 5)]
        alerts = engine.analyse(pkts)
        syn_alerts = [a for a in alerts if a.rule_id == RULE_SYN_SCAN]
        assert len(syn_alerts) == 0

    def test_non_syn_packets_ignored(self):
        engine = self._engine(threshold=3)
        # ACK packets to many ports — should not trigger SYN scan
        pkts = [_pkt(dport=p, flags="A", ts=float(p)) for p in range(1, 10)]
        alerts = engine.analyse(pkts)
        syn_alerts = [a for a in alerts if a.rule_id == RULE_SYN_SCAN]
        assert len(syn_alerts) == 0

    def test_udp_packets_ignored_by_syn_rule(self):
        engine = self._engine(threshold=3)
        pkts = [_udp(dport=p, ts=float(p)) for p in range(1, 10)]
        alerts = engine.analyse(pkts)
        syn_alerts = [a for a in alerts if a.rule_id == RULE_SYN_SCAN]
        assert len(syn_alerts) == 0

    def test_reason_contains_port_count(self):
        engine = self._engine(threshold=3)
        pkts = [_syn(dport=p, ts=float(p)) for p in range(1, 5)]
        alerts = engine.analyse(pkts)
        syn_alerts = [a for a in alerts if a.rule_id == RULE_SYN_SCAN]
        assert "port" in syn_alerts[0].reason.lower()


# ---------------------------------------------------------------------------
# 2. High-rate rule
# ---------------------------------------------------------------------------

class TestHighRateRule:
    def _engine(self, threshold=10, window=5):
        return DetectionEngine(high_rate_pkt_threshold=threshold,
                               high_rate_window=window)

    def test_below_threshold_no_alert(self):
        engine = self._engine(threshold=10)
        pkts = [_pkt(ts=float(i)) for i in range(9)]
        alerts = engine.analyse(pkts)
        hr = [a for a in alerts if a.rule_id == RULE_HIGH_RATE]
        assert len(hr) == 0

    def test_at_threshold_triggers_alert(self):
        engine = self._engine(threshold=10, window=60)
        pkts = [_pkt(ts=float(i)) for i in range(10)]
        alerts = engine.analyse(pkts)
        hr = [a for a in alerts if a.rule_id == RULE_HIGH_RATE]
        assert len(hr) == 1

    def test_alert_severity_is_medium(self):
        engine = self._engine(threshold=5, window=60)
        pkts = [_pkt(ts=float(i)) for i in range(6)]
        alerts = engine.analyse(pkts)
        hr = [a for a in alerts if a.rule_id == RULE_HIGH_RATE]
        assert hr[0].severity == SEVERITY_MEDIUM

    def test_one_alert_per_source(self):
        engine = self._engine(threshold=5, window=60)
        pkts = [_pkt(ts=float(i)) for i in range(20)]
        alerts = engine.analyse(pkts)
        hr = [a for a in alerts if a.rule_id == RULE_HIGH_RATE]
        assert len(hr) == 1

    def test_two_sources_independent(self):
        engine = self._engine(threshold=5, window=60)
        pkts  = [_pkt(src="1.1.1.1", ts=float(i)) for i in range(6)]
        pkts += [_pkt(src="2.2.2.2", ts=float(i)) for i in range(6)]
        alerts = engine.analyse(pkts)
        hr = [a for a in alerts if a.rule_id == RULE_HIGH_RATE]
        assert len(hr) == 2

    def test_spread_over_time_no_alert(self):
        engine = self._engine(threshold=5, window=5)
        # 10 packets but each 10 seconds apart — never 5 in 5s window
        pkts = [_pkt(ts=float(i * 10)) for i in range(10)]
        alerts = engine.analyse(pkts)
        hr = [a for a in alerts if a.rule_id == RULE_HIGH_RATE]
        assert len(hr) == 0


# ---------------------------------------------------------------------------
# 3. Repeated connection rule
# ---------------------------------------------------------------------------

class TestRepeatedConnRule:
    def _engine(self, threshold=5, window=60):
        return DetectionEngine(repeated_conn_threshold=threshold,
                               repeated_conn_window=window)

    def test_below_threshold_no_alert(self):
        engine = self._engine(threshold=5)
        pkts = [_syn(dport=80, ts=float(i)) for i in range(4)]
        alerts = engine.analyse(pkts)
        rc = [a for a in alerts if a.rule_id == RULE_REPEATED_CONN]
        assert len(rc) == 0

    def test_at_threshold_triggers_alert(self):
        engine = self._engine(threshold=5)
        pkts = [_syn(dport=80, ts=float(i)) for i in range(5)]
        alerts = engine.analyse(pkts)
        rc = [a for a in alerts if a.rule_id == RULE_REPEATED_CONN]
        assert len(rc) == 1

    def test_alert_severity_is_low(self):
        engine = self._engine(threshold=3)
        pkts = [_syn(dport=80, ts=float(i)) for i in range(4)]
        alerts = engine.analyse(pkts)
        rc = [a for a in alerts if a.rule_id == RULE_REPEATED_CONN]
        assert rc[0].severity == SEVERITY_LOW

    def test_dst_port_recorded(self):
        engine = self._engine(threshold=3)
        pkts = [_syn(dport=443, ts=float(i)) for i in range(4)]
        alerts = engine.analyse(pkts)
        rc = [a for a in alerts if a.rule_id == RULE_REPEATED_CONN]
        assert rc[0].dst_port == 443

    def test_different_ports_separate_alerts(self):
        engine = self._engine(threshold=3)
        pkts  = [_syn(dport=80,  ts=float(i)) for i in range(4)]
        pkts += [_syn(dport=443, ts=float(i)) for i in range(4)]
        alerts = engine.analyse(pkts)
        rc = [a for a in alerts if a.rule_id == RULE_REPEATED_CONN]
        ports = {a.dst_port for a in rc}
        assert ports == {80, 443}

    def test_outside_window_no_alert(self):
        engine = self._engine(threshold=3, window=10)
        pkts = [_syn(dport=80, ts=float(i * 20)) for i in range(4)]
        alerts = engine.analyse(pkts)
        rc = [a for a in alerts if a.rule_id == RULE_REPEATED_CONN]
        assert len(rc) == 0


# ---------------------------------------------------------------------------
# 4. Alert deduplication
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_same_source_same_rule_one_alert(self):
        engine = DetectionEngine(syn_scan_port_threshold=3)
        pkts = [_syn(dport=p, ts=float(p)) for p in range(1, 20)]
        alerts = engine.analyse(pkts)
        syn_alerts = [a for a in alerts if a.rule_id == RULE_SYN_SCAN]
        assert len(syn_alerts) == 1

    def test_multiple_rules_can_fire_independently(self):
        # Trigger both SYN scan and high rate from same source
        engine = DetectionEngine(
            syn_scan_port_threshold=3,
            high_rate_pkt_threshold=5,
            high_rate_window=60,
        )
        pkts = [_syn(dport=p, ts=float(p)) for p in range(1, 10)]
        alerts = engine.analyse(pkts)
        rules = {a.rule_id for a in alerts}
        assert RULE_SYN_SCAN in rules
        assert RULE_HIGH_RATE in rules

    def test_empty_packet_list_no_alerts(self):
        engine = DetectionEngine()
        assert engine.analyse([]) == []

    def test_alert_has_new_status_by_default(self):
        engine = DetectionEngine(syn_scan_port_threshold=3)
        pkts = [_syn(dport=p, ts=float(p)) for p in range(1, 5)]
        alerts = engine.analyse(pkts)
        for a in alerts:
            assert a.status == STATUS_NEW

    def test_alert_timestamp_is_set(self):
        engine = DetectionEngine(syn_scan_port_threshold=3)
        pkts = [_syn(dport=p, ts=float(p)) for p in range(1, 5)]
        alerts = engine.analyse(pkts)
        for a in alerts:
            assert a.timestamp != ""


# ---------------------------------------------------------------------------
# 5. PCAP validation
# ---------------------------------------------------------------------------

class TestPcapValidation:
    def test_nonexistent_file_raises(self):
        with pytest.raises(PcapValidationError, match="not found"):
            validate_pcap_path("/nonexistent/path/file.pcap")

    def test_wrong_extension_raises(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"data")
            path = f.name
        try:
            with pytest.raises(PcapValidationError, match="extension"):
                validate_pcap_path(path)
        finally:
            os.unlink(path)

    def test_empty_file_raises(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            path = f.name
        try:
            with pytest.raises(PcapValidationError, match="empty"):
                validate_pcap_path(path)
        finally:
            os.unlink(path)

    def test_empty_path_raises(self):
        with pytest.raises(PcapValidationError):
            validate_pcap_path("")

    def test_none_path_raises(self):
        with pytest.raises(PcapValidationError):
            validate_pcap_path(None)

    def test_valid_pcap_path_passes(self, tmp_path):
        p = tmp_path / "test.pcap"
        p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
        validate_pcap_path(str(p))  # should not raise

    def test_pcapng_extension_accepted(self, tmp_path):
        p = tmp_path / "test.pcapng"
        p.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 20)
        validate_pcap_path(str(p))

    def test_cap_extension_accepted(self, tmp_path):
        p = tmp_path / "test.cap"
        p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
        validate_pcap_path(str(p))

    def test_oversized_file_raises(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "security.network_monitor.MAX_PCAP_SIZE_BYTES", 10
        )
        p = tmp_path / "big.pcap"
        p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
        with pytest.raises(PcapValidationError, match="exceeds"):
            validate_pcap_path(str(p))


# ---------------------------------------------------------------------------
# 6. Persistence — save_alerts
# ---------------------------------------------------------------------------

TEST_AES_KEY = "ab" * 32


@pytest.fixture()
def db_conn(monkeypatch, tmp_path):
    """Isolated SQLite DB for persistence tests."""
    db_path = str(tmp_path / "test.db")
    monkeypatch.setenv("DB_PATH", db_path)
    monkeypatch.setenv("DS_AES_KEY", TEST_AES_KEY)
    import importlib
    import database
    importlib.reload(database)
    database.init_db()
    conn = database.get_db()
    yield conn
    conn.close()


class TestAlertPersistence:
    def _make_alert(self, rule=RULE_SYN_SCAN, src="1.2.3.4",
                    dst=None, port=None, fname="test.pcap"):
        return NetworkAlert(
            rule_id=rule, severity=SEVERITY_HIGH,
            src_ip=src, dst_ip=dst, dst_port=port,
            reason="test reason", source_file=fname,
        )

    def test_alert_inserted(self, db_conn):
        alert = self._make_alert()
        n = save_alerts([alert], db_conn)
        assert n == 1
        row = db_conn.execute("SELECT * FROM network_alerts").fetchone()
        assert row["rule_id"] == RULE_SYN_SCAN
        assert row["src_ip"] == "1.2.3.4"

    def test_duplicate_not_reinserted(self, db_conn):
        alert = self._make_alert()
        save_alerts([alert], db_conn)
        n2 = save_alerts([alert], db_conn)
        assert n2 == 0
        count = db_conn.execute(
            "SELECT COUNT(*) FROM network_alerts"
        ).fetchone()[0]
        assert count == 1

    def test_different_source_file_not_duplicate(self, db_conn):
        a1 = self._make_alert(fname="file1.pcap")
        a2 = self._make_alert(fname="file2.pcap")
        save_alerts([a1], db_conn)
        n = save_alerts([a2], db_conn)
        assert n == 1

    def test_status_defaults_to_new(self, db_conn):
        save_alerts([self._make_alert()], db_conn)
        row = db_conn.execute("SELECT status FROM network_alerts").fetchone()
        assert row["status"] == STATUS_NEW

    def test_severity_stored_correctly(self, db_conn):
        alert = NetworkAlert(
            rule_id=RULE_HIGH_RATE, severity=SEVERITY_MEDIUM,
            src_ip="1.1.1.1", dst_ip=None, dst_port=None,
            reason="rate test", source_file="x.pcap",
        )
        save_alerts([alert], db_conn)
        row = db_conn.execute("SELECT severity FROM network_alerts").fetchone()
        assert row["severity"] == SEVERITY_MEDIUM

    def test_multiple_alerts_all_inserted(self, db_conn):
        alerts = [
            self._make_alert(src="1.1.1.1", fname="f.pcap"),
            NetworkAlert(rule_id=RULE_HIGH_RATE, severity=SEVERITY_MEDIUM,
                         src_ip="2.2.2.2", dst_ip=None, dst_port=None,
                         reason="r", source_file="f.pcap"),
        ]
        n = save_alerts(alerts, db_conn)
        assert n == 2

    def test_schema_version_8_present(self, db_conn):
        versions = {r[0] for r in db_conn.execute(
            "SELECT version FROM schema_version"
        ).fetchall()}
        assert 8 in versions

    def test_network_alerts_table_exists(self, db_conn):
        tables = {r[0] for r in db_conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        assert "network_alerts" in tables


# ---------------------------------------------------------------------------
# 7. Synthetic PCAP creation helper
# ---------------------------------------------------------------------------

def _write_minimal_pcap(path: str, packets: list[dict]) -> None:
    """
    Write a minimal libpcap file (little-endian, link type ETHERNET=1)
    containing synthetic IP/TCP packets built from packet dicts.
    This avoids needing real captured traffic in tests.
    """
    import struct, socket

    PCAP_MAGIC    = 0xA1B2C3D4
    VERSION_MAJOR = 2
    VERSION_MINOR = 4
    THISZONE      = 0
    SIGFIGS       = 0
    SNAPLEN       = 65535
    NETWORK       = 1  # LINKTYPE_ETHERNET

    def ip_to_bytes(ip_str):
        try:
            return socket.inet_aton(ip_str)
        except Exception:
            return b"\x00\x00\x00\x00"

    def make_eth_ip_tcp(src_ip, dst_ip, dport, flags_int):
        eth = b"\xff\xff\xff\xff\xff\xff" + b"\x00" * 6 + b"\x08\x00"
        sport = 12345
        seq = ack = 0
        data_off = 5
        window = 1024
        checksum = 0
        urg = 0
        tcp = struct.pack(
            "!HHIIBBHHH",
            sport, dport, seq, ack,
            (data_off << 4), flags_int,
            window, checksum, urg,
        )
        total_len = 20 + len(tcp)
        ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, total_len, 0, 0, 64, 6, 0,
            ip_to_bytes(src_ip), ip_to_bytes(dst_ip),
        )
        return eth + ip + tcp

    with open(path, "wb") as f:
        # Global header
        f.write(struct.pack(
            "<IHHiIII",
            PCAP_MAGIC, VERSION_MAJOR, VERSION_MINOR,
            THISZONE, SIGFIGS, SNAPLEN, NETWORK,
        ))
        for pkt in packets:
            src   = pkt.get("src_ip", "1.2.3.4")
            dst   = pkt.get("dst_ip", "5.6.7.8")
            dport = pkt.get("dst_port", 80)
            flags = 0x02 if pkt.get("flags", "S") == "S" else 0x10
            ts    = pkt.get("timestamp_float", 0.0)
            ts_sec  = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)
            frame = make_eth_ip_tcp(src, dst, dport, flags)
            f.write(struct.pack("<IIII",
                                ts_sec, ts_usec, len(frame), len(frame)))
            f.write(frame)


# ---------------------------------------------------------------------------
# 8. PCAP parsing integration
# ---------------------------------------------------------------------------

class TestPcapParsing:
    def test_parse_synthetic_pcap(self, tmp_path):
        from security.network_monitor import parse_pcap
        path = str(tmp_path / "test.pcap")
        _write_minimal_pcap(path, [
            {"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8",
             "dst_port": 80, "flags": "S", "timestamp_float": 1.0},
        ])
        pkts = parse_pcap(path)
        assert len(pkts) == 1
        assert pkts[0]["src_ip"] == "1.2.3.4"
        assert pkts[0]["dst_ip"] == "5.6.7.8"
        assert pkts[0]["dst_port"] == 80
        assert pkts[0]["proto"] == "TCP"

    def test_syn_flag_detected(self, tmp_path):
        from security.network_monitor import parse_pcap
        path = str(tmp_path / "syn.pcap")
        _write_minimal_pcap(path, [
            {"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8",
             "dst_port": 80, "flags": "S", "timestamp_float": 0.0},
        ])
        pkts = parse_pcap(path)
        assert "S" in pkts[0]["flags"]

    def test_full_pipeline_syn_scan_detected(self, tmp_path):
        from security.network_monitor import analyse_pcap_file
        path = str(tmp_path / "scan.pcap")
        raw = [{"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1",
                "dst_port": p, "flags": "S", "timestamp_float": float(p)}
               for p in range(1, 20)]
        _write_minimal_pcap(path, raw)
        engine = DetectionEngine(syn_scan_port_threshold=5)
        from security.network_monitor import parse_pcap
        pkts = parse_pcap(path)
        alerts = engine.analyse(pkts)
        syn_alerts = [a for a in alerts if a.rule_id == RULE_SYN_SCAN]
        assert len(syn_alerts) >= 1

    def test_analyse_pcap_file_returns_summary(self, tmp_path):
        from security.network_monitor import analyse_pcap_file
        path = str(tmp_path / "empty_traffic.pcap")
        _write_minimal_pcap(path, [
            {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
             "dst_port": 80, "flags": "S", "timestamp_float": 0.0},
        ])
        result = analyse_pcap_file(path)
        assert "pcap_file" in result
        assert "packets_read" in result
        assert "alerts" in result
        assert result["packets_read"] == 1

    def test_analyse_pcap_file_sets_source_file(self, tmp_path):
        from security.network_monitor import analyse_pcap_file
        path = str(tmp_path / "named.pcap")
        raw = [{"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1",
                "dst_port": p, "flags": "S", "timestamp_float": float(p)}
               for p in range(1, 20)]
        _write_minimal_pcap(path, raw)
        result = analyse_pcap_file(path)
        for alert in result["alerts"]:
            assert alert.source_file == "named.pcap"

    def test_invalid_path_raises_validation_error(self):
        from security.network_monitor import analyse_pcap_file
        with pytest.raises(PcapValidationError):
            analyse_pcap_file("/no/such/file.pcap")


# ---------------------------------------------------------------------------
# 9. Flask route access control
# ---------------------------------------------------------------------------

@pytest.fixture()
def app(monkeypatch, tmp_path):
    db_path = str(tmp_path / "app_test.db")
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
        TESTING=True, SECRET_KEY="nm-test", WTF_CSRF_ENABLED=False,
    )
    yield app_module.app


@pytest.fixture()
def client(app):
    return app.test_client()


def _seed_user(app, role="staff", username="u1", password="Password1!"):
    from database import get_db
    from werkzeug.security import generate_password_hash
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


class TestMonitorRouteAccess:
    def test_unauthenticated_redirected(self, client):
        rv = client.get("/monitor", follow_redirects=True)
        assert b"log in" in rv.data.lower()

    def test_staff_cannot_access_monitor(self, app, client):
        _seed_user(app, role="staff")
        _login(client, {"username": "u1", "password": "Password1!"})
        rv = client.get("/monitor", follow_redirects=True)
        assert b"permission" in rv.data.lower()

    def test_doctor_cannot_access_monitor(self, app, client):
        _seed_user(app, role="doctor")
        _login(client, {"username": "u1", "password": "Password1!"})
        rv = client.get("/monitor", follow_redirects=True)
        assert b"permission" in rv.data.lower()

    def test_admin_can_access_monitor(self, app, client):
        _seed_user(app, role="admin")
        _login(client, {"username": "u1", "password": "Password1!"})
        rv = client.get("/monitor")
        assert rv.status_code == 200
        assert b"Network Monitor" in rv.data

    def test_monitor_shows_offline_disclaimer(self, app, client):
        _seed_user(app, role="admin")
        _login(client, {"username": "u1", "password": "Password1!"})
        rv = client.get("/monitor")
        assert b"offline" in rv.data.lower()


# ---------------------------------------------------------------------------
# 10. Alert review route
# ---------------------------------------------------------------------------

class TestAlertReview:
    def _insert_alert(self, app):
        from database import get_db
        db = get_db()
        db.execute(
            "INSERT INTO network_alerts"
            " (rule_id, severity, src_ip, reason, status, source_file)"
            " VALUES (?,?,?,?,?,?)",
            (RULE_SYN_SCAN, SEVERITY_HIGH, "1.2.3.4",
             "test reason", STATUS_NEW, "test.pcap"),
        )
        db.commit()
        aid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        db.close()
        return aid

    def test_review_marks_alert_reviewed(self, app, client):
        _seed_user(app, role="admin")
        _login(client, {"username": "u1", "password": "Password1!"})
        aid = self._insert_alert(app)
        client.post(f"/monitor/{aid}/review", follow_redirects=True)
        from database import get_db
        db = get_db()
        row = db.execute(
            "SELECT status FROM network_alerts WHERE id=?", (aid,)
        ).fetchone()
        db.close()
        assert row["status"] == STATUS_REVIEWED

    def test_review_nonexistent_alert_returns_404(self, app, client):
        _seed_user(app, role="admin")
        _login(client, {"username": "u1", "password": "Password1!"})
        rv = client.post("/monitor/999999/review", follow_redirects=False)
        assert rv.status_code == 404

    def test_staff_cannot_review_alert(self, app, client):
        _seed_user(app, role="staff")
        _login(client, {"username": "u1", "password": "Password1!"})
        rv = client.post("/monitor/1/review", follow_redirects=True)
        assert b"permission" in rv.data.lower()

    def test_review_logs_audit_event(self, app, client):
        _seed_user(app, role="admin")
        _login(client, {"username": "u1", "password": "Password1!"})
        aid = self._insert_alert(app)
        client.post(f"/monitor/{aid}/review", follow_redirects=True)
        from database import get_db
        db = get_db()
        event = db.execute(
            "SELECT * FROM audit_events WHERE event_type='ALERT_REVIEWED'"
            " ORDER BY id DESC LIMIT 1"
        ).fetchone()
        db.close()
        assert event is not None


# ---------------------------------------------------------------------------
# 11. Monitor page filters and pagination
# ---------------------------------------------------------------------------

class TestMonitorFilters:
    def _insert_alerts(self, app, n=5, severity=SEVERITY_HIGH,
                       status=STATUS_NEW, rule=RULE_SYN_SCAN):
        from database import get_db
        db = get_db()
        for i in range(n):
            db.execute(
                "INSERT INTO network_alerts"
                " (rule_id, severity, src_ip, reason, status, source_file)"
                " VALUES (?,?,?,?,?,?)",
                (rule, severity, f"1.2.3.{i}",
                 f"reason {i}", status, "f.pcap"),
            )
        db.commit()
        db.close()

    def test_severity_filter_high(self, app, client):
        _seed_user(app, role="admin")
        self._insert_alerts(app, 3, severity=SEVERITY_HIGH)
        self._insert_alerts(app, 2, severity=SEVERITY_LOW)
        _login(client, {"username": "u1", "password": "Password1!"})
        rv = client.get("/monitor?severity=high")
        assert rv.data.count(b"RULE_SYN_SCAN") >= 3

    def test_status_filter_new(self, app, client):
        _seed_user(app, role="admin")
        self._insert_alerts(app, 3, status=STATUS_NEW)
        self._insert_alerts(app, 2, status=STATUS_REVIEWED)
        _login(client, {"username": "u1", "password": "Password1!"})
        rv = client.get("/monitor?status=new")
        # Scope assertion to table body only — the filter form always contains
        # the raw status values as <option value="..."> attributes.
        table_body = rv.data.lower().split(b"alerts-tbody")[1].split(b"end-alerts-tbody")[0]
        assert b"reviewed" not in table_body

    def test_rule_filter(self, app, client):
        _seed_user(app, role="admin")
        self._insert_alerts(app, 2, rule=RULE_SYN_SCAN)
        self._insert_alerts(app, 2, rule=RULE_HIGH_RATE)
        _login(client, {"username": "u1", "password": "Password1!"})
        rv = client.get("/monitor?rule=RULE_SYN_SCAN")
        # Scope assertion to table body only — the filter form always contains
        # all rule values as <option value="..."> attributes.
        table_body = rv.data.split(b"alerts-tbody")[1].split(b"end-alerts-tbody")[0]
        assert b"RULE_SYN_SCAN" in table_body
        assert b"RULE_HIGH_RATE" not in table_body

    def test_pagination_page_2(self, app, client):
        _seed_user(app, role="admin")
        self._insert_alerts(app, 25)
        _login(client, {"username": "u1", "password": "Password1!"})
        rv = client.get("/monitor?page=2")
        assert rv.status_code == 200

    def test_no_alerts_shows_empty_message(self, app, client):
        _seed_user(app, role="admin")
        _login(client, {"username": "u1", "password": "Password1!"})
        rv = client.get("/monitor")
        assert b"No alerts" in rv.data
