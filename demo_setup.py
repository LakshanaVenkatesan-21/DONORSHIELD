"""Prepare an isolated DONORSHIELD demo database on Windows.

The AES key is kept in the current Windows user's environment registry value
DS_DEMO_AES_KEY and is never printed. The production DS_AES_KEY and database
are never read as cryptographic inputs or written by this helper.
"""
from __future__ import annotations

import argparse
import getpass
import ipaddress
import os
import re
import secrets
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ORIGINAL_DB = (ROOT / "donorshield.db").resolve()
DEMO_DB = (ROOT / "donorshield-demo.db").resolve()
PCAP = ROOT / "test_snort.pcap"
DEMO_TLS_CERT = ROOT / "certs" / "demo-localhost.crt"
DEMO_TLS_KEY = ROOT / "certs" / "demo-localhost.key"

BLOOD_DONORS = [
    ("Demo Blood Donor 01", "A+", "+1-202-555-0101", "active"),
    ("Demo Blood Donor 02", "A-", "+1-202-555-0102", "active"),
    ("Demo Blood Donor 03", "B+", "+1-202-555-0103", "active"),
    ("Demo Blood Donor 04", "B-", "+1-202-555-0104", "active"),
    ("Demo Blood Donor 05", "AB+", "+1-202-555-0105", "active"),
    ("Demo Blood Donor 06", "AB-", "+1-202-555-0106", "active"),
    ("Demo Blood Donor 07", "O+", "+1-202-555-0107", "inactive"),
    ("Demo Blood Donor 08", "O-", "+1-202-555-0108", "active"),
]
ORGAN_DONORS = [
    ("Demo Organ Donor 09", "AB+", "+1-202-555-0109", "kidney", "active"),
    ("Demo Organ Donor 10", "O+", "+1-202-555-0110", "liver", "inactive"),
]
INVENTORY = {"A+": 12, "A-": 3, "B+": 8, "B-": 2,
             "AB+": 0, "AB-": 1, "O+": 15, "O-": 0}


def assert_isolated_path(path: Path) -> None:
    original = ORIGINAL_DB.resolve()
    demo = path.resolve()
    if demo != DEMO_DB or demo == original:
        raise RuntimeError("Refusing database access: target is not the verified demo database.")


def _original_donor_count() -> int:
    if not ORIGINAL_DB.is_file():
        raise RuntimeError("Original database is missing; refusing setup.")
    uri = ORIGINAL_DB.as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        return int(conn.execute("SELECT COUNT(*) FROM donors").fetchone()[0])


def _offline_alerts():
    if not PCAP.is_file():
        raise RuntimeError("The project's sample PCAP is missing; no database was changed.")
    from security.network_monitor import analyse_pcap_file
    from security.snort_runner import run_snort_on_pcap

    scapy_result = analyse_pcap_file(str(PCAP), source_name=PCAP.name)
    snort_result = run_snort_on_pcap(str(PCAP), source_name=PCAP.name)
    if not scapy_result["alerts"] or not snort_result["alerts"]:
        raise RuntimeError("The sample PCAP did not produce both Scapy and Snort alerts; no database was changed.")
    return scapy_result["alerts"], snort_result["alerts"]


def _load_or_create_demo_key() -> str:
    if os.name != "nt":
        raise RuntimeError("This demo key setup uses the Windows current-user environment store.")
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ) as key:
            value, _kind = winreg.QueryValueEx(key, "DS_DEMO_AES_KEY")
    except FileNotFoundError:
        value = None

    if value is None:
        value = secrets.token_hex(32)
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "DS_DEMO_AES_KEY", 0, winreg.REG_SZ, value)
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise RuntimeError("The existing DS_DEMO_AES_KEY user setting is malformed; it was not replaced.")
    return value


def _seed_demo(db, scapy_alerts, snort_alerts) -> dict:
    from security.crypto import encrypt, decrypt_str
    from security.network_monitor import save_alerts
    from seed_data import seed_blood_banks

    bank_stats = seed_blood_banks(db, str(ROOT / "blood-banks.csv"))
    db.execute("""CREATE TABLE IF NOT EXISTS demo_seed_registry (
        seed_key TEXT PRIMARY KEY,
        donor_id INTEGER NOT NULL UNIQUE REFERENCES donors(id) ON DELETE CASCADE
    )""")
    db.commit()

    added = 0
    specs = []
    for name, group, contact, status in BLOOD_DONORS:
        specs.append((name, group, contact, "blood", None, status))
    for name, group, contact, organ, status in ORGAN_DONORS:
        specs.append((name, group, contact, "organ", organ, status))

    for name, group, contact, donation_type, organ, status in specs:
        seed_key = name
        prior = db.execute(
            "SELECT donor_id FROM demo_seed_registry WHERE seed_key = ?", (seed_key,)
        ).fetchone()
        if prior and db.execute("SELECT 1 FROM donors WHERE id = ?", (prior[0],)).fetchone():
            continue
        if prior:
            db.execute("DELETE FROM demo_seed_registry WHERE seed_key = ?", (seed_key,))
        cur = db.execute(
            "INSERT INTO donors (full_name, blood_group, contact, donation_type, organ_type, status) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (encrypt(name), group, encrypt(contact), donation_type,
             encrypt(organ) if organ else None, status),
        )
        db.execute(
            "INSERT INTO demo_seed_registry (seed_key, donor_id) VALUES (?, ?)",
            (seed_key, cur.lastrowid),
        )
        added += 1

    for group, units in INVENTORY.items():
        changed = db.execute(
            "UPDATE blood_inventory SET units = ?, updated_at = datetime('now') WHERE blood_group = ?",
            (units, group),
        ).rowcount
        if changed != 1:
            raise RuntimeError("Expected blood inventory groups are missing; setup stopped.")

    save_alerts(scapy_alerts, db, source="scapy")
    save_alerts(snort_alerts, db, source="snort")
    db.commit()

    rows = db.execute(
        "SELECT d.full_name, d.donation_type, d.status FROM donors d "
        "JOIN demo_seed_registry r ON r.donor_id = d.id ORDER BY r.seed_key"
    ).fetchall()
    names = [decrypt_str(row["full_name"]) for row in rows]
    if len(rows) != 10 or len(set(names)) != 10:
        raise RuntimeError("Demo donor verification failed.")
    if sum(row["donation_type"] == "blood" for row in rows) != 8:
        raise RuntimeError("Demo blood donor verification failed.")
    if sum(row["donation_type"] == "organ" for row in rows) != 2:
        raise RuntimeError("Demo organ donor verification failed.")
    if not any(row["status"] == "inactive" for row in rows):
        raise RuntimeError("Demo status verification failed.")
    return {"donors_added": added, "blood_banks_imported": bank_stats["imported"]}


def prepare_demo() -> None:
    # Verify both full paths before any write; the demo file must never resolve to production.
    assert_isolated_path(DEMO_DB)
    if DEMO_DB == ORIGINAL_DB:
        raise RuntimeError("Original and demo database paths must differ.")
    original_count_before = _original_donor_count()

    # Analyze offline before initializing or writing the demo database.
    scapy_alerts, snort_alerts = _offline_alerts()
    demo_key = _load_or_create_demo_key()
    os.environ["DB_PATH"] = str(DEMO_DB)
    os.environ["DS_AES_KEY"] = demo_key

    import database
    assert_isolated_path(Path(database.DB_PATH))
    if Path(database.DB_PATH).resolve() != DEMO_DB:
        raise RuntimeError("Database module path check failed; refusing writes.")

    database.init_db()
    assert_isolated_path(Path(database.DB_PATH))
    db = database.get_db()
    try:
        stats = _seed_demo(db, scapy_alerts, snort_alerts)
        counts = {
            "donors": db.execute("SELECT COUNT(*) FROM donors").fetchone()[0],
            "blood_groups": db.execute("SELECT COUNT(*) FROM blood_inventory").fetchone()[0],
            "blood_banks": db.execute("SELECT COUNT(*) FROM blood_banks").fetchone()[0],
            "alerts": db.execute("SELECT COUNT(*) FROM network_alerts").fetchone()[0],
            "scapy_alerts": db.execute("SELECT COUNT(*) FROM network_alerts WHERE source='scapy'").fetchone()[0],
            "snort_alerts": db.execute("SELECT COUNT(*) FROM network_alerts WHERE source='snort'").fetchone()[0],
        }
        if counts["blood_banks"] < 1:
            raise RuntimeError("Blood-bank data was not imported into the demo database.")
        if not counts["scapy_alerts"] or not counts["snort_alerts"]:
            raise RuntimeError("Saved offline alerts could not be verified.")
    finally:
        db.close()

    original_count_after = _original_donor_count()
    if original_count_after != original_count_before:
        raise RuntimeError("Original donor count changed during demo setup; investigate before proceeding.")
    print(f"Demo database verified: {DEMO_DB}")
    print(f"Demo donor records: {counts['donors']} (added this run: {stats['donors_added']})")
    print(f"Blood inventory groups: {counts['blood_groups']}")
    print(f"Blood bank rows in demo database: {counts['blood_banks']} (new this run: {stats['blood_banks_imported']})")
    print(f"Offline network alerts: Scapy={counts['scapy_alerts']}, Snort={counts['snort_alerts']}")
    print("Original donor count unchanged.")


def create_demo_admin() -> None:
    prepare_demo()
    from database import get_db
    from werkzeug.security import generate_password_hash

    db = get_db()
    try:
        if db.execute("SELECT 1 FROM users WHERE role='admin' LIMIT 1").fetchone():
            print("A demo admin already exists; no account was changed.")
            return
        username = input("Choose demo admin username: ").strip()
        password = getpass.getpass("Choose demo admin password (at least 8 characters): ")
        if len(username) < 3 or len(password) < 8:
            raise RuntimeError("Username must be at least 3 characters and password at least 8 characters.")
        db.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')",
            (username, generate_password_hash(password),),
        )
        db.commit()
        print("Demo admin created. The password was not displayed.")
    finally:
        db.close()


def ensure_demo_tls_certificate() -> tuple[Path, Path]:
    """Create a self-signed localhost certificate without replacing existing files."""
    cert_path, key_path = DEMO_TLS_CERT, DEMO_TLS_KEY
    if cert_path.exists() or key_path.exists():
        if cert_path.is_file() and key_path.is_file():
            return cert_path, key_path
        raise RuntimeError(
            "Only one demo TLS certificate file exists; refusing to replace it. "
            "Move the incomplete pair aside before retrying."
        )

    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    try:
        key_path.write_bytes(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    except Exception:
        # Do not leave a partial pair that a later run might mistake for valid.
        for path in (cert_path, key_path):
            try:
                path.unlink()
            except OSError:
                pass
        raise
    return cert_path, key_path


def run_demo(https: bool = False) -> None:
    prepare_demo()
    import app as app_module
    app_module.app.config["SESSION_COOKIE_SECURE"] = bool(https)
    ssl_context = None
    if https:
        cert_path, key_path = ensure_demo_tls_certificate()
        ssl_context = (str(cert_path), str(key_path))
    app_module.app.run(
        host="127.0.0.1", port=5000, debug=False, ssl_context=ssl_context
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Set up or run the isolated DONORSHIELD demo database.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--create-admin", action="store_true", help="Create the first demo admin interactively.")
    group.add_argument("--run", action="store_true", help="Prepare the demo and start Flask on localhost.")
    group.add_argument("--run-https", action="store_true", help="Prepare the demo and start Flask over HTTPS on localhost.")
    args = parser.parse_args()
    if args.create_admin:
        create_demo_admin()
    elif args.run:
        run_demo()
    elif args.run_https:
        run_demo(https=True)
    else:
        prepare_demo()

