import os
import sqlite3

DB_PATH = os.environ.get("DB_PATH") or os.path.join(os.path.dirname(__file__), "donorshield.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT    NOT NULL UNIQUE,
            password   TEXT    NOT NULL,
            role       TEXT    NOT NULL CHECK(role IN ('admin', 'doctor', 'staff')),
            created_at TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS donors (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            -- full_name, contact, organ_type are AES-256-GCM tokens (v1:nonce:ct).
            -- blood_group and donation_type are stored in plaintext for
            -- operational filtering and inventory management.
            full_name     TEXT    NOT NULL,
            blood_group   TEXT    NOT NULL
                              CHECK(blood_group IN ('A+','A-','B+','B-','AB+','AB-','O+','O-')),
            contact       TEXT,
            donation_type TEXT    NOT NULL CHECK(donation_type IN ('blood', 'organ')),
            organ_type    TEXT,
            status        TEXT    NOT NULL DEFAULT 'active'
                              CHECK(status IN ('active', 'inactive')),
            registered_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS blood_inventory (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            blood_group TEXT    NOT NULL UNIQUE,
            units       INTEGER NOT NULL DEFAULT 0 CHECK(units >= 0),
            updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type  TEXT    NOT NULL,
            description TEXT,
            user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
            ip_address  TEXT,
            timestamp   TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS doctor_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doctor_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            request_type TEXT NOT NULL CHECK(request_type IN ('blood','organ')),
            blood_group TEXT,
            organ_type TEXT,
            quantity INTEGER NOT NULL CHECK(quantity > 0),
            location TEXT NOT NULL,
            urgency TEXT NOT NULL CHECK(urgency IN ('routine','urgent','emergency')),
            details TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN ('Pending','Approved','Rejected','Fulfilled')),
            response TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            processed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
            transferred_units INTEGER,
            transfer_completed_at TEXT,
            CHECK((request_type='blood' AND blood_group IS NOT NULL AND organ_type IS NULL)
               OR (request_type='organ' AND organ_type IS NOT NULL AND blood_group IS NULL))
        );
        CREATE INDEX IF NOT EXISTS idx_doctor_requests_doctor ON doctor_requests(doctor_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_doctor_requests_status ON doctor_requests(status, created_at DESC);

        -- schema_version records applied migrations for future reference.
        CREATE TABLE IF NOT EXISTS schema_version (
            version     INTEGER PRIMARY KEY,
            description TEXT    NOT NULL,
            applied_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        -- Stage 5: Nationwide blood bank directory imported from blood-banks.csv.
        -- Kept separate from registered donors and blood_inventory.
        CREATE TABLE IF NOT EXISTS blood_banks (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            name             TEXT    NOT NULL,
            state            TEXT    NOT NULL,
            district         TEXT    NOT NULL,
            city             TEXT    NOT NULL,
            address          TEXT,
            pincode          TEXT,
            contact_no       TEXT,
            mobile           TEXT,
            helpline         TEXT,
            email            TEXT,
            website          TEXT,
            category         TEXT,
            blood_component  TEXT,
            apheresis        TEXT,
            service_time     TEXT,
            license_no       TEXT,
            latitude         REAL,
            longitude        REAL,
            source           TEXT    NOT NULL DEFAULT 'blood-banks.csv'
        );

        CREATE INDEX IF NOT EXISTS idx_bb_state    ON blood_banks(state);
        CREATE INDEX IF NOT EXISTS idx_bb_district ON blood_banks(district);
        CREATE INDEX IF NOT EXISTS idx_bb_city     ON blood_banks(city);

        -- Stage 6: RFMTC donation-behaviour records from transfusion.data (UCI).
        -- These are anonymised historical records from a Taiwanese blood service.
        -- No donor identity is stored. Used for statistical display only.
        CREATE TABLE IF NOT EXISTS transfusion_records (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            recency     INTEGER NOT NULL,
            frequency   INTEGER NOT NULL,
            monetary    INTEGER NOT NULL,
            time_months INTEGER NOT NULL,
            donated     INTEGER NOT NULL CHECK(donated IN (0, 1)),
            source      TEXT    NOT NULL DEFAULT 'transfusion.data'
        );

        -- Stage 7: Brute-force / account-lockout tracking.
        -- Stores failed login attempts keyed by username.
        -- Rows are expired by comparing attempted_at to the current time;
        -- no cron job or restart is required to lift a lockout.
        -- Passwords and secrets are never stored here.
        CREATE TABLE IF NOT EXISTS login_attempts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            username     TEXT    NOT NULL,
            ip_address   TEXT,
            attempted_at TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_la_username ON login_attempts(username);
        CREATE INDEX IF NOT EXISTS idx_la_ip       ON login_attempts(ip_address);

        -- Stage 8: Network intrusion detection alerts from offline PCAP analysis.
        -- Full packet payloads, credentials, and private data are never stored.
        -- source column distinguishes 'scapy' (built-in rules) from 'snort' (Snort 2.9).
        CREATE TABLE IF NOT EXISTS network_alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id     TEXT    NOT NULL,
            severity    TEXT    NOT NULL CHECK(severity IN ('low','medium','high')),
            src_ip      TEXT,
            dst_ip      TEXT,
            dst_port    INTEGER,
            reason      TEXT    NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'new'
                            CHECK(status IN ('new','reviewed')),
            source_file TEXT,
            source      TEXT    NOT NULL DEFAULT 'scapy'
                            CHECK(source IN ('scapy','snort')),
            detected_at TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_na_severity ON network_alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_na_status   ON network_alerts(status);
    """)

    for bg in ("A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"):
        cur.execute(
            "INSERT OR IGNORE INTO blood_inventory (blood_group, units) VALUES (?, 0)", (bg,)
        )

    # Record baseline schema version.
    cur.execute(
        "INSERT OR IGNORE INTO schema_version (version, description) VALUES (?, ?)",
        (3, "Stage 3: full_name, contact, organ_type stored as AES-256-GCM tokens"),
    )
    cur.execute(
        "INSERT OR IGNORE INTO schema_version (version, description) VALUES (?, ?)",
        (4, "Stage 4: RSA-PSS signed audit report export added"),
    )
    cur.execute(
        "INSERT OR IGNORE INTO schema_version (version, description) VALUES (?, ?)",
        (5, "Stage 5: blood_banks directory table added"),
    )
    cur.execute(
        "INSERT OR IGNORE INTO schema_version (version, description) VALUES (?, ?)",
        (6, "Stage 6: transfusion_records RFMTC table added"),
    )
    cur.execute(
        "INSERT OR IGNORE INTO schema_version (version, description) VALUES (?, ?)",
        (7, "Stage 7: login_attempts table for brute-force detection"),
    )
    cur.execute(
        "INSERT OR IGNORE INTO schema_version (version, description) VALUES (?, ?)",
        (8, "Stage 8: network_alerts table for intrusion detection"),
    )

    cur.execute(
        "INSERT OR IGNORE INTO schema_version (version, description) VALUES (?, ?)",
        (9, "Stage 9: per-IP login rate limiting and input length validation"),
    )
    cur.execute(
        "INSERT OR IGNORE INTO schema_version (version, description) VALUES (?, ?)",
        (10, "Stage 10: Snort/Wireshark integration — source column on network_alerts"),
    )

    cur.execute(
        "INSERT OR IGNORE INTO schema_version (version, description) VALUES (?, ?)",
        (11, "Stage 11: doctor request management"),
    )

    request_cols = {row[1] for row in cur.execute("PRAGMA table_info(doctor_requests)").fetchall()}
    if "transferred_units" not in request_cols:
        cur.execute("ALTER TABLE doctor_requests ADD COLUMN transferred_units INTEGER")
    if "transfer_completed_at" not in request_cols:
        cur.execute("ALTER TABLE doctor_requests ADD COLUMN transfer_completed_at TEXT")
    cur.execute(
        "INSERT OR IGNORE INTO schema_version (version, description) VALUES (?, ?)",
        (12, "Stage 12: atomic blood transfer completion tracking"),
    )

    # Migration: add source column to existing databases that lack it.
    existing_cols = {row[1] for row in cur.execute("PRAGMA table_info(network_alerts)").fetchall()}
    if "source" not in existing_cols:
        cur.execute(
            "ALTER TABLE network_alerts ADD COLUMN source TEXT NOT NULL DEFAULT 'scapy'"
        )

    conn.commit()
    conn.close()
