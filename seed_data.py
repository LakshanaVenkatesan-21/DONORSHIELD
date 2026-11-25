"""
seed_data.py — Import blood-banks.csv and transfusion.data into DonorShield.

Usage (with .venv active):
    python seed_data.py

Safe to re-run: existing rows are detected by (name, state, district, city)
for blood banks, and the transfusion table is cleared and reloaded each run
(it contains no user-generated data).

Sources:
  blood-banks.csv   — National Blood Transfusion Council of India (NBTC) /
                      eRaktKosh open data. No personal donor identities.
  transfusion.data  — UCI ML Repository, Blood Transfusion Service Center
                      dataset. Prof. I-Cheng Yeh, Chung-Hua University, Taiwan.
                      DOI: 10.1016/j.eswa.2008.07.018
                      Anonymised; no individual can be identified.
"""

import csv
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from database import get_db, init_db

# ---------------------------------------------------------------------------
# Required columns in each source file
# ---------------------------------------------------------------------------
BB_REQUIRED = {" Blood Bank Name", " State", " District", " City"}
TF_REQUIRED = {
    "Recency (months)", "Frequency (times)",
    "Monetary (c.c. blood)", "Time (months)",
    "whether he/she donated blood in March 2007",
}

VALID_CATEGORIES = {"Government", "Charity", "Private", ""}


def _clean(val: str) -> str:
    """Strip whitespace; replace common null-like strings with empty string."""
    v = val.strip()
    return "" if v.upper() in ("N/A", "NA", "NIL", "NONE", "-", "") else v


def _safe_float(val: str):
    try:
        return float(val.strip())
    except (ValueError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# Blood banks
# ---------------------------------------------------------------------------

def seed_blood_banks(db, csv_path: str) -> dict:
    stats = {"imported": 0, "skipped_dup": 0, "rejected": 0}

    with open(csv_path, encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        headers = set(reader.fieldnames or [])

        missing = BB_REQUIRED - headers
        if missing:
            print(f"  ERROR: blood-banks.csv is missing required columns: {missing}")
            return stats

        seen_keys = set()

        for row in reader:
            name     = _clean(row.get(" Blood Bank Name", ""))
            state    = _clean(row.get(" State", ""))
            district = _clean(row.get(" District", ""))
            city     = _clean(row.get(" City", ""))

            # Reject rows missing mandatory identity fields
            if not name or not state:
                stats["rejected"] += 1
                continue

            # Normalise district/city fallbacks
            district = district or state
            city     = city or district

            # Deduplicate within this import run
            key = (name.lower(), state.lower(), district.lower(), city.lower())
            if key in seen_keys:
                stats["skipped_dup"] += 1
                continue
            seen_keys.add(key)

            # Skip if already in DB (idempotent re-runs)
            existing = db.execute(
                "SELECT id FROM blood_banks WHERE name=? AND state=? AND district=? AND city=?",
                (name, state, district, city),
            ).fetchone()
            if existing:
                stats["skipped_dup"] += 1
                continue

            category = _clean(row.get(" Category", ""))
            if category not in VALID_CATEGORIES:
                category = ""

            db.execute(
                """INSERT INTO blood_banks
                   (name, state, district, city, address, pincode,
                    contact_no, mobile, helpline, email, website,
                    category, blood_component, apheresis, service_time,
                    license_no, latitude, longitude)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    name, state, district, city,
                    _clean(row.get(" Address", "")),
                    _clean(row.get("Pincode", "")),
                    _clean(row.get(" Contact No", "")),
                    _clean(row.get(" Mobile", "")),
                    _clean(row.get(" Helpline", "")),
                    _clean(row.get(" Email", "")),
                    _clean(row.get(" Website", "")),
                    category,
                    _clean(row.get(" Blood Component Available", "")),
                    _clean(row.get(" Apheresis", "")),
                    _clean(row.get(" Service Time", "")),
                    _clean(row.get(" License #", "")),
                    _safe_float(row.get(" Latitude", "")),
                    _safe_float(row.get(" Longitude", "")),
                ),
            )
            stats["imported"] += 1

    db.commit()
    return stats


# ---------------------------------------------------------------------------
# Transfusion RFMTC records
# ---------------------------------------------------------------------------

def seed_transfusion(db, data_path: str) -> dict:
    stats = {"imported": 0, "skipped_dup": 0, "rejected": 0}

    with open(data_path, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        headers = set(reader.fieldnames or [])

        missing = TF_REQUIRED - headers
        if missing:
            print(f"  ERROR: transfusion.data is missing required columns: {missing}")
            return stats

        # Clear and reload — no user data in this table
        db.execute("DELETE FROM transfusion_records")

        seen_tuples = set()

        for row in reader:
            try:
                r = int(row["Recency (months)"].strip())
                f_val = int(row["Frequency (times)"].strip())
                m = int(row["Monetary (c.c. blood)"].strip())
                t = int(row["Time (months)"].strip())
                d = int(row["whether he/she donated blood in March 2007"].strip())
            except (ValueError, KeyError):
                stats["rejected"] += 1
                continue

            if d not in (0, 1):
                stats["rejected"] += 1
                continue

            key = (r, f_val, m, t, d)
            if key in seen_tuples:
                stats["skipped_dup"] += 1
                continue
            seen_tuples.add(key)

            db.execute(
                "INSERT INTO transfusion_records (recency, frequency, monetary, time_months, donated)"
                " VALUES (?,?,?,?,?)",
                (r, f_val, m, t, d),
            )
            stats["imported"] += 1

    db.commit()
    return stats


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    bb_path = os.path.join(BASE_DIR, "blood-banks.csv")
    tf_path = os.path.join(BASE_DIR, "transfusion.data")

    for path in (bb_path, tf_path):
        if not os.path.isfile(path):
            print(f"ERROR: Dataset file not found: {path}")
            sys.exit(1)

    print("Initialising database schema...")
    init_db()

    db = get_db()

    print("\nImporting blood-banks.csv...")
    bb = seed_blood_banks(db, bb_path)
    print(f"  Imported : {bb['imported']}")
    print(f"  Skipped  : {bb['skipped_dup']}  (duplicates / already present)")
    print(f"  Rejected : {bb['rejected']}  (missing mandatory fields)")

    print("\nImporting transfusion.data...")
    tf = seed_transfusion(db, tf_path)
    print(f"  Imported : {tf['imported']}")
    print(f"  Skipped  : {tf['skipped_dup']}  (duplicate RFMTC tuples)")
    print(f"  Rejected : {tf['rejected']}  (invalid values)")

    db.close()

    total_bb = db.execute if False else None  # just for clarity
    print("\nDone.")


if __name__ == "__main__":
    main()
