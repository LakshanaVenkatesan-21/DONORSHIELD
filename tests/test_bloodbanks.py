"""
DonorShield - Stage 5/6 dataset integration tests.
Covers: blood bank import, validation, dedup, search, filter, pagination,
        access control, DB integrity, and transfusion seed.
Run with:  .venv/Scripts/pytest tests/ -v
"""
import os
import tempfile
import csv
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

    import importlib
    import database
    import app as app_module
    importlib.reload(database)
    importlib.reload(app_module)

    database.init_db()
    app_module.app.config.update(TESTING=True, SECRET_KEY="bb-test", WTF_CSRF_ENABLED=False)

    yield app_module.app

    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture()
def client(app):
    return app.test_client()


def _seed_user(app, role="staff", username="testuser", password="Password1!"):
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


def _insert_bank(db, name="Test Bank", state="TestState", district="TestDist",
                 city="TestCity", category="Government"):
    db.execute(
        "INSERT INTO blood_banks (name, state, district, city, category, blood_component)"
        " VALUES (?,?,?,?,?,?)",
        (name, state, district, city, category, "YES"),
    )
    db.commit()
    return db.execute("SELECT last_insert_rowid()").fetchone()[0]


# ---------------------------------------------------------------------------
# 1. Database schema
# ---------------------------------------------------------------------------

class TestSchema:
    def test_blood_banks_table_exists(self, app):
        from database import get_db
        db = get_db()
        tables = {r[0] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        db.close()
        assert "blood_banks" in tables

    def test_transfusion_records_table_exists(self, app):
        from database import get_db
        db = get_db()
        tables = {r[0] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        db.close()
        assert "transfusion_records" in tables

    def test_schema_versions_5_and_6_recorded(self, app):
        from database import get_db
        db = get_db()
        versions = {r[0] for r in db.execute(
            "SELECT version FROM schema_version"
        ).fetchall()}
        db.close()
        assert {5, 6}.issubset(versions)

    def test_existing_tables_not_dropped(self, app):
        from database import get_db
        db = get_db()
        tables = {r[0] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        db.close()
        assert {"users", "donors", "blood_inventory", "audit_events"}.issubset(tables)


# ---------------------------------------------------------------------------
# 2. Seed script — blood banks
# ---------------------------------------------------------------------------

class TestBloodBankSeed:
    def _make_csv(self, tmp_path, rows):
        """Write a minimal blood-banks.csv to tmp_path and return its path."""
        path = str(tmp_path / "test_bb.csv")
        headers = [
            "Sr No", " Blood Bank Name", " State", " District", " City",
            " Address", "Pincode", " Contact No", " Mobile", " Helpline",
            " Fax", " Email", " Website", " Nodal Officer ",
            " Contact Nodal Officer", " Mobile Nodal Officer",
            " Email Nodal Officer", " Qualification Nodal Officer",
            " Category", " Blood Component Available", " Apheresis",
            " Service Time", " License #", " Date License Obtained",
            " Date of Renewal", " Latitude", " Longitude",
        ]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(headers)
            for r in rows:
                w.writerow(r)
        return path

    def _base_row(self, n=1, name="Alpha Bank", state="Kerala",
                  district="Ernakulam", city="Kochi", category="Government"):
        return [
            str(n), name, state, district, city,
            "123 Main St", "682001", "0484-123456", "9876543210", "N/A",
            "N/A", "test@bank.com", "", "Dr. Test", "0484-123456",
            "9876543210", "test@bank.com", "MBBS", category,
            "YES", "NO", "24X7", "LIC001", "01.01.2010", "01.01.2020",
            "10.0", "76.0",
        ]

    def test_valid_rows_imported(self, app, tmp_path):
        from database import get_db
        from seed_data import seed_blood_banks
        db = get_db()
        path = self._make_csv(tmp_path, [self._base_row()])
        stats = seed_blood_banks(db, path)
        db.close()
        assert stats["imported"] == 1
        assert stats["rejected"] == 0

    def test_duplicate_rows_skipped(self, app, tmp_path):
        from database import get_db
        from seed_data import seed_blood_banks
        db = get_db()
        row = self._base_row()
        path = self._make_csv(tmp_path, [row, row])  # exact duplicate
        stats = seed_blood_banks(db, path)
        db.close()
        assert stats["imported"] == 1
        assert stats["skipped_dup"] == 1

    def test_idempotent_reimport(self, app, tmp_path):
        from database import get_db
        from seed_data import seed_blood_banks
        db = get_db()
        path = self._make_csv(tmp_path, [self._base_row()])
        seed_blood_banks(db, path)
        stats2 = seed_blood_banks(db, path)  # second run
        db.close()
        assert stats2["imported"] == 0
        assert stats2["skipped_dup"] == 1

    def test_row_missing_name_rejected(self, app, tmp_path):
        from database import get_db
        from seed_data import seed_blood_banks
        db = get_db()
        row = self._base_row()
        row[1] = ""  # blank name
        path = self._make_csv(tmp_path, [row])
        stats = seed_blood_banks(db, path)
        db.close()
        assert stats["rejected"] == 1
        assert stats["imported"] == 0

    def test_row_missing_state_rejected(self, app, tmp_path):
        from database import get_db
        from seed_data import seed_blood_banks
        db = get_db()
        row = self._base_row()
        row[2] = ""  # blank state
        path = self._make_csv(tmp_path, [row])
        stats = seed_blood_banks(db, path)
        db.close()
        assert stats["rejected"] == 1

    def test_invalid_category_normalised_to_empty(self, app, tmp_path):
        from database import get_db
        from seed_data import seed_blood_banks
        db = get_db()
        row = self._base_row(category="Unknown_Type")
        path = self._make_csv(tmp_path, [row])
        seed_blood_banks(db, path)
        bank = db.execute("SELECT category FROM blood_banks ORDER BY id DESC LIMIT 1").fetchone()
        db.close()
        assert bank["category"] == ""

    def test_na_values_normalised_to_empty(self, app, tmp_path):
        from database import get_db
        from seed_data import seed_blood_banks
        db = get_db()
        row = self._base_row()
        row[7] = "N/A"   # contact_no
        row[11] = "NA"   # email
        path = self._make_csv(tmp_path, [row])
        seed_blood_banks(db, path)
        bank = db.execute(
            "SELECT contact_no, email FROM blood_banks ORDER BY id DESC LIMIT 1"
        ).fetchone()
        db.close()
        assert bank["contact_no"] == ""
        assert bank["email"] == ""

    def test_multiple_distinct_rows_all_imported(self, app, tmp_path):
        from database import get_db
        from seed_data import seed_blood_banks
        db = get_db()
        rows = [
            self._base_row(1, "Bank A", "Kerala", "Ernakulam", "Kochi"),
            self._base_row(2, "Bank B", "Tamil Nadu", "Chennai", "Chennai"),
            self._base_row(3, "Bank C", "Maharashtra", "Pune", "Pune"),
        ]
        path = self._make_csv(tmp_path, rows)
        stats = seed_blood_banks(db, path)
        db.close()
        assert stats["imported"] == 3


# ---------------------------------------------------------------------------
# 3. Seed script — transfusion records
# ---------------------------------------------------------------------------

class TestTransfusionSeed:
    def _make_tf_csv(self, tmp_path, rows):
        path = str(tmp_path / "test_tf.data")
        headers = [
            "Recency (months)", "Frequency (times)",
            "Monetary (c.c. blood)", "Time (months)",
            "whether he/she donated blood in March 2007",
        ]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(headers)
            for r in rows:
                w.writerow(r)
        return path

    def test_valid_records_imported(self, app, tmp_path):
        from database import get_db
        from seed_data import seed_transfusion
        db = get_db()
        path = self._make_tf_csv(tmp_path, [[2, 5, 1250, 16, 1], [4, 3, 750, 8, 0]])
        stats = seed_transfusion(db, path)
        db.close()
        assert stats["imported"] == 2

    def test_duplicate_tuples_skipped(self, app, tmp_path):
        from database import get_db
        from seed_data import seed_transfusion
        db = get_db()
        row = [2, 5, 1250, 16, 1]
        path = self._make_tf_csv(tmp_path, [row, row])
        stats = seed_transfusion(db, path)
        db.close()
        assert stats["imported"] == 1
        assert stats["skipped_dup"] == 1

    def test_reimport_clears_and_reloads(self, app, tmp_path):
        from database import get_db
        from seed_data import seed_transfusion
        db = get_db()
        path = self._make_tf_csv(tmp_path, [[2, 5, 1250, 16, 1]])
        seed_transfusion(db, path)
        # Second run with different data — old rows cleared
        path2 = self._make_tf_csv(tmp_path, [[4, 3, 750, 8, 0], [1, 1, 250, 2, 0]])
        stats2 = seed_transfusion(db, path2)
        count = db.execute("SELECT COUNT(*) FROM transfusion_records").fetchone()[0]
        db.close()
        assert stats2["imported"] == 2
        assert count == 2  # old row gone

    def test_invalid_target_value_rejected(self, app, tmp_path):
        from database import get_db
        from seed_data import seed_transfusion
        db = get_db()
        path = self._make_tf_csv(tmp_path, [[2, 5, 1250, 16, 99]])  # 99 is invalid
        stats = seed_transfusion(db, path)
        db.close()
        assert stats["rejected"] == 1

    def test_non_numeric_row_rejected(self, app, tmp_path):
        from database import get_db
        from seed_data import seed_transfusion
        db = get_db()
        path = self._make_tf_csv(tmp_path, [["abc", "def", "ghi", "jkl", "mno"]])
        stats = seed_transfusion(db, path)
        db.close()
        assert stats["rejected"] == 1


# ---------------------------------------------------------------------------
# 4. Access control
# ---------------------------------------------------------------------------

class TestBloodBankAccess:
    def test_unauthenticated_redirected_to_login(self, client):
        rv = client.get("/bloodbanks", follow_redirects=True)
        assert b"log in" in rv.data.lower()

    def test_unauthenticated_detail_redirected(self, client):
        rv = client.get("/bloodbanks/1", follow_redirects=True)
        assert b"log in" in rv.data.lower()

    def test_staff_can_access_directory(self, app, client):
        creds = _seed_user(app, role="staff")
        _login(client, creds)
        rv = client.get("/bloodbanks")
        assert rv.status_code == 200

    def test_doctor_can_access_directory(self, app, client):
        creds = _seed_user(app, role="doctor", username="doc1")
        _login(client, creds)
        rv = client.get("/bloodbanks")
        assert rv.status_code == 200

    def test_admin_can_access_directory(self, app, client):
        creds = _seed_user(app, role="admin", username="adm1")
        _login(client, creds)
        rv = client.get("/bloodbanks")
        assert rv.status_code == 200

    def test_nonexistent_bank_returns_404(self, app, client):
        creds = _seed_user(app)
        _login(client, creds)
        rv = client.get("/bloodbanks/999999")
        assert rv.status_code == 404


# ---------------------------------------------------------------------------
# 5. Search and filtering
# ---------------------------------------------------------------------------

class TestBloodBankSearch:
    def _setup(self, app):
        from database import get_db
        db = get_db()
        _insert_bank(db, "Apollo Blood Bank", "Maharashtra", "Mumbai", "Mumbai", "Private")
        _insert_bank(db, "Red Cross Centre", "Kerala", "Ernakulam", "Kochi", "Charity")
        _insert_bank(db, "Govt Hospital Bank", "Kerala", "Thrissur", "Thrissur", "Government")
        db.close()

    def test_search_by_name(self, app, client):
        self._setup(app)
        creds = _seed_user(app)
        _login(client, creds)
        rv = client.get("/bloodbanks?name=apollo")
        assert b"Apollo Blood Bank" in rv.data
        assert b"Red Cross" not in rv.data

    def test_search_by_state(self, app, client):
        self._setup(app)
        creds = _seed_user(app)
        _login(client, creds)
        rv = client.get("/bloodbanks?state=Kerala")
        assert b"Red Cross Centre" in rv.data
        assert b"Govt Hospital Bank" in rv.data
        assert b"Apollo Blood Bank" not in rv.data

    def test_search_by_city(self, app, client):
        self._setup(app)
        creds = _seed_user(app)
        _login(client, creds)
        rv = client.get("/bloodbanks?city=kochi")
        assert b"Red Cross Centre" in rv.data
        assert b"Apollo Blood Bank" not in rv.data

    def test_search_by_district(self, app, client):
        self._setup(app)
        creds = _seed_user(app)
        _login(client, creds)
        rv = client.get("/bloodbanks?district=thrissur")
        assert b"Govt Hospital Bank" in rv.data
        assert b"Red Cross Centre" not in rv.data

    def test_filter_by_category(self, app, client):
        self._setup(app)
        creds = _seed_user(app)
        _login(client, creds)
        rv = client.get("/bloodbanks?category=Government")
        assert b"Govt Hospital Bank" in rv.data
        assert b"Apollo Blood Bank" not in rv.data

    def test_no_results_shows_empty_message(self, app, client):
        self._setup(app)
        creds = _seed_user(app)
        _login(client, creds)
        rv = client.get("/bloodbanks?name=zzznomatch")
        assert b"No blood banks match" in rv.data

    def test_combined_state_and_name_filter(self, app, client):
        self._setup(app)
        creds = _seed_user(app)
        _login(client, creds)
        rv = client.get("/bloodbanks?state=Kerala&name=red")
        assert b"Red Cross Centre" in rv.data
        assert b"Govt Hospital Bank" not in rv.data


# ---------------------------------------------------------------------------
# 6. Pagination
# ---------------------------------------------------------------------------

class TestBloodBankPagination:
    def _insert_many(self, app, n=30):
        from database import get_db
        db = get_db()
        for i in range(n):
            db.execute(
                "INSERT INTO blood_banks (name, state, district, city, category)"
                " VALUES (?,?,?,?,?)",
                (f"Bank {i:03d}", "PaginState", "PaginDist", "PaginCity", "Government"),
            )
        db.commit()
        db.close()

    def test_first_page_has_25_results(self, app, client):
        self._insert_many(app, 30)
        creds = _seed_user(app)
        _login(client, creds)
        rv = client.get("/bloodbanks?state=PaginState")
        # 25 "View" buttons = 25 rows on page 1
        assert rv.data.count(b"View") == 25

    def test_second_page_has_remaining_results(self, app, client):
        self._insert_many(app, 30)
        creds = _seed_user(app)
        _login(client, creds)
        rv = client.get("/bloodbanks?state=PaginState&page=2")
        assert rv.data.count(b"View") == 5

    def test_invalid_page_defaults_to_1(self, app, client):
        self._insert_many(app, 5)
        creds = _seed_user(app)
        _login(client, creds)
        rv = client.get("/bloodbanks?page=notanumber")
        assert rv.status_code == 200

    def test_total_count_displayed(self, app, client):
        self._insert_many(app, 10)
        creds = _seed_user(app)
        _login(client, creds)
        rv = client.get("/bloodbanks?state=PaginState")
        assert b"10 result" in rv.data


# ---------------------------------------------------------------------------
# 7. Detail page
# ---------------------------------------------------------------------------

class TestBloodBankDetail:
    def test_detail_shows_bank_name(self, app, client):
        from database import get_db
        db = get_db()
        bid = _insert_bank(db, name="Detail Test Bank", state="Goa",
                           district="North Goa", city="Panaji")
        db.close()
        creds = _seed_user(app)
        _login(client, creds)
        rv = client.get(f"/bloodbanks/{bid}")
        assert rv.status_code == 200
        assert b"Detail Test Bank" in rv.data

    def test_detail_shows_source_disclaimer(self, app, client):
        from database import get_db
        db = get_db()
        bid = _insert_bank(db)
        db.close()
        creds = _seed_user(app)
        _login(client, creds)
        rv = client.get(f"/bloodbanks/{bid}")
        assert b"not live" in rv.data

    def test_detail_shows_state_and_city(self, app, client):
        from database import get_db
        db = get_db()
        bid = _insert_bank(db, state="Rajasthan", city="Jaipur")
        db.close()
        creds = _seed_user(app)
        _login(client, creds)
        rv = client.get(f"/bloodbanks/{bid}")
        assert b"Rajasthan" in rv.data
        assert b"Jaipur" in rv.data


# ---------------------------------------------------------------------------
# 8. DB integrity — blood_banks is separate from donors
# ---------------------------------------------------------------------------

class TestDataSeparation:
    def test_blood_banks_not_in_donors_table(self, app):
        from database import get_db
        db = get_db()
        _insert_bank(db, name="Isolation Bank")
        donor_count = db.execute("SELECT COUNT(*) FROM donors").fetchone()[0]
        bb_count = db.execute("SELECT COUNT(*) FROM blood_banks").fetchone()[0]
        db.close()
        assert donor_count == 0
        assert bb_count == 1

    def test_transfusion_records_not_in_donors(self, app):
        from database import get_db
        db = get_db()
        db.execute(
            "INSERT INTO transfusion_records (recency, frequency, monetary, time_months, donated)"
            " VALUES (2, 5, 1250, 16, 1)"
        )
        db.commit()
        donor_count = db.execute("SELECT COUNT(*) FROM donors").fetchone()[0]
        tf_count = db.execute("SELECT COUNT(*) FROM transfusion_records").fetchone()[0]
        db.close()
        assert donor_count == 0
        assert tf_count == 1

    def test_deleting_blood_bank_does_not_affect_donors(self, app):
        from database import get_db
        db = get_db()
        bid = _insert_bank(db)
        # Insert a donor
        from security.crypto import encrypt
        db.execute(
            "INSERT INTO donors (full_name, blood_group, donation_type, registered_by)"
            " VALUES (?,?,?,NULL)",
            (encrypt("Test Donor"), "A+", "blood"),
        )
        db.commit()
        db.execute("DELETE FROM blood_banks WHERE id=?", (bid,))
        db.commit()
        donor_count = db.execute("SELECT COUNT(*) FROM donors").fetchone()[0]
        db.close()
        assert donor_count == 1
