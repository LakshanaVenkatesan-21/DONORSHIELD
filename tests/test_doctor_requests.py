import importlib
import os
import tempfile
import pytest
from werkzeug.security import generate_password_hash


@pytest.fixture()
def app():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.environ["DB_PATH"] = path
    os.environ["TESTING"] = "true"
    os.environ["DS_AES_KEY"] = "ab" * 32
    import database
    import app as app_module
    importlib.reload(database)
    importlib.reload(app_module)
    database.init_db()
    app_module.app.config.update(TESTING=True, SECRET_KEY="test-secret", WTF_CSRF_ENABLED=False)
    yield app_module.app
    os.close(fd)
    os.unlink(path)
    for key in ("DB_PATH", "TESTING", "DS_AES_KEY"):
        os.environ.pop(key, None)


@pytest.fixture()
def client(app):
    return app.test_client()


def _db():
    from database import get_db
    return get_db()


def _user(app, username, role):
    db = _db()
    cur = db.execute("INSERT INTO users(username,password,role) VALUES(?,?,?)",
                     (username, generate_password_hash("Password1!"), role))
    db.commit()
    user_id = cur.lastrowid
    db.close()
    return user_id


def _login(client, username):
    return client.post("/login", data={"username": username, "password": "Password1!"}, follow_redirects=True)


def _payload():
    return {"request_type": "blood", "blood_group": "O+", "quantity": "2",
            "location": "Central Hospital", "urgency": "urgent", "details": "Two units needed"}


def test_doctor_create_is_audited_and_requests_are_private(app, client):
    doctor_id = _user(app, "doc_one", "doctor")
    _user(app, "doc_two", "doctor")
    _login(client, "doc_one")
    response = client.post("/requests", data=_payload(), follow_redirects=True)
    assert response.status_code == 200 and b"Two units needed" in response.data
    db = _db()
    row = db.execute("SELECT * FROM doctor_requests WHERE doctor_id=?", (doctor_id,)).fetchone()
    event = db.execute("SELECT * FROM audit_events WHERE event_type='DOCTOR_REQUEST_CREATED'").fetchone()
    db.close()
    assert row["status"] == "Pending" and event is not None
    client.get("/logout")
    _login(client, "doc_two")
    assert b"Two units needed" not in client.get("/requests").data
    assert client.post(f"/requests/{row['id']}/status", data={"status": "Approved"}).status_code == 302
    db = _db()
    assert db.execute("SELECT status FROM doctor_requests WHERE id=?", (row["id"],)).fetchone()[0] == "Pending"
    db.close()


def test_staff_updates_request_and_audit_records_change(app, client):
    doctor_id = _user(app, "doc_three", "doctor")
    staff_id = _user(app, "staff_three", "staff")
    db = _db()
    cur = db.execute("INSERT INTO doctor_requests(doctor_id,request_type,blood_group,quantity,location,urgency,details) VALUES(?,?,?,?,?,?,?)",
                     (doctor_id, "blood", "A+", 1, "Clinic", "routine", "Need blood"))
    db.commit()
    request_id = cur.lastrowid
    db.close()
    _login(client, "staff_three")
    response = client.post(f"/requests/{request_id}/status", data={"status": "Approved", "response": "Ready"}, follow_redirects=True)
    assert response.status_code == 200
    db = _db()
    row = db.execute("SELECT * FROM doctor_requests WHERE id=?", (request_id,)).fetchone()
    event = db.execute("SELECT * FROM audit_events WHERE event_type='DOCTOR_REQUEST_STATUS'").fetchone()
    db.close()
    assert (row["status"], row["response"], row["processed_by"]) == ("Approved", "Ready", staff_id)
    assert event is not None and f"#{request_id}" in event["description"]


def test_status_endpoint_rejects_invalid_state(app, client):
    doctor_id = _user(app, "doc_four", "doctor")
    _user(app, "admin_four", "admin")
    db = _db()
    cur = db.execute("INSERT INTO doctor_requests(doctor_id,request_type,organ_type,quantity,location,urgency,details) VALUES(?,?,?,?,?,?,?)",
                     (doctor_id, "organ", "Kidney", 1, "Hospital", "emergency", "Urgent need"))
    db.commit()
    request_id = cur.lastrowid
    db.close()
    _login(client, "admin_four")
    response = client.post(f"/requests/{request_id}/status", data={"status": "Invalid"}, follow_redirects=True)
    assert b"Invalid request status" in response.data
    db = _db()
    assert db.execute("SELECT status FROM doctor_requests WHERE id=?", (request_id,)).fetchone()[0] == "Pending"
    db.close()


def _blood_request(doctor_id, units, blood_group="A+"):
    db = _db()
    cur = db.execute("INSERT INTO doctor_requests(doctor_id,request_type,blood_group,quantity,location,urgency,details,status) "
                     "VALUES(?,?,?,?,?,?,?,'Approved')",
                     (doctor_id, "blood", blood_group, units, "Clinic", "urgent", "Test request"))
    db.commit()
    request_id = cur.lastrowid
    db.close()
    return request_id


def _set_units(group, units):
    db = _db()
    db.execute("UPDATE blood_inventory SET units=? WHERE blood_group=?", (units, group))
    db.commit()
    db.close()


def test_inventory_displays_actual_counts_and_prediction_demo(app, client):
    _user(app, "stock_admin", "admin")
    _set_units("O+", 27)
    _login(client, "stock_admin")
    inventory = client.get("/inventory")
    dashboard = client.get("/dashboard")
    assert b"27" in inventory.data
    assert b"DEMONSTRATION MODE" in inventory.data
    assert b"DEMONSTRATION MODE" in dashboard.data
    assert b"Demonstration risk" in dashboard.data


def test_quantity_must_be_positive_integer(app, client):
    _user(app, "quantity_doc", "doctor")
    _login(client, "quantity_doc")
    response = client.post("/requests", data={**_payload(), "quantity": "0"}, follow_redirects=True)
    assert b"Quantity must be between 1 and 9999" in response.data
    db = _db()
    assert db.execute("SELECT COUNT(*) FROM doctor_requests").fetchone()[0] == 0
    db.close()


def test_transfer_deducts_once_atomically_and_audits(app, client):
    doctor_id = _user(app, "transfer_doc", "doctor")
    staff_id = _user(app, "transfer_staff", "staff")
    _set_units("A+", 7)
    request_id = _blood_request(doctor_id, 3)
    _login(client, "transfer_staff")
    completed = client.post(f"/requests/{request_id}/complete-transfer", data={}, follow_redirects=True)
    assert completed.status_code == 200 and b"Transfer completed" in completed.data
    db = _db()
    stock = db.execute("SELECT units FROM blood_inventory WHERE blood_group='A+'").fetchone()[0]
    row = db.execute("SELECT * FROM doctor_requests WHERE id=?", (request_id,)).fetchone()
    event = db.execute("SELECT * FROM audit_events WHERE event_type='BLOOD_TRANSFER_COMPLETED'").fetchone()
    assert stock == 4
    assert (row["status"], row["transferred_units"], row["processed_by"]) == ("Fulfilled", 3, staff_id)
    assert row["transfer_completed_at"] and event["user_id"] == staff_id
    assert all(term in event["description"] for term in (f"#{request_id}", "3 units", "7->4"))
    db.close()
    duplicate = client.post(f"/requests/{request_id}/complete-transfer", data={}, follow_redirects=True)
    assert b"Only approved, incomplete blood requests" in duplicate.data
    db = _db()
    assert db.execute("SELECT units FROM blood_inventory WHERE blood_group='A+'").fetchone()[0] == 4
    db.close()


def test_insufficient_stock_and_unauthorized_transfer_do_not_change_data(app, client):
    doctor_id = _user(app, "limited_doc", "doctor")
    _user(app, "other_doc", "doctor")
    _user(app, "limited_staff", "staff")
    _set_units("B+", 2)
    request_id = _blood_request(doctor_id, 5, "B+")
    _login(client, "other_doc")
    denied = client.post(f"/requests/{request_id}/complete-transfer", data={})
    assert denied.status_code == 302
    client.get("/logout")
    _login(client, "limited_staff")
    insufficient = client.post(f"/requests/{request_id}/complete-transfer", data={}, follow_redirects=True)
    assert b"Insufficient inventory" in insufficient.data
    db = _db()
    assert db.execute("SELECT units FROM blood_inventory WHERE blood_group='B+'").fetchone()[0] == 2
    assert db.execute("SELECT status FROM doctor_requests WHERE id=?", (request_id,)).fetchone()[0] == "Approved"
    assert db.execute("SELECT COUNT(*) FROM audit_events WHERE event_type='BLOOD_TRANSFER_COMPLETED'").fetchone()[0] == 0
    db.close()


def test_approved_request_does_not_deduct_until_transfer_confirmation(app, client):
    doctor_id = _user(app, "approval_doc", "doctor")
    _user(app, "approval_staff", "staff")
    _set_units("AB+", 9)
    request_id = _blood_request(doctor_id, 4, "AB+")
    _login(client, "approval_staff")
    page = client.get("/requests")
    assert b"Confirm Transfer Completed" in page.data
    db = _db()
    assert db.execute("SELECT units FROM blood_inventory WHERE blood_group='AB+'").fetchone()[0] == 9
    db.close()


def test_random_forest_prediction_has_risk_for_each_group(app):
    from security.shortage_prediction import predict_shortage_risks, MODE
    db = _db()
    inventory = db.execute("SELECT blood_group,units FROM blood_inventory ORDER BY blood_group").fetchall()
    db.close()
    result = predict_shortage_risks(inventory, {"A+": 14})
    assert result["mode"] == MODE and "DEMONSTRATION" in result["mode"]
    assert len(result["risks"]) == 8
    assert {item["risk"] for item in result["risks"]} <= {"Low", "Medium", "High"}
