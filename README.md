# DonorShield

**Secure Blood and Organ Donation Management with Network Threat Detection**
MCA – Network and Cyber Security Project, 2025

---

## Tech Stack

| Layer    | Technology |
|----------|------------|
| Backend  | Python 3.13, Flask 3.1 |
| Database | SQLite (via Python `sqlite3`) |
| Frontend | HTML5, Bootstrap 5.3, JavaScript |
| Security | Werkzeug password hashing (scrypt/PBKDF2), secure sessions, role-based access control, audit logging, AES-256-GCM encryption, RSA-PSS digital signatures, CSRF protection (Flask-WTF), brute-force lockout, security HTTP headers, offline PCAP intrusion detection (`cryptography`, `Flask-WTF`, `scapy` libraries) |

---

## Project Structure

```
DONORSHIELD/
├── app.py                  # Flask application, routes, session config
├── database.py             # Schema creation and DB connection helper
├── seed_data.py            # Import script for blood-banks.csv and transfusion.data
├── requirements.txt        # Pinned dependencies
├── pytest.ini              # pytest configuration
├── conftest.py             # pytest sys.path fix
├── .env.example            # Environment variable reference (NOT auto-loaded — see Setup)
├── .gitignore
├── blood-banks.csv         # NBTC/eRaktKosh blood bank directory (2823 records)
├── transfusion.data        # UCI RFMTC dataset — 748 records, 5 columns
├── transfusion.names       # UCI dataset description and citation
├── donorshield.db          # Created automatically on first run (git-ignored)
├── security/
│   ├── __init__.py
│   ├── crypto.py           # AES-256-GCM encrypt/decrypt, SHA-256 integrity
│   ├── signatures.py       # RSA-2048 key generation, PSS sign/verify
│   └── network_monitor.py  # Offline PCAP analysis, detection engine, alert persistence
├── tests/
│   ├── test_app.py               # Stage 1 — auth, roles, audit logging
│   ├── test_crypto.py            # Stage 2 — AES-256-GCM, SHA-256
│   ├── test_donor_encryption.py  # Stage 3 — donor field encryption
│   ├── test_signatures.py        # Stage 4 — RSA key generation and signing
│   ├── test_report.py            # Stage 4 — signed audit report export
│   ├── test_bloodbanks.py        # Stage 5/6 — blood bank directory and RFMTC data
│   ├── test_security.py          # Stage 7 — brute-force, headers, CSRF, security dashboard
│   └── test_network_monitor.py   # Stage 8 — offline PCAP analysis and intrusion detection
├── keys/
│   ├── private.pem         # RSA private key — git-ignored, never commit
│   └── public.pem          # RSA public key — safe to distribute
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── dashboard.html
│   ├── login.html
│   ├── register.html
│   ├── donors.html
│   ├── add_donor.html
│   ├── audit.html
│   ├── security.html         # Admin-only security dashboard
│   ├── csrf_error.html       # CSRF validation failure page
│   ├── bloodbanks.html       # Blood bank directory with search/filter/pagination
│   ├── bloodbank_detail.html # Individual blood bank detail page
│   └── monitor.html          # Admin-only network alert dashboard
└── static/
    ├── css/style.css
    └── js/main.js
```

---

## Roles

| Role   | Permissions |
|--------|-------------|
| admin  | Full access: all data, audit log, donor management, security dashboard, network monitor |
| staff  | Register donors, view inventory, donor list, blood bank directory |
| doctor | View donors, inventory, blood bank directory (read-only) |

Admin accounts are created only via `flask create-admin`. Public registration is limited to `staff` and `doctor` roles.

---

## Setup (Windows PowerShell)

### 1. Navigate to the project folder

```powershell
cd "$env:USERPROFILE\Documents\DONORSHIELD"
```

### 2. Create and activate the virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

> If you get an execution policy error, run once:
> ```powershell
> Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
> ```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

### 4. Set required environment variables

DonorShield reads configuration from environment variables. The `.env.example`
file is a reference only — it is **not** loaded automatically (there is no
`python-dotenv` dependency). Set variables in your PowerShell session before
running the app or tests.

**Required for donor encryption (must be set before first run):**

```powershell
# Generate a 64-character hex key (run once, save the output securely):
python -c "import secrets; print(secrets.token_hex(32))"

# Set for the current session:
$env:DS_AES_KEY = "paste-your-64-char-hex-key-here"

# Set permanently for your Windows user account (survives reboots):
[System.Environment]::SetEnvironmentVariable("DS_AES_KEY", "paste-your-64-char-hex-key-here", "User")
# Restart PowerShell after setting permanently.
```

**Optional (safe defaults are used if not set):**

```powershell
# Flask session secret — auto-generated each restart if not set.
# Set permanently for a stable session across restarts:
$env:SECRET_KEY = "paste-a-long-random-string-here"

# Enable the Secure cookie flag (HTTPS deployments only):
# $env:SESSION_COOKIE_SECURE = "true"
```

**Verify the AES key is loaded:**

```powershell
python -c "from security.crypto import encrypt, decrypt_str; print(decrypt_str(encrypt('ok')))"
# Expected output: ok
```

> **Security note:** Never commit `DS_AES_KEY` or `SECRET_KEY` to version
> control. Never log them or include them in HTTP responses. If `DS_AES_KEY`
> is lost, encrypted donor data cannot be recovered.

### 5. Run the application

```powershell
python app.py
```

The database (`donorshield.db`) is created automatically on first run.

### 6. Import datasets (run once after first launch)

```powershell
python seed_data.py
```

Expected output:
```
Initialising database schema...

Importing blood-banks.csv...
  Imported : 2815
  Skipped  : 8  (duplicates / already present)
  Rejected : 0  (missing mandatory fields)

Importing transfusion.data...
  Imported : 533
  Skipped  : 215  (duplicate RFMTC tuples)
  Rejected : 0  (invalid values)
```

The script is safe to re-run — blood bank rows already in the database are
skipped, and transfusion records are cleared and reloaded.

### 7. Create the first admin account

In a second terminal with `.venv` active:

```powershell
$env:FLASK_APP = "app.py"
flask create-admin
```

Follow the prompts. Admin accounts cannot be created through the public
registration form.

### 8. Generate RSA keys for signed audit reports (run once)

```powershell
$env:FLASK_APP = "app.py"
flask generate-keys
```

This creates `keys/private.pem` (keep secret) and `keys/public.pem` (safe to
distribute). `keys/private.pem` is excluded from version control by
`.gitignore`.

### 9. Open the application

Visit **http://127.0.0.1:5000**

Staff and Doctor accounts can self-register at **/register**.

---

## Running Tests

```powershell
.\.venv\Scripts\pytest tests\ -v
```

343 tests across 8 test files. All should pass.

> Tests use isolated temporary databases and a fixed test AES key — they do
> not require `DS_AES_KEY` to be set in the environment.

---

## Demonstration Walkthrough

The following sequence covers every major feature for a college demonstration.

### 1. Registration and login

- Visit `/register` → create a **staff** account and a **doctor** account.
- Log in as staff → confirm Dashboard, Donors, Register Donor, Blood Banks are visible.
- Log in as doctor → confirm Register Donor is not visible (read-only access).

### 2. Donor registration and encryption

- Log in as staff → **Register Donor** → fill in name, blood group, contact.
- Confirm the donor appears in the Donor Registry with decrypted fields.
- Open `donorshield.db` in any SQLite viewer → confirm `full_name`, `contact`,
  `organ_type` columns contain `v1:…` ciphertext tokens, not plaintext.

### 3. Blood bank directory

- Navigate to **Blood Banks** → search by state, district, or name.
- Click any result to view the detail page.
- Confirm the static-data disclaimer is shown.

### 4. Brute-force and IP rate-limit protection

- Log out → attempt login with a wrong password 5 times for the same username.
- The 6th attempt (even with the correct password) is blocked with a generic
  error — the account is locked for 15 minutes.
- The Security Dashboard (`/security`, admin only) shows the locked account
  and failed-login count.

### 5. Signed audit report export and verification

- Log in as admin → **Audit Log** → **Export Signed Report**.
- Save the downloaded `audit_report_<timestamp>.zip`.
- Verify the signature offline:

```powershell
$env:FLASK_APP = "app.py"
flask verify-report audit_report_20250101_120000.zip
# Expected: VALID — signature verified. The report has not been modified.
```

- Open the ZIP, edit one character in `report.json`, re-run verify-report:

```
INVALID — signature verification failed. The report may have been tampered with.
```

### 6. Offline PCAP analysis

```powershell
$env:FLASK_APP = "app.py"

# Analyse without saving:
flask analyze-pcap path\to\capture.pcap

# Analyse and persist alerts to the database:
flask analyze-pcap path\to\capture.pcap --save
```

- After `--save`, log in as admin → **Network Monitor** to view, filter, and
  mark alerts as reviewed.
- Confirm non-admin roles cannot access `/monitor`.

### 7. CSRF protection

- Open browser developer tools → submit the login form without the hidden
  `csrf_token` field → confirm HTTP 400 and the CSRF error page.

### 8. Security HTTP headers

- Open browser developer tools → Network tab → inspect any response headers.
- Confirm `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Content-Security-Policy`, `Referrer-Policy`, and `Permissions-Policy` are
  present on every response.

---

## Security Notes

- Passwords are stored as **scrypt hashes** (Werkzeug 3.x default on Python
  3.13; falls back to PBKDF2-SHA256 on older builds). No plaintext passwords
  are ever saved or logged.
- Every login, failed login, registration, logout, and donor registration is
  recorded in `audit_events`.
- Sessions expire after **30 minutes** of inactivity.
- `HttpOnly` and `SameSite=Lax` cookie flags are set. `Secure` flag is enabled
  via `SESSION_COOKIE_SECURE=true` for HTTPS deployments.
- Role-based access control is enforced server-side on every protected route.
- **Brute-force protection:** 5 failed login attempts within 15 minutes locks
  the account for the remainder of that window. Lockout is time-based (no
  restart bypass). Error messages are generic — locked accounts are
  indistinguishable from wrong-password responses.
- **CSRF protection:** All state-changing POST forms include a Flask-WTF CSRF
  token. Requests without a valid token receive HTTP 400.
- **Security HTTP headers:** Every response includes `Content-Security-Policy`,
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`,
  and `Permissions-Policy`.
- **Security dashboard** at `/security` (admin only): shows failed-login
  events, currently locked accounts, and 24-hour failure counts. IP addresses
  are visible only to admins.

---

## Cryptographic Protection (Stage 2 & 3)

- **AES-256-GCM** authenticated encryption (`security/crypto.py`). Every
  encryption call uses a fresh 12-byte random nonce. The stored token format
  is versioned (`v1:<nonce>:<ciphertext+tag>`) to allow future algorithm
  migration without breaking existing data.
- **SHA-256 file integrity** utility for exported reports.
- Donor records are encrypted in the database. The `full_name`, `contact`, and
  `organ_type` fields are stored as AES-256-GCM tokens. `blood_group` and
  `donation_type` are stored in plaintext for operational filtering.

---

## Digital Signatures and Signed Audit Reports (Stage 4)

- **RSA-2048 key-pair generation** (`security/signatures.py`). Keys are saved
  as PEM files. The private key is stored outside the database and outside
  version control (`keys/private.pem` is in `.gitignore`).
- **RSA-PSS/SHA-256 signing** of exported audit reports.
- **Signed audit report export** at `/audit/export` (admin only). Returns a
  ZIP archive containing:
  - `report.json` — audit metadata (no passwords, AES keys, or decrypted PII)
  - `report.sig`  — detached RSA-PSS signature over the exact `report.json` bytes
- **`flask verify-report <zip>`** CLI command for offline verification using
  only the public key.
- The report is tamper-evident: any modification to `report.json` after export
  causes signature verification to fail.

### Verifying a report offline

```powershell
$env:FLASK_APP = "app.py"
flask verify-report audit_report_20250101_120000.zip
```

Expected output when unmodified:
```
VALID — signature verified. The report has not been modified.
```

If tampered:
```
INVALID — signature verification failed. The report may have been tampered with.
```

---

## Offline PCAP Analysis and Intrusion Detection (Stage 8)

- **Offline PCAP analysis only.** This module reads existing `.pcap`,
  `.pcapng`, or `.cap` files that the administrator explicitly provides. It
  does **not** perform live packet capture. Live capture is not implemented.
- **Three detection rules:**
  - `RULE_SYN_SCAN` — one source IP contacts ≥ 15 distinct destination ports
    via TCP SYN within 60 seconds. Severity: **high**.
  - `RULE_HIGH_RATE` — one source IP sends ≥ 200 packets within 10 seconds.
    Severity: **medium**.
  - `RULE_REPEATED_CONN` — one source IP makes ≥ 20 TCP SYN attempts to the
    same destination IP:port within 60 seconds. Severity: **low**.
- **Alert deduplication** within a single run; re-analysing the same file does
  not insert duplicate rows.
- **No payload storage.** Only source IP, destination IP, destination port,
  protocol, and TCP flags are extracted.
- **Safety limits:** files larger than 50 MB are rejected; analysis stops after
  100 000 packets per run.
- **Admin-only dashboard** at `/monitor`: view, filter, paginate, and mark
  alerts as reviewed.

### Analysing a PCAP file

```powershell
$env:FLASK_APP = "app.py"

# Analyse and print results without saving:
flask analyze-pcap path\to\capture.pcap

# Analyse and persist alerts to the database:
flask analyze-pcap path\to\capture.pcap --save
```

Example output:
```
[OFFLINE ANALYSIS] capture.pcap
  Packets read : 4821
  Alerts found : 2

  [HIGH  ] RULE_SYN_SCAN: 10.0.0.5 sent SYN packets to 18 distinct ports within 60s (threshold: 15)
  [MEDIUM] RULE_HIGH_RATE: 10.0.0.5 sent 247 packets within 10s (threshold: 200)
```

### Limitations and safe-use notice

- **Only analyse traffic you own or have explicit written permission to capture.**
  Analysing third-party traffic without authorisation may be illegal.
- Scapy (`pip install scapy`) is required and is included in `requirements.txt`.
  On Windows, Npcap is **not** required for reading existing PCAP files — only
  for live capture, which is not used here.
- Thresholds are configurable in `security/network_monitor.py`.

---

## Datasets

### blood-banks.csv — Nationwide Blood Bank Directory

| Property | Value |
|----------|-------|
| Rows | 2823 (2815 imported after dedup) |
| Columns | 27 |
| Source | NBTC / eRaktKosh open government data (India) |
| Key fields | Blood Bank Name, State, District, City, Address, Pincode, Contact, Category, Blood Component Available, Service Time, Latitude, Longitude |
| Missing data | Website (79%), Email (40%), Helpline (61%) — handled gracefully |
| Duplicates | 8 exact duplicate rows — skipped on import |
| Licence | Open government data; no personal donor identities |

**Limitation:** Contact details and availability are static as of the dataset
export date. They are **not live**. Verify directly with the blood bank before
acting on this information.

### transfusion.data — RFMTC Donation Behaviour Dataset

| Property | Value |
|----------|-------|
| Rows | 748 (533 unique after dedup) |
| Columns | 5 (Recency, Frequency, Monetary, Time, donated) |
| Source | UCI ML Repository — Blood Transfusion Service Center, Hsin-Chu City, Taiwan |
| Citation | Yeh, I-Cheng et al., *Expert Systems with Applications*, 2008. DOI: 10.1016/j.eswa.2008.07.018 |
| Target | Binary: donated in March 2007 (24% positive class) |
| Duplicates | 215 duplicate RFMTC tuples — skipped on import |
| Licence | Unlimited reuse with retention of copyright notice for Prof. I-Cheng Yeh |

**Limitation:** This dataset contains no individual identities. It is stored in
`transfusion_records` for statistical reference only. No ML model is trained or
claimed in this project.

---

## Stopping the Server

Press `Ctrl+C` in the PowerShell window running `python app.py`.
