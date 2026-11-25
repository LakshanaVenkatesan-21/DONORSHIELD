"""
security/snort_runner.py
========================
Snort 2.x integration for DonorShield — offline PCAP analysis only.

Scope and limitations
---------------------
* Runs Snort 2.9.x in offline read-file mode (-r <pcap>) against a
  caller-supplied PCAP file.  No live capture is performed.
* Snort must already be installed.  The executable path is resolved from
  the DS_SNORT_PATH environment variable, then a fixed Windows default,
  then PATH.
* A minimal snort.conf and donorshield.rules file are written to a temp
  directory for each run so the caller's Snort installation is not modified.
* Alerts are parsed from Snort's fast-alert output (-A fast) and returned
  as NetworkAlert objects with source="snort" so they are visually distinct
  from Scapy results in the dashboard.
* Full packet payloads are never stored.  Only timestamp, rule message,
  classification, priority, src IP, dst IP, and dst port are extracted.

Snort alert line format (fast mode):
  MM/DD-HH:MM:SS.ffffff  [**] [gid:sid:rev] msg [**] [Classification: ...] [Priority: N] {PROTO} src:sport -> dst:dport
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from security.network_monitor import NetworkAlert, STATUS_NEW

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SNORT_DEFAULT_PATH = r"C:\Users\Admin\Snort\bin\snort.exe"
SNORT_CONF_FILENAME = "donorshield_snort.conf"
SNORT_RULES_FILENAME = "donorshield.rules"

# Snort rules tuned for the three threat patterns DonorShield already detects
# with Scapy, plus common web-attack signatures relevant to a health portal.
# Uses standalone event_filter directives in the conf (Snort 2.9 correct syntax)
# rather than inline threshold/detection_filter keywords.
DONORSHIELD_RULES = """\
# DonorShield Snort rules — offline analysis only
# Rate-based suppression is configured via event_filter in the conf file.
# Priority: 1=high, 2=medium, 3=low (maps to DonorShield severity labels).

# --- Port scan / SYN flood indicators (HIGH) ---
alert tcp any any -> $HOME_NET any (msg:"DS SYN Scan Detected"; flags:S; priority:1; sid:9100001; rev:3;)

# --- High connection rate / DoS indicator (MEDIUM) ---
alert tcp any any -> $HOME_NET any (msg:"DS High Connection Rate"; flags:S; priority:2; sid:9100002; rev:3;)

# --- Repeated connection attempts to same port / brute-force (LOW) ---
alert tcp any any -> $HOME_NET 22 (msg:"DS Repeated SSH Connection Attempts"; flags:S; priority:3; sid:9100003; rev:3;)
alert tcp any any -> $HOME_NET 80 (msg:"DS Repeated HTTP Connection Attempts"; flags:S; priority:3; sid:9100004; rev:3;)
alert tcp any any -> $HOME_NET 443 (msg:"DS Repeated HTTPS Connection Attempts"; flags:S; priority:3; sid:9100005; rev:3;)
alert tcp any any -> $HOME_NET 5000 (msg:"DS Repeated Flask Port Connection Attempts"; flags:S; priority:3; sid:9100006; rev:3;)

# --- ICMP ping sweep (MEDIUM) ---
alert icmp any any -> $HOME_NET any (msg:"DS ICMP Ping Sweep"; itype:8; priority:2; sid:9100007; rev:3;)

# --- HTTP suspicious patterns (HIGH) ---
alert tcp any any -> $HOME_NET 80 (msg:"DS SQL Injection Attempt"; content:"UNION SELECT"; nocase; priority:1; sid:9100008; rev:3;)
alert tcp any any -> $HOME_NET 80 (msg:"DS XSS Attempt"; content:"<script>"; nocase; priority:1; sid:9100009; rev:3;)
"""

# Minimal snort.conf for offline analysis.
# event_filter directives suppress repeated alerts from the same source
# until the count threshold is reached within the time window.
# This is the correct Snort 2.9 syntax (not inline threshold/detection_filter).
SNORT_CONF_TEMPLATE = """\
ipvar HOME_NET any
ipvar EXTERNAL_NET any

# Disable checksum validation so Snort processes synthetic/replayed PCAPs
# that may have incorrect checksums (e.g. traffic captured with offloading).
config checksum_mode: none

config detection: search-method ac-split search-optimize max-pattern-len 20

include {rules_path}

# Rate-based event filters — fire once per source after count is reached
# SYN scan: alert after 15 SYNs from same src within 60s
event_filter gen_id 1, sig_id 9100001, type threshold, track by_src, count 15, seconds 60
# High rate: alert after 50 packets from same src within 10s
event_filter gen_id 1, sig_id 9100002, type threshold, track by_src, count 50, seconds 10
# Repeated SSH: alert after 20 SYNs from same src within 60s
event_filter gen_id 1, sig_id 9100003, type threshold, track by_src, count 20, seconds 60
# Repeated HTTP: alert after 20 SYNs from same src within 60s
event_filter gen_id 1, sig_id 9100004, type threshold, track by_src, count 20, seconds 60
# Repeated HTTPS: alert after 20 SYNs from same src within 60s
event_filter gen_id 1, sig_id 9100005, type threshold, track by_src, count 20, seconds 60
# Repeated Flask port: alert after 20 SYNs from same src within 60s
event_filter gen_id 1, sig_id 9100006, type threshold, track by_src, count 20, seconds 60
# ICMP ping sweep: alert after 10 pings from same src within 60s
event_filter gen_id 1, sig_id 9100007, type threshold, track by_src, count 10, seconds 60
"""

# Regex for Snort fast-alert output lines:
# 01/15-14:23:01.123456  [**] [1:9100001:1] DS SYN Scan Detected [**] [Priority: 2] {TCP} 10.0.0.5:54321 -> 192.168.1.1:80
_FAST_ALERT_RE = re.compile(
    r"(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)"   # timestamp
    r"\s+\[\*\*\]\s+"
    r"\[[\d:]+\]\s+"                             # [gid:sid:rev]
    r"(.+?)"                                     # message
    r"\s+\[\*\*\]"
    r"(?:\s+\[Classification:\s*([^\]]*)\])?"    # optional classification
    r"\s+\[Priority:\s*(\d+)\]"                  # priority
    r"\s+\{(\w+)\}"                              # protocol
    r"\s+([\d.]+)(?::(\d+))?"                    # src_ip[:sport]
    r"\s+->\s+"
    r"([\d.]+)(?::(\d+))?"                       # dst_ip[:dport]
)

# Map Snort priority (1=high, 2=medium, 3+=low) to DonorShield severity labels
def _priority_to_severity(priority: int) -> str:
    if priority <= 1:
        return "high"
    if priority == 2:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

class SnortNotFoundError(Exception):
    """Raised when the Snort executable cannot be located."""


def find_snort() -> str:
    """
    Return the absolute path to snort.exe.
    Resolution order:
      1. DS_SNORT_PATH environment variable
      2. SNORT_DEFAULT_PATH constant (C:\\Users\\Admin\\Snort\\bin\\snort.exe)
      3. 'snort' on PATH (via shutil.which)
    Raises SnortNotFoundError if none found.
    """
    candidates = [
        os.environ.get("DS_SNORT_PATH", ""),
        SNORT_DEFAULT_PATH,
    ]
    import shutil
    path_hit = shutil.which("snort")
    if path_hit:
        candidates.append(path_hit)

    for c in candidates:
        if c and os.path.isfile(c):
            return c

    raise SnortNotFoundError(
        "Snort executable not found. Install Snort and set DS_SNORT_PATH, "
        "or ensure snort.exe is on PATH."
    )


def find_tshark() -> str:
    """
    Return the absolute path to tshark.exe (Wireshark CLI).
    Resolution order:
      1. DS_TSHARK_PATH environment variable
      2. Default Wireshark install path on Windows
      3. 'tshark' on PATH
    Raises FileNotFoundError if not found.
    """
    candidates = [
        os.environ.get("DS_TSHARK_PATH", ""),
        r"C:\Program Files\Wireshark\tshark.exe",
    ]
    import shutil
    path_hit = shutil.which("tshark")
    if path_hit:
        candidates.append(path_hit)

    for c in candidates:
        if c and os.path.isfile(c):
            return c

    raise FileNotFoundError(
        "tshark not found. Install Wireshark and ensure tshark.exe is accessible, "
        "or set DS_TSHARK_PATH."
    )


class TsharkNotFoundError(Exception):
    """Raised when TShark cannot be located."""


class TsharkRunError(Exception):
    """Raised when TShark cannot analyse a capture."""


def run_tshark_on_pcap(pcap_path: str, source_name: str | None = None) -> dict:
    """Summarize offline capture metadata without reading packet payloads."""
    import csv
    import io
    from collections import Counter

    from security.network_monitor import PcapValidationError, validate_pcap_path

    try:
        validate_pcap_path(pcap_path)
    except PcapValidationError as exc:
        raise TsharkRunError(f"Invalid PCAP file: {exc}") from exc

    try:
        tshark_exe = find_tshark()
    except FileNotFoundError as exc:
        raise TsharkNotFoundError(str(exc)) from exc

    cmd = [
        tshark_exe,
        "-r", os.path.abspath(pcap_path),
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.protocols",
        "-e", "ip.src",
        "-e", "ipv6.src",
        "-e", "ip.dst",
        "-e", "ipv6.dst",
        "-c", "100001",
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        raise TsharkRunError("TShark timed out after 30 seconds.") from exc
    except FileNotFoundError as exc:
        raise TsharkNotFoundError(
            f"TShark executable not found: {tshark_exe}"
        ) from exc

    if proc.returncode:
        detail = (proc.stderr or "TShark could not read this capture.").strip()
        raise TsharkRunError(detail[:500])

    protocols = Counter()
    sources = Counter()
    destinations = Counter()
    packet_count = 0

    for row in csv.reader(io.StringIO(proc.stdout), delimiter="\t"):
        if not row or not row[0]:
            continue

        packet_count += 1
        protocol_stack = row[1].split(":") if len(row) > 1 and row[1] else []
        protocol = protocol_stack[-1].upper() if protocol_stack else "UNKNOWN"
        protocols[protocol] += 1

        source_ip = next(
            (row[i] for i in (2, 3) if len(row) > i and row[i]), ""
        )
        destination_ip = next(
            (row[i] for i in (4, 5) if len(row) > i and row[i]), ""
        )
        if source_ip:
            sources[source_ip] += 1
        if destination_ip:
            destinations[destination_ip] += 1

    return {
        "pcap_file": source_name or os.path.basename(pcap_path),
        "tshark_path": tshark_exe,
        "packets_read": min(packet_count, 100000),
        "truncated": packet_count > 100000,
        "protocols": [
            {"name": name, "count": count}
            for name, count in protocols.most_common(12)
        ],
        "sources": [
            {"ip": ip, "count": count}
            for ip, count in sources.most_common(10)
        ],
        "destinations": [
            {"ip": ip, "count": count}
            for ip, count in destinations.most_common(10)
        ],
    }


# ---------------------------------------------------------------------------
# Alert parsing
# ---------------------------------------------------------------------------

def parse_snort_fast_output(output: str, source_file: str = "") -> list[NetworkAlert]:
    """
    Parse Snort fast-alert output text and return a list of NetworkAlert objects.
    Each alert has source_file set and rule_id prefixed with 'SNORT_'.
    Duplicate (msg, src_ip, dst_ip, dst_port) combinations within one output
    are deduplicated — Snort may emit the same alert multiple times.
    """
    alerts: list[NetworkAlert] = []
    seen: set[tuple] = set()

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _FAST_ALERT_RE.search(line)
        if not m:
            continue

        (ts_str, msg, classification, priority_str,
         proto, src_ip, src_port, dst_ip, dst_port_str) = m.groups()

        priority = int(priority_str) if priority_str else 3
        dst_port = int(dst_port_str) if dst_port_str else None

        # Derive a stable rule_id from the message text
        rule_id = "SNORT_" + re.sub(r"[^A-Z0-9]+", "_", msg.upper()).strip("_")

        dedup_key = (rule_id, src_ip, dst_ip, dst_port)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        reason_parts = [f"{msg} ({proto} {src_ip} -> {dst_ip}"]
        if dst_port:
            reason_parts.append(f":{dst_port}")
        reason_parts.append(")")
        if classification:
            reason_parts.append(f" [{classification.strip()}]")
        reason = "".join(reason_parts)

        alerts.append(NetworkAlert(
            rule_id=rule_id,
            severity=_priority_to_severity(priority),
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            reason=reason,
            source_file=source_file,
            status=STATUS_NEW,
        ))

    return alerts


# ---------------------------------------------------------------------------
# Snort runner
# ---------------------------------------------------------------------------

class SnortRunError(Exception):
    """Raised when Snort exits with an error."""


def run_snort_on_pcap(pcap_path: str, source_name: str | None = None) -> dict:
    """
    Run Snort 2.9.x in offline mode against *pcap_path*.

    Writes a temporary snort.conf and rules file, runs:
        snort.exe -c <conf> -r <pcap> -A fast -l <logdir> -K none -q

    Returns a dict:
        {
            "pcap_file":   str,
            "alerts":      list[NetworkAlert],   # source="snort" implied by rule_id prefix
            "snort_path":  str,
            "raw_output":  str,   # full stdout+stderr for diagnostics
        }

    Raises SnortNotFoundError if Snort is not installed.
    Raises SnortRunError if Snort exits non-zero with a fatal error.
    """
    snort_exe = find_snort()
    basename = source_name if source_name else os.path.basename(pcap_path)

    with tempfile.TemporaryDirectory() as tmpdir:
        rules_path = os.path.join(tmpdir, SNORT_RULES_FILENAME)
        conf_path  = os.path.join(tmpdir, SNORT_CONF_FILENAME)
        log_dir    = os.path.join(tmpdir, "log")
        os.makedirs(log_dir, exist_ok=True)

        with open(rules_path, "w") as f:
            f.write(DONORSHIELD_RULES)

        conf_content = SNORT_CONF_TEMPLATE.replace("{rules_path}", rules_path)
        with open(conf_path, "w") as f:
            f.write(conf_content)

        cmd = [
            snort_exe,
            "-c", conf_path,
            "-r", pcap_path,
            "-A", "fast",
            "-l", log_dir,
            "-K", "none",   # no binary logging
            "-q",           # quiet — suppress banner
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            raise SnortRunError("Snort timed out after 120 seconds.")
        except FileNotFoundError:
            raise SnortNotFoundError(f"Snort executable not found at: {snort_exe}")

        raw_output = proc.stdout + proc.stderr

        # Snort 2.9 exits 0 on success and also on "no alerts found".
        # A non-zero exit with no output usually means a config error.
        if proc.returncode != 0 and not raw_output.strip():
            raise SnortRunError(
                f"Snort exited with code {proc.returncode} and no output. "
                "Check that the PCAP file is valid and Snort is correctly installed."
            )

        # Snort 2.9 on Windows writes fast-alert output to alert.ids in the
        # log directory (not to stdout).  Read all candidate alert files.
        for alert_filename in ("alert", "alert.ids", "alert.txt"):
            alert_file = os.path.join(log_dir, alert_filename)
            if os.path.isfile(alert_file) and os.path.getsize(alert_file) > 0:
                with open(alert_file, errors="replace") as af:
                    raw_output += af.read()

        alerts = parse_snort_fast_output(raw_output, source_file=basename)

    return {
        "pcap_file":  basename,
        "alerts":     alerts,
        "snort_path": snort_exe,
        "raw_output": raw_output,
    }
