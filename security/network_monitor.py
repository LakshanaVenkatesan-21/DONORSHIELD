"""
security/network_monitor.py
===========================
Offline PCAP analysis and network intrusion detection for DonorShield.

IMPORTANT — scope and limitations
----------------------------------
* This module performs OFFLINE analysis of PCAP files that the administrator
  explicitly selects.  It does NOT perform live packet capture.
* Live capture requires administrator/root privileges and a libpcap provider
  (Npcap on Windows, libpcap on Linux/macOS).  That is NOT implemented here.
* Never analyse traffic you do not own or have explicit permission to capture.
* Full packet payloads, credentials, cookies, and private data are never stored.

Detection rules implemented
---------------------------
RULE_SYN_SCAN
    A single source IP contacts more than SYN_SCAN_PORT_THRESHOLD distinct
    destination ports using TCP SYN packets within SYN_SCAN_WINDOW_SECONDS.
    Indicative of a port-scan attempt.

RULE_HIGH_RATE
    A single source IP sends more than HIGH_RATE_PKT_THRESHOLD packets within
    HIGH_RATE_WINDOW_SECONDS.  Indicative of a flood or DoS attempt.

RULE_REPEATED_CONN
    A single source IP makes more than REPEATED_CONN_THRESHOLD TCP connection
    attempts (SYN packets) to the same destination port within
    REPEATED_CONN_WINDOW_SECONDS.  Indicative of brute-force or service abuse.

Alert deduplication
-------------------
Within a single analysis run, identical (rule, src_ip, dst_ip, dst_port)
tuples are deduplicated — only one alert is raised per unique combination.
Across runs, the caller is responsible for deduplication (the CLI tool
reports a summary rather than re-inserting duplicates).
"""

from __future__ import annotations

import os
import collections
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

# ---------------------------------------------------------------------------
# Configurable thresholds (can be overridden in tests)
# ---------------------------------------------------------------------------

SYN_SCAN_PORT_THRESHOLD   = 15    # distinct ports within window → SYN scan
SYN_SCAN_WINDOW_SECONDS   = 60

HIGH_RATE_PKT_THRESHOLD   = 200   # total packets within window → high rate
HIGH_RATE_WINDOW_SECONDS  = 10

REPEATED_CONN_THRESHOLD   = 20    # SYN packets to same dst port → repeated conn
REPEATED_CONN_WINDOW_SECONDS = 60

MAX_PACKETS_PER_ANALYSIS  = 100_000   # safety cap per PCAP analysis run
MAX_PCAP_SIZE_BYTES       = 50 * 1024 * 1024  # 50 MB

SEVERITY_LOW    = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH   = "high"

STATUS_NEW      = "new"
STATUS_REVIEWED = "reviewed"

RULE_SYN_SCAN      = "RULE_SYN_SCAN"
RULE_HIGH_RATE     = "RULE_HIGH_RATE"
RULE_REPEATED_CONN = "RULE_REPEATED_CONN"


# ---------------------------------------------------------------------------
# Alert data class
# ---------------------------------------------------------------------------

@dataclass
class NetworkAlert:
    rule_id:     str
    severity:    str
    src_ip:      Optional[str]
    dst_ip:      Optional[str]
    dst_port:    Optional[int]
    reason:      str
    timestamp:   str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status:      str = STATUS_NEW
    source_file: Optional[str] = None   # PCAP filename (basename only, no path)


# ---------------------------------------------------------------------------
# Detection engine
# ---------------------------------------------------------------------------

class DetectionEngine:
    """
    Stateless detection engine.  Feed it a list of parsed packet summaries
    (dicts with keys: src_ip, dst_ip, dst_port, proto, flags, timestamp_float)
    and receive a deduplicated list of NetworkAlert objects.
    """

    def __init__(
        self,
        syn_scan_port_threshold:    int = SYN_SCAN_PORT_THRESHOLD,
        syn_scan_window:            int = SYN_SCAN_WINDOW_SECONDS,
        high_rate_pkt_threshold:    int = HIGH_RATE_PKT_THRESHOLD,
        high_rate_window:           int = HIGH_RATE_WINDOW_SECONDS,
        repeated_conn_threshold:    int = REPEATED_CONN_THRESHOLD,
        repeated_conn_window:       int = REPEATED_CONN_WINDOW_SECONDS,
    ):
        self.syn_scan_port_threshold = syn_scan_port_threshold
        self.syn_scan_window         = syn_scan_window
        self.high_rate_pkt_threshold = high_rate_pkt_threshold
        self.high_rate_window        = high_rate_window
        self.repeated_conn_threshold = repeated_conn_threshold
        self.repeated_conn_window    = repeated_conn_window

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyse(self, packets: list[dict]) -> list[NetworkAlert]:
        """
        Run all detection rules over *packets* and return deduplicated alerts.

        Each packet dict must contain:
            src_ip          str | None
            dst_ip          str | None
            dst_port        int | None
            proto           str  ('TCP', 'UDP', 'OTHER')
            flags           str  (TCP flags string, e.g. 'S', 'SA', '' for non-TCP)
            timestamp_float float (Unix epoch seconds)
        """
        alerts: list[NetworkAlert] = []
        seen: set[tuple] = set()

        alerts += self._rule_syn_scan(packets, seen)
        alerts += self._rule_high_rate(packets, seen)
        alerts += self._rule_repeated_conn(packets, seen)

        return alerts

    # ------------------------------------------------------------------
    # Internal rules
    # ------------------------------------------------------------------

    def _dedup_key(self, rule: str, src: str | None,
                   dst: str | None, port: int | None) -> tuple:
        return (rule, src, dst, port)

    def _rule_syn_scan(self, packets: list[dict],
                       seen: set[tuple]) -> list[NetworkAlert]:
        """
        Group SYN packets by (src_ip, time_bucket).  If a source touches
        more than syn_scan_port_threshold distinct dst_ports in one window,
        raise one HIGH alert per source.
        """
        alerts = []
        # src_ip → list of (timestamp_float, dst_port)
        src_syns: dict[str, list[tuple[float, int]]] = collections.defaultdict(list)

        for pkt in packets:
            if pkt.get("proto") == "TCP" and "S" in pkt.get("flags", ""):
                src = pkt.get("src_ip") or "unknown"
                port = pkt.get("dst_port")
                ts   = pkt.get("timestamp_float", 0.0)
                if port is not None:
                    src_syns[src].append((ts, port))

        for src, entries in src_syns.items():
            if not entries:
                continue
            entries.sort(key=lambda x: x[0])
            # Sliding window
            window_start = 0
            for i, (ts, _) in enumerate(entries):
                while entries[window_start][0] < ts - self.syn_scan_window:
                    window_start += 1
                window_ports = {e[1] for e in entries[window_start:i + 1]}
                if len(window_ports) >= self.syn_scan_port_threshold:
                    key = self._dedup_key(RULE_SYN_SCAN, src, None, None)
                    if key not in seen:
                        seen.add(key)
                        alerts.append(NetworkAlert(
                            rule_id=RULE_SYN_SCAN,
                            severity=SEVERITY_HIGH,
                            src_ip=src,
                            dst_ip=None,
                            dst_port=None,
                            reason=(
                                f"{src} sent SYN packets to {len(window_ports)} distinct ports "
                                f"within {self.syn_scan_window}s "
                                f"(threshold: {self.syn_scan_port_threshold})"
                            ),
                        ))
                    break  # one alert per source is enough

        return alerts

    def _rule_high_rate(self, packets: list[dict],
                        seen: set[tuple]) -> list[NetworkAlert]:
        """
        Count all packets per source in a sliding window.  If any source
        exceeds high_rate_pkt_threshold packets in high_rate_window seconds,
        raise one MEDIUM alert per source.
        """
        alerts = []
        src_times: dict[str, list[float]] = collections.defaultdict(list)

        for pkt in packets:
            src = pkt.get("src_ip") or "unknown"
            src_times[src].append(pkt.get("timestamp_float", 0.0))

        for src, times in src_times.items():
            times.sort()
            window_start = 0
            for i, ts in enumerate(times):
                while times[window_start] < ts - self.high_rate_window:
                    window_start += 1
                count = i - window_start + 1
                if count >= self.high_rate_pkt_threshold:
                    key = self._dedup_key(RULE_HIGH_RATE, src, None, None)
                    if key not in seen:
                        seen.add(key)
                        alerts.append(NetworkAlert(
                            rule_id=RULE_HIGH_RATE,
                            severity=SEVERITY_MEDIUM,
                            src_ip=src,
                            dst_ip=None,
                            dst_port=None,
                            reason=(
                                f"{src} sent {count} packets within "
                                f"{self.high_rate_window}s "
                                f"(threshold: {self.high_rate_pkt_threshold})"
                            ),
                        ))
                    break

        return alerts

    def _rule_repeated_conn(self, packets: list[dict],
                            seen: set[tuple]) -> list[NetworkAlert]:
        """
        Count SYN packets per (src_ip, dst_ip, dst_port) in a sliding window.
        If any triple exceeds repeated_conn_threshold, raise one LOW alert.
        """
        alerts = []
        # (src, dst, port) → list of timestamps
        conn_times: dict[tuple, list[float]] = collections.defaultdict(list)

        for pkt in packets:
            if pkt.get("proto") == "TCP" and "S" in pkt.get("flags", ""):
                src  = pkt.get("src_ip")  or "unknown"
                dst  = pkt.get("dst_ip")  or "unknown"
                port = pkt.get("dst_port")
                ts   = pkt.get("timestamp_float", 0.0)
                if port is not None:
                    conn_times[(src, dst, port)].append(ts)

        for (src, dst, port), times in conn_times.items():
            times.sort()
            window_start = 0
            for i, ts in enumerate(times):
                while times[window_start] < ts - self.repeated_conn_window:
                    window_start += 1
                count = i - window_start + 1
                if count >= self.repeated_conn_threshold:
                    key = self._dedup_key(RULE_REPEATED_CONN, src, dst, port)
                    if key not in seen:
                        seen.add(key)
                        alerts.append(NetworkAlert(
                            rule_id=RULE_REPEATED_CONN,
                            severity=SEVERITY_LOW,
                            src_ip=src,
                            dst_ip=dst,
                            dst_port=port,
                            reason=(
                                f"{src} made {count} connection attempts to "
                                f"{dst}:{port} within {self.repeated_conn_window}s "
                                f"(threshold: {self.repeated_conn_threshold})"
                            ),
                        ))
                    break

        return alerts


# ---------------------------------------------------------------------------
# PCAP parsing
# ---------------------------------------------------------------------------

class PcapValidationError(Exception):
    """Raised when a PCAP file fails validation checks."""


def validate_pcap_path(path: str) -> None:
    """
    Validate that *path* points to an existing, readable PCAP file within
    the configured size limit.  Raises PcapValidationError on any failure.
    """
    if not path or not isinstance(path, str):
        raise PcapValidationError("Path must be a non-empty string.")
    if not os.path.isfile(path):
        raise PcapValidationError(f"File not found: {path}")
    if not path.lower().endswith((".pcap", ".pcapng", ".cap")):
        raise PcapValidationError(
            "File must have a .pcap, .pcapng, or .cap extension."
        )
    size = os.path.getsize(path)
    if size == 0:
        raise PcapValidationError("File is empty.")
    if size > MAX_PCAP_SIZE_BYTES:
        raise PcapValidationError(
            f"File size {size // (1024*1024)} MB exceeds the "
            f"{MAX_PCAP_SIZE_BYTES // (1024*1024)} MB limit."
        )


def parse_pcap(path: str) -> list[dict]:
    """
    Read a PCAP file and return a list of packet summary dicts.
    Stops after MAX_PACKETS_PER_ANALYSIS packets.
    Never stores payload data, credentials, or private content.

    Requires scapy (pip install scapy).
    On Windows, libpcap/Npcap is NOT required for reading existing PCAP files.
    """
    try:
        from scapy.utils import rdpcap
        from scapy.layers.inet import IP, TCP, UDP
    except ImportError as exc:
        raise ImportError(
            "scapy is required for PCAP analysis. "
            "Install it with: pip install scapy"
        ) from exc

    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        raw_packets = rdpcap(path)

    result = []
    for i, pkt in enumerate(raw_packets):
        if i >= MAX_PACKETS_PER_ANALYSIS:
            break

        summary: dict = {
            "src_ip":          None,
            "dst_ip":          None,
            "dst_port":        None,
            "proto":           "OTHER",
            "flags":           "",
            "timestamp_float": float(pkt.time) if hasattr(pkt, "time") else 0.0,
        }

        if IP in pkt:
            summary["src_ip"] = pkt[IP].src
            summary["dst_ip"] = pkt[IP].dst

            if TCP in pkt:
                summary["proto"]    = "TCP"
                summary["dst_port"] = pkt[TCP].dport
                # Scapy flags object — convert to string
                summary["flags"]    = str(pkt[TCP].flags)
            elif UDP in pkt:
                summary["proto"]    = "UDP"
                summary["dst_port"] = pkt[UDP].dport

        result.append(summary)

    return result


# ---------------------------------------------------------------------------
# Database persistence
# ---------------------------------------------------------------------------

def save_alerts(alerts: list[NetworkAlert], db, source: str = "scapy") -> int:
    """
    Persist *alerts* to the network_alerts table.
    Returns the number of rows inserted.
    Skips alerts that already exist with the same (rule_id, src_ip, dst_ip,
    dst_port, source_file, source) to prevent duplicate imports on re-analysis.
    *source* must be 'scapy' or 'snort'.
    """
    inserted = 0
    for alert in alerts:
        existing = db.execute(
            "SELECT id FROM network_alerts"
            " WHERE rule_id=? AND src_ip IS ? AND dst_ip IS ?"
            " AND dst_port IS ? AND source_file IS ? AND source=?",
            (alert.rule_id, alert.src_ip, alert.dst_ip,
             alert.dst_port, alert.source_file, source),
        ).fetchone()
        if existing:
            continue
        db.execute(
            "INSERT INTO network_alerts"
            " (rule_id, severity, src_ip, dst_ip, dst_port,"
            "  reason, status, source_file, source, detected_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                alert.rule_id, alert.severity,
                alert.src_ip, alert.dst_ip, alert.dst_port,
                alert.reason, alert.status,
                alert.source_file, source, alert.timestamp,
            ),
        )
        inserted += 1
    db.commit()
    return inserted


# ---------------------------------------------------------------------------
# High-level analysis entry point
# ---------------------------------------------------------------------------

def analyse_pcap_file(path: str, db=None, source_name: str | None = None) -> dict:
    """
    Validate, parse, and analyse a PCAP file.  Optionally persist alerts.

    *source_name* overrides the basename used in alert records (useful when
    the file was uploaded under a temp name but the original filename is known).

    Returns a summary dict:
        {
            "pcap_file":      str,
            "packets_read":   int,
            "alerts":         list[NetworkAlert],
            "alerts_saved":   int,   # 0 if db is None
            "truncated":      bool,  # True if packet limit was hit
        }
    """
    validate_pcap_path(path)
    packets = parse_pcap(path)
    truncated = len(packets) >= MAX_PACKETS_PER_ANALYSIS

    engine = DetectionEngine()
    alerts = engine.analyse(packets)

    basename = source_name if source_name else os.path.basename(path)
    for alert in alerts:
        alert.source_file = basename

    saved = 0
    if db is not None:
        saved = save_alerts(alerts, db)

    return {
        "pcap_file":    basename,
        "packets_read": len(packets),
        "alerts":       alerts,
        "alerts_saved": saved,
        "truncated":    truncated,
    }
