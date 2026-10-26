"""Central configuration for the Network Traffic Monitoring tool.

All tunable parameters live here so that implementation logic stays free of
magic numbers. Values can be overridden at runtime from the dashboard Settings
page (they are copied into Streamlit session state, not mutated here).
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from pathlib import Path

# --- Project paths ---------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
CAPTURES_DIR = BASE_DIR / "captures"
DB_PATH = DATA_DIR / "packets.db"

DATA_DIR.mkdir(exist_ok=True)
CAPTURES_DIR.mkdir(exist_ok=True)

# --- Application metadata --------------------------------------------------
APP_NAME = "Network Traffic Monitor"
APP_VERSION = "1.0.0"

# --- Capture defaults ------------------------------------------------------
# Upper bound on packets kept in memory for the live view. Prevents unbounded
# memory growth during long monitoring sessions (requirement 5).
MAX_PACKETS_IN_MEMORY = 10_000

# Size of the thread-safe queue that hands packets from the capture worker to
# the dashboard. If the UI falls behind, the oldest items are dropped.
CAPTURE_QUEUE_SIZE = 5_000

# Default capture limits (None == unlimited; the UI exposes these).
DEFAULT_PACKET_LIMIT: int | None = None
DEFAULT_DURATION_LIMIT: int | None = None  # seconds

# How often (seconds) the dashboard auto-refreshes while monitoring.
DEFAULT_REFRESH_INTERVAL = 2

# --- Well-known ports used for application-protocol classification ---------
# Classification is heuristic: it is based on port numbers and Scapy layers,
# NOT on decrypting payloads. See README for the limitations discussion.
WELL_KNOWN_PORTS: dict[int, str] = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 465: "SMTPS", 514: "Syslog", 587: "SMTP", 993: "IMAPS",
    995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
}

# Protocol categories shown in the protocol-distribution charts.
PROTOCOL_CATEGORIES = [
    "TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS/TLS", "ARP", "Other",
]


@dataclass
class AnomalyThresholds:
    """Configurable, explainable thresholds for the rule-based detector.

    These are deliberately conservative defaults suitable for a classroom demo.
    None of them constitute proof of an attack; they flag patterns worth a
    human look (see README: anomaly detection vs intrusion detection).
    """

    # Packets from a single source within the window to flag a high-rate source.
    high_packet_rate: int = 100
    # Window length (seconds) over which rates are evaluated.
    rate_window_seconds: int = 10
    # Distinct destination ports contacted by one source -> possible port scan.
    port_scan_distinct_ports: int = 15
    # Packet size (bytes) above which a packet is flagged as unusually large.
    large_packet_bytes: int = 3_000
    # Factor by which traffic must exceed the running mean to count as a spike.
    traffic_spike_factor: float = 3.0
    # Count of RST/failed-handshake events from one source to flag resets.
    reset_connection_count: int = 20

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Settings:
    """Mutable runtime settings, seeded from the constants above."""

    interface: str | None = None
    refresh_interval: int = DEFAULT_REFRESH_INTERVAL
    packet_limit: int | None = DEFAULT_PACKET_LIMIT
    duration_limit: int | None = DEFAULT_DURATION_LIMIT
    max_packets_in_memory: int = MAX_PACKETS_IN_MEMORY
    thresholds: AnomalyThresholds = field(default_factory=AnomalyThresholds)


def default_settings() -> Settings:
    """Return a fresh Settings object (used when seeding session state)."""
    return Settings()
