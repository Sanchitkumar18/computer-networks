"""Parse raw Scapy packets into normalized, flat ``PacketRecord`` objects.

Design goals:
    * Never assume a packet has every field. Real traffic contains malformed,
      truncated, encrypted and unsupported frames; parsing must degrade
      gracefully and never raise to the caller.
    * Classification is heuristic (ports + Scapy layers). We identify TLS/HTTPS
      traffic, we do NOT decrypt it.

The module imports Scapy lazily so that pure-data parts of the app (demo mode,
analysis, the dashboard) run even if Scapy / libpcap is not installed.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, asdict, field
from typing import Any

from config import WELL_KNOWN_PORTS

# TCP flag bit -> single-letter label, in display order.
_TCP_FLAG_MAP = [
    (0x01, "F"),  # FIN
    (0x02, "S"),  # SYN
    (0x04, "R"),  # RST
    (0x08, "P"),  # PSH
    (0x10, "A"),  # ACK
    (0x20, "U"),  # URG
    (0x40, "E"),  # ECE
    (0x80, "C"),  # CWR
]


@dataclass
class PacketRecord:
    """A flat, analysis-ready representation of one observed packet.

    Fields that do not apply to a given packet are left as ``None`` / 0 rather
    than omitted, so downstream code can rely on a stable schema.
    """

    timestamp: float
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = "Other"          # transport/link: TCP/UDP/ICMP/ARP/...
    app_protocol: str = "Other"      # category used by the dashboard
    length: int = 0                  # packet size in bytes
    tcp_flags: str | None = None     # e.g. "SA"
    ip_version: int | None = None    # 4 or 6
    dns_query: str | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    ttl: int | None = None
    is_simulated: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("extra", None)
        return d


def decode_tcp_flags(flag_value: int) -> str:
    """Convert a numeric TCP flags field into a letter string (e.g. 0x12 -> 'SA')."""
    try:
        value = int(flag_value)
    except (TypeError, ValueError):
        return ""
    return "".join(label for bit, label in _TCP_FLAG_MAP if value & bit)


def _classify_app_protocol(
    transport: str, src_port: int | None, dst_port: int | None, has_dns: bool
) -> str:
    """Map a packet to one of the dashboard protocol categories.

    Heuristic only. Port 443 is reported as HTTPS/TLS because that is what the
    port conventionally carries; we never inspect the encrypted payload.
    """
    if has_dns:
        return "DNS"
    ports = {p for p in (src_port, dst_port) if p is not None}
    if 443 in ports or 8443 in ports:
        return "HTTPS/TLS"
    if 80 in ports or 8080 in ports:
        return "HTTP"
    if 53 in ports:
        return "DNS"
    if transport in ("TCP", "UDP", "ICMP", "ARP"):
        return transport
    return "Other"


def app_protocol_label(src_port: int | None, dst_port: int | None) -> str:
    """Return a friendly service name from well-known ports, or 'Unknown'."""
    for port in (dst_port, src_port):
        if port in WELL_KNOWN_PORTS:
            return WELL_KNOWN_PORTS[port]
    return "Unknown"


def parse_packet(pkt: Any, timestamp: float | None = None) -> PacketRecord:
    """Parse a single Scapy packet into a :class:`PacketRecord`.

    This function is defensive: any unexpected layer or missing attribute is
    tolerated and results in ``None`` fields rather than an exception.
    """
    # Scapy is imported lazily; in demo/test contexts packets are built with it
    # too, so if we got a packet object Scapy is already importable.
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP
    from scapy.layers.dns import DNS, DNSQR

    if timestamp is None:
        # Scapy stores capture time on pkt.time when available.
        timestamp = float(getattr(pkt, "time", None) or time.time())

    rec = PacketRecord(timestamp=float(timestamp))

    try:
        rec.length = int(len(pkt))
    except Exception:
        rec.length = 0

    try:
        # --- Link / network layer -------------------------------------
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            rec.protocol = "ARP"
            rec.app_protocol = "ARP"
            rec.src_ip = getattr(arp, "psrc", None)
            rec.dst_ip = getattr(arp, "pdst", None)
            return rec

        if pkt.haslayer(IP):
            ip = pkt[IP]
            rec.ip_version = 4
            rec.src_ip = ip.src
            rec.dst_ip = ip.dst
            rec.ttl = getattr(ip, "ttl", None)
        elif pkt.haslayer(IPv6):
            ip6 = pkt[IPv6]
            rec.ip_version = 6
            rec.src_ip = ip6.src
            rec.dst_ip = ip6.dst
            rec.ttl = getattr(ip6, "hlim", None)

        # --- Transport layer ------------------------------------------
        has_dns = pkt.haslayer(DNS)

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            rec.protocol = "TCP"
            rec.src_port = int(tcp.sport)
            rec.dst_port = int(tcp.dport)
            rec.tcp_flags = decode_tcp_flags(int(tcp.flags))
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            rec.protocol = "UDP"
            rec.src_port = int(udp.sport)
            rec.dst_port = int(udp.dport)
        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            rec.protocol = "ICMP"
            rec.icmp_type = int(getattr(icmp, "type", 0))
            rec.icmp_code = int(getattr(icmp, "code", 0))

        # --- DNS query name -------------------------------------------
        if has_dns and pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="replace")
                rec.dns_query = qname.rstrip(".") if qname else None
            except Exception:
                rec.dns_query = None

        rec.app_protocol = _classify_app_protocol(
            rec.protocol, rec.src_port, rec.dst_port, has_dns
        )
    except Exception as exc:  # never let a weird packet crash the pipeline
        rec.extra["parse_error"] = str(exc)
        if rec.protocol == "Other":
            rec.app_protocol = "Other"

    return rec


__all__ = [
    "PacketRecord",
    "parse_packet",
    "decode_tcp_flags",
    "app_protocol_label",
]
