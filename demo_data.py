"""Synthetic traffic generator for Demo Mode.

Generates realistic ``PacketRecord`` objects WITHOUT any live capture or
elevated privileges. The data is clearly flagged as simulated (every record
has ``is_simulated=True``) and deliberately includes a few suspicious patterns
so the analysis and alerting features can be demonstrated offline.
"""
from __future__ import annotations

import random
import time

from packet_parser import PacketRecord

_INTERNAL_HOSTS = [f"192.168.1.{i}" for i in range(2, 12)]
_EXTERNAL_HOSTS = [
    "93.184.216.34", "142.250.72.14", "151.101.1.69", "104.16.132.229",
    "20.205.243.166", "199.232.45.66", "8.8.8.8", "1.1.1.1",
]
_DNS_NAMES = [
    "example.com", "google.com", "github.com", "cloudflare.com",
    "wikipedia.org", "openai.com", "vitstudent.ac.in", "microsoft.com",
]

# (app_protocol, transport, typical dst_port, size range) weighted mix.
_NORMAL_MIX = [
    ("HTTPS/TLS", "TCP", 443, (200, 1400), 40),
    ("HTTP", "TCP", 80, (200, 1400), 15),
    ("DNS", "UDP", 53, (60, 180), 20),
    ("TCP", "TCP", 22, (60, 400), 5),
    ("ICMP", "ICMP", None, (56, 98), 5),
    ("UDP", "UDP", 123, (76, 90), 5),
]


def _tcp_flags_for(app_proto: str) -> str:
    """Pick plausible TCP flags for a normal connection packet."""
    return random.choice(["S", "SA", "A", "PA", "FA", "A"])


def _make_normal_packet(ts: float) -> PacketRecord:
    proto, transport, port, size_range, _w = random.choices(
        _NORMAL_MIX, weights=[m[4] for m in _NORMAL_MIX], k=1
    )[0]
    internal = random.choice(_INTERNAL_HOSTS)
    external = random.choice(_EXTERNAL_HOSTS)
    outbound = random.random() < 0.6
    src_ip, dst_ip = (internal, external) if outbound else (external, internal)

    rec = PacketRecord(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=transport,
        app_protocol=proto,
        length=random.randint(*size_range),
        ip_version=4,
        ttl=random.choice([64, 128, 255]),
        is_simulated=True,
    )
    if transport == "TCP":
        rec.src_port = random.randint(49152, 65535) if outbound else port
        rec.dst_port = port if outbound else random.randint(49152, 65535)
        rec.tcp_flags = _tcp_flags_for(proto)
    elif transport == "UDP":
        rec.src_port = random.randint(49152, 65535)
        rec.dst_port = port
        if proto == "DNS":
            rec.dns_query = random.choice(_DNS_NAMES)
    elif transport == "ICMP":
        rec.icmp_type = random.choice([0, 8])
        rec.icmp_code = 0
    return rec


def _port_scan_burst(ts: float, attacker: str, target: str) -> list[PacketRecord]:
    """A single source hitting many ports on one target (SYN scan pattern)."""
    out = []
    for port in random.sample(range(1, 1024), 40):
        out.append(PacketRecord(
            timestamp=ts + random.random() * 0.5,
            src_ip=attacker, dst_ip=target,
            src_port=random.randint(40000, 65535), dst_port=port,
            protocol="TCP", app_protocol="TCP",
            length=random.randint(40, 60), tcp_flags="S",
            ip_version=4, ttl=64, is_simulated=True,
        ))
    return out


def _flood_burst(ts: float, attacker: str, target: str) -> list[PacketRecord]:
    """A high packet-rate flood from one source (triggers rate + spike rules)."""
    out = []
    for _ in range(250):
        out.append(PacketRecord(
            timestamp=ts + random.random(),  # all within ~1s
            src_ip=attacker, dst_ip=target,
            src_port=random.randint(1024, 65535), dst_port=80,
            protocol="TCP", app_protocol="HTTP",
            length=random.randint(40, 120), tcp_flags="S",
            ip_version=4, ttl=64, is_simulated=True,
        ))
    return out


def _large_packets(ts: float) -> list[PacketRecord]:
    """A couple of oversized packets to trigger the large-packet rule."""
    return [
        PacketRecord(
            timestamp=ts + i,
            src_ip=random.choice(_EXTERNAL_HOSTS),
            dst_ip=random.choice(_INTERNAL_HOSTS),
            src_port=443, dst_port=random.randint(40000, 65535),
            protocol="TCP", app_protocol="HTTPS/TLS",
            length=random.randint(4000, 6000), tcp_flags="PA",
            ip_version=4, ttl=128, is_simulated=True,
        )
        for i in range(3)
    ]


def generate_traffic(
    num_packets: int = 800,
    include_anomalies: bool = True,
    seed: int | None = None,
    start_time: float | None = None,
) -> list[PacketRecord]:
    """Generate a list of simulated packets spanning roughly 60 seconds.

    Args:
        num_packets: approximate count of baseline (normal) packets.
        include_anomalies: whether to inject suspicious bursts.
        seed: optional RNG seed for reproducible demos/tests.
        start_time: epoch seconds for the first packet (defaults to now-60s).
    """
    if seed is not None:
        random.seed(seed)
    base = start_time if start_time is not None else time.time() - 60.0

    records: list[PacketRecord] = []
    for _ in range(max(0, num_packets)):
        ts = base + random.random() * 60.0
        records.append(_make_normal_packet(ts))

    if include_anomalies:
        records += _port_scan_burst(base + 20, "45.33.12.7", "192.168.1.5")
        records += _flood_burst(base + 35, "203.0.113.9", "192.168.1.10")
        records += _large_packets(base + 50)

    records.sort(key=lambda r: r.timestamp)
    return records


__all__ = ["generate_traffic"]
