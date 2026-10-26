"""Rule-based, explainable traffic anomaly detection.

This is NOT an intrusion detection system. It applies a handful of transparent,
configurable heuristics and emits alerts that a human should review. Every
alert records why it fired and which statistics support it. No alert should be
read as proof of an attack (see README: anomaly detection vs IDS).
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import Sequence

import pandas as pd

from config import AnomalyThresholds

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass
class Alert:
    """A single detection result."""

    timestamp: float
    category: str
    severity: str          # low | medium | high
    src_ip: str | None
    dst_ip: str | None
    reason: str
    stat: str              # supporting statistic, human-readable

    def as_dict(self) -> dict:
        return asdict(self)


def _col(df: pd.DataFrame, name: str) -> pd.Series:
    return df[name] if name in df.columns else pd.Series(dtype="object")


def detect_high_packet_rate(df: pd.DataFrame, t: AnomalyThresholds) -> list[Alert]:
    """Flag any source IP sending more than ``high_packet_rate`` packets
    within a single ``rate_window_seconds`` window."""
    alerts: list[Alert] = []
    if df.empty or "src_ip" not in df.columns:
        return alerts
    work = df.dropna(subset=["src_ip"]).copy()
    if work.empty:
        return alerts
    work["window"] = (work["timestamp"].astype(float) // t.rate_window_seconds)
    grouped = work.groupby(["src_ip", "window"]).size()
    for (src_ip, _win), count in grouped.items():
        if count > t.high_packet_rate:
            alerts.append(Alert(
                timestamp=float(work["timestamp"].max()),
                category="High packet rate",
                severity="high" if count > t.high_packet_rate * 2 else "medium",
                src_ip=src_ip, dst_ip=None,
                reason=(f"{src_ip} sent {count} packets in a "
                        f"{t.rate_window_seconds}s window "
                        f"(threshold {t.high_packet_rate})."),
                stat=f"{count} packets / {t.rate_window_seconds}s",
            ))
    return alerts


def detect_port_scan(df: pd.DataFrame, t: AnomalyThresholds) -> list[Alert]:
    """Flag a source probing many distinct ports on a SINGLE destination.

    A real (SYN) port scan is one host sending connection-initiation packets
    to many ports on one target. Two refinements keep this precise:

    * Count distinct ports per (src_ip, dst_ip) pair, not per source across all
      destinations — a normal client talking to many servers is not a scan.
    * When TCP flag information is available, count only *connection
      initiations* (SYN set, ACK clear). This excludes ordinary reply traffic,
      whose packets land on random ephemeral ports but are not lone SYNs, and
      which otherwise causes false positives at scale.
    """
    alerts: list[Alert] = []
    if df.empty or "src_ip" not in df.columns or "dst_port" not in df.columns:
        return alerts
    work = df.dropna(subset=["src_ip", "dst_port"])
    if "dst_ip" not in work.columns:
        return alerts
    work = work.dropna(subset=["dst_ip"])
    # Restrict to connection initiations when flags are present.
    if "tcp_flags" in work.columns:
        flags = work["tcp_flags"].astype(str)
        syn_only = work[flags.str.contains("S", na=False)
                        & ~flags.str.contains("A", na=False)]
        if not syn_only.empty:
            work = syn_only
    if work.empty:
        return alerts
    distinct = work.groupby(["src_ip", "dst_ip"])["dst_port"].nunique()
    for (src_ip, dst_ip), n_ports in distinct.items():
        if n_ports >= t.port_scan_distinct_ports:
            alerts.append(Alert(
                timestamp=float(work["timestamp"].max()),
                category="Possible port scan",
                severity="high" if n_ports >= t.port_scan_distinct_ports * 2 else "medium",
                src_ip=src_ip, dst_ip=dst_ip,
                reason=(f"{src_ip} contacted {n_ports} distinct ports on "
                        f"{dst_ip} (threshold {t.port_scan_distinct_ports})."),
                stat=f"{n_ports} distinct ports on one host",
            ))
    return alerts


def detect_large_packets(df: pd.DataFrame, t: AnomalyThresholds) -> list[Alert]:
    """Flag individual packets larger than ``large_packet_bytes``."""
    alerts: list[Alert] = []
    if df.empty or "length" not in df.columns:
        return alerts
    big = df[df["length"].fillna(0) > t.large_packet_bytes]
    for _, row in big.iterrows():
        alerts.append(Alert(
            timestamp=float(row["timestamp"]),
            category="Unusually large packet",
            severity="low",
            src_ip=row.get("src_ip"), dst_ip=row.get("dst_ip"),
            reason=(f"Packet of {int(row['length'])} bytes exceeds "
                    f"threshold {t.large_packet_bytes}."),
            stat=f"{int(row['length'])} bytes",
        ))
    return alerts


def detect_traffic_spike(df: pd.DataFrame, t: AnomalyThresholds) -> list[Alert]:
    """Flag per-second buckets whose packet count far exceeds the mean."""
    alerts: list[Alert] = []
    if df.empty:
        return alerts
    work = df.copy()
    work["sec"] = work["timestamp"].astype(float).astype(int)
    per_sec = work.groupby("sec").size()
    if len(per_sec) < 3:
        return alerts
    mean = per_sec.mean()
    if mean <= 0:
        return alerts
    threshold = mean * t.traffic_spike_factor
    for sec, count in per_sec.items():
        if count > threshold:
            alerts.append(Alert(
                timestamp=float(sec),
                category="Traffic spike",
                severity="medium",
                src_ip=None, dst_ip=None,
                reason=(f"{count} packets in one second vs mean "
                        f"{mean:.1f} (x{t.traffic_spike_factor} threshold)."),
                stat=f"{count} pkts/s (mean {mean:.1f})",
            ))
    return alerts


def detect_connection_resets(df: pd.DataFrame, t: AnomalyThresholds) -> list[Alert]:
    """Flag sources with many TCP RST packets (resets / refused connections)."""
    alerts: list[Alert] = []
    if df.empty or "tcp_flags" not in df.columns:
        return alerts
    work = df.dropna(subset=["tcp_flags"]).copy()
    if work.empty:
        return alerts
    resets = work[work["tcp_flags"].astype(str).str.contains("R", na=False)]
    if resets.empty or "src_ip" not in resets.columns:
        return alerts
    counts = resets.dropna(subset=["src_ip"]).groupby("src_ip").size()
    for src_ip, count in counts.items():
        if count >= t.reset_connection_count:
            alerts.append(Alert(
                timestamp=float(work["timestamp"].max()),
                category="Repeated TCP resets",
                severity="medium",
                src_ip=src_ip, dst_ip=None,
                reason=(f"{src_ip} involved in {count} RST packets "
                        f"(threshold {t.reset_connection_count})."),
                stat=f"{count} RST packets",
            ))
    return alerts


def detect_all(
    df: pd.DataFrame, thresholds: AnomalyThresholds | None = None
) -> list[Alert]:
    """Run every detector and return alerts sorted by severity (high first)."""
    t = thresholds or AnomalyThresholds()
    alerts: list[Alert] = []
    for detector in (
        detect_high_packet_rate,
        detect_port_scan,
        detect_large_packets,
        detect_traffic_spike,
        detect_connection_resets,
    ):
        try:
            alerts.extend(detector(df, t))
        except Exception:
            # A detector failing on odd data must not break the others.
            continue
    alerts.sort(key=lambda a: SEVERITY_ORDER.get(a.severity, 0), reverse=True)
    return alerts


def alerts_to_dataframe(alerts: Sequence[Alert]) -> pd.DataFrame:
    cols = ["timestamp", "category", "severity", "src_ip", "dst_ip", "reason", "stat"]
    if not alerts:
        return pd.DataFrame(columns=cols)
    df = pd.DataFrame([a.as_dict() for a in alerts])
    df["datetime"] = pd.to_datetime(df["timestamp"], unit="s")
    return df


__all__ = [
    "Alert",
    "detect_all",
    "detect_high_packet_rate",
    "detect_port_scan",
    "detect_large_packets",
    "detect_traffic_spike",
    "detect_connection_resets",
    "alerts_to_dataframe",
]
