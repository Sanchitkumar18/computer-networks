"""Aggregate ``PacketRecord`` collections into statistics and DataFrames.

This module is pure data processing: no capture, no UI. It is safe to call on
empty inputs and returns stable, empty structures in that case.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Iterable, Sequence

import pandas as pd

from packet_parser import PacketRecord

# Columns guaranteed to exist in the packets DataFrame.
PACKET_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "app_protocol", "length", "tcp_flags", "ip_version", "dns_query",
    "icmp_type", "icmp_code", "ttl", "is_simulated",
]


def records_to_dataframe(records: Sequence[PacketRecord]) -> pd.DataFrame:
    """Build a normalized DataFrame from packet records (empty-safe)."""
    if not records:
        return pd.DataFrame(columns=PACKET_COLUMNS)
    df = pd.DataFrame([r.as_dict() for r in records])
    # Ensure every expected column exists even if records lacked some.
    for col in PACKET_COLUMNS:
        if col not in df.columns:
            df[col] = None
    df["datetime"] = pd.to_datetime(df["timestamp"], unit="s")
    return df[PACKET_COLUMNS + ["datetime"]]


@dataclass
class TrafficSummary:
    """Top-line counters shown on the Overview page."""

    total_packets: int = 0
    total_bytes: int = 0
    avg_packet_size: float = 0.0
    duration_seconds: float = 0.0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    unique_src_ips: int = 0
    unique_dst_ips: int = 0


def summarize(df: pd.DataFrame) -> TrafficSummary:
    """Compute overview statistics from a packets DataFrame."""
    if df.empty:
        return TrafficSummary()
    total_packets = len(df)
    total_bytes = int(df["length"].fillna(0).sum())
    ts = df["timestamp"].astype(float)
    duration = max(float(ts.max() - ts.min()), 0.0)
    pps = total_packets / duration if duration > 0 else float(total_packets)
    bps = total_bytes / duration if duration > 0 else float(total_bytes)
    return TrafficSummary(
        total_packets=total_packets,
        total_bytes=total_bytes,
        avg_packet_size=total_bytes / total_packets if total_packets else 0.0,
        duration_seconds=duration,
        packets_per_second=pps,
        bytes_per_second=bps,
        unique_src_ips=int(df["src_ip"].nunique(dropna=True)),
        unique_dst_ips=int(df["dst_ip"].nunique(dropna=True)),
    )


def protocol_distribution(df: pd.DataFrame) -> pd.DataFrame:
    """Packets and bytes per application-protocol category."""
    if df.empty:
        return pd.DataFrame(columns=["protocol", "packets", "bytes", "pct_packets"])
    grp = (
        df.groupby("app_protocol")
        .agg(packets=("app_protocol", "size"), bytes=("length", "sum"))
        .reset_index()
        .rename(columns={"app_protocol": "protocol"})
    )
    total = grp["packets"].sum()
    grp["pct_packets"] = (grp["packets"] / total * 100).round(2) if total else 0.0
    return grp.sort_values("packets", ascending=False).reset_index(drop=True)


def top_talkers(df: pd.DataFrame, column: str, n: int = 10) -> pd.DataFrame:
    """Top-N values of ``column`` by packet count and total bytes."""
    empty = pd.DataFrame(columns=[column, "packets", "bytes"])
    if df.empty or column not in df.columns:
        return empty
    sub = df.dropna(subset=[column])
    if sub.empty:
        return empty
    grp = (
        sub.groupby(column)
        .agg(packets=(column, "size"), bytes=("length", "sum"))
        .reset_index()
        .sort_values("packets", ascending=False)
        .head(n)
        .reset_index(drop=True)
    )
    return grp


def top_ports(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Most frequently observed destination ports."""
    empty = pd.DataFrame(columns=["port", "packets"])
    if df.empty:
        return empty
    ports = df["dst_port"].dropna()
    if ports.empty:
        return empty
    counts = Counter(int(p) for p in ports)
    rows = [{"port": p, "packets": c} for p, c in counts.most_common(n)]
    return pd.DataFrame(rows)


def top_conversations(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Most active source->destination IP pairs."""
    empty = pd.DataFrame(columns=["src_ip", "dst_ip", "packets", "bytes"])
    if df.empty:
        return empty
    sub = df.dropna(subset=["src_ip", "dst_ip"])
    if sub.empty:
        return empty
    grp = (
        sub.groupby(["src_ip", "dst_ip"])
        .agg(packets=("length", "size"), bytes=("length", "sum"))
        .reset_index()
        .sort_values("packets", ascending=False)
        .head(n)
        .reset_index(drop=True)
    )
    return grp


def traffic_over_time(df: pd.DataFrame, bucket_seconds: int = 1) -> pd.DataFrame:
    """Packets-per-second and bytes-per-second time series.

    NOTE: this measures the *capture rate* seen by this tool, which is not the
    same as the physical link throughput (see README).
    """
    cols = ["bucket", "packets", "bytes"]
    if df.empty:
        return pd.DataFrame(columns=cols)
    work = df.copy()
    work["bucket"] = (work["timestamp"].astype(float) // bucket_seconds) * bucket_seconds
    grp = (
        work.groupby("bucket")
        .agg(packets=("length", "size"), bytes=("length", "sum"))
        .reset_index()
        .sort_values("bucket")
    )
    grp["datetime"] = pd.to_datetime(grp["bucket"], unit="s")
    # Normalize to per-second rates.
    grp["packets_per_sec"] = grp["packets"] / bucket_seconds
    grp["bytes_per_sec"] = grp["bytes"] / bucket_seconds
    return grp.reset_index(drop=True)


def packet_size_distribution(df: pd.DataFrame) -> pd.DataFrame:
    """Histogram-ready binning of packet sizes."""
    cols = ["size_bucket", "count"]
    if df.empty:
        return pd.DataFrame(columns=cols)
    bins = [0, 64, 128, 256, 512, 1024, 1500, float("inf")]
    labels = ["0-64", "65-128", "129-256", "257-512", "513-1024",
              "1025-1500", "1500+"]
    cut = pd.cut(df["length"].fillna(0), bins=bins, labels=labels, right=True)
    out = cut.value_counts().reindex(labels, fill_value=0).reset_index()
    out.columns = cols
    return out


__all__ = [
    "records_to_dataframe",
    "TrafficSummary",
    "summarize",
    "protocol_distribution",
    "top_talkers",
    "top_ports",
    "top_conversations",
    "traffic_over_time",
    "packet_size_distribution",
    "PACKET_COLUMNS",
]
