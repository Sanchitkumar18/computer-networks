"""Post-capture packet filtering.

Filters operate on an already-captured DataFrame so the user can refine the
view without restarting monitoring. All filters are optional; a ``None`` value
means "do not constrain on this field".
"""
from __future__ import annotations

from dataclasses import dataclass

import pandas as pd


@dataclass
class PacketFilter:
    """A set of optional constraints applied to a packets DataFrame."""

    src_ip: str | None = None
    dst_ip: str | None = None
    protocol: str | None = None       # matches app_protocol or protocol
    port: int | None = None           # matches src_port or dst_port
    min_size: int | None = None
    max_size: int | None = None
    start_time: float | None = None   # epoch seconds, inclusive
    end_time: float | None = None     # epoch seconds, inclusive
    dns_query_contains: str | None = None

    def is_empty(self) -> bool:
        return all(
            getattr(self, f) is None
            for f in (
                "src_ip", "dst_ip", "protocol", "port", "min_size",
                "max_size", "start_time", "end_time", "dns_query_contains",
            )
        )


def apply_filter(df: pd.DataFrame, flt: PacketFilter) -> pd.DataFrame:
    """Return the subset of ``df`` matching every set constraint in ``flt``.

    Empty-safe and non-mutating. Unknown/missing columns are ignored rather
    than raising.
    """
    if df.empty or flt.is_empty():
        return df.copy()

    mask = pd.Series(True, index=df.index)

    if flt.src_ip and "src_ip" in df.columns:
        mask &= df["src_ip"].astype(str).str.contains(
            str(flt.src_ip), case=False, na=False, regex=False
        )
    if flt.dst_ip and "dst_ip" in df.columns:
        mask &= df["dst_ip"].astype(str).str.contains(
            str(flt.dst_ip), case=False, na=False, regex=False
        )
    if flt.protocol:
        proto = str(flt.protocol).upper()
        proto_mask = pd.Series(False, index=df.index)
        if "app_protocol" in df.columns:
            proto_mask |= df["app_protocol"].astype(str).str.upper() == proto
        if "protocol" in df.columns:
            proto_mask |= df["protocol"].astype(str).str.upper() == proto
        mask &= proto_mask
    if flt.port is not None:
        port_mask = pd.Series(False, index=df.index)
        for col in ("src_port", "dst_port"):
            if col in df.columns:
                port_mask |= df[col] == flt.port
        mask &= port_mask
    if flt.min_size is not None and "length" in df.columns:
        mask &= df["length"].fillna(0) >= flt.min_size
    if flt.max_size is not None and "length" in df.columns:
        mask &= df["length"].fillna(0) <= flt.max_size
    if flt.start_time is not None and "timestamp" in df.columns:
        mask &= df["timestamp"].astype(float) >= flt.start_time
    if flt.end_time is not None and "timestamp" in df.columns:
        mask &= df["timestamp"].astype(float) <= flt.end_time
    if flt.dns_query_contains and "dns_query" in df.columns:
        mask &= df["dns_query"].astype(str).str.contains(
            str(flt.dns_query_contains), case=False, na=False, regex=False
        )

    return df[mask].copy()


__all__ = ["PacketFilter", "apply_filter"]
