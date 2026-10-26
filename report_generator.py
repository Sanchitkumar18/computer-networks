"""CSV exports and a human-readable summary report.

All exported data is header metadata only. CSV generation uses pandas' quoting
so that field values cannot break the CSV structure.
"""
from __future__ import annotations

import csv
from datetime import datetime
from io import StringIO
from typing import Sequence

import pandas as pd

from anomaly_detector import Alert, alerts_to_dataframe
from traffic_analyzer import (
    TrafficSummary,
    protocol_distribution,
    summarize,
    top_talkers,
)
from utils import human_bytes


def packets_to_csv(df: pd.DataFrame) -> str:
    """Serialize a packets DataFrame to CSV text (safe quoting)."""
    if df.empty:
        return ""
    export = df.drop(columns=[c for c in ("datetime",) if c in df.columns])
    return export.to_csv(index=False, quoting=csv.QUOTE_NONNUMERIC)


def alerts_to_csv(alerts: Sequence[Alert]) -> str:
    """Serialize alerts to CSV text."""
    df = alerts_to_dataframe(alerts)
    if df.empty:
        return ""
    export = df.drop(columns=[c for c in ("datetime",) if c in df.columns])
    return export.to_csv(index=False, quoting=csv.QUOTE_NONNUMERIC)


def build_summary_report(
    df: pd.DataFrame, alerts: Sequence[Alert], simulated: bool
) -> str:
    """Produce a plain-text summary report suitable for download."""
    buf = StringIO()
    summary: TrafficSummary = summarize(df)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    buf.write("=" * 60 + "\n")
    buf.write("NETWORK TRAFFIC MONITORING - SUMMARY REPORT\n")
    buf.write("=" * 60 + "\n")
    buf.write(f"Generated:        {now}\n")
    buf.write(f"Data source:      {'SIMULATED (demo mode)' if simulated else 'Live/Imported capture'}\n")
    buf.write("\n--- Overview ---\n")
    buf.write(f"Total packets:    {summary.total_packets}\n")
    buf.write(f"Total bytes:      {summary.total_bytes} ({human_bytes(summary.total_bytes)})\n")
    buf.write(f"Avg packet size:  {summary.avg_packet_size:.1f} bytes\n")
    buf.write(f"Capture window:   {summary.duration_seconds:.1f} s\n")
    buf.write(f"Capture rate:     {summary.packets_per_second:.1f} pkt/s, "
              f"{human_bytes(summary.bytes_per_second)}/s\n")
    buf.write(f"Unique src IPs:   {summary.unique_src_ips}\n")
    buf.write(f"Unique dst IPs:   {summary.unique_dst_ips}\n")
    buf.write("(Note: capture rate is what this tool observed, not link bandwidth.)\n")

    buf.write("\n--- Protocol distribution ---\n")
    proto = protocol_distribution(df)
    if proto.empty:
        buf.write("(no data)\n")
    else:
        for _, row in proto.iterrows():
            buf.write(f"  {row['protocol']:<12} {int(row['packets']):>8} pkts "
                      f"{row['pct_packets']:>6.1f}%  {human_bytes(row['bytes'])}\n")

    buf.write("\n--- Top source IPs ---\n")
    talkers = top_talkers(df, "src_ip", n=5)
    if talkers.empty:
        buf.write("(no data)\n")
    else:
        for _, row in talkers.iterrows():
            buf.write(f"  {str(row['src_ip']):<18} {int(row['packets']):>8} pkts "
                      f"{human_bytes(row['bytes'])}\n")

    buf.write(f"\n--- Anomaly alerts ({len(alerts)}) ---\n")
    if not alerts:
        buf.write("(no alerts)\n")
    else:
        for a in alerts:
            buf.write(f"  [{a.severity.upper():<6}] {a.category}: {a.reason}\n")

    buf.write("\n" + "=" * 60 + "\n")
    buf.write("Educational tool. Alerts are heuristic, not proof of attack.\n")
    return buf.getvalue()


__all__ = ["packets_to_csv", "alerts_to_csv", "build_summary_report"]
