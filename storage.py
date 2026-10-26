"""Optional persistence: SQLite metadata store and PCAP read/write.

Only packet-header *metadata* is stored by default (no payloads), honoring the
project's privacy requirements. SQLite use is entirely optional; the app runs
fully in-memory without it.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Sequence

import pandas as pd

from config import DB_PATH
from packet_parser import PacketRecord, parse_packet
from utils import safe_output_path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS packets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   REAL,
    src_ip      TEXT,
    dst_ip      TEXT,
    src_port    INTEGER,
    dst_port    INTEGER,
    protocol    TEXT,
    app_protocol TEXT,
    length      INTEGER,
    tcp_flags   TEXT,
    ip_version  INTEGER,
    dns_query   TEXT,
    icmp_type   INTEGER,
    icmp_code   INTEGER,
    ttl         INTEGER,
    is_simulated INTEGER
);
"""


class PacketStore:
    """Thin SQLite wrapper for persisting packet metadata."""

    def __init__(self, db_path: Path | str = DB_PATH) -> None:
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    def insert_records(self, records: Sequence[PacketRecord]) -> int:
        if not records:
            return 0
        rows = [
            (
                r.timestamp, r.src_ip, r.dst_ip, r.src_port, r.dst_port,
                r.protocol, r.app_protocol, r.length, r.tcp_flags,
                r.ip_version, r.dns_query, r.icmp_type, r.icmp_code, r.ttl,
                int(r.is_simulated),
            )
            for r in records
        ]
        self._conn.executemany(
            """INSERT INTO packets
               (timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                app_protocol, length, tcp_flags, ip_version, dns_query,
                icmp_type, icmp_code, ttl, is_simulated)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            rows,
        )
        self._conn.commit()
        return len(rows)

    def load_dataframe(self) -> pd.DataFrame:
        return pd.read_sql_query("SELECT * FROM packets", self._conn)

    def clear(self) -> None:
        self._conn.execute("DELETE FROM packets")
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()


# --- PCAP support ---------------------------------------------------------
def save_pcap(packets: Sequence, filename: str) -> Path:
    """Write raw Scapy packets to a PCAP file under the captures directory.

    ``packets`` must be Scapy packet objects (not PacketRecords). Returns the
    resolved output path. Requires Scapy.
    """
    from scapy.utils import wrpcap

    out_path = safe_output_path(filename, )
    if out_path.suffix.lower() != ".pcap":
        out_path = out_path.with_suffix(".pcap")
    wrpcap(str(out_path), list(packets))
    return out_path


def load_pcap(path: str | Path, limit: int | None = None) -> list[PacketRecord]:
    """Read a PCAP file and return parsed ``PacketRecord`` objects.

    Validates the path and tolerates malformed packets. Requires Scapy.
    """
    # Register the protocol layers (Ether -> IP -> TCP/UDP/DNS ...) before
    # reading; without this rdpcap dissects every frame as Raw bytes.
    import scapy.layers.all  # noqa: F401
    from scapy.utils import rdpcap

    p = Path(path)
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(f"PCAP file not found: {p}")
    packets = rdpcap(str(p))
    records: list[PacketRecord] = []
    for i, pkt in enumerate(packets):
        if limit is not None and i >= limit:
            break
        try:
            records.append(parse_packet(pkt))
        except Exception:
            continue
    return records


__all__ = ["PacketStore", "save_pcap", "load_pcap"]
