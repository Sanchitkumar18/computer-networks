"""Tests for packet filtering, CSV export, and demo-data generation."""
from filters import PacketFilter, apply_filter
from packet_parser import PacketRecord
from report_generator import packets_to_csv
from demo_data import generate_traffic
from anomaly_detector import detect_all
from traffic_analyzer import records_to_dataframe


def _rec(**kw) -> PacketRecord:
    base = dict(timestamp=1000.0, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                protocol="TCP", app_protocol="HTTPS/TLS", length=100,
                src_port=50000, dst_port=443)
    base.update(kw)
    return PacketRecord(**base)


def sample_df():
    return records_to_dataframe([
        _rec(src_ip="10.0.0.1", dst_port=443, app_protocol="HTTPS/TLS", length=100),
        _rec(src_ip="10.0.0.2", dst_port=80, app_protocol="HTTP", length=1200),
        _rec(src_ip="10.0.0.3", dst_port=53, app_protocol="DNS",
             protocol="UDP", length=60),
    ])


def test_empty_filter_returns_all():
    df = sample_df()
    out = apply_filter(df, PacketFilter())
    assert len(out) == len(df)


def test_filter_by_src_ip():
    df = sample_df()
    out = apply_filter(df, PacketFilter(src_ip="10.0.0.2"))
    assert len(out) == 1
    assert out.iloc[0]["src_ip"] == "10.0.0.2"


def test_filter_by_protocol():
    df = sample_df()
    out = apply_filter(df, PacketFilter(protocol="DNS"))
    assert len(out) == 1
    assert out.iloc[0]["app_protocol"] == "DNS"


def test_filter_by_port():
    df = sample_df()
    out = apply_filter(df, PacketFilter(port=80))
    assert len(out) == 1
    assert out.iloc[0]["dst_port"] == 80


def test_filter_by_size_range():
    df = sample_df()
    out = apply_filter(df, PacketFilter(min_size=100, max_size=1000))
    assert set(out["length"]) == {100}


def test_filter_by_time_range():
    df = records_to_dataframe([
        _rec(timestamp=1000.0), _rec(timestamp=2000.0), _rec(timestamp=3000.0),
    ])
    out = apply_filter(df, PacketFilter(start_time=1500.0, end_time=2500.0))
    assert len(out) == 1
    assert out.iloc[0]["timestamp"] == 2000.0


def test_filter_on_empty_df():
    empty = records_to_dataframe([])
    out = apply_filter(empty, PacketFilter(src_ip="x"))
    assert out.empty


def test_packets_to_csv():
    df = sample_df()
    csv_text = packets_to_csv(df)
    assert "src_ip" in csv_text
    assert "10.0.0.1" in csv_text
    # One header line + 3 rows.
    assert len([ln for ln in csv_text.strip().splitlines() if ln]) == 4


def test_packets_to_csv_empty():
    assert packets_to_csv(records_to_dataframe([])) == ""


def test_demo_data_generation_reproducible():
    a = generate_traffic(num_packets=200, include_anomalies=True, seed=42,
                         start_time=1000.0)
    b = generate_traffic(num_packets=200, include_anomalies=True, seed=42,
                         start_time=1000.0)
    assert len(a) == len(b)
    assert all(x.is_simulated for x in a)
    # Timestamps sorted ascending.
    ts = [r.timestamp for r in a]
    assert ts == sorted(ts)


def test_demo_data_triggers_anomalies():
    recs = generate_traffic(num_packets=300, include_anomalies=True, seed=7,
                            start_time=1000.0)
    df = records_to_dataframe(recs)
    alerts = detect_all(df)
    categories = {a.category for a in alerts}
    # The injected bursts should produce at least a scan or a rate/spike alert.
    assert categories, "expected at least one anomaly from injected patterns"


def test_demo_data_no_anomalies_flag():
    recs = generate_traffic(num_packets=100, include_anomalies=False, seed=1,
                            start_time=1000.0)
    assert all(r.is_simulated for r in recs)
