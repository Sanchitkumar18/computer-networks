"""Tests for the rule-based anomaly detectors."""
from config import AnomalyThresholds
from anomaly_detector import (
    alerts_to_dataframe,
    detect_all,
    detect_connection_resets,
    detect_high_packet_rate,
    detect_large_packets,
    detect_port_scan,
)
from packet_parser import PacketRecord
from traffic_analyzer import records_to_dataframe


def _rec(**kw) -> PacketRecord:
    base = dict(timestamp=1000.0, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                protocol="TCP", app_protocol="TCP", length=100)
    base.update(kw)
    return PacketRecord(**base)


def test_empty_is_safe():
    df = records_to_dataframe([])
    assert detect_all(df) == []
    assert alerts_to_dataframe([]).empty


def test_high_packet_rate_fires():
    t = AnomalyThresholds(high_packet_rate=10, rate_window_seconds=10)
    recs = [_rec(timestamp=1000.0 + i * 0.1, src_ip="9.9.9.9") for i in range(25)]
    df = records_to_dataframe(recs)
    alerts = detect_high_packet_rate(df, t)
    assert alerts and alerts[0].category == "High packet rate"
    assert alerts[0].src_ip == "9.9.9.9"


def test_high_packet_rate_below_threshold_silent():
    t = AnomalyThresholds(high_packet_rate=100, rate_window_seconds=10)
    recs = [_rec(timestamp=1000.0 + i, src_ip="9.9.9.9") for i in range(5)]
    df = records_to_dataframe(recs)
    assert detect_high_packet_rate(df, t) == []


def test_port_scan_fires():
    t = AnomalyThresholds(port_scan_distinct_ports=10)
    recs = [_rec(src_ip="45.0.0.1", dst_port=p) for p in range(20)]
    df = records_to_dataframe(recs)
    alerts = detect_port_scan(df, t)
    assert alerts and alerts[0].category == "Possible port scan"


def test_large_packet_fires():
    t = AnomalyThresholds(large_packet_bytes=3000)
    recs = [_rec(length=5000), _rec(length=100)]
    df = records_to_dataframe(recs)
    alerts = detect_large_packets(df, t)
    assert len(alerts) == 1
    assert "5000" in alerts[0].stat


def test_connection_resets_fire():
    t = AnomalyThresholds(reset_connection_count=5)
    recs = [_rec(src_ip="7.7.7.7", tcp_flags="R") for _ in range(8)]
    df = records_to_dataframe(recs)
    alerts = detect_connection_resets(df, t)
    assert alerts and alerts[0].category == "Repeated TCP resets"


def test_detect_all_sorts_by_severity():
    t = AnomalyThresholds(high_packet_rate=5, port_scan_distinct_ports=5,
                          large_packet_bytes=3000)
    recs = [_rec(length=5000)]  # low severity
    recs += [_rec(timestamp=1000.0 + i * 0.1, src_ip="1.2.3.4",
                  dst_port=i) for i in range(30)]  # high severity
    df = records_to_dataframe(recs)
    alerts = detect_all(df, t)
    assert alerts
    severities = [a.severity for a in alerts]
    # First alert should be the most severe.
    assert severities[0] in ("high", "medium")


def test_alerts_to_dataframe_schema():
    t = AnomalyThresholds(large_packet_bytes=100)
    df = records_to_dataframe([_rec(length=5000)])
    alerts = detect_all(df, t)
    adf = alerts_to_dataframe(alerts)
    for col in ("timestamp", "category", "severity", "reason", "stat"):
        assert col in adf.columns
