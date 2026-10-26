"""Tests for traffic aggregation and statistics (no network required)."""
from packet_parser import PacketRecord
from traffic_analyzer import (
    packet_size_distribution,
    protocol_distribution,
    records_to_dataframe,
    summarize,
    top_conversations,
    top_ports,
    top_talkers,
    traffic_over_time,
)


def _rec(**kw) -> PacketRecord:
    base = dict(timestamp=1000.0, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                protocol="TCP", app_protocol="HTTPS/TLS", length=100)
    base.update(kw)
    return PacketRecord(**base)


def sample_records():
    return [
        _rec(timestamp=1000.0, length=100, app_protocol="HTTPS/TLS",
             src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=443),
        _rec(timestamp=1001.0, length=200, app_protocol="HTTP",
             src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=80),
        _rec(timestamp=1002.0, length=60, app_protocol="DNS", protocol="UDP",
             src_ip="10.0.0.2", dst_ip="1.1.1.1", dst_port=53),
        _rec(timestamp=1003.0, length=60, app_protocol="DNS", protocol="UDP",
             src_ip="10.0.0.2", dst_ip="1.1.1.1", dst_port=53),
    ]


def test_empty_dataframe_is_safe():
    df = records_to_dataframe([])
    assert df.empty
    s = summarize(df)
    assert s.total_packets == 0 and s.total_bytes == 0
    assert protocol_distribution(df).empty
    assert top_talkers(df, "src_ip").empty
    assert top_ports(df).empty
    assert traffic_over_time(df).empty


def test_summarize_counts_and_rates():
    df = records_to_dataframe(sample_records())
    s = summarize(df)
    assert s.total_packets == 4
    assert s.total_bytes == 420
    assert s.avg_packet_size == 105.0
    # Duration is 3s (1000..1003); 4 packets over 3s.
    assert round(s.duration_seconds, 1) == 3.0
    assert round(s.packets_per_second, 2) == round(4 / 3, 2)
    assert s.unique_src_ips == 2


def test_protocol_distribution_percentages():
    df = records_to_dataframe(sample_records())
    dist = protocol_distribution(df)
    dns = dist[dist["protocol"] == "DNS"].iloc[0]
    assert dns["packets"] == 2
    assert dns["pct_packets"] == 50.0


def test_top_talkers_and_ports():
    df = records_to_dataframe(sample_records())
    talkers = top_talkers(df, "src_ip")
    assert set(talkers["src_ip"]) == {"10.0.0.1", "10.0.0.2"}
    ports = top_ports(df)
    assert int(ports.iloc[0]["port"]) == 53  # 53 appears twice


def test_top_conversations():
    df = records_to_dataframe(sample_records())
    conv = top_conversations(df)
    top = conv.iloc[0]
    assert top["packets"] == 2  # 10.0.0.2 -> 1.1.1.1 twice


def test_traffic_over_time_buckets():
    df = records_to_dataframe(sample_records())
    tot = traffic_over_time(df, bucket_seconds=1)
    assert len(tot) == 4
    assert (tot["packets_per_sec"] == 1).all()


def test_packet_size_distribution():
    df = records_to_dataframe(sample_records())
    sizes = packet_size_distribution(df)
    assert sizes["count"].sum() == 4
