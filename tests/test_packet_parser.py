"""Tests for packet parsing using synthetic Scapy packet fixtures.

These build real Scapy packets in memory, so no live network or elevated
privileges are needed.
"""
import pytest

from packet_parser import PacketRecord, decode_tcp_flags, parse_packet

scapy = pytest.importorskip("scapy.all")
from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Ether, Raw  # noqa: E402


def test_decode_tcp_flags():
    assert decode_tcp_flags(0x02) == "S"       # SYN
    assert decode_tcp_flags(0x12) == "SA"      # SYN-ACK
    assert decode_tcp_flags(0x10) == "A"       # ACK
    assert decode_tcp_flags(0x04) == "R"       # RST
    assert decode_tcp_flags(0x01) == "F"       # FIN
    assert decode_tcp_flags("nonsense") == ""


def test_parse_tcp_https():
    pkt = IP(src="192.168.1.5", dst="93.184.216.34") / TCP(
        sport=50000, dport=443, flags="S"
    )
    rec = parse_packet(pkt, timestamp=100.0)
    assert rec.protocol == "TCP"
    assert rec.app_protocol == "HTTPS/TLS"
    assert rec.src_ip == "192.168.1.5"
    assert rec.dst_port == 443
    assert rec.tcp_flags == "S"
    assert rec.ip_version == 4
    assert rec.length > 0


def test_parse_udp_dns_query():
    pkt = IP(src="192.168.1.5", dst="8.8.8.8") / UDP(sport=5353, dport=53) / DNS(
        rd=1, qd=DNSQR(qname="example.com")
    )
    rec = parse_packet(pkt)
    assert rec.protocol == "UDP"
    assert rec.app_protocol == "DNS"
    assert rec.dns_query == "example.com"
    assert rec.dst_port == 53


def test_parse_icmp():
    pkt = IP(src="192.168.1.5", dst="8.8.8.8") / ICMP(type=8, code=0)
    rec = parse_packet(pkt)
    assert rec.protocol == "ICMP"
    assert rec.app_protocol == "ICMP"
    assert rec.icmp_type == 8
    assert rec.icmp_code == 0


def test_parse_arp():
    pkt = ARP(psrc="192.168.1.1", pdst="192.168.1.5")
    rec = parse_packet(pkt)
    assert rec.protocol == "ARP"
    assert rec.app_protocol == "ARP"
    assert rec.src_ip == "192.168.1.1"


def test_parse_ipv6_tcp():
    pkt = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=1234, dport=80)
    rec = parse_packet(pkt)
    assert rec.ip_version == 6
    assert rec.protocol == "TCP"
    assert rec.app_protocol == "HTTP"


def test_parse_http_port80():
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40000, dport=80, flags="PA") / Raw(load=b"GET / HTTP/1.1")
    rec = parse_packet(pkt)
    assert rec.app_protocol == "HTTP"
    assert "P" in rec.tcp_flags and "A" in rec.tcp_flags


def test_parse_malformed_does_not_crash():
    # A bare Ethernet frame with junk payload and no IP layer.
    pkt = Ether() / Raw(load=b"\x00\x01\x02malformed\xff")
    rec = parse_packet(pkt)
    assert isinstance(rec, PacketRecord)
    assert rec.protocol in ("Other", "ARP")  # no IP/TCP/UDP -> Other
    assert rec.app_protocol == "Other"


def test_parse_missing_fields_are_none():
    pkt = IP(src="1.1.1.1", dst="2.2.2.2")  # no transport layer
    rec = parse_packet(pkt)
    assert rec.src_port is None
    assert rec.dst_port is None
    assert rec.tcp_flags is None
    assert rec.dns_query is None


def test_as_dict_stable_schema():
    rec = parse_packet(IP() / UDP(dport=53))
    d = rec.as_dict()
    for key in ("timestamp", "src_ip", "dst_ip", "protocol", "app_protocol",
                "length", "tcp_flags"):
        assert key in d
    assert "extra" not in d
