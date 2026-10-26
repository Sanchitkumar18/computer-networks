"""Tests for PCAP round-tripping in storage.py."""
import subprocess
import sys
from pathlib import Path

from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether, wrpcap

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_load_pcap_parses_layers_in_fresh_process(tmp_path):
    """load_pcap must dissect IP/TCP/UDP even when nothing imported scapy.all.

    Runs in a subprocess because other tests import scapy.all, which would
    register the layers and hide the bug in this process.
    """
    pcap = tmp_path / "sample.pcap"
    wrpcap(str(pcap), [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40000, dport=443, flags="S"),
        Ether() / IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=5353, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com")),
    ])
    script = (
        "import sys; from storage import load_pcap\n"
        "r = load_pcap(sys.argv[1])\n"
        "print(r[0].protocol, r[0].src_ip, r[0].dst_port, r[0].tcp_flags)\n"
        "print(r[1].protocol, r[1].dns_query)\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", script, str(pcap)],
        cwd=PROJECT_ROOT, capture_output=True, text=True, check=True,
    ).stdout.splitlines()
    assert out[0] == "TCP 10.0.0.1 443 S"
    assert out[1].startswith("UDP example.com")
