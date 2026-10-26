"""Streamlit dashboard for the Network Traffic Monitoring and Analysis Tool.

Run with:  streamlit run app.py

Architecture note: capture runs on a background thread (see packet_capture.py).
Streamlit reruns the whole script on every interaction, so all long-lived
objects (the capture worker, accumulated packets) live in ``st.session_state``
and are created exactly once. This prevents reruns from spawning duplicate
capture threads.
"""
from __future__ import annotations

import time

import pandas as pd
import plotly.express as px
import streamlit as st

import config
from anomaly_detector import alerts_to_dataframe, detect_all
from demo_data import generate_traffic
from filters import PacketFilter, apply_filter
from packet_capture import (
    CaptureWorker,
    list_interfaces,
    scapy_available,
)
from report_generator import alerts_to_csv, build_summary_report, packets_to_csv
from storage import load_pcap
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
from utils import human_bytes, human_rate, safe_output_path, timestamp_slug

st.set_page_config(
    page_title=config.APP_NAME,
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="expanded",
)


# --------------------------------------------------------------------------
# Session state initialization (runs once per session)
# --------------------------------------------------------------------------
def init_state() -> None:
    ss = st.session_state
    ss.setdefault("packets", [])            # list[PacketRecord]
    ss.setdefault("worker", None)           # CaptureWorker | None
    ss.setdefault("monitoring", False)
    ss.setdefault("data_source", "none")    # none | demo | live | pcap
    ss.setdefault("settings", config.default_settings())
    ss.setdefault("thresholds", config.AnomalyThresholds())


init_state()


# --------------------------------------------------------------------------
# Data helpers
# --------------------------------------------------------------------------
def current_dataframe() -> pd.DataFrame:
    return records_to_dataframe(st.session_state.packets)


def ingest_from_worker() -> None:
    """Drain the capture queue into session state, bounding memory growth."""
    worker: CaptureWorker | None = st.session_state.worker
    if worker is None:
        return
    new = worker.drain()
    if new:
        st.session_state.packets.extend(new)
    cap = st.session_state.settings.max_packets_in_memory
    if len(st.session_state.packets) > cap:
        # Keep only the most recent `cap` packets.
        st.session_state.packets = st.session_state.packets[-cap:]
    if worker.error:
        st.session_state.monitoring = False


def stop_monitoring() -> None:
    worker: CaptureWorker | None = st.session_state.worker
    if worker is not None:
        worker.stop()
        ingest_from_worker()
    st.session_state.worker = None
    st.session_state.monitoring = False


def start_live_capture() -> None:
    stop_monitoring()
    s = st.session_state.settings
    worker = CaptureWorker(
        interface=s.interface or None,
        packet_limit=s.packet_limit,
        duration_limit=s.duration_limit,
    )
    worker.start()
    st.session_state.worker = worker
    st.session_state.monitoring = True
    st.session_state.data_source = "live"


def load_demo_data() -> None:
    stop_monitoring()
    records = generate_traffic(num_packets=800, include_anomalies=True)
    st.session_state.packets = records
    st.session_state.data_source = "demo"


# --------------------------------------------------------------------------
# Sidebar: controls
# --------------------------------------------------------------------------
def render_sidebar() -> str:
    st.sidebar.title("📡 " + config.APP_NAME)
    st.sidebar.caption(f"v{config.APP_VERSION}")

    page = st.sidebar.radio(
        "Navigate",
        [
            "Overview", "Live Traffic", "Protocol Analysis", "IP Analytics",
            "Anomaly Alerts", "Packet Explorer", "PCAP Analysis",
            "Reports & Export", "Settings",
        ],
    )

    st.sidebar.divider()
    st.sidebar.subheader("Data source")

    if not scapy_available():
        st.sidebar.info("Scapy not detected → live capture disabled. "
                        "Demo Mode works fully.")

    col1, col2 = st.sidebar.columns(2)
    with col1:
        if st.button("▶ Demo", use_container_width=True,
                     help="Generate simulated traffic (no privileges needed)."):
            load_demo_data()
    with col2:
        live_disabled = not scapy_available()
        if st.session_state.monitoring:
            if st.button("⏹ Stop", use_container_width=True, type="primary"):
                stop_monitoring()
        else:
            if st.button("● Live", use_container_width=True,
                         disabled=live_disabled,
                         help="Start live capture (needs elevated privileges)."):
                try:
                    start_live_capture()
                except Exception as exc:
                    st.sidebar.error(str(exc))

    if st.sidebar.button("🗑 Clear data", use_container_width=True):
        stop_monitoring()
        st.session_state.packets = []
        st.session_state.data_source = "none"

    # Status indicator
    st.sidebar.divider()
    src = st.session_state.data_source
    if st.session_state.monitoring:
        st.sidebar.success("● MONITORING (live)")
    elif src == "demo":
        st.sidebar.warning("◼ Simulated data loaded")
    elif src == "pcap":
        st.sidebar.info("◼ PCAP file loaded")
    else:
        st.sidebar.caption("◻ Idle — no data")

    worker = st.session_state.worker
    if worker is not None and worker.error:
        st.sidebar.error(worker.error)

    return page


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------
def page_overview(df: pd.DataFrame) -> None:
    st.header("Overview")
    if st.session_state.data_source == "demo":
        st.info("Showing **simulated** traffic — this is generated data, not a "
                "real network capture.", icon="🧪")
    if df.empty:
        st.info("No data yet. Start **Demo** mode or **Live** capture from the "
                "sidebar.", icon="ℹ️")
        return

    s = summarize(df)
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total packets", f"{s.total_packets:,}")
    c2.metric("Total bytes", human_bytes(s.total_bytes))
    c3.metric("Avg packet size", f"{s.avg_packet_size:.0f} B")
    c4.metric("Capture rate", f"{s.packets_per_second:.1f} pkt/s")
    status = "LIVE" if st.session_state.monitoring else "Stopped"
    c5.metric("Status", status)

    st.caption("Capture rate reflects packets observed by this tool over the "
               "capture window — not the physical link bandwidth.")

    left, right = st.columns(2)
    with left:
        st.subheader("Protocol mix")
        proto = protocol_distribution(df)
        if not proto.empty:
            fig = px.pie(proto, names="protocol", values="packets", hole=0.45)
            fig.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=320)
            st.plotly_chart(fig, use_container_width=True)
    with right:
        st.subheader("Traffic over time")
        tot = traffic_over_time(df)
        if not tot.empty:
            fig = px.line(tot, x="datetime", y="packets_per_sec",
                          labels={"packets_per_sec": "pkt/s", "datetime": "time"})
            fig.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=320)
            st.plotly_chart(fig, use_container_width=True)


def page_live_traffic(df: pd.DataFrame) -> None:
    st.header("Live Traffic")
    if st.session_state.monitoring:
        st.success("Capturing… table updates on each refresh.", icon="🟢")
    if df.empty:
        st.info("No packets captured yet.", icon="ℹ️")
        return

    s = summarize(df)
    c1, c2, c3 = st.columns(3)
    c1.metric("Packets", f"{s.total_packets:,}")
    c2.metric("Data", human_bytes(s.total_bytes))
    c3.metric("Rate", human_rate(s.bytes_per_second))

    st.subheader("Most recent packets")
    recent = df.sort_values("timestamp", ascending=False).head(200)
    st.dataframe(
        recent[["datetime", "src_ip", "dst_ip", "src_port", "dst_port",
                "protocol", "app_protocol", "length", "tcp_flags"]],
        use_container_width=True, height=420,
    )


def page_protocol_analysis(df: pd.DataFrame) -> None:
    st.header("Protocol Analysis")
    if df.empty:
        st.info("No data to analyze.", icon="ℹ️")
        return

    st.caption("HTTPS/TLS traffic is **identified** by port/handshake — its "
               "encrypted contents are never inspected or decrypted.")
    proto = protocol_distribution(df)
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Packets per protocol")
        fig = px.bar(proto, x="protocol", y="packets", color="protocol")
        fig.update_layout(showlegend=False, height=340,
                          margin=dict(t=10, b=10, l=10, r=10))
        st.plotly_chart(fig, use_container_width=True)
    with c2:
        st.subheader("Bytes per protocol")
        fig = px.bar(proto, x="protocol", y="bytes", color="protocol")
        fig.update_layout(showlegend=False, height=340,
                          margin=dict(t=10, b=10, l=10, r=10))
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Packet-size distribution")
    sizes = packet_size_distribution(df)
    fig = px.bar(sizes, x="size_bucket", y="count")
    fig.update_layout(height=320, margin=dict(t=10, b=10, l=10, r=10),
                      xaxis_title="packet size (bytes)")
    st.plotly_chart(fig, use_container_width=True)

    st.dataframe(proto, use_container_width=True)


def page_ip_analytics(df: pd.DataFrame) -> None:
    st.header("IP Analytics")
    if df.empty:
        st.info("No data to analyze.", icon="ℹ️")
        return

    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Top source IPs")
        src = top_talkers(df, "src_ip")
        if not src.empty:
            fig = px.bar(src, x="packets", y="src_ip", orientation="h")
            fig.update_layout(height=320, margin=dict(t=10, b=10, l=10, r=10),
                              yaxis=dict(autorange="reversed"))
            st.plotly_chart(fig, use_container_width=True)
            st.dataframe(src, use_container_width=True)
    with c2:
        st.subheader("Top destination IPs")
        dst = top_talkers(df, "dst_ip")
        if not dst.empty:
            fig = px.bar(dst, x="packets", y="dst_ip", orientation="h")
            fig.update_layout(height=320, margin=dict(t=10, b=10, l=10, r=10),
                              yaxis=dict(autorange="reversed"))
            st.plotly_chart(fig, use_container_width=True)
            st.dataframe(dst, use_container_width=True)

    c3, c4 = st.columns(2)
    with c3:
        st.subheader("Most frequent destination ports")
        st.dataframe(top_ports(df), use_container_width=True)
    with c4:
        st.subheader("Top conversations (src → dst)")
        st.dataframe(top_conversations(df), use_container_width=True)


def page_anomaly_alerts(df: pd.DataFrame) -> None:
    st.header("Anomaly Alerts")
    st.caption("Heuristic, rule-based detection. Alerts flag patterns worth "
               "review — they are **not** proof of an attack or an IDS verdict.")
    if df.empty:
        st.info("No data to analyze.", icon="ℹ️")
        return

    alerts = detect_all(df, st.session_state.thresholds)
    if not alerts:
        st.success("No anomalies detected with the current thresholds.", icon="✅")
        return

    counts = {"high": 0, "medium": 0, "low": 0}
    for a in alerts:
        counts[a.severity] = counts.get(a.severity, 0) + 1
    c1, c2, c3 = st.columns(3)
    c1.metric("🔴 High", counts["high"])
    c2.metric("🟠 Medium", counts["medium"])
    c3.metric("🟡 Low", counts["low"])

    adf = alerts_to_dataframe(alerts)
    st.dataframe(
        adf[["datetime", "severity", "category", "src_ip", "dst_ip",
             "reason", "stat"]],
        use_container_width=True, height=400,
    )

    st.download_button(
        "⬇ Export alerts (CSV)", data=alerts_to_csv(alerts),
        file_name=f"alerts-{timestamp_slug()}.csv", mime="text/csv",
    )


def page_packet_explorer(df: pd.DataFrame) -> None:
    st.header("Packet Explorer")
    if df.empty:
        st.info("No data to explore.", icon="ℹ️")
        return

    with st.expander("🔍 Filters", expanded=True):
        c1, c2, c3 = st.columns(3)
        src_ip = c1.text_input("Source IP contains")
        dst_ip = c2.text_input("Destination IP contains")
        proto = c3.selectbox("Protocol", ["(any)"] + config.PROTOCOL_CATEGORIES)
        c4, c5, c6 = st.columns(3)
        port = c4.text_input("Port (src or dst)")
        min_size = c5.number_input("Min size (B)", min_value=0, value=0)
        max_size = c6.number_input("Max size (B)", min_value=0, value=0)
        dns = st.text_input("DNS query contains")

    flt = PacketFilter(
        src_ip=src_ip or None,
        dst_ip=dst_ip or None,
        protocol=None if proto == "(any)" else proto,
        port=int(port) if port.strip().isdigit() else None,
        min_size=int(min_size) if min_size > 0 else None,
        max_size=int(max_size) if max_size > 0 else None,
        dns_query_contains=dns or None,
    )
    filtered = apply_filter(df, flt)
    st.caption(f"Showing {len(filtered):,} of {len(df):,} packets.")
    st.dataframe(
        filtered[["datetime", "src_ip", "dst_ip", "src_port", "dst_port",
                  "protocol", "app_protocol", "length", "tcp_flags",
                  "dns_query", "ttl"]],
        use_container_width=True, height=460,
    )


def page_pcap_analysis() -> None:
    st.header("PCAP Analysis")
    st.write("Upload a previously saved `.pcap` / `.pcapng` file for offline "
             "analysis. No live capture or special privileges required.")
    if not scapy_available():
        st.warning("Scapy is required to read PCAP files and is not available.")
        return

    uploaded = st.file_uploader("Choose a PCAP file", type=["pcap", "pcapng"])
    if uploaded is None:
        return
    # Write to a sanitized path inside captures/ then parse.
    safe_path = safe_output_path(uploaded.name)
    try:
        with open(safe_path, "wb") as fh:
            fh.write(uploaded.getbuffer())
        records = load_pcap(safe_path)
    except Exception as exc:
        st.error(f"Could not read PCAP: {exc}")
        return

    if not records:
        st.warning("No parseable packets found in that file.")
        return
    st.session_state.packets = records
    st.session_state.data_source = "pcap"
    st.success(f"Loaded {len(records):,} packets from {uploaded.name}. "
               "Browse the other pages to analyze them.", icon="✅")


def page_reports(df: pd.DataFrame) -> None:
    st.header("Reports & Export")
    if df.empty:
        st.info("No data to export.", icon="ℹ️")
        return

    alerts = detect_all(df, st.session_state.thresholds)
    simulated = st.session_state.data_source == "demo"

    c1, c2, c3 = st.columns(3)
    with c1:
        st.download_button(
            "⬇ Packets (CSV)", data=packets_to_csv(df),
            file_name=f"packets-{timestamp_slug()}.csv", mime="text/csv",
            use_container_width=True,
        )
    with c2:
        st.download_button(
            "⬇ Alerts (CSV)", data=alerts_to_csv(alerts),
            file_name=f"alerts-{timestamp_slug()}.csv", mime="text/csv",
            use_container_width=True,
        )
    with c3:
        st.download_button(
            "⬇ Summary report (TXT)",
            data=build_summary_report(df, alerts, simulated),
            file_name=f"report-{timestamp_slug()}.txt", mime="text/plain",
            use_container_width=True,
        )

    st.subheader("Report preview")
    st.text(build_summary_report(df, alerts, simulated))


def page_settings() -> None:
    st.header("Settings")
    s = st.session_state.settings
    t = st.session_state.thresholds

    st.subheader("Capture")
    interfaces = list_interfaces()
    if interfaces:
        options = ["(default)"] + interfaces
        idx = options.index(s.interface) if s.interface in options else 0
        choice = st.selectbox("Network interface", options, index=idx)
        s.interface = None if choice == "(default)" else choice
    else:
        st.caption("No interfaces detected (Scapy unavailable or no privileges).")

    s.refresh_interval = st.slider("Dashboard refresh interval (s)", 1, 10,
                                   s.refresh_interval)
    limit = st.number_input("Packet limit (0 = unlimited)", min_value=0,
                            value=s.packet_limit or 0)
    s.packet_limit = int(limit) or None
    dur = st.number_input("Duration limit seconds (0 = unlimited)", min_value=0,
                          value=s.duration_limit or 0)
    s.duration_limit = int(dur) or None
    s.max_packets_in_memory = st.number_input(
        "Max packets kept in memory", min_value=1000, value=s.max_packets_in_memory,
        step=1000, help="Bounds memory during long sessions.",
    )

    st.subheader("Anomaly thresholds")
    t.high_packet_rate = st.number_input("High packet rate (pkts/window)",
                                         min_value=1, value=t.high_packet_rate)
    t.rate_window_seconds = st.number_input("Rate window (s)", min_value=1,
                                            value=t.rate_window_seconds)
    t.port_scan_distinct_ports = st.number_input("Port-scan distinct ports",
                                                 min_value=1,
                                                 value=t.port_scan_distinct_ports)
    t.large_packet_bytes = st.number_input("Large packet (bytes)", min_value=1,
                                           value=t.large_packet_bytes)
    t.traffic_spike_factor = st.number_input("Traffic spike factor", min_value=1.0,
                                             value=float(t.traffic_spike_factor),
                                             step=0.5)
    t.reset_connection_count = st.number_input("RST count threshold", min_value=1,
                                               value=t.reset_connection_count)
    st.success("Settings apply immediately on the next interaction.", icon="⚙️")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main() -> None:
    page = render_sidebar()

    # Drain live packets before rendering any page.
    if st.session_state.monitoring:
        ingest_from_worker()

    df = current_dataframe()

    if page == "Overview":
        page_overview(df)
    elif page == "Live Traffic":
        page_live_traffic(df)
    elif page == "Protocol Analysis":
        page_protocol_analysis(df)
    elif page == "IP Analytics":
        page_ip_analytics(df)
    elif page == "Anomaly Alerts":
        page_anomaly_alerts(df)
    elif page == "Packet Explorer":
        page_packet_explorer(df)
    elif page == "PCAP Analysis":
        page_pcap_analysis()
    elif page == "Reports & Export":
        page_reports(df)
    elif page == "Settings":
        page_settings()

    # Auto-refresh loop while monitoring, without blocking the whole app.
    if st.session_state.monitoring:
        worker = st.session_state.worker
        if worker is not None and not worker.running and not worker.error:
            # Capture finished on its own (hit a limit).
            st.session_state.monitoring = False
        time.sleep(st.session_state.settings.refresh_interval)
        st.rerun()


if __name__ == "__main__":
    main()
