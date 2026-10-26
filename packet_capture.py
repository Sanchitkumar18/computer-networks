"""Live packet capture worker built on Scapy.

Runs sniffing on a background thread and hands parsed ``PacketRecord`` objects
to the dashboard through a bounded, thread-safe queue. The capture thread owns
no Streamlit state; the dashboard drains the queue on each rerun.

Privileges: live capture requires raw-socket access, which needs elevated
privileges on every OS (root/sudo on Linux & macOS, Administrator + Npcap on
Windows). Demo mode needs none of this — see README.
"""
from __future__ import annotations

import queue
import threading
import time
from typing import Any

from config import CAPTURE_QUEUE_SIZE
from packet_parser import parse_packet, PacketRecord


class ScapyUnavailableError(RuntimeError):
    """Raised when Scapy cannot be imported for a live-capture operation."""


def scapy_available() -> bool:
    """Return True if Scapy can be imported in this environment."""
    try:
        import scapy  # noqa: F401
        return True
    except Exception:
        return False


def list_interfaces() -> list[str]:
    """Return available network interface names, or [] if unavailable."""
    try:
        from scapy.arch import get_if_list
        return sorted(get_if_list())
    except Exception:
        return []


class CaptureWorker:
    """Background Scapy sniffer feeding a thread-safe queue.

    One instance owns one thread. Create a fresh instance per monitoring
    session; call :meth:`start` once and :meth:`stop` to release resources.
    The dashboard guards against Streamlit reruns spawning duplicate workers by
    keeping a single instance in session state.
    """

    def __init__(
        self,
        interface: str | None = None,
        bpf_filter: str | None = None,
        packet_limit: int | None = None,
        duration_limit: int | None = None,
        queue_size: int = CAPTURE_QUEUE_SIZE,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_limit = packet_limit
        self.duration_limit = duration_limit
        self.queue: "queue.Queue[PacketRecord]" = queue.Queue(maxsize=queue_size)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._started_at: float | None = None
        self._packet_count = 0
        self._error: str | None = None
        self._lock = threading.Lock()

    # --- lifecycle --------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def packet_count(self) -> int:
        with self._lock:
            return self._packet_count

    @property
    def error(self) -> str | None:
        return self._error

    @property
    def elapsed(self) -> float:
        return time.time() - self._started_at if self._started_at else 0.0

    def start(self) -> None:
        """Start the capture thread. Raises ScapyUnavailableError if no Scapy."""
        if self.running:
            return
        if not scapy_available():
            raise ScapyUnavailableError(
                "Scapy is not available; live capture is disabled. Use Demo Mode."
            )
        self._stop_event.clear()
        self._error = None
        self._started_at = time.time()
        self._thread = threading.Thread(
            target=self._run, name="capture-worker", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 3.0) -> None:
        """Signal the capture thread to stop and wait for it to exit."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    # --- draining ---------------------------------------------------------
    def drain(self, max_items: int = 2000) -> list[PacketRecord]:
        """Pop up to ``max_items`` parsed records from the queue (non-blocking)."""
        out: list[PacketRecord] = []
        for _ in range(max_items):
            try:
                out.append(self.queue.get_nowait())
            except queue.Empty:
                break
        return out

    # --- internals --------------------------------------------------------
    def _should_stop(self) -> bool:
        if self._stop_event.is_set():
            return True
        if self.packet_limit and self._packet_count >= self.packet_limit:
            return True
        if self.duration_limit and self.elapsed >= self.duration_limit:
            return True
        return False

    def _handle(self, pkt: Any) -> None:
        """Scapy prn callback: parse and enqueue one packet."""
        try:
            rec = parse_packet(pkt)
        except Exception:
            return
        try:
            self.queue.put_nowait(rec)
        except queue.Full:
            # UI fell behind; drop the oldest to bound memory, then enqueue.
            try:
                self.queue.get_nowait()
                self.queue.put_nowait(rec)
            except queue.Empty:
                pass
        with self._lock:
            self._packet_count += 1

    def _run(self) -> None:
        """Thread body: drive Scapy's sniff loop with cooperative stopping."""
        try:
            from scapy.sendrecv import sniff
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._handle,
                store=False,                 # do not retain packets in memory
                stop_filter=lambda _pkt: self._should_stop(),
                timeout=self.duration_limit,
            )
        except PermissionError:
            self._error = (
                "Permission denied. Live capture needs elevated privileges "
                "(run with sudo / as Administrator). Try Demo Mode instead."
            )
        except OSError as exc:
            self._error = f"Interface error: {exc}. Check the selected interface."
        except Exception as exc:  # pragma: no cover - defensive
            self._error = f"Capture failed: {exc}"


__all__ = [
    "CaptureWorker",
    "ScapyUnavailableError",
    "scapy_available",
    "list_interfaces",
]
