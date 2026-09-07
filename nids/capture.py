"""
Packet / interface capture helpers (lab use only).

Requires: pip install scapy
Run with admin rights on Windows for live sniffing.
Never capture on networks without permission.
"""
from __future__ import annotations

from typing import Callable, Optional


def sniff_summaries(interface: Optional[str] = None, count: int = 20, timeout: int = 10) -> None:
    """Print packet summaries — smoke test that the NIC is visible to Scapy."""
    try:
        from scapy.all import sniff
    except ImportError as exc:
        raise ImportError("Install scapy: pip install scapy") from exc

    def _prn(pkt) -> None:
        print(pkt.summary())

    sniff(iface=interface, prn=_prn, count=count, timeout=timeout, store=False)


def sniff_to_callback(
    callback: Callable,
    interface: Optional[str] = None,
    count: int = 0,
    timeout: Optional[int] = None,
) -> None:
    """Forward each packet to callback(pkt). count=0 means unlimited until timeout/Ctrl+C."""
    from scapy.all import sniff

    sniff(iface=interface, prn=callback, count=count, timeout=timeout, store=False)


if __name__ == "__main__":
    print("Sniffing 10 packets (Ctrl+C to stop earlier)...")
    sniff_summaries(count=10, timeout=15)
