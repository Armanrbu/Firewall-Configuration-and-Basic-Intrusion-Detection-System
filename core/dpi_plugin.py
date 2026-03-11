"""
DPI (Deep Packet Inspection) Plugin for NetGuard IDS.

Installable as a third-party plugin via:
    pip install netguard-dpi-plugin

Or activated locally by adding to pyproject.toml entry-points:
    [project.entry-points."netguard.detectors"]
    dpi = "core.dpi_plugin:DPIDetector"

Inspects packet payloads for known malicious patterns without Scapy dependency
falling back to psutil connection metadata when Scapy is unavailable (headless
environments, Docker without raw-socket privilege, etc.).

Detected patterns:
  - SQL injection payloads (HTTP GET/POST params)
  - Directory traversal sequences in HTTP paths
  - Shell command injection in HTTP headers
  - TOR/VPN fingerprinting via port probability heuristics
  - C2 beacon periodicity (uniform inter-arrival times)
  - Cleartext password submission (HTTP Basic auth without TLS)
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any

from core.detector_abc import AbstractDetector, DetectorResult
from utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Signature database
# ---------------------------------------------------------------------------

# Regex patterns matched against reassembled payload strings
_PAYLOAD_SIGNATURES: list[tuple[str, str, float]] = [
    # (name, pattern, score)
    ("sql_injection",      r"(?i)(union\s+select|drop\s+table|insert\s+into|' or '1'='1|--\s*$)", 0.85),
    ("dir_traversal",      r"(?i)(\.\.\/|\.\.\\|%2e%2e%2f|%252e%252e%252f)",                       0.80),
    ("cmd_injection",      r"(?i)(;\s*(ls|cat|wget|curl|nc|bash|sh)\b|`[^`]+`|\$\(.*\))",          0.90),
    ("log4j_exploit",      r"(?i)\$\{jndi:(ldap|rmi|dns|corba)://",                                0.99),
    ("shellcode_nop_sled", r"(?i)(\x90{8,}|\\x90{8,}|%90{8,})",                                   0.95),
    ("xss_basic",          r"(?i)(<script\b|javascript:|onerror=|onload=)",                         0.70),
    ("http_basic_auth",    r"(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/=]{4,}",                     0.40),
]

_COMPILED_SIGS: list[tuple[str, re.Pattern, float]] = [
    (name, re.compile(pat), score)
    for name, pat, score in _PAYLOAD_SIGNATURES
]

# Ports frequently used by C2 frameworks and non-standard tunnels
_SUSPICIOUS_PORTS: set[int] = {
    1080,   # SOCKS proxy
    4444,   # Metasploit default
    5555,   # ADB / Android debug
    6666,   # IRC/botnet
    6667,   # IRC
    8443,   # Alt HTTPS (often C2)
    9001,   # Tor
    9030,   # Tor directory
    31337,  # "elite" / old trojan port
}


@dataclass
class _PayloadMatch:
    sig_name: str
    score: float
    excerpt: str = ""


# ---------------------------------------------------------------------------
# DPI Detector
# ---------------------------------------------------------------------------

class DPIDetector(AbstractDetector):
    """
    Deep Packet Inspection detector.

    When running with Scapy + CAP_NET_RAW (Linux root / Windows with Npcap)
    it captures live packets for the target IP and inspects payloads.
    Otherwise, it falls back to connection-metadata heuristics (port scoring,
    beacon periodicity, connection-count anomalies).

    Configuration (config.yaml):
        dpi:
          enabled: true
          max_payload_bytes: 2048   # bytes of payload to inspect per packet
          beacon_variance_ms: 200   # max std-dev for C2 beacon detection (ms)
          suspicious_port_score: 0.4
    """

    name    = "dpi"
    version = "1.1.0"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        cfg = (config or {}).get("dpi", {})
        self._enabled               = cfg.get("enabled", True)
        self._max_payload_bytes     = int(cfg.get("max_payload_bytes", 2048))
        self._beacon_variance_ms    = float(cfg.get("beacon_variance_ms", 200.0))
        self._suspicious_port_score = float(cfg.get("suspicious_port_score", 0.4))
        self._scapy_available       = False
        self._captures: dict[str, list[bytes]] = {}   # ip → recent raw payloads

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_start(self) -> None:
        try:
            import scapy.all  # noqa: F401
            self._scapy_available = True
            logger.info("DPI plugin: Scapy available — live packet inspection enabled.")
        except ImportError:
            logger.warning(
                "DPI plugin: Scapy not installed or no raw-socket privilege. "
                "Falling back to connection-metadata heuristics."
            )

    def on_stop(self) -> None:
        self._captures.clear()
        logger.debug("DPI plugin stopped and capture buffer cleared.")

    # ------------------------------------------------------------------
    # Core analysis
    # ------------------------------------------------------------------

    def analyze(
        self,
        ip: str,
        events: list[Any],
        *,
        context: dict[str, Any] | None = None,
    ) -> DetectorResult:
        if not self._enabled or not events:
            return DetectorResult(triggered=False)

        matches: list[_PayloadMatch] = []

        # 1. Payload signature scan (if captures available)
        for raw in self._captures.get(ip, []):
            payload_str = _bytes_to_str(raw, self._max_payload_bytes)
            for sig_name, pattern, base_score in _COMPILED_SIGS:
                if pattern.search(payload_str):
                    excerpt = _extract_excerpt(payload_str, pattern)
                    matches.append(_PayloadMatch(sig_name, base_score, excerpt))

        # 2. Suspicious port heuristic
        ports_hit = {getattr(e, "port", 0) for e in events if getattr(e, "port", 0)}
        suspicious = ports_hit & _SUSPICIOUS_PORTS
        if suspicious:
            matches.append(_PayloadMatch(
                "suspicious_ports",
                self._suspicious_port_score * min(1.0, len(suspicious) / 3),
                f"ports: {suspicious}",
            ))

        # 3. C2 beacon detection (periodic inter-arrival time)
        timestamps = sorted(
            getattr(e, "timestamp", 0.0) for e in events if hasattr(e, "timestamp")
        )
        if len(timestamps) >= 5:
            beacon_result = _check_beacon_periodicity(
                timestamps, self._beacon_variance_ms
            )
            if beacon_result:
                matches.append(beacon_result)

        if not matches:
            return DetectorResult(triggered=False, score=0.0,
                                  features={"ports_hit": len(ports_hit)})

        # Aggregate: take max score, combine reasons
        top = max(matches, key=lambda m: m.score)
        composite = min(1.0, sum(m.score for m in matches) / max(1, len(matches)) * 1.5)
        reasons = "; ".join(f"{m.sig_name}({m.score:.2f})" for m in matches)

        return DetectorResult(
            triggered=True,
            score=round(composite, 4),
            reason=f"DPI: {reasons}",
            features={
                "signatures_matched": len(matches),
                "ports_hit": len(ports_hit),
                "suspicious_ports": list(suspicious),
                "top_sig": top.sig_name,
                "top_score": top.score,
            },
            rule_id="dpi_builtin",
            action="block" if composite >= 0.85 else "alert",
        )

    # ------------------------------------------------------------------
    # Public API for live capture feed
    # ------------------------------------------------------------------

    def feed_packet(self, ip: str, raw_payload: bytes) -> None:
        """Push a raw packet payload into the per-IP capture buffer.

        Called by the Scapy sniffer thread (if available) or unit tests.
        """
        buf = self._captures.setdefault(ip, [])
        buf.append(raw_payload[: self._max_payload_bytes])
        # Keep buffer bounded
        if len(buf) > 50:
            buf.pop(0)

    def clear_captures(self, ip: str | None = None) -> None:
        """Clear the capture buffer for *ip* (or all IPs if None)."""
        if ip is None:
            self._captures.clear()
        else:
            self._captures.pop(ip, None)

    def get_capture_summary(self) -> dict[str, int]:
        """Return {ip: packet_count} for the current buffer."""
        return {ip: len(pkts) for ip, pkts in self._captures.items()}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bytes_to_str(raw: bytes, limit: int) -> str:
    """Decode bytes as latin-1 (lossless) and truncate."""
    return raw[:limit].decode("latin-1", errors="replace")


def _extract_excerpt(text: str, pattern: re.Pattern, window: int = 40) -> str:
    """Return the matched text and a little surrounding context."""
    m = pattern.search(text)
    if not m:
        return ""
    start = max(0, m.start() - 10)
    end   = min(len(text), m.end() + window)
    return repr(text[start:end])


def _check_beacon_periodicity(
    timestamps: list[float],
    max_variance_ms: float,
) -> _PayloadMatch | None:
    """
    Detect C2 beacon behaviour: highly regular connection intervals.

    A variance of inter-arrival times below *max_variance_ms* milliseconds
    across ≥5 connections suggests automated/beaconing traffic.
    """
    if len(timestamps) < 5:
        return None
    intervals_ms = [
        (timestamps[i + 1] - timestamps[i]) * 1000
        for i in range(len(timestamps) - 1)
    ]
    if not intervals_ms:
        return None
    mean = sum(intervals_ms) / len(intervals_ms)
    if mean <= 0:
        return None
    variance = sum((x - mean) ** 2 for x in intervals_ms) / len(intervals_ms)
    std_dev = variance ** 0.5

    if std_dev < max_variance_ms and mean < 60_000:  # < 1-minute beacon interval
        score = max(0.3, min(0.9, 1.0 - (std_dev / max_variance_ms)))
        return _PayloadMatch(
            "c2_beacon",
            round(score, 3),
            f"interval={mean:.0f}ms std={std_dev:.1f}ms",
        )
    return None
