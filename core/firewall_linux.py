"""
Linux firewall backend using iptables.

All subprocess calls use list-form ``_run()`` — **never** ``os.system()``
or f-string shell interpolation.
"""

from __future__ import annotations

from typing import Any

from core.firewall_abc import FirewallBackend, FirewallResult
from utils.logger import get_logger

logger = get_logger(__name__)


def _run(*args: str, timeout: int = 20) -> tuple[int, str, str]:
    """Run a subprocess command safely and return (returncode, stdout, stderr)."""
    import subprocess
    try:
        result = subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError as exc:
        return 1, "", f"Command not found: {exc}"
    except subprocess.TimeoutExpired:
        return 1, "", "Command timed out"
    except Exception as exc:  # noqa: BLE001
        return 1, "", str(exc)


class LinuxIptablesBackend(FirewallBackend):
    """Linux firewall backend using ``iptables``."""

    def block_ip(self, ip: str, rule_name: str) -> FirewallResult:
        # Try with comment tag first for easier identification/cleanup
        rc, _, err = _run(
            "iptables", "-I", "INPUT", "-s", ip,
            "-m", "comment", "--comment", rule_name, "-j", "DROP",
        )
        if rc != 0:
            # Fall back to plain rule (comment module may not be available)
            rc, _, err = _run("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP")
        ok = rc == 0
        msg = f"IP {ip} blocked." if ok else err
        logger.info("block_ip %s → %s", ip, msg)
        return {"success": ok, "message": msg, "rule_name": rule_name}

    def unblock_ip(self, ip: str, rule_name: str) -> FirewallResult:
        rc, _, err = _run("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
        ok = rc == 0
        msg = f"IP {ip} unblocked." if ok else err
        logger.info("unblock_ip %s → %s", ip, msg)
        return {"success": ok, "message": msg}

    def block_port(self, port: int, protocol: str, rule_name: str) -> FirewallResult:
        proto = protocol.lower()
        rc, _, err = _run(
            "iptables", "-I", "INPUT", "-p", proto,
            "--dport", str(port), "-j", "DROP",
        )
        ok = rc == 0
        msg = f"Port {port}/{protocol.upper()} blocked." if ok else err
        logger.info("block_port %s/%s → %s", port, protocol.upper(), msg)
        return {"success": ok, "message": msg, "rule_name": rule_name}

    def unblock_port(self, port: int, protocol: str, rule_name: str) -> FirewallResult:
        proto = protocol.lower()
        rc, _, err = _run(
            "iptables", "-D", "INPUT", "-p", proto,
            "--dport", str(port), "-j", "DROP",
        )
        ok = rc == 0
        msg = f"Port {port}/{protocol.upper()} unblocked." if ok else err
        return {"success": ok, "message": msg}

    def list_rules(self, prefix: str) -> FirewallResult:
        rc, out, err = _run("iptables", "-L", "INPUT", "-n", "--line-numbers")
        if rc != 0:
            return {"success": False, "message": err, "rules": []}
        rules: list[dict[str, str]] = []
        for line in out.splitlines():
            if "DROP" in line or "REJECT" in line:
                rules.append({"raw": line.strip()})
        return {"success": True, "message": f"{len(rules)} DROP/REJECT rules found.", "rules": rules}

    def get_status(self) -> FirewallResult:
        rc, out, err = _run("iptables", "-L", "-n", "--line-numbers")
        state = "ON" if rc == 0 else "UNKNOWN"
        return {"success": rc == 0, "message": out or err, "profiles": {"Linux": state}}

    def enable(self) -> FirewallResult:
        cmds = [
            ["iptables", "-P", "INPUT", "DROP"],
            ["iptables", "-P", "FORWARD", "DROP"],
            ["iptables", "-P", "OUTPUT", "ACCEPT"],
            ["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
            ["iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ]
        for cmd in cmds:
            rc, _, err = _run(*cmd)
            if rc != 0:
                logger.error("enable_firewall step %s failed: %s", cmd, err)
                return {"success": False, "message": err}
        return {"success": True, "message": "Linux iptables firewall enabled (default DROP)."}

    def disable(self) -> FirewallResult:
        cmds = [
            ["iptables", "-P", "INPUT", "ACCEPT"],
            ["iptables", "-P", "FORWARD", "ACCEPT"],
            ["iptables", "-P", "OUTPUT", "ACCEPT"],
            ["iptables", "-F"],
        ]
        for cmd in cmds:
            rc, _, err = _run(*cmd)
            if rc != 0:
                return {"success": False, "message": err}
        return {"success": True, "message": "Linux iptables firewall disabled (ACCEPT all)."}

    def enable_logging(self, log_path: str) -> FirewallResult:
        # Linux uses syslog/journald for iptables logging, not a custom file
        rc, _, err = _run(
            "iptables", "-A", "INPUT", "-j", "LOG",
            "--log-prefix", "NetGuard: ", "--log-level", "4",
        )
        ok = rc == 0
        msg = "iptables LOG rule added (output via syslog)." if ok else err
        return {"success": ok, "message": msg}
