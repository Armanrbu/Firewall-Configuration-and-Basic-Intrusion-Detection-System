"""
Windows firewall backend using netsh advfirewall.

All subprocess calls use list-form ``_run()`` — **never** ``os.system()``
or f-string shell interpolation.
"""

from __future__ import annotations

import os
import re
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


class WindowsNetshBackend(FirewallBackend):
    """Windows firewall backend using ``netsh advfirewall``."""

    def block_ip(self, ip: str, rule_name: str) -> FirewallResult:
        rc, out, err = _run(
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}",
        )
        ok = rc == 0
        msg = f"IP {ip} blocked." if ok else err
        logger.info("block_ip %s → %s", ip, msg)
        return {"success": ok, "message": msg, "rule_name": rule_name}

    def unblock_ip(self, ip: str, rule_name: str) -> FirewallResult:
        rc, _, err = _run(
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}",
        )
        ok = rc == 0
        msg = f"IP {ip} unblocked." if ok else err
        logger.info("unblock_ip %s → %s", ip, msg)
        return {"success": ok, "message": msg}

    def block_port(self, port: int, protocol: str, rule_name: str) -> FirewallResult:
        proto = protocol.upper()
        rc, _, err = _run(
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", "action=block",
            f"protocol={proto}", f"localport={port}",
        )
        ok = rc == 0
        msg = f"Port {port}/{proto} blocked." if ok else err
        logger.info("block_port %s/%s → %s", port, proto, msg)
        return {"success": ok, "message": msg, "rule_name": rule_name}

    def unblock_port(self, port: int, protocol: str, rule_name: str) -> FirewallResult:
        rc, _, err = _run(
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}",
        )
        ok = rc == 0
        msg = f"Port {port}/{protocol.upper()} unblocked." if ok else err
        return {"success": ok, "message": msg}

    def list_rules(self, prefix: str) -> FirewallResult:
        rc, out, err = _run(
            "netsh", "advfirewall", "firewall", "show", "rule",
            "name=all", "dir=in",
        )
        if rc != 0:
            return {"success": False, "message": err, "rules": []}

        rules: list[dict[str, str]] = []
        current: dict[str, str] = {}
        for line in out.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("---"):
                continue
            if ":" in stripped:
                key, _, val = stripped.partition(":")
                key = key.strip()
                val = val.strip()
                if key == "Rule Name":
                    if current.get("name", "").startswith(prefix):
                        rules.append(current)
                    current = {"name": val}
                elif current:
                    current[key.lower().replace(" ", "_")] = val
        if current.get("name", "").startswith(prefix):
            rules.append(current)

        formatted = [
            {
                "name": r.get("name", ""),
                "direction": r.get("direction", ""),
                "action": r.get("action", ""),
                "enabled": r.get("enabled", ""),
            }
            for r in rules
        ]
        return {"success": True, "message": f"{len(formatted)} rules found.", "rules": formatted}

    def get_status(self) -> FirewallResult:
        rc, out, err = _run(
            "netsh", "advfirewall", "show", "allprofiles", "state",
        )
        if rc != 0:
            logger.error("get_status failed: %s", err)
            return {"success": False, "message": err, "profiles": {}}

        profiles: dict[str, str] = {}
        current = ""
        for line in out.splitlines():
            m = re.match(r"^\s*(Domain|Private|Public)\s+Profile\s+Settings:", line)
            if m:
                current = m.group(1)
            sm = re.match(r"^\s*State\s+(ON|OFF)", line)
            if sm and current:
                profiles[current] = sm.group(1)
        return {"success": True, "message": "OK", "profiles": profiles}

    def enable(self) -> FirewallResult:
        rc, out, err = _run("netsh", "advfirewall", "set", "allprofiles", "state", "on")
        ok = rc == 0
        msg = "Firewall enabled." if ok else err
        logger.info("enable_firewall → %s", msg)
        return {"success": ok, "message": msg}

    def disable(self) -> FirewallResult:
        rc, out, err = _run("netsh", "advfirewall", "set", "allprofiles", "state", "off")
        ok = rc == 0
        msg = "Firewall disabled." if ok else err
        logger.info("disable_firewall → %s", msg)
        return {"success": ok, "message": msg}

    def enable_logging(self, log_path: str) -> FirewallResult:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        cmds = [
            ["netsh", "advfirewall", "set", "currentprofile", "logging", "filename", log_path],
            ["netsh", "advfirewall", "set", "currentprofile", "logging", "maxfilesize", "16384"],
            ["netsh", "advfirewall", "set", "currentprofile", "logging", "droppedconnections", "enable"],
            ["netsh", "advfirewall", "set", "currentprofile", "logging", "allowedconnections", "enable"],
        ]
        for cmd in cmds:
            rc, _, err = _run(*cmd)
            if rc != 0:
                return {"success": False, "message": err}
        return {"success": True, "message": f"Logging enabled → {log_path}"}
