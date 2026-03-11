"""
Cross-platform firewall backend.

Supports Windows (netsh advfirewall) and Linux (iptables).
All public functions return a dict: {"success": bool, "message": str, ...}
"""

from __future__ import annotations

import platform
import re
import subprocess
import time
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)

_OS = platform.system()          # "Windows" | "Linux" | "Darwin"
_RULES_PREFIX = "NetGuard_"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run(*args: str, timeout: int = 20) -> tuple[int, str, str]:
    """Run a subprocess command safely and return (returncode, stdout, stderr)."""
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


def _run_ps(command: str, timeout: int = 20) -> tuple[int, str, str]:
    """Run a PowerShell command (Windows only)."""
    return _run("powershell", "-NoProfile", "-Command", command, timeout=timeout)


def _rule_name(ip: str) -> str:
    return f"{_RULES_PREFIX}Block_{ip.replace('/', '_')}"


def _port_rule_name(port: int, protocol: str) -> str:
    return f"{_RULES_PREFIX}Port_{protocol}_{port}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_status() -> dict[str, Any]:
    """Return firewall status for all profiles (or current profile on Linux)."""
    if _OS == "Windows":
        rc, out, err = _run(
            "netsh", "advfirewall", "show", "allprofiles", "state"
        )
        if rc != 0:
            logger.error("get_status failed: %s", err)
            return {"success": False, "message": err, "profiles": {}}
        profiles: dict[str, str] = {}
        for line in out.splitlines():
            m = re.match(r"^\s*(Domain|Private|Public)\s+Profile\s+Settings:", line)
            if m:
                current = m.group(1)
            sm = re.match(r"^\s*State\s+(ON|OFF)", line)
            if sm:
                profiles[current] = sm.group(1)
        return {"success": True, "message": "OK", "profiles": profiles}

    elif _OS == "Linux":
        rc, out, err = _run("iptables", "-L", "-n", "--line-numbers")
        state = "ON" if rc == 0 else "UNKNOWN"
        return {"success": rc == 0, "message": out or err, "profiles": {"Linux": state}}

    return {"success": False, "message": f"Unsupported OS: {_OS}", "profiles": {}}


def enable_firewall() -> dict[str, Any]:
    """Enable the system firewall."""
    if _OS == "Windows":
        rc, out, err = _run("netsh", "advfirewall", "set", "allprofiles", "state", "on")
        ok = rc == 0
        msg = "Firewall enabled." if ok else err
        logger.info("enable_firewall → %s", msg)
        return {"success": ok, "message": msg}

    elif _OS == "Linux":
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

    return {"success": False, "message": f"Unsupported OS: {_OS}"}


def disable_firewall() -> dict[str, Any]:
    """Disable the system firewall."""
    if _OS == "Windows":
        rc, out, err = _run("netsh", "advfirewall", "set", "allprofiles", "state", "off")
        ok = rc == 0
        msg = "Firewall disabled." if ok else err
        logger.info("disable_firewall → %s", msg)
        return {"success": ok, "message": msg}

    elif _OS == "Linux":
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

    return {"success": False, "message": f"Unsupported OS: {_OS}"}


def block_ip(ip: str, rule_name: str | None = None) -> dict[str, Any]:
    """Block all inbound traffic from *ip*."""
    name = rule_name or _rule_name(ip)
    if _OS == "Windows":
        rc, out, err = _run_ps(
            f'New-NetFirewallRule -DisplayName "{name}" '
            f'-Direction Inbound -Action Block -RemoteAddress {ip}'
        )
        ok = rc == 0
        msg = f"IP {ip} blocked." if ok else err
        logger.info("block_ip %s → %s", ip, msg)
        return {"success": ok, "message": msg, "rule_name": name}

    elif _OS == "Linux":
        rc, _, err = _run("iptables", "-I", "INPUT", "-s", ip, "-j", "DROP")
        rc2, _, err2 = _run("iptables", "-I", "INPUT", "-m", "comment",
                            "--comment", name, "-s", ip, "-j", "DROP")
        ok = rc == 0 or rc2 == 0
        msg = f"IP {ip} blocked." if ok else (err or err2)
        logger.info("block_ip %s → %s", ip, msg)
        return {"success": ok, "message": msg, "rule_name": name}

    return {"success": False, "message": f"Unsupported OS: {_OS}"}


def unblock_ip(ip: str) -> dict[str, Any]:
    """Remove the block rule for *ip*."""
    name = _rule_name(ip)
    if _OS == "Windows":
        rc, _, err = _run_ps(
            f'Remove-NetFirewallRule -DisplayName "{name}" -ErrorAction SilentlyContinue'
        )
        ok = rc == 0
        msg = f"IP {ip} unblocked." if ok else err
        logger.info("unblock_ip %s → %s", ip, msg)
        return {"success": ok, "message": msg}

    elif _OS == "Linux":
        rc, _, err = _run("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
        ok = rc == 0
        msg = f"IP {ip} unblocked." if ok else err
        logger.info("unblock_ip %s → %s", ip, msg)
        return {"success": ok, "message": msg}

    return {"success": False, "message": f"Unsupported OS: {_OS}"}


def block_port(port: int, protocol: str = "TCP") -> dict[str, Any]:
    """Block a specific port for the given protocol."""
    name = _port_rule_name(port, protocol)
    proto = protocol.upper()
    if _OS == "Windows":
        rc, _, err = _run_ps(
            f'New-NetFirewallRule -DisplayName "{name}" '
            f'-Direction Inbound -Action Block -Protocol {proto} -LocalPort {port}'
        )
        ok = rc == 0
        msg = f"Port {port}/{proto} blocked." if ok else err
        logger.info("block_port %s/%s → %s", port, proto, msg)
        return {"success": ok, "message": msg, "rule_name": name}

    elif _OS == "Linux":
        rc, _, err = _run(
            "iptables", "-I", "INPUT", "-p", proto.lower(),
            "--dport", str(port), "-j", "DROP"
        )
        ok = rc == 0
        msg = f"Port {port}/{proto} blocked." if ok else err
        logger.info("block_port %s/%s → %s", port, proto, msg)
        return {"success": ok, "message": msg, "rule_name": name}

    return {"success": False, "message": f"Unsupported OS: {_OS}"}


def unblock_port(port: int, protocol: str = "TCP") -> dict[str, Any]:
    """Remove the block rule for a specific port."""
    name = _port_rule_name(port, protocol)
    proto = protocol.upper()
    if _OS == "Windows":
        rc, _, err = _run_ps(
            f'Remove-NetFirewallRule -DisplayName "{name}" -ErrorAction SilentlyContinue'
        )
        ok = rc == 0
        msg = f"Port {port}/{proto} unblocked." if ok else err
        return {"success": ok, "message": msg}

    elif _OS == "Linux":
        rc, _, err = _run(
            "iptables", "-D", "INPUT", "-p", proto.lower(),
            "--dport", str(port), "-j", "DROP"
        )
        ok = rc == 0
        msg = f"Port {port}/{proto} unblocked." if ok else err
        return {"success": ok, "message": msg}

    return {"success": False, "message": f"Unsupported OS: {_OS}"}


def list_rules() -> dict[str, Any]:
    """Return active firewall rules added by this app."""
    rules: list[dict[str, str]] = []
    if _OS == "Windows":
        rc, out, err = _run_ps(
            f'Get-NetFirewallRule | Where-Object {{$_.DisplayName -like "{_RULES_PREFIX}*"}} | '
            'Select-Object DisplayName,Direction,Action,Enabled | ConvertTo-Csv -NoTypeInformation'
        )
        if rc != 0:
            return {"success": False, "message": err, "rules": []}
        for line in out.splitlines()[1:]:
            parts = [p.strip('"') for p in line.split(",")]
            if len(parts) >= 4:
                rules.append({
                    "name": parts[0],
                    "direction": parts[1],
                    "action": parts[2],
                    "enabled": parts[3],
                })
        return {"success": True, "message": f"{len(rules)} rules found.", "rules": rules}

    elif _OS == "Linux":
        rc, out, err = _run("iptables", "-L", "INPUT", "-n", "--line-numbers")
        if rc != 0:
            return {"success": False, "message": err, "rules": []}
        for line in out.splitlines():
            if "DROP" in line or "REJECT" in line:
                rules.append({"raw": line.strip()})
        return {"success": True, "message": f"{len(rules)} DROP/REJECT rules found.", "rules": rules}

    return {"success": False, "message": f"Unsupported OS: {_OS}", "rules": []}


def enable_logging(log_path: str = r"C:\Temp\pfirewall.log") -> dict[str, Any]:
    """Enable Windows Firewall connection logging (Windows only)."""
    if _OS != "Windows":
        return {"success": False, "message": "Firewall logging config is Windows-only via netsh."}
    import os
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
