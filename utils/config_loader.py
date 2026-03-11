"""
Load and save the application's YAML configuration file.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    logger.warning("PyYAML not installed; config will use defaults only.")

_DEFAULT_CONFIG: dict[str, Any] = {
    "app": {
        "name": "NetGuard IDS",
        "theme": "dark",
        "minimize_to_tray": True,
    },
    "ids": {
        "alert_threshold": 10,
        "time_window_seconds": 60,
        "auto_block": True,
        "port_scan_threshold": 5,
        "port_scan_window_seconds": 30,
    },
    "firewall": {
        "log_path": r"C:\Temp\pfirewall.log",
        "rules_prefix": "NetGuard_",
    },
    "notifications": {
        "desktop": True,
        "email": False,
        "sms": False,
    },
    "email": {
        "smtp_host": "smtp.gmail.com",
        "smtp_port": 465,
        "username": "",
        "password": "",
        "recipient": "",
    },
    "api": {
        "enabled": False,
        "port": 5000,
        "api_key": "change-me-in-settings",
    },
    "anomaly": {
        "enabled": True,
        "retrain_interval_minutes": 60,
        "model_path": "anomaly_model.pkl",
    },
    "logging": {
        "level": "INFO",
        "file": "netguard.log",
        "max_bytes": 10_485_760,
        "backup_count": 5,
    },
}

_config: dict[str, Any] = copy.deepcopy(_DEFAULT_CONFIG)
_config_path: str = "config.yaml"


def load(path: str = "config.yaml") -> dict[str, Any]:
    """
    Load configuration from *path*, merging with defaults.

    Returns the merged config dict (also stored internally).
    """
    global _config, _config_path
    _config_path = path

    if not HAS_YAML:
        return copy.deepcopy(_DEFAULT_CONFIG)

    p = Path(path)
    if not p.exists():
        logger.info("Config file not found at %s; using defaults.", path)
        _config = copy.deepcopy(_DEFAULT_CONFIG)
        return copy.deepcopy(_config)

    try:
        with p.open("r", encoding="utf-8") as fh:
            loaded: dict[str, Any] = yaml.safe_load(fh) or {}
        _config = _deep_merge(_DEFAULT_CONFIG, loaded)
        logger.info("Configuration loaded from %s", path)
    except Exception as exc:
        logger.error("Failed to load config from %s: %s", path, exc)
        _config = copy.deepcopy(_DEFAULT_CONFIG)

    return copy.deepcopy(_config)


def save(config: dict[str, Any] | None = None, path: str | None = None) -> bool:
    """
    Persist *config* (or the currently loaded config) to *path*.

    Returns True on success.
    """
    global _config
    target = path or _config_path
    data = config if config is not None else _config

    if not HAS_YAML:
        logger.warning("PyYAML not installed; cannot save config.")
        return False

    try:
        with open(target, "w", encoding="utf-8") as fh:
            yaml.safe_dump(data, fh, default_flow_style=False, allow_unicode=True)
        _config = copy.deepcopy(data)
        logger.info("Configuration saved to %s", target)
        return True
    except Exception as exc:
        logger.error("Failed to save config to %s: %s", target, exc)
        return False


def get(key: str, default: Any = None) -> Any:
    """
    Retrieve a top-level config section by *key*.

    For nested access, use ``get_nested("section.subsection.key")``.
    """
    return copy.deepcopy(_config.get(key, default))


def get_nested(dotted_key: str, default: Any = None) -> Any:
    """Access a config value using dot-separated keys, e.g. ``"ids.alert_threshold"``."""
    parts = dotted_key.split(".")
    node: Any = _config
    for part in parts:
        if not isinstance(node, dict):
            return default
        node = node.get(part, default)
    return node


def set_nested(dotted_key: str, value: Any) -> None:
    """Set a value using a dot-separated key path in the live config dict."""
    parts = dotted_key.split(".")
    node = _config
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


def current() -> dict[str, Any]:
    """Return a copy of the full current configuration dict."""
    return copy.deepcopy(_config)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into *base*, returning a new dict."""
    result = copy.deepcopy(base)
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = copy.deepcopy(val)
    return result
