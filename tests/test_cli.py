"""
Tests for the Typer CLI (cli/main.py).
Uses typer.testing.CliRunner — no real firewall calls (all mocked out).
"""

from __future__ import annotations

import json
import sys
import os
from unittest.mock import patch, MagicMock

import pytest
from typer.testing import CliRunner

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.main import app


runner = CliRunner()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(*args, **kwargs):
    return runner.invoke(app, list(args), **kwargs)


# ---------------------------------------------------------------------------
# Help / root
# ---------------------------------------------------------------------------

class TestHelp:
    def test_top_level_help(self) -> None:
        result = _run("--help")
        assert result.exit_code == 0
        assert "NetGuard" in result.output

    def test_status_help(self) -> None:
        result = _run("status", "--help")
        assert result.exit_code == 0
        assert "status" in result.output.lower() or "engine" in result.output.lower()

    def test_block_help(self) -> None:
        result = _run("block", "--help")
        assert result.exit_code == 0
        assert "ip" in result.output.lower() or "IP" in result.output

    def test_rules_help(self) -> None:
        result = _run("rules", "--help")
        assert result.exit_code == 0
        assert "rules" in result.output.lower()


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

class TestStatus:

    @patch("core.firewall.get_status", return_value={"active": True, "platform": "Windows"})
    @patch("core.blocklist.get_stats_today", return_value={"blocks_today": 3})
    @patch("core.blocklist.get_alerts", return_value=[])
    @patch("core.blocklist.get_all_blocked", return_value=["1.1.1.1"])
    @patch("core.blocklist.get_db")
    def test_status_runs(self, *mocks) -> None:
        result = _run("status")
        assert result.exit_code == 0
        assert "Firewall" in result.output or "✅" in result.output

    @patch("core.firewall.get_status", return_value={"active": False, "platform": "Linux"})
    @patch("core.blocklist.get_stats_today", return_value={})
    @patch("core.blocklist.get_alerts", return_value=[])
    @patch("core.blocklist.get_all_blocked", return_value=[])
    @patch("core.blocklist.get_db")
    def test_status_shows_inactive(self, *mocks) -> None:
        result = _run("status")
        assert result.exit_code == 0
        assert "❌" in result.output or "Linux" in result.output


# ---------------------------------------------------------------------------
# block / unblock
# ---------------------------------------------------------------------------

class TestBlock:

    @patch("core.firewall.block_ip", return_value={"success": True, "message": "Blocked"})
    @patch("core.blocklist.add_block")
    @patch("core.blocklist.get_db")
    def test_block_valid_ip(self, *mocks) -> None:
        result = _run("block", "1.2.3.4")
        assert result.exit_code == 0
        assert "✅" in result.output or "blocked" in result.output.lower()

    def test_block_invalid_ip(self) -> None:
        result = _run("block", "not-an-ip")
        assert result.exit_code != 0
        assert "Invalid" in result.output or "invalid" in result.output

    @patch("core.firewall.block_ip", return_value={"success": False, "message": "Permission denied"})
    @patch("core.blocklist.get_db")
    def test_block_failure_exits_nonzero(self, *mocks) -> None:
        result = _run("block", "9.9.9.9")
        assert result.exit_code != 0
        assert "❌" in result.output or "Failed" in result.output

    @patch("core.firewall.unblock_ip", return_value={"success": True, "message": "Unblocked"})
    @patch("core.blocklist.remove_block")
    @patch("core.blocklist.get_db")
    def test_unblock_valid_ip(self, *mocks) -> None:
        result = _run("unblock", "1.2.3.4")
        assert result.exit_code == 0
        assert "✅" in result.output or "unblocked" in result.output.lower()

    def test_unblock_invalid_ip(self) -> None:
        result = _run("unblock", "999.999.999.999")
        assert result.exit_code != 0

    @patch("core.firewall.block_ip", return_value={"success": True, "message": "ok"})
    @patch("core.blocklist.add_block")
    @patch("core.blocklist.get_db")
    def test_block_custom_reason(self, mock_db, mock_add, mock_block) -> None:
        result = _run("block", "10.0.0.1", "--reason", "Port scan detected")
        assert result.exit_code == 0
        mock_add.assert_called_once_with("10.0.0.1", "Port scan detected")


# ---------------------------------------------------------------------------
# alerts
# ---------------------------------------------------------------------------

class TestAlerts:

    _SAMPLE = [{"id": 1, "ip_address": "5.5.5.5", "alert_type": "Scan", "details": "det", "resolved": False, "timestamp": "2026-03-11 10:00:00"}]

    @patch("core.blocklist.get_alerts", return_value=_SAMPLE)
    @patch("core.blocklist.get_db")
    def test_alerts_table(self, *mocks) -> None:
        result = _run("alerts")
        assert result.exit_code == 0
        assert "5.5.5.5" in result.output

    @patch("core.blocklist.get_alerts", return_value=_SAMPLE)
    @patch("core.blocklist.get_db")
    def test_alerts_json_output(self, *mocks) -> None:
        result = _run("alerts", "--json")
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert data[0]["ip_address"] == "5.5.5.5"

    @patch("core.blocklist.get_alerts", return_value=[])
    @patch("core.blocklist.get_db")
    def test_alerts_empty(self, *mocks) -> None:
        result = _run("alerts")
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# blocklist
# ---------------------------------------------------------------------------

class TestBlocklist:

    _SAMPLE = [{"ip_address": "1.2.3.4", "reason": "Manual", "blocked_at": "2026-03-11 09:00:00"}]

    @patch("core.blocklist.get_all_blocked", return_value=_SAMPLE)
    @patch("core.blocklist.get_db")
    def test_blocklist_table(self, *mocks) -> None:
        result = _run("blocklist")
        assert result.exit_code == 0
        assert "1.2.3.4" in result.output

    @patch("core.blocklist.get_all_blocked", return_value=_SAMPLE)
    @patch("core.blocklist.get_db")
    def test_blocklist_json(self, *mocks) -> None:
        result = _run("blocklist", "--json")
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data[0]["ip_address"] == "1.2.3.4"


# ---------------------------------------------------------------------------
# connections
# ---------------------------------------------------------------------------

class TestConnections:

    def test_connections_no_psutil_exits_cleanly(self) -> None:
        import builtins
        real_import = builtins.__import__
        def _no_psutil(name, *a, **kw):
            if name == "psutil":
                raise ImportError("mocked")
            return real_import(name, *a, **kw)
        with patch("builtins.__import__", side_effect=_no_psutil):
            result = _run("connections")
        assert result.exit_code != 0
        assert "psutil" in result.output

    @patch("psutil.net_connections")
    def test_connections_shows_table(self, mock_conns) -> None:
        Addr = MagicMock()
        Addr.ip = "192.168.1.1"
        Addr.port = 443
        conn = MagicMock()
        conn.raddr = Addr
        conn.laddr = Addr
        conn.status = "ESTABLISHED"
        conn.pid = 1234
        mock_conns.return_value = [conn] * 3
        result = _run("connections")
        assert result.exit_code == 0
        assert "192.168.1.1" in result.output


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

class TestConfig:

    @patch("utils.config_loader.load", return_value={"ids": {"alert_threshold": 10}, "logging": {}})
    def test_config_show_all(self, *mocks) -> None:
        result = _run("config", "show")
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "ids" in data

    @patch("utils.config_loader.load", return_value={"ids": {"alert_threshold": 10}, "logging": {}})
    def test_config_show_section(self, *mocks) -> None:
        result = _run("config", "show", "ids")
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "ids" in data

    @patch("utils.config_loader.load", return_value={"ids": {}})
    def test_config_show_missing_section(self, *mocks) -> None:
        result = _run("config", "show", "nonexistent")
        assert result.exit_code != 0
        assert "not found" in result.output.lower() or "nonexistent" in result.output


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------

class TestRules:

    @patch("core.rule_engine.get_rule_engine")
    def test_rules_list(self, mock_engine) -> None:
        re_inst = MagicMock()
        re_inst.rules = [
            {"id": "rule-1", "name": "Test Rule", "action": "alert", "conditions": [{"field": "count"}]},
        ]
        mock_engine.return_value = re_inst
        result = _run("rules", "list")
        assert result.exit_code == 0
        assert "rule-1" in result.output

    @patch("core.rule_engine.get_rule_engine")
    def test_rules_list_empty(self, mock_engine) -> None:
        re_inst = MagicMock()
        re_inst.rules = []
        mock_engine.return_value = re_inst
        result = _run("rules", "list")
        assert result.exit_code == 0
        assert "No rules" in result.output

    @patch("core.rule_engine.get_rule_engine")
    def test_rules_reload(self, mock_engine) -> None:
        re_inst = MagicMock()
        re_inst.reload_if_changed.return_value = 2
        re_inst.rules = [{}] * 5
        mock_engine.return_value = re_inst
        result = _run("rules", "reload")
        assert result.exit_code == 0
        assert "2" in result.output
        re_inst.reload_if_changed.assert_called_once_with(force=True)

    def test_rules_validate_missing_file(self) -> None:
        result = _run("rules", "validate", "/nonexistent/path.yaml")
        assert result.exit_code != 0
        assert "not found" in result.output.lower() or "File" in result.output

    def test_rules_validate_valid_file(self, tmp_path) -> None:
        f = tmp_path / "valid.yaml"
        f.write_text("rules:\n  - id: r1\n    action: alert\n    conditions:\n      - field: count\n")
        result = _run("rules", "validate", str(f))
        assert result.exit_code == 0
        assert "Valid" in result.output or "✅" in result.output

    def test_rules_validate_invalid_yaml(self, tmp_path) -> None:
        f = tmp_path / "bad.yaml"
        f.write_text("this: is: : invalid: yaml:\n  - [")
        result = _run("rules", "validate", str(f))
        assert result.exit_code != 0

    def test_rules_validate_missing_id(self, tmp_path) -> None:
        f = tmp_path / "noid.yaml"
        f.write_text("rules:\n  - action: alert\n    conditions:\n      - field: count\n")
        result = _run("rules", "validate", str(f))
        assert result.exit_code != 0
        assert "missing" in result.output.lower() or "id" in result.output.lower()
