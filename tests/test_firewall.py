"""
Tests for the firewall backend.

Uses unittest.mock to patch subprocess so no actual firewall commands run.
"""

import platform
import subprocess
from unittest.mock import MagicMock, patch

import pytest

import core.firewall as fw


def _mock_run(returncode=0, stdout="OK", stderr=""):
    mock = MagicMock()
    mock.returncode = returncode
    mock.stdout = stdout
    mock.stderr = stderr
    return mock


@pytest.fixture(autouse=True)
def mock_subprocess():
    """Patch subprocess.run for all tests in this module."""
    with patch("subprocess.run") as mock:
        mock.return_value = _mock_run()
        yield mock


class TestBlockIp:
    def test_block_success(self, mock_subprocess):
        mock_subprocess.return_value = _mock_run(returncode=0)
        result = fw.block_ip("1.2.3.4")
        assert result["success"]
        assert "1.2.3.4" in result["message"] or "blocked" in result["message"].lower()

    def test_block_failure(self, mock_subprocess):
        mock_subprocess.return_value = _mock_run(returncode=1, stderr="Access denied")
        result = fw.block_ip("1.2.3.4")
        assert not result["success"]

    def test_custom_rule_name(self, mock_subprocess):
        result = fw.block_ip("2.3.4.5", rule_name="MyCustomRule")
        assert result.get("rule_name") == "MyCustomRule"


class TestUnblockIp:
    def test_unblock_success(self, mock_subprocess):
        mock_subprocess.return_value = _mock_run(returncode=0)
        result = fw.unblock_ip("1.2.3.4")
        assert result["success"]

    def test_unblock_failure(self, mock_subprocess):
        mock_subprocess.return_value = _mock_run(returncode=1, stderr="Rule not found")
        result = fw.unblock_ip("1.2.3.4")
        assert not result["success"]


class TestBlockPort:
    def test_block_port_tcp(self, mock_subprocess):
        mock_subprocess.return_value = _mock_run(returncode=0)
        result = fw.block_port(22, "TCP")
        assert result["success"]

    def test_block_port_udp(self, mock_subprocess):
        mock_subprocess.return_value = _mock_run(returncode=0)
        result = fw.block_port(53, "UDP")
        assert result["success"]


class TestRuleName:
    def test_rule_name_format(self):
        name = fw._rule_name("10.0.0.1")
        assert "NetGuard_" in name
        assert "10.0.0.1" in name

    def test_port_rule_name_format(self):
        name = fw._port_rule_name(80, "TCP")
        assert "NetGuard_" in name
        assert "80" in name
        assert "TCP" in name


class TestEnableDisableFirewall:
    def test_enable(self, mock_subprocess):
        mock_subprocess.return_value = _mock_run(returncode=0)
        result = fw.enable_firewall()
        assert result["success"]

    def test_disable(self, mock_subprocess):
        mock_subprocess.return_value = _mock_run(returncode=0)
        result = fw.disable_firewall()
        assert result["success"]

    def test_enable_failure(self, mock_subprocess):
        mock_subprocess.return_value = _mock_run(returncode=1, stderr="Permission denied")
        result = fw.enable_firewall()
        assert not result["success"]


class TestRunHelper:
    def test_run_timeout(self, mock_subprocess):
        mock_subprocess.side_effect = subprocess.TimeoutExpired(cmd="test", timeout=1)
        rc, out, err = fw._run("some", "command")
        assert rc == 1
        assert "timed out" in err.lower()

    def test_run_not_found(self, mock_subprocess):
        mock_subprocess.side_effect = FileNotFoundError("not found")
        rc, out, err = fw._run("no-such-command")
        assert rc == 1
        assert "not found" in err.lower()
