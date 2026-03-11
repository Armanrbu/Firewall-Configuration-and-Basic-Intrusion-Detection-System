"""Tests for the FirewallBackend ABC and backend management."""

from __future__ import annotations

import sys
import os
import pytest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.firewall_abc import FirewallBackend, FirewallResult


# ---------------------------------------------------------------------------
# ABC contract tests
# ---------------------------------------------------------------------------

class TestFirewallBackendABC:
    """Tests for the abstract FirewallBackend contract."""

    def test_cannot_instantiate_directly(self) -> None:
        """FirewallBackend is abstract and cannot be instantiated."""
        with pytest.raises(TypeError):
            FirewallBackend()  # type: ignore

    def test_incomplete_subclass_raises(self) -> None:
        """A subclass that doesn't implement all methods raises TypeError."""
        class IncompleteBackend(FirewallBackend):
            def block_ip(self, ip, rule_name):
                return {"success": True, "message": "ok"}
            # Missing: unblock_ip, block_port, unblock_port, list_rules,
            #          get_status, enable, disable, enable_logging

        with pytest.raises(TypeError):
            IncompleteBackend()

    def test_complete_subclass_works(self) -> None:
        """A subclass implementing all methods can be instantiated."""
        class CompleteBackend(FirewallBackend):
            def block_ip(self, ip, rule_name):
                return {"success": True, "message": f"blocked {ip}"}
            def unblock_ip(self, ip, rule_name):
                return {"success": True, "message": f"unblocked {ip}"}
            def block_port(self, port, protocol, rule_name):
                return {"success": True, "message": f"blocked port {port}"}
            def unblock_port(self, port, protocol, rule_name):
                return {"success": True, "message": f"unblocked port {port}"}
            def list_rules(self, prefix):
                return {"success": True, "rules": [], "message": "0 rules"}
            def get_status(self):
                return {"success": True, "profiles": {}, "message": "ok"}
            def enable(self):
                return {"success": True, "message": "enabled"}
            def disable(self):
                return {"success": True, "message": "disabled"}
            def enable_logging(self, log_path):
                return {"success": True, "message": f"logging → {log_path}"}

        backend = CompleteBackend()
        assert isinstance(backend, FirewallBackend)
        result = backend.block_ip("10.0.0.1", "Rule1")
        assert result["success"] is True

    def test_abstract_methods_list(self) -> None:
        """All 9 abstract methods are present."""
        expected = {
            "block_ip", "unblock_ip", "block_port", "unblock_port",
            "list_rules", "get_status", "enable", "disable", "enable_logging",
        }
        assert FirewallBackend.__abstractmethods__ == expected


# ---------------------------------------------------------------------------
# Backend injection tests
# ---------------------------------------------------------------------------

class TestBackendInjection:
    """Tests for set_firewall_backend / get_firewall_backend."""

    def setup_method(self) -> None:
        """Reset the backend singleton before each test."""
        from core import firewall
        self._original = firewall._backend
        firewall._backend = None

    def teardown_method(self) -> None:
        """Restore the original backend after each test."""
        from core import firewall
        firewall._backend = self._original

    def test_set_and_get_backend(self) -> None:
        """set_firewall_backend injects a custom backend that is returned by get."""
        from core.firewall import set_firewall_backend, get_firewall_backend

        mock_backend = MagicMock(spec=FirewallBackend)
        set_firewall_backend(mock_backend)
        assert get_firewall_backend() is mock_backend

    def test_reset_backend_to_auto_detect(self) -> None:
        """Passing None to set_firewall_backend resets auto-detection."""
        from core.firewall import set_firewall_backend, get_firewall_backend

        mock_backend = MagicMock(spec=FirewallBackend)
        set_firewall_backend(mock_backend)
        set_firewall_backend(None)
        # Should auto-detect (on Windows, it'll create a WindowsNetshBackend)
        backend = get_firewall_backend()
        assert backend is not mock_backend

    def test_facade_delegates_block_ip(self) -> None:
        """The block_ip facade function delegates to the backend."""
        from core.firewall import set_firewall_backend, block_ip

        mock_backend = MagicMock(spec=FirewallBackend)
        mock_backend.block_ip.return_value = {"success": True, "message": "mocked", "rule_name": "R1"}
        set_firewall_backend(mock_backend)

        result = block_ip("192.168.1.1")
        assert result["success"] is True
        mock_backend.block_ip.assert_called_once()

    def test_facade_validates_ip_before_backend(self) -> None:
        """Invalid IPs are rejected by the facade before reaching the backend."""
        from core.firewall import set_firewall_backend, block_ip

        mock_backend = MagicMock(spec=FirewallBackend)
        set_firewall_backend(mock_backend)

        result = block_ip("not-an-ip")
        assert result["success"] is False
        assert "Invalid" in result["message"]
        mock_backend.block_ip.assert_not_called()

    def test_facade_delegates_unblock_ip(self) -> None:
        from core.firewall import set_firewall_backend, unblock_ip

        mock_backend = MagicMock(spec=FirewallBackend)
        mock_backend.unblock_ip.return_value = {"success": True, "message": "unblocked"}
        set_firewall_backend(mock_backend)

        result = unblock_ip("10.0.0.1")
        assert result["success"] is True

    def test_facade_delegates_block_port(self) -> None:
        from core.firewall import set_firewall_backend, block_port

        mock_backend = MagicMock(spec=FirewallBackend)
        mock_backend.block_port.return_value = {"success": True, "message": "blocked", "rule_name": "P1"}
        set_firewall_backend(mock_backend)

        result = block_port(8080, "TCP")
        assert result["success"] is True
        mock_backend.block_port.assert_called_once()

    def test_facade_validates_port_before_backend(self) -> None:
        from core.firewall import set_firewall_backend, block_port

        mock_backend = MagicMock(spec=FirewallBackend)
        set_firewall_backend(mock_backend)

        result = block_port(99999)
        assert result["success"] is False
        mock_backend.block_port.assert_not_called()

    def test_facade_delegates_get_status(self) -> None:
        from core.firewall import set_firewall_backend, get_status

        mock_backend = MagicMock(spec=FirewallBackend)
        mock_backend.get_status.return_value = {"success": True, "profiles": {"Test": "ON"}, "message": "OK"}
        set_firewall_backend(mock_backend)

        result = get_status()
        assert result["profiles"]["Test"] == "ON"

    def test_facade_delegates_list_rules(self) -> None:
        from core.firewall import set_firewall_backend, list_rules

        mock_backend = MagicMock(spec=FirewallBackend)
        mock_backend.list_rules.return_value = {"success": True, "rules": [{"name": "R1"}], "message": "1 rule"}
        set_firewall_backend(mock_backend)

        result = list_rules()
        assert len(result["rules"]) == 1

    def test_facade_delegates_enable_disable(self) -> None:
        from core.firewall import set_firewall_backend, enable_firewall, disable_firewall

        mock_backend = MagicMock(spec=FirewallBackend)
        mock_backend.enable.return_value = {"success": True, "message": "enabled"}
        mock_backend.disable.return_value = {"success": True, "message": "disabled"}
        set_firewall_backend(mock_backend)

        assert enable_firewall()["success"] is True
        assert disable_firewall()["success"] is True


# ---------------------------------------------------------------------------
# Platform implementation import tests
# ---------------------------------------------------------------------------

class TestPlatformImplementations:
    """Tests that platform implementations exist and are correct subclasses."""

    def test_windows_backend_is_subclass(self) -> None:
        from core.firewall_windows import WindowsNetshBackend
        assert issubclass(WindowsNetshBackend, FirewallBackend)

    def test_linux_backend_is_subclass(self) -> None:
        from core.firewall_linux import LinuxIptablesBackend
        assert issubclass(LinuxIptablesBackend, FirewallBackend)

    def test_windows_backend_instantiates(self) -> None:
        from core.firewall_windows import WindowsNetshBackend
        backend = WindowsNetshBackend()
        assert isinstance(backend, FirewallBackend)

    def test_linux_backend_instantiates(self) -> None:
        from core.firewall_linux import LinuxIptablesBackend
        backend = LinuxIptablesBackend()
        assert isinstance(backend, FirewallBackend)
