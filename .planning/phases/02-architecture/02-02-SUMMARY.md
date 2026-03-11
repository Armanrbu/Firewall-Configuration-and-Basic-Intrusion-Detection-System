---
phase: 02-architecture
plan: 02
status: complete
completed_at: 2026-03-11
---

# Plan 02-02 Summary: FirewallBackend ABC

## What was done

### Task 1: core/firewall_abc.py — Abstract interface
- Created `FirewallBackend` ABC with **9 abstract methods**:
  `block_ip`, `unblock_ip`, `block_port`, `unblock_port`, `list_rules`,
  `get_status`, `enable`, `disable`, `enable_logging`
- `FirewallResult = dict[str, Any]` type alias for return values
- Input validation stays in the facade — backends receive pre-validated arguments

### Task 2: core/firewall_windows.py — Windows implementation
- `WindowsNetshBackend(FirewallBackend)` — all 9 methods using `netsh advfirewall`
- Private `_run()` helper (list-form subprocess, no shell=True)
- All logic extracted from the monolithic `core/firewall.py`

### Task 3: core/firewall_linux.py — Linux implementation
- `LinuxIptablesBackend(FirewallBackend)` — all 9 methods using `iptables`
- Private `_run()` helper identical to Windows version
- `block_ip` uses comment tag fallback pattern

### Task 4: core/firewall.py — Thin facade refactor
- `get_firewall_backend()` factory auto-detects platform (`_OS`), lazy-initializes singleton
- `set_firewall_backend(backend | None)` for test injection and plugin backends
- All **9 public function signatures remain identical** — zero caller changes required
- Input validation (IP, port, protocol) performed in facade before delegating to backend
- `RuntimeError` from backend caught and returned as `{"success": False}` dict

## Verification
- `pytest tests/test_firewall_abc.py tests/test_firewall.py -v` → **all pass**
- `FirewallBackend.__abstractmethods__` = all 9 methods
- `issubclass(WindowsNetshBackend, FirewallBackend)` → True
- `issubclass(LinuxIptablesBackend, FirewallBackend)` → True
- `set_firewall_backend(mock); get_firewall_backend() is mock` → True
- `block_ip("not-an-ip")` → `{"success": False}` without calling backend
- Full suite: **130 passing** (no regressions)

## Files created/modified
- `core/firewall_abc.py` — NEW: FirewallBackend ABC + FirewallResult type alias
- `core/firewall_windows.py` — NEW: WindowsNetshBackend implementation
- `core/firewall_linux.py` — NEW: LinuxIptablesBackend implementation
- `core/firewall.py` — MODIFIED: thin facade with factory + injection
- `tests/test_firewall_abc.py` — NEW: ABC contract + injection + platform tests
- `tests/test_firewall.py` — MODIFIED: TestRunHelper uses backend _run, fixture resets singleton
