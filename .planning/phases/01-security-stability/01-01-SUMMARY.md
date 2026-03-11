---
phase: 01-security-stability
plan: 01
status: complete
completed_at: 2026-03-11
---

# Plan 01-01 Summary: Command Injection Fix

## What was done

### Task 1: Eliminate PowerShell f-string injection in core/firewall.py
- **Removed `_run_ps()` entirely** — no more PowerShell string-based command execution
- All Windows firewall commands now use `netsh` via list-form `_run()` with proper argument separation
- Added IP validation gate at the top of `block_ip()`, `unblock_ip()` using `is_valid_ip()` and `is_valid_cidr()`
- Added port validation gate at the top of `block_port()`, `unblock_port()` using `is_valid_port()`
- Added `is_valid_ipv6()` to `utils/validators.py`
- Added `is_valid_ip_or_cidr()` convenience function
- Comprehensive tests in `tests/test_firewall.py` and `tests/test_validators.py`

### Task 2: Audit and fix remaining subprocess/IP usage
- Full codebase grep confirmed: **zero** `os.system()`, `_run_ps()`, or `shell=True` calls remain
- `core/ids.py` correctly delegates to hardened `block_ip()`
- `core/geo.py` uses `requests.get()` (no subprocess)
- `api/server.py` validates IPs at `/block` and `/unblock` endpoints

## Verification
- `grep -rn "os.system|_run_ps|shell=True"` → Clean (zero results)
- `pytest tests/test_firewall.py tests/test_validators.py -x -v` → All pass
- IPv6 validation works: `is_valid_ip("2001:db8::1")` → True

## Files modified
- `core/firewall.py` — Hardened all subprocess calls
- `utils/validators.py` — Added `is_valid_ipv6()`, `is_valid_ip_or_cidr()`
- `tests/test_firewall.py` — Security tests for injection rejection, IPv6
- `tests/test_validators.py` — Tests for new validator functions
