# Phase 5: Notifications & Scheduler

**Status:** Complete ✅ (Twilio SMS pending as optional v2 feature)
**Goal:** Desktop and email notifications on alert events, time-based firewall rule scheduler in a background thread.

## Plans

- [x] 05-01: `core/notifier.py` — desktop (plyer) and email (smtplib) notifications
- [x] 05-02: `core/scheduler.py` — `schedule`-based background rule engine

## Key Files

- `core/notifier.py`
- `core/scheduler.py`

## Notes

- Twilio SMS (NOTF-03) is optional and fail-safe; implementation stub present in notifier.py
- All notification methods catch exceptions and log — never crash the application
