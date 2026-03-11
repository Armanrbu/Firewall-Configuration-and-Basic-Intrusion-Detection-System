"""
Time-based firewall rule scheduler.

Uses the `schedule` library and a background thread to apply/remove
firewall rules at configured times.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)

try:
    import schedule as _schedule
    HAS_SCHEDULE = True
except ImportError:
    HAS_SCHEDULE = False
    logger.warning("'schedule' library not installed; time-based rules disabled.")


class ScheduledRule:
    """Represents a single time-based firewall rule."""

    def __init__(
        self,
        rule_id: int,
        action: str,
        target: str,
        target_type: str,
        protocol: str,
        start_time: str,
        end_time: str,
        days: list[str],
        enabled: bool = True,
    ) -> None:
        self.rule_id = rule_id
        self.action = action          # "block" | "unblock"
        self.target = target          # IP or port number
        self.target_type = target_type  # "ip" | "port"
        self.protocol = protocol      # "TCP" | "UDP"
        self.start_time = start_time  # "HH:MM"
        self.end_time = end_time      # "HH:MM"
        self.days = days              # ["monday", "tuesday", ...]
        self.enabled = enabled

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "action": self.action,
            "target": self.target,
            "target_type": self.target_type,
            "protocol": self.protocol,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "days": self.days,
            "enabled": self.enabled,
        }


class RuleScheduler:
    """
    Background scheduler that applies and removes firewall rules on a timer.
    """

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._running = False
        self._rules: list[ScheduledRule] = []
        self._load_from_db()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="Scheduler")
        self._thread.start()
        logger.info("Rule scheduler started.")

    def stop(self) -> None:
        self._running = False
        if HAS_SCHEDULE:
            _schedule.clear()
        logger.info("Rule scheduler stopped.")

    # ------------------------------------------------------------------
    # Rule management
    # ------------------------------------------------------------------

    def add_rule(self, rule: ScheduledRule) -> None:
        self._rules.append(rule)
        self._save_to_db(rule)
        if HAS_SCHEDULE and rule.enabled:
            self._register(rule)

    def remove_rule(self, rule_id: int) -> None:
        self._rules = [r for r in self._rules if r.rule_id != rule_id]
        self._delete_from_db(rule_id)
        if HAS_SCHEDULE:
            _schedule.clear(str(rule_id))

    def get_rules(self) -> list[ScheduledRule]:
        return list(self._rules)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _loop(self) -> None:
        if not HAS_SCHEDULE:
            return
        for rule in self._rules:
            if rule.enabled:
                self._register(rule)
        while self._running:
            _schedule.run_pending()
            time.sleep(30)

    def _register(self, rule: ScheduledRule) -> None:
        if not HAS_SCHEDULE:
            return
        tag = str(rule.rule_id)

        def apply_rule():
            self._apply(rule)

        def remove_rule_action():
            self._remove_action(rule)

        days = rule.days or ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
        for day in days:
            try:
                getattr(_schedule.every(), day).at(rule.start_time).do(apply_rule).tag(tag)
                getattr(_schedule.every(), day).at(rule.end_time).do(remove_rule_action).tag(tag)
            except Exception as exc:
                logger.warning("Could not schedule rule %d on %s: %s", rule.rule_id, day, exc)

    def _apply(self, rule: ScheduledRule) -> None:
        try:
            from core import firewall
            if rule.target_type == "ip":
                firewall.block_ip(rule.target)
                logger.info("Scheduled: blocked IP %s", rule.target)
            else:
                firewall.block_port(int(rule.target), rule.protocol)
                logger.info("Scheduled: blocked port %s/%s", rule.target, rule.protocol)
        except Exception as exc:
            logger.error("Scheduled rule apply failed: %s", exc)

    def _remove_action(self, rule: ScheduledRule) -> None:
        try:
            from core import firewall
            if rule.target_type == "ip":
                firewall.unblock_ip(rule.target)
                logger.info("Scheduled: unblocked IP %s", rule.target)
            else:
                firewall.unblock_port(int(rule.target), rule.protocol)
                logger.info("Scheduled: unblocked port %s/%s", rule.target, rule.protocol)
        except Exception as exc:
            logger.error("Scheduled rule remove failed: %s", exc)

    def _save_to_db(self, rule: ScheduledRule) -> None:
        try:
            from core.blocklist import get_db
            db = get_db()
            db.execute("""
                CREATE TABLE IF NOT EXISTS scheduled_rules (
                    rule_id    INTEGER PRIMARY KEY,
                    data_json  TEXT
                )
            """)
            db.execute(
                "INSERT OR REPLACE INTO scheduled_rules (rule_id, data_json) VALUES (?, ?)",
                (rule.rule_id, json.dumps(rule.to_dict())),
            )
            db.commit()
        except Exception as exc:
            logger.warning("Could not save scheduled rule: %s", exc)

    def _delete_from_db(self, rule_id: int) -> None:
        try:
            from core.blocklist import get_db
            db = get_db()
            db.execute("DELETE FROM scheduled_rules WHERE rule_id = ?", (rule_id,))
            db.commit()
        except Exception as exc:
            logger.warning("Could not delete scheduled rule: %s", exc)

    def _load_from_db(self) -> None:
        try:
            from core.blocklist import get_db
            db = get_db()
            db.execute("""
                CREATE TABLE IF NOT EXISTS scheduled_rules (
                    rule_id    INTEGER PRIMARY KEY,
                    data_json  TEXT
                )
            """)
            for row in db.execute("SELECT data_json FROM scheduled_rules").fetchall():
                data = json.loads(row[0])
                self._rules.append(ScheduledRule(**data))
            logger.info("Loaded %d scheduled rules from DB.", len(self._rules))
        except Exception as exc:
            logger.warning("Could not load scheduled rules: %s", exc)


# Singleton instance
_scheduler: RuleScheduler | None = None


def get_scheduler() -> RuleScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = RuleScheduler()
    return _scheduler
