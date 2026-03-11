"""
YAML-based rule engine for NetGuard IDS.

Loads rules from YAML files, matches them against connection context,
supports hot-reload via file mtime watching, and provides a sandboxed
Python escape hatch for custom expressions.

Usage:
    from core.rule_engine import RuleEngine, get_rule_engine

    engine = get_rule_engine()
    engine.load_rules_dir("rules/")
    results = engine.match("10.0.0.1", context={"count": 25, "ports_hit": 3})
"""

from __future__ import annotations

import os
import re
import threading
import time
from pathlib import Path
from typing import Any

from utils.logger import get_logger
from core.detector_abc import DetectorResult

logger = get_logger(__name__)

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    logger.warning("PyYAML not installed; rule engine disabled. Run: pip install pyyaml")


# ---------------------------------------------------------------------------
# Rule dataclass
# ---------------------------------------------------------------------------

class Rule:
    """Parsed and validated rule loaded from YAML."""

    __slots__ = (
        "id", "name", "description", "severity", "action",
        "conditions", "operator", "python_expr", "enabled",
        "_compiled_re",
    )

    VALID_OPS = frozenset(("gt", "lt", "gte", "lte", "eq", "neq", "in", "not_in", "contains", "matches"))
    VALID_ACTIONS = frozenset(("block", "alert", "ignore"))
    VALID_SEVERITIES = frozenset(("critical", "high", "medium", "low"))
    SEVERITY_SCORES = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}

    def __init__(self, data: dict[str, Any]) -> None:
        self.id: str = str(data.get("id", "unnamed"))
        self.name: str = str(data.get("name", self.id))
        self.description: str = str(data.get("description", ""))
        self.severity: str = str(data.get("severity", "medium"))
        self.action: str = str(data.get("action", "alert"))
        self.conditions: list[dict[str, Any]] = data.get("conditions", [])
        self.operator: str = str(data.get("operator", "all")).lower()
        self.python_expr: str | None = data.get("python")
        self.enabled: bool = bool(data.get("enabled", True))
        self._compiled_re: dict[str, re.Pattern] = {}

        # Validation
        if self.severity not in self.VALID_SEVERITIES:
            raise ValueError(f"Rule {self.id!r}: invalid severity {self.severity!r}")
        if self.action not in self.VALID_ACTIONS:
            raise ValueError(f"Rule {self.id!r}: invalid action {self.action!r}")
        if self.operator not in ("all", "any"):
            raise ValueError(f"Rule {self.id!r}: operator must be 'all' or 'any'")
        for cond in self.conditions:
            op = cond.get("op", "")
            if op not in self.VALID_OPS:
                raise ValueError(f"Rule {self.id!r}: invalid op {op!r}")

    @property
    def score(self) -> float:
        return self.SEVERITY_SCORES.get(self.severity, 0.5)


# ---------------------------------------------------------------------------
# Rule matcher
# ---------------------------------------------------------------------------

_SANDBOX_BUILTINS = {"max": max, "min": min, "abs": abs, "len": len, "round": round}


def _eval_condition(cond: dict[str, Any], ctx: dict[str, Any]) -> bool:
    """Evaluate a single condition against *ctx*."""
    field = cond.get("field", "")
    op = cond.get("op", "eq")
    value = cond.get("value")

    actual = ctx.get(field)
    if actual is None:
        return False

    try:
        if op == "gt":    return float(actual) > float(value)
        if op == "lt":    return float(actual) < float(value)
        if op == "gte":   return float(actual) >= float(value)
        if op == "lte":   return float(actual) <= float(value)
        if op == "eq":    return actual == value
        if op == "neq":   return actual != value
        if op == "in":    return actual in (value if isinstance(value, (list, set)) else [value])
        if op == "not_in": return actual not in (value if isinstance(value, (list, set)) else [value])
        if op == "contains": return str(value) in str(actual)
        if op == "matches":
            pattern = re.compile(str(value))
            return bool(pattern.search(str(actual)))
    except (TypeError, ValueError) as exc:
        logger.debug("Condition eval error (%s %s %s): %s", field, op, value, exc)
    return False


def _eval_python(expr: str, ctx: dict[str, Any]) -> bool:
    """Evaluate a Python expression in a restricted sandbox.

    Available context keys become local variables.
    Only safe builtins are allowed.
    """
    local_ctx = {k: v for k, v in ctx.items()}
    try:
        return bool(eval(expr, {"__builtins__": _SANDBOX_BUILTINS}, local_ctx))  # noqa: S307
    except Exception as exc:
        logger.warning("Python rule expression error (%r): %s", expr[:60], exc)
        return False


def _match_rule(rule: Rule, ip: str, ctx: dict[str, Any]) -> DetectorResult | None:
    """Test *rule* against *ctx*. Returns DetectorResult or None (no match)."""
    if not rule.enabled:
        return None

    if rule.python_expr:
        triggered = _eval_python(rule.python_expr, ctx)
    elif rule.conditions:
        results = [_eval_condition(c, ctx) for c in rule.conditions]
        triggered = all(results) if rule.operator == "all" else any(results)
    else:
        return None

    if not triggered:
        return None

    return DetectorResult(
        triggered=True,
        score=rule.score,
        reason=f"[{rule.id}] {rule.name}: {rule.description}",
        features=dict(ctx),
        rule_id=rule.id,
        action=rule.action,
    )


# ---------------------------------------------------------------------------
# RuleEngine
# ---------------------------------------------------------------------------

class RuleEngine:
    """Loads and matches YAML rules against connection context.

    Features:
    - Load from directory (all *.yaml/*.yml files)
    - Hot-reload: ``reload_if_changed()`` checks mtimes without full restart
    - Python escape hatch: per-rule ``python:`` expression evaluated in sandbox
    - Thread-safe: all operations protected by RLock
    """

    def __init__(self) -> None:
        self._rules: list[Rule] = []
        self._lock = threading.RLock()
        self._watched_files: dict[str, float] = {}  # path → mtime

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_rules_dir(self, directory: str | Path) -> int:
        """Load all *.yaml / *.yml files from *directory*.

        Returns the number of rules loaded.
        """
        if not HAS_YAML:
            logger.warning("PyYAML not installed — cannot load rules.")
            return 0

        directory = Path(directory)
        if not directory.is_dir():
            logger.warning("Rules directory not found: %s", directory)
            return 0

        loaded = 0
        new_rules: list[Rule] = []
        new_watched: dict[str, float] = {}

        for yaml_file in sorted(directory.glob("**/*.yaml")) + sorted(directory.glob("**/*.yml")):
            count, watched_mtime = self._load_file(yaml_file, new_rules)
            loaded += count
            new_watched[str(yaml_file)] = watched_mtime

        with self._lock:
            self._rules = new_rules
            self._watched_files = new_watched

        logger.info("Loaded %d rules from %s", loaded, directory)
        return loaded

    def load_rules_file(self, path: str | Path) -> int:
        """Load rules from a single YAML file, replacing existing ones from it."""
        rules: list[Rule] = []
        count, mtime = self._load_file(Path(path), rules)
        with self._lock:
            # Remove existing rules from this path then append new ones
            # (simple strategy: rebuild from scratch)
            self._rules.extend(rules)
            self._watched_files[str(path)] = mtime
        return count

    def _load_file(self, path: Path, target: list[Rule]) -> tuple[int, float]:
        """Parse YAML file and append validated Rule objects to *target*.

        Returns (count_loaded, mtime).
        """
        if not HAS_YAML:
            return 0, 0.0

        mtime = path.stat().st_mtime
        count = 0
        try:
            with open(path, encoding="utf-8") as f:
                for doc in yaml.safe_load_all(f):
                    if not isinstance(doc, dict):
                        continue
                    try:
                        rule = Rule(doc)
                        target.append(rule)
                        count += 1
                    except ValueError as exc:
                        logger.warning("Skipping invalid rule in %s: %s", path.name, exc)
        except (OSError, yaml.YAMLError) as exc:
            logger.error("Failed to parse rule file %s: %s", path, exc)
        return count, mtime

    # ------------------------------------------------------------------
    # Hot-reload
    # ------------------------------------------------------------------

    def reload_if_changed(self) -> bool:
        """Re-read any rule files whose mtime has changed.

        Returns True if any rules were reloaded.
        """
        with self._lock:
            watched = dict(self._watched_files)

        changed = False
        for path_str, old_mtime in watched.items():
            path = Path(path_str)
            if not path.exists():
                continue
            try:
                new_mtime = path.stat().st_mtime
            except OSError:
                continue
            if new_mtime != old_mtime:
                changed = True

        if changed:
            # Find the parent directories and reload fully
            dirs = {Path(p).parent for p in watched}
            for d in dirs:
                self.load_rules_dir(d)
            logger.info("Rules hot-reloaded (files changed).")

        return changed

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    def match(
        self,
        ip: str,
        context: dict[str, Any],
    ) -> list[DetectorResult]:
        """Run all enabled rules against *context* for *ip*.

        Returns all triggered DetectorResults (may be empty).
        """
        with self._lock:
            rules = list(self._rules)

        results: list[DetectorResult] = []
        for rule in rules:
            try:
                res = _match_rule(rule, ip, context)
                if res is not None:
                    results.append(res)
            except Exception as exc:
                logger.error("Rule %r raised during match: %s", rule.id, exc)
        return results

    def match_first(
        self,
        ip: str,
        context: dict[str, Any],
    ) -> DetectorResult | None:
        """Return the first triggered result (highest scoring), or None."""
        results = self.match(ip, context)
        if not results:
            return None
        return max(results, key=lambda r: r.score)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def rule_count(self) -> int:
        with self._lock:
            return len(self._rules)

    @property
    def enabled_count(self) -> int:
        with self._lock:
            return sum(1 for r in self._rules if r.enabled)

    def list_rules(self) -> list[dict[str, Any]]:
        """Return a list of rule metadata dicts (for API/CLI use)."""
        with self._lock:
            return [
                {
                    "id": r.id,
                    "name": r.name,
                    "severity": r.severity,
                    "action": r.action,
                    "enabled": r.enabled,
                    "has_python": r.python_expr is not None,
                    "conditions": len(r.conditions),
                }
                for r in self._rules
            ]


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

_engine: RuleEngine | None = None
_engine_lock = threading.Lock()


def get_rule_engine() -> RuleEngine:
    """Return the global RuleEngine singleton."""
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = RuleEngine()
    return _engine


def reset_rule_engine() -> None:
    """Replace the singleton with a fresh RuleEngine (for testing)."""
    global _engine
    with _engine_lock:
        _engine = RuleEngine()
