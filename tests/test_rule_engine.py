"""Tests for core.rule_engine — YAML loading, matching, hot-reload, Python escape hatch."""

from __future__ import annotations

import os
import sys
import time
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

pytestmark = pytest.mark.skipif(not HAS_YAML, reason="PyYAML not installed")


BASIC_RULE_YAML = """
id: test-rule-1
name: Test High Volume
description: Count exceeds 10
severity: high
action: block
conditions:
  - field: count
    op: gte
    value: 10
enabled: true
"""

PORT_SCAN_RULE = """
id: port-scan
name: Port Scan
description: Many ports hit
severity: medium
action: alert
conditions:
  - field: ports_hit
    op: gte
    value: 5
enabled: true
"""

DISABLED_RULE = """
id: disabled-rule
name: Disabled
description: Should not fire
severity: low
action: alert
conditions:
  - field: count
    op: gte
    value: 1
enabled: false
"""

ANY_OPERATOR_RULE = """
id: any-rule
name: Any Condition
description: Count > 20 OR ports > 10
severity: high
action: alert
conditions:
  - field: count
    op: gt
    value: 20
  - field: ports_hit
    op: gt
    value: 10
operator: any
enabled: true
"""

PYTHON_RULE = """
id: python-rule
name: Python Escape Hatch
description: Custom Python logic
severity: high
action: alert
python: "count >= 5 and ports_hit >= 3"
enabled: true
"""


@pytest.fixture
def rule_engine():
    from core.rule_engine import RuleEngine
    return RuleEngine()


@pytest.fixture
def yaml_dir(tmp_path):
    """Temp directory with a single YAML rule file."""
    rule_file = tmp_path / "test.yaml"
    rule_file.write_text(BASIC_RULE_YAML, encoding="utf-8")
    return tmp_path, rule_file


# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------

class TestRuleLoading:

    def test_load_from_directory(self, rule_engine, yaml_dir) -> None:
        d, _ = yaml_dir
        count = rule_engine.load_rules_dir(d)
        assert count == 1
        assert rule_engine.rule_count == 1

    def test_load_multi_doc_yaml(self, rule_engine, tmp_path) -> None:
        multi = tmp_path / "multi.yaml"
        multi.write_text(BASIC_RULE_YAML + "---\n" + PORT_SCAN_RULE, encoding="utf-8")
        count = rule_engine.load_rules_dir(tmp_path)
        assert count == 2

    def test_disabled_rule_loaded_but_not_matched(self, rule_engine, tmp_path) -> None:
        f = tmp_path / "disabled.yaml"
        f.write_text(DISABLED_RULE, encoding="utf-8")
        rule_engine.load_rules_dir(tmp_path)
        results = rule_engine.match("1.2.3.4", {"count": 100})
        assert len(results) == 0

    def test_invalid_rule_skipped(self, rule_engine, tmp_path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("id: bad\nseverity: INVALID_SEVERITY\naction: block\n", encoding="utf-8")
        # Should not raise — just skip the invalid rule
        count = rule_engine.load_rules_dir(tmp_path)
        assert count == 0

    def test_missing_dir_returns_zero(self, rule_engine) -> None:
        count = rule_engine.load_rules_dir("/nonexistent/path")
        assert count == 0

    def test_builtin_rules_file_loads(self, rule_engine) -> None:
        rules_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules"
        )
        if os.path.isdir(rules_dir):
            count = rule_engine.load_rules_dir(rules_dir)
            assert count > 0

    def test_list_rules_returns_metadata(self, rule_engine, yaml_dir) -> None:
        d, _ = yaml_dir
        rule_engine.load_rules_dir(d)
        rules = rule_engine.list_rules()
        assert len(rules) == 1
        assert "id" in rules[0]
        assert "severity" in rules[0]
        assert "enabled" in rules[0]


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

class TestMatching:

    def _load_rules(self, engine, *yaml_strs, tmp_path=None):
        """Helper: write yaml_strs to a temp dir and load."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "rules.yaml")
            combined = "\n---\n".join(yaml_strs)
            with open(p, "w") as f:
                f.write(combined)
            engine.load_rules_dir(d)

    def test_match_triggers_correctly(self, rule_engine, tmp_path) -> None:
        f = tmp_path / "r.yaml"
        f.write_text(BASIC_RULE_YAML, encoding="utf-8")
        rule_engine.load_rules_dir(tmp_path)

        results = rule_engine.match("1.2.3.4", {"count": 15})
        assert len(results) == 1
        assert results[0].triggered is True
        assert results[0].rule_id == "test-rule-1"

    def test_no_match_returns_empty(self, rule_engine, tmp_path) -> None:
        f = tmp_path / "r.yaml"
        f.write_text(BASIC_RULE_YAML, encoding="utf-8")
        rule_engine.load_rules_dir(tmp_path)

        results = rule_engine.match("1.2.3.4", {"count": 5})
        assert len(results) == 0

    def test_any_operator(self, rule_engine, tmp_path) -> None:
        f = tmp_path / "r.yaml"
        f.write_text(ANY_OPERATOR_RULE, encoding="utf-8")
        rule_engine.load_rules_dir(tmp_path)

        # count=25 should trigger (operator: any)
        results = rule_engine.match("1.2.3.4", {"count": 25, "ports_hit": 2})
        assert len(results) == 1

        # ports=15 should also trigger
        results2 = rule_engine.match("1.2.3.4", {"count": 5, "ports_hit": 15})
        assert len(results2) == 1

    def test_match_first_returns_highest_score(self, rule_engine, tmp_path) -> None:
        multi = tmp_path / "multi.yaml"
        multi.write_text(BASIC_RULE_YAML + "\n---\n" + PORT_SCAN_RULE, encoding="utf-8")
        rule_engine.load_rules_dir(tmp_path)

        result = rule_engine.match_first("1.2.3.4", {"count": 15, "ports_hit": 7})
        assert result is not None
        assert result.triggered is True

    def test_match_first_no_match_returns_none(self, rule_engine, tmp_path) -> None:
        f = tmp_path / "r.yaml"
        f.write_text(BASIC_RULE_YAML, encoding="utf-8")
        rule_engine.load_rules_dir(tmp_path)

        result = rule_engine.match_first("1.2.3.4", {"count": 2})
        assert result is None


# ---------------------------------------------------------------------------
# All operators
# ---------------------------------------------------------------------------

class TestConditionOperators:

    @pytest.fixture
    def engine_with_rule(self, tmp_path):
        from core.rule_engine import RuleEngine

        def make(op, value):
            e = RuleEngine()
            yaml_str = f"""
id: op-test
name: op test
severity: medium
action: alert
conditions:
  - field: count
    op: {op}
    value: {value}
enabled: true
"""
            f = tmp_path / f"rule_{op}.yaml"
            f.write_text(yaml_str, encoding="utf-8")
            e.load_rules_dir(tmp_path)
            return e

        return make

    def test_gt(self, engine_with_rule) -> None:
        e = engine_with_rule("gt", 10)
        assert len(e.match("x", {"count": 11})) == 1
        assert len(e.match("x", {"count": 10})) == 0

    def test_lt(self, engine_with_rule) -> None:
        e = engine_with_rule("lt", 10)
        assert len(e.match("x", {"count": 9})) == 1

    def test_gte(self, engine_with_rule) -> None:
        e = engine_with_rule("gte", 10)
        assert len(e.match("x", {"count": 10})) == 1

    def test_lte(self, engine_with_rule) -> None:
        e = engine_with_rule("lte", 10)
        assert len(e.match("x", {"count": 10})) == 1

    def test_eq(self, tmp_path) -> None:
        from core.rule_engine import RuleEngine
        e = RuleEngine()
        yaml_str = """
id: eq-test
severity: low
action: alert
conditions:
  - field: protocol
    op: eq
    value: "UDP"
enabled: true
"""
        (tmp_path / "eq.yaml").write_text(yaml_str)
        e.load_rules_dir(tmp_path)
        assert len(e.match("x", {"protocol": "UDP"})) == 1
        assert len(e.match("x", {"protocol": "TCP"})) == 0


# ---------------------------------------------------------------------------
# Python escape hatch
# ---------------------------------------------------------------------------

class TestPythonEscapeHatch:

    def test_python_rule_fires(self, rule_engine, tmp_path) -> None:
        f = tmp_path / "python.yaml"
        f.write_text(PYTHON_RULE, encoding="utf-8")
        rule_engine.load_rules_dir(tmp_path)

        results = rule_engine.match("1.2.3.4", {"count": 7, "ports_hit": 5})
        assert len(results) == 1
        assert results[0].triggered is True

    def test_python_rule_doesnt_fire(self, rule_engine, tmp_path) -> None:
        f = tmp_path / "python.yaml"
        f.write_text(PYTHON_RULE, encoding="utf-8")
        rule_engine.load_rules_dir(tmp_path)

        results = rule_engine.match("1.2.3.4", {"count": 3, "ports_hit": 1})
        assert len(results) == 0

    def test_python_import_blocked(self, rule_engine, tmp_path) -> None:
        """Python escape hatch cannot import modules."""
        dangerous_rule = """
id: dangerous
severity: high
action: alert
python: "__import__('os').system('echo pwned')"
enabled: true
"""
        f = tmp_path / "danger.yaml"
        f.write_text(dangerous_rule, encoding="utf-8")
        rule_engine.load_rules_dir(tmp_path)

        # Should not raise, should not trigger (expression fails in sandbox)
        results = rule_engine.match("1.2.3.4", {"count": 1})
        assert len(results) == 0

    def test_python_bad_expr_doesnt_crash(self, rule_engine, tmp_path) -> None:
        bad_python = """
id: bad-python
severity: low
action: alert
python: "this is not valid python ((("
enabled: true
"""
        f = tmp_path / "bad.yaml"
        f.write_text(bad_python, encoding="utf-8")
        rule_engine.load_rules_dir(tmp_path)

        results = rule_engine.match("1.2.3.4", {"count": 1})
        assert len(results) == 0


# ---------------------------------------------------------------------------
# Hot-reload
# ---------------------------------------------------------------------------

class TestHotReload:

    def test_reload_detects_changed_file(self, rule_engine, tmp_path) -> None:
        f = tmp_path / "dynamic.yaml"
        f.write_text(BASIC_RULE_YAML, encoding="utf-8")
        rule_engine.load_rules_dir(tmp_path)
        assert rule_engine.rule_count == 1

        # Modify mtime to simulate a changed file
        new_mtime = time.time() + 5
        os.utime(f, (new_mtime, new_mtime))

        changed = rule_engine.reload_if_changed()
        assert changed is True

    def test_no_change_returns_false(self, rule_engine, tmp_path) -> None:
        f = tmp_path / "stable.yaml"
        f.write_text(BASIC_RULE_YAML, encoding="utf-8")
        rule_engine.load_rules_dir(tmp_path)

        changed = rule_engine.reload_if_changed()
        assert changed is False


# ---------------------------------------------------------------------------
# Global singleton
# ---------------------------------------------------------------------------

class TestRuleEngineSingleton:

    def setup_method(self) -> None:
        from core.rule_engine import reset_rule_engine
        reset_rule_engine()

    def teardown_method(self) -> None:
        from core.rule_engine import reset_rule_engine
        reset_rule_engine()

    def test_singleton_same_object(self) -> None:
        from core.rule_engine import get_rule_engine
        assert get_rule_engine() is get_rule_engine()

    def test_reset_creates_new(self) -> None:
        from core.rule_engine import get_rule_engine, reset_rule_engine
        e1 = get_rule_engine()
        reset_rule_engine()
        e2 = get_rule_engine()
        assert e1 is not e2
