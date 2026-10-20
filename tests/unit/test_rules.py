"""Tests for rule matching and redaction."""

from __future__ import annotations

from proofmesh.rules import redact, scan_text


def test_redact_short() -> None:
    assert "REDACTED" in redact("abcd")


def test_redact_long() -> None:
    value = "AKIAIOSFODNN7EXAMPLE"
    out = redact(value)
    assert "REDACTED" in out
    assert value not in out
    assert out.startswith("AKIA")


def test_aws_key_detected() -> None:
    text = "key = AKIAIOSFODNN7EXAMPLE\n"
    matches = scan_text(text, "config.py", include_risky=False)
    assert any(m.rule_id == "secret.aws_access_key" for m in matches)
    for m in matches:
        assert "AKIAIOSFODNN7EXAMPLE" not in m.matched_preview


def test_eval_detected() -> None:
    text = "x = eval(user_input)\n"
    matches = scan_text(text, "app.py", include_secrets=False)
    assert any(m.rule_id == "risky.eval" for m in matches)


def test_no_false_positive_on_clean() -> None:
    text = "print('hello world')\nx = 1 + 2\n"
    matches = scan_text(text, "clean.py")
    assert matches == []
