"""Operational fail-closed guarantees for bounded user-input scanning."""
from __future__ import annotations

from ko_prompt_guard import Category, Guard, GuardPolicy, Verdict


def test_input_limit_blocks_before_normalization(monkeypatch: object) -> None:
    guard = Guard(GuardPolicy(max_input_chars=3))

    def fail_if_normalized(*args: object, **kwargs: object) -> object:
        raise AssertionError("normalization must not run for over-limit input")

    monkeypatch.setattr("ko_prompt_guard.guard.normalize", fail_if_normalized)  # type: ignore[attr-defined]
    result = guard.check("four")
    assert result.verdict is Verdict.BLOCK
    assert result.original_text == ""
    assert result.normalized_text == ""
    assert result.violations[0].code == "input_too_long"
    assert result.violations[0].category is Category.RESOURCE_LIMIT


def test_combined_message_limit_blocks_before_normalization(monkeypatch: object) -> None:
    guard = Guard(GuardPolicy(max_message_chars=4, max_combined_message_chars=7))

    def fail_if_normalized(*args: object, **kwargs: object) -> object:
        raise AssertionError("normalization must not run for over-limit messages")

    monkeypatch.setattr("ko_prompt_guard.guard.normalize", fail_if_normalized)  # type: ignore[attr-defined]
    result = guard.check_messages(["four", "four"])
    assert result.verdict is Verdict.BLOCK
    assert result.violations[0].code == "combined_messages_too_long"
    assert result.violations[0].category is Category.RESOURCE_LIMIT


def test_context_limit_quarantines_before_normalization(monkeypatch: object) -> None:
    guard = Guard(GuardPolicy(max_input_chars=3))

    def fail_if_normalized(*args: object, **kwargs: object) -> object:
        raise AssertionError("normalization must not run for over-limit context")

    monkeypatch.setattr("ko_prompt_guard.guard.normalize", fail_if_normalized)  # type: ignore[attr-defined]
    result = guard.scan_context("four", source="rag")
    assert result.poisoned is True
    assert result.recommendation == "quarantine"
    assert result.normalized_text == ""
    assert result.violations[0].code == "context_too_long"
    assert result.violations[0].category is Category.RESOURCE_LIMIT
