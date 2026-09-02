"""Bounded stateful helpers for multi-turn and chunked prompt input."""
from __future__ import annotations

from dataclasses import dataclass

from .guard import Guard
from .result import GuardResult


class StreamSessionClosed(RuntimeError):
    """Raised when a closed prompt stream is reused."""


class StreamSessionLimitExceeded(ValueError):
    """Raised after a prompt stream exceeds its configured budget."""


@dataclass(frozen=True)
class PromptStreamStatus:
    """Content-free state safe for operational telemetry."""

    buffered_chars: int
    max_chars: int
    closed: bool
    failed: bool


class PromptStreamSession:
    """Buffer arbitrary chunks and inspect the complete prompt before forwarding.

    Individual transport chunks are not security boundaries: an attacker can
    split a trigger between them. ``feed`` therefore returns metadata only.
    """

    def __init__(self, guard: Guard | None = None, *, max_chars: int | None = None) -> None:
        self.guard = guard or Guard()
        configured = self.guard.policy.max_input_chars if max_chars is None else max_chars
        if not isinstance(configured, int) or isinstance(configured, bool) or configured < 1:
            raise ValueError("max_chars must be a positive integer")
        if configured > self.guard.policy.max_input_chars:
            raise ValueError("max_chars cannot exceed GuardPolicy.max_input_chars")
        self.max_chars = configured
        self._chunks: list[str] = []
        self._chars = 0
        self._closed = False
        self._failed = False

    @property
    def status(self) -> PromptStreamStatus:
        return PromptStreamStatus(self._chars, self.max_chars, self._closed, self._failed)

    def feed(self, chunk: str) -> PromptStreamStatus:
        self._ensure_open()
        if not isinstance(chunk, str):
            raise TypeError(f"feed() expects str, got {type(chunk).__name__}")
        if self._chars + len(chunk) > self.max_chars:
            self._chunks.clear()
            self._chars = 0
            self._closed = True
            self._failed = True
            raise StreamSessionLimitExceeded(
                f"prompt stream exceeds max_chars={self.max_chars}; no content was released"
            )
        self._chunks.append(chunk)
        self._chars += len(chunk)
        return self.status

    def finalize(self) -> GuardResult:
        self._ensure_open()
        source = "".join(self._chunks)
        self._chunks.clear()
        self._chars = 0
        self._closed = True
        try:
            return self.guard.check(source)
        except Exception:
            self._failed = True
            raise

    def abort(self) -> PromptStreamStatus:
        self._ensure_open()
        self._chunks.clear()
        self._chars = 0
        self._closed = True
        return self.status

    def _ensure_open(self) -> None:
        if self._closed:
            raise StreamSessionClosed("prompt stream is already closed")


class ConversationGuardSession:
    """Maintain a bounded rolling conversation and scan relevant turns together."""

    def __init__(
        self,
        guard: Guard | None = None,
        *,
        last_n: int = 6,
        roles: tuple[str, ...] = ("user",),
    ) -> None:
        self.guard = guard or Guard()
        if not isinstance(last_n, int) or isinstance(last_n, bool) or last_n < 1:
            raise ValueError("last_n must be a positive integer")
        if last_n > self.guard.policy.max_message_count:
            raise ValueError("last_n cannot exceed GuardPolicy.max_message_count")
        if not roles or any(not isinstance(role, str) or not role.strip() for role in roles):
            raise ValueError("roles must contain non-empty strings")
        self.last_n = last_n
        self.roles = roles
        self._messages: list[dict[str, str]] = []

    @property
    def message_count(self) -> int:
        return len(self._messages)

    def add(self, role: str, content: str) -> GuardResult:
        if not isinstance(role, str) or not role.strip():
            raise TypeError("role must be a non-empty string")
        if not isinstance(content, str):
            raise TypeError("content must be a string")
        self._messages.append({"role": role, "content": content})
        maximum = self.guard.policy.max_message_count
        if len(self._messages) > maximum:
            del self._messages[:-maximum]
        return self.guard.check_messages(
            self._messages,
            last_n=self.last_n,
            roles=self.roles,
        )

    def clear(self) -> None:
        self._messages.clear()


__all__ = [
    "ConversationGuardSession",
    "PromptStreamSession",
    "PromptStreamStatus",
    "StreamSessionClosed",
    "StreamSessionLimitExceeded",
]
