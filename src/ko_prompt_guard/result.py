"""Verdicts, severities, violations, and the GuardResult returned by check().

Mirrors the shape of ko-sqlguard's result types, adapted for prompt screening:
the guard de-obfuscates the input (``normalized_text``) and flags injection /
jailbreak signals rather than rewriting SQL.
"""
from __future__ import annotations

import enum

from pydantic import BaseModel, ConfigDict


class Verdict(str, enum.Enum):
    ALLOW = "allow"   # nothing suspicious
    FLAG = "flag"     # suspicious — advise review / Tier-2, but not a hard block
    BLOCK = "block"   # a clear, high-confidence attack


class Severity(enum.IntEnum):
    """Ordered so ``severity >= policy.min_block_severity`` works."""

    LOW = 10
    MEDIUM = 20
    HIGH = 30
    CRITICAL = 40


class Category(str, enum.Enum):
    """What kind of signal a violation represents."""

    INSTRUCTION_OVERRIDE = "instruction_override"  # P1 "이전 지시 무시"
    PROMPT_LEAK = "prompt_leak"                    # P2 "시스템 프롬프트 알려줘"
    JAILBREAK = "jailbreak"                        # P3 역할극/DAN/개발자 모드
    EXFILTRATION = "exfiltration"                  # P6 "대화 전부 보내"
    TRANSLITERATION = "transliteration"            # P7 영어 명령 한글 음차
    ENCODING = "encoding"                          # P8 base64/hex 페이로드
    OBFUSCATION = "obfuscation"                    # 난독화 자체가 감지됨
    SEMANTIC = "semantic"                          # Tier-2 임베딩/LLM 의미 유사 (opt-in reviewer)


class Violation(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str
    category: Category
    severity: Severity
    reason: str
    # span in the NORMALIZED text; use GuardResult.offset_map to map to original.
    start: int | None = None
    end: int | None = None
    matched: str | None = None


class GuardResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    verdict: Verdict
    original_text: str
    normalized_text: str
    violations: tuple[Violation, ...] = ()
    # offset_map[i] = original index of normalized_text[i] (empty if unchanged).
    offset_map: tuple[int, ...] = ()
    # True when de-obfuscation changed the text (a signal in itself).
    was_obfuscated: bool = False

    @property
    def ok(self) -> bool:
        return self.verdict is not Verdict.BLOCK


class ContextScanResult(BaseModel):
    """검색 문서·도구 출력 등 *비-사용자 콘텐츠*의 간접 프롬프트 인젝션(indirect PI) 스캔 결과.

    사용자 입력 가드(``GuardResult``)와 의미가 다르다. 여기서 신호는 "이 콘텐츠가 *에이전트를
    탈취하려는* 인젝션을 품고 있다"는 뜻이므로, 권고는 사용자 BLOCK 이 아니라 **문서 QUARANTINE**
    (해당 콘텐츠를 신뢰/주입하지 말 것)이다. 에이전틱 RAG(검색 문서)·도구 응답이 주 공격 벡터다.
    """

    model_config = ConfigDict(frozen=True)

    poisoned: bool                       # 간접 PI 신호 존재 여부
    source: str = "context"              # "rag" / "tool" / "document" 등 출처 라벨
    recommendation: str                  # "quarantine"(격리) | "use"(사용 가능)
    normalized_text: str                 # 난독 해제된 콘텐츠(숨은 인젝션이 드러남)
    violations: tuple[Violation, ...] = ()
    was_obfuscated: bool = False         # 콘텐츠가 난독화돼 있었는지(그 자체로 의심 신호)

    @property
    def ok(self) -> bool:
        return not self.poisoned


class GuardBlocked(Exception):
    """Raised by Guard.enforce() when the input is blocked."""

    def __init__(self, result: GuardResult) -> None:
        self.result = result
        reasons = "; ".join(f"[{v.category.value}] {v.reason}" for v in result.violations)
        super().__init__(f"prompt blocked: {reasons or 'unknown reason'}")
