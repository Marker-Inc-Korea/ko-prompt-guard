"""Guard: 결정론 한국어 프롬프트 가드의 진입점.

check() 는 순수 함수다: 입력을 normalize() 로 난독 해제한 뒤 패턴 룰로 스캔하고
GuardResult 를 반환한다. 네트워크·LLM·임베딩 호출이 전혀 없다(그건 Tier-2 seam).
의미 기반 공격(역할극의 신종 변형 등)은 룰만으로 못 잡으므로, 보수적으로 high·
명백한 카테고리만 BLOCK 하고 나머지는 FLAG 한다(인젝션 오탐은 정상 사용자를 막는다).
"""
from __future__ import annotations

from . import patterns
from .normalize import normalize
from .normalize.leet import deleet_variants
from .policy import GuardPolicy
from .result import (
    Category,
    ContextScanResult,
    GuardBlocked,
    GuardResult,
    Verdict,
    Violation,
)

# 검색 문서·도구 출력에서 "에이전트를 탈취하려는" 신호로 보는 카테고리 (간접 PI).
# OBFUSCATION/SEMANTIC 은 단독으로는 격리 사유 아님(정상 문서도 이모지/난독 있을 수 있음).
_INDIRECT_PI_CATEGORIES = frozenset(
    {
        Category.INSTRUCTION_OVERRIDE,
        Category.PROMPT_LEAK,
        Category.JAILBREAK,
        Category.EXFILTRATION,
        Category.TRANSLITERATION,
        Category.ENCODING,
    }
)


class Guard:
    """정책에 묶인 재사용 가능한 가드. check() 호출 간 상태 없음."""

    def __init__(self, policy: GuardPolicy | None = None) -> None:
        self.policy = policy or GuardPolicy()

    def _collect(
        self, text: str, *, apply_input_fp_gates: bool = True
    ) -> tuple[list[Violation], str, bool]:
        """정규화 + 전체 탐지기 파이프라인. (violations, normalized, changed) 반환.

        ``apply_input_fp_gates`` 는 *사용자 입력* 전용 오탐 억제(번역/인용 프레이밍, decode
        how-to)를 켤지다. check() 는 켠다(기본). scan_context() 는 끈다 — 검색문서·도구출력에선
        그 프레이밍 자체가 간접 인젝션 은닉 표면이라, 룰이 이미 잡은 명시 override 가 억제로
        새는 것을 막는다(신뢰 코어 recall 누수 차단). 사용자 입력 FPR 엔 영향 없음.
        """
        policy = self.policy
        normalized, changed = normalize(text, policy)

        violations: list[Violation] = list(
            patterns.scan(normalized, apply_translation_gate=apply_input_fp_gates)
        )
        # 단일 스크립트 외국어 literal lexicon 은 '폴딩 이전' 텍스트로 한 번 더 스캔한다.
        # homoglyph 단일 스크립트 폴딩(PG-2)이 'систем'→'cиctem' 처럼 키릴 토큰을
        # 부분 변형해 literal 매칭을 깨기 때문. 폴딩 끈 정규화는 멱등하고 부작용이 없다.
        if policy.fold_homoglyphs:
            pre_fold, _ = normalize(text, policy.model_copy(update={"fold_homoglyphs": False}))
            if pre_fold != normalized:
                seen_fl = {(v.category, v.code) for v in violations}
                for v in patterns.scan_foreign_literal(
                    pre_fold, apply_translation_gate=apply_input_fp_gates
                ):
                    if (v.category, v.code) not in seen_fl:
                        violations.append(v)
                        seen_fl.add((v.category, v.code))
        if policy.detect_encoding:
            violations.extend(
                patterns.scan_encoding(text, apply_dev_gate=apply_input_fp_gates)
            )
        # leetspeak 보강: 숫자→글자 디코드본에서 '추가로' 잡히는 공격만 더한다. 원본
        # FLAG/was_obfuscated 에는 영향 없음(정상 'mp3'/'버전3' 과탐 방지).
        if policy.de_leet:
            seen = {(v.category, v.code) for v in violations}
            for deleeted in deleet_variants(normalized):
                if deleeted == normalized:
                    continue
                for v in patterns.scan(deleeted, apply_translation_gate=apply_input_fp_gates):
                    if (v.category, v.code) not in seen:
                        violations.append(v)
                        seen.add((v.category, v.code))
        return violations, normalized, changed

    def check(self, text: str) -> GuardResult:
        if not isinstance(text, str):
            raise TypeError(f"check() expects str, got {type(text).__name__}")
        policy = self.policy
        violations, normalized, changed = self._collect(text)

        blocking = [
            v
            for v in violations
            if v.severity >= policy.min_block_severity and v.category in policy.block_categories
        ]
        if blocking:
            verdict = Verdict.BLOCK
        elif violations or (changed and policy.flag_pure_obfuscation):
            verdict = Verdict.FLAG
        else:
            verdict = Verdict.ALLOW

        return GuardResult(
            verdict=verdict,
            original_text=text,
            normalized_text=normalized,
            violations=tuple(violations),
            was_obfuscated=changed,
        )

    def enforce(self, text: str) -> str:
        """안전하면 (난독 해제된) 텍스트 반환, BLOCK 이면 GuardBlocked 발생."""
        result = self.check(text)
        if result.verdict is Verdict.BLOCK:
            raise GuardBlocked(result)
        return result.normalized_text

    def scan_context(self, content: str, *, source: str = "context") -> ContextScanResult:
        """검색 문서·도구 출력 등 *비-사용자 콘텐츠*를 간접 프롬프트 인젝션(indirect PI)으로 스캔.

        에이전틱 공격의 주 벡터는 사용자 턴이 아니라 *검색된 문서·도구 응답* 안에 숨은 인젝션이다
        (예: RAG 로 끌어온 문서에 "이전 지시 무시하고 …"). ``check()`` 의 normalize()+탐지기를
        그대로 재사용하므로 **난독(초성화/제로폭/전각/호몰로그)으로 숨긴 인젝션도 펴서 잡는다** —
        입력 가드와 동일한 난독 강건성이 검색 콘텐츠에도 적용된다.

        단 판정 의미가 다르다: 신호가 있으면 사용자 BLOCK 이 아니라 **문서 QUARANTINE**
        (해당 콘텐츠를 신뢰/주입하지 말 것). 검색 콘텐츠의 인젝션 패턴은 FLAG 수준 약신호라도
        격리 대상이므로 FLAG/BLOCK 을 모두 ``poisoned`` 로 본다.
        """
        # 입력용 FP 게이트를 끄고 수집 — 검색문서/도구출력에선 '번역/디코딩 방법' 프레이밍이
        # 곧 간접 인젝션 은닉 표면이라, 룰이 이미 탐지한 명시 override 가 격리에서 새지 않게 한다.
        violations, normalized, changed = self._collect(content, apply_input_fp_gates=False)
        pi = tuple(v for v in violations if v.category in _INDIRECT_PI_CATEGORIES)
        poisoned = bool(pi)
        return ContextScanResult(
            poisoned=poisoned,
            source=source,
            recommendation="quarantine" if poisoned else "use",
            normalized_text=normalized,
            violations=pi,
            was_obfuscated=changed,
        )

    def check_messages(
        self,
        messages: "list[str | dict]",
        *,
        last_n: int = 6,
        roles: tuple[str, ...] = ("user",),
    ) -> GuardResult:
        """멀티턴 대화를 *합쳐서* 스캔 — 턴 경계로 쪼갠 분할 주입 우회를 막는다.

        per-turn 스캔은 ('이전 지시' 한 턴 + '무시해줘' 다음 턴)처럼 트리거 구절을 턴 경계로
        분할하면 각 턴이 ALLOW 로 새지만, 합치면 룰이 잡는다. 최근 ``last_n`` 개 ``roles`` 턴을
        공백으로 이어 붙인 뒤 기존 normalize+scan 을 재사용한다(분류기 재학습 불필요).

        ``messages`` 는 OpenAI chat 형식 ``[{"role","content"}, ...]`` 또는 문자열 리스트.
        """
        texts: list[str] = []
        for m in messages:
            if isinstance(m, str):
                texts.append(m)
            elif isinstance(m, dict) and m.get("role") in roles and m.get("content"):
                texts.append(str(m["content"]))
        # 공백 결합: '\n' 은 일부 패턴의 [^.\n] 클래스에 막혀 재조합이 안 되므로 공백으로 잇는다.
        return self.check(" ".join(texts[-last_n:]))


def check(text: str, policy: GuardPolicy | None = None) -> GuardResult:
    """모듈 레벨 편의 함수 — Guard(policy).check(text)."""
    return Guard(policy).check(text)


def scan_context(content: str, policy: GuardPolicy | None = None, *, source: str = "context") -> ContextScanResult:
    """모듈 레벨 편의 함수 — Guard(policy).scan_context(content). 간접 PI(검색문서/도구출력) 스캔."""
    return Guard(policy).scan_context(content, source=source)


def check_messages(
    messages: "list[str | dict]",
    policy: GuardPolicy | None = None,
    *,
    last_n: int = 6,
    roles: tuple[str, ...] = ("user",),
) -> GuardResult:
    """모듈 레벨 편의 함수 — Guard(policy).check_messages(...). 멀티턴 분할 주입 방지."""
    return Guard(policy).check_messages(messages, last_n=last_n, roles=roles)
