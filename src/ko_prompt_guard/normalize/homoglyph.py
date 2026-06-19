"""유니코드 호몰로그(confusable) 폴딩 — mixed-script 토큰만 (정규화 단계 4).

키릴/그리스 글리프를 닮은꼴 라틴으로 펴되, 토큰이 두 개 이상 스크립트를 섞었을
때만 적용한다 → 정상 러시아어/그리스어 문장(단일 스크립트)은 파괴하지 않는다.
코드포인트는 UTS#39 confusables 기반(util.unicode.org 검증). stdlib only.
"""
from __future__ import annotations

import re
import unicodedata

# 키릴 → 라틴 (확실한 동형 위주; 일부 근사는 주석)
CYRILLIC_TO_LATIN: dict[str, str] = {
    "а": "a", "о": "o", "е": "e", "р": "p", "с": "c", "у": "y", "х": "x",
    "к": "k", "м": "m", "т": "t", "в": "b", "н": "h", "і": "i", "ј": "j",
    "ѕ": "s", "ӏ": "l", "ԁ": "d", "ԛ": "q", "ԝ": "w", "є": "e",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X", "І": "I", "Ј": "J",
    "Ѕ": "S", "г": "r", "п": "n",
    "ү": "y", "Ү": "Y", "ұ": "y", "Ұ": "Y", "ӯ": "y", "ў": "y", "Ў": "Y",
}

# 라틴 확장/IPA 닮은꼴 — 단일 스크립트라도 ASCII 와 혼동되므로 mixed-script 게이팅
# 없이 무조건 폴딩한다(UTS#39 confusables; 정상 텍스트엔 거의 안 쓰이는 음성 글자).
# 예: 'iɡnore'(U+0261)·'disreɡard'는 전부 라틴이라 mixed 판정에 안 걸려 통과했다.
# ★ ı(U+0131 터키어)·ł(U+0142 폴란드어)은 실제 언어의 정상 글자라 여기서 빼고
#   mixed-script 게이트 뒤로 옮긴다(아래 LATIN_CONFUSABLE_GATED) — 'kırmızı'·폴란드어
#   단어가 통째로 망가지는 과탐 방지(PG-4).
LATIN_CONFUSABLE: dict[str, str] = {
    "ɡ": "g", "ɢ": "g", "ɩ": "i", "ɪ": "i", "ɫ": "l",
    "ɴ": "n", "ʀ": "r", "ᴄ": "c", "ᴇ": "e", "ᴏ": "o", "ᴘ": "p", "ʟ": "l",
    "ɑ": "a", "ᴀ": "a", "ѕ": "s", "ɓ": "b", "ԁ": "d", "ɥ": "h", "ʜ": "h",
    "ᴋ": "k", "ᴍ": "m", "ᴛ": "t", "ᴜ": "u", "ᴠ": "v", "ᴡ": "w", "ʏ": "y",
}

# ı/ł — 정상 언어 글자라 mixed-script(라틴+딴 스크립트) 토큰일 때만 폴딩한다.
LATIN_CONFUSABLE_GATED: dict[str, str] = {"ı": "i", "ł": "l"}

# 그리스 → 라틴
GREEK_TO_LATIN: dict[str, str] = {
    "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "υ": "u", "κ": "k",
    "ι": "i", "η": "n", "γ": "y", "χ": "x", "μ": "u",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    "β": "B",
}

HOMOGLYPH_TO_LATIN: dict[str, str] = {**CYRILLIC_TO_LATIN, **GREEK_TO_LATIN}

# 한글 자모 닮은꼴 — UTS#39 밖, 정상 'ㅇㅇ'/'ㅋㅋ' 파괴 위험 → 기본 OFF.
HANGUL_TO_LATIN: dict[str, str] = {"ㅇ": "O", "ㅣ": "l", "ㅡ": "-", "ㄱ": "r", "ㄴ": "L"}

_SCRIPT_BY_RANGE: tuple[tuple[int, int, str], ...] = (
    (0x0041, 0x005A, "LATIN"), (0x0061, 0x007A, "LATIN"), (0x00C0, 0x024F, "LATIN"),
    (0x1E00, 0x1EFF, "LATIN"), (0xFF21, 0xFF3A, "LATIN"), (0xFF41, 0xFF5A, "LATIN"),
    (0x0370, 0x03FF, "GREEK"), (0x1F00, 0x1FFF, "GREEK"),
    (0x0400, 0x04FF, "CYRILLIC"), (0x0500, 0x052F, "CYRILLIC"),
    (0x2DE0, 0x2DFF, "CYRILLIC"), (0xA640, 0xA69F, "CYRILLIC"),
    (0xAC00, 0xD7A3, "HANGUL"), (0x1100, 0x11FF, "HANGUL"), (0x3130, 0x318F, "HANGUL"),
    (0xA960, 0xA97F, "HANGUL"), (0xD7B0, 0xD7FF, "HANGUL"),
    (0x3040, 0x30FF, "KANA"), (0x4E00, 0x9FFF, "HAN"), (0x3400, 0x4DBF, "HAN"),
)

_WS_SPLIT = re.compile(r"(\s+)")


def char_script(ch: str) -> str | None:
    """문자 1개의 스크립트 추정. 숫자/기호/공백 등 폴딩 무관 문자는 None."""
    if not ch:
        return None
    cat = unicodedata.category(ch)
    if cat[0] != "L" and cat not in ("Mn", "Mc"):
        return None
    cp = ord(ch)
    for lo, hi, name in _SCRIPT_BY_RANGE:
        if lo <= cp <= hi:
            return name
    try:
        nm = unicodedata.name(ch)
    except ValueError:
        return "OTHER"
    for key in ("LATIN", "GREEK", "CYRILLIC", "HANGUL", "CJK", "HIRAGANA", "KATAKANA"):
        if nm.startswith(key):
            return "HAN" if key == "CJK" else key
    return "OTHER"


def token_scripts(token: str) -> set[str]:
    return {s for s in (char_script(c) for c in token) if s is not None}


def is_mixed_script(token: str) -> bool:
    """토큰 안에 2개 이상의 글자 스크립트가 섞였으면 True (호몰로그 공격 신호)."""
    return len(token_scripts(token)) >= 2


# 단일 스크립트 confusable 토큰 폴딩 게이트: 글자 중 라틴 매핑 보유 비율이 이 값
# 이상이면 (정상 러시아어/그리스어가 아니라) 라틴 위장으로 보고 폴딩한다. 0.8 은
# 'систем'(0.83)·'промпт'(1.0)·'гереат'(1.0) 같은 위장은 잡고, 'Привет'(0.67)·
# 'дела'(0.5)·'Γνῶθι'(0.4) 같은 정상어는 폴딩하지 않게 한다. 비율이 높아 폴딩된
# 정상어('как'→'kak')라도 인젝션 어휘가 아니면 패턴이 매칭하지 않아 ALLOW 유지(과탐無).
_CONFUSABLE_RATIO_GATE = 0.8
# 길이 3 이상이면 폴딩 대상 — 'тне'(=the) 같은 짧은 위장어도 펴야 'repeat the initial
# prompt' 처럼 단어 단위로 재구성된다. 폴딩된 정상어('как'→'kak')는 인젝션 어휘가
# 아니면 패턴 미매칭 → ALLOW 유지(과탐無). 1~2자 토큰은 우연 일치가 흔해 제외.
_MIN_CONFUSABLE_LEN = 3


# 문서 전체가 'confusable 위장'으로 판정되는 라틴 매핑 비율 — 이 이상이면 짧은(3자)
# 토큰('тне'=the)도 폴딩한다. 미만이면(정상어 'Привет'·'дела' 가 섞인 진짜 러시아어
# 문장) 짧은 토큰은 보존한다('как'=3자 정상어 보호). 이로써 'тне'(공격)와 'как'(정상)을
# 같은 3자라도 '주변 문맥'으로 구분한다.
_DOC_DISGUISE_GATE = 0.9


def _confusable_ratio(token: str, mapping: dict[str, str]) -> tuple[float, int]:
    letters = [c for c in token if unicodedata.category(c)[0] == "L"]
    if not letters:
        return 0.0, 0
    mapped = sum(1 for c in letters if c in mapping)
    return mapped / len(letters), len(letters)


def _is_disguise_doc(text: str) -> bool:
    """문서의 키릴/그리스 글자 중 라틴 매핑 비율이 매우 높으면 위장 문서로 본다."""
    mapped = total = 0
    by_script = {"CYRILLIC": CYRILLIC_TO_LATIN, "GREEK": GREEK_TO_LATIN}
    for c in text:
        s = char_script(c)
        m = by_script.get(s) if s is not None else None
        if m is None:
            continue
        total += 1
        mapped += c in m
    return total > 0 and mapped / total >= _DOC_DISGUISE_GATE


def _fold_single_script(token: str, *, disguise_doc: bool) -> str:
    """단일 스크립트 키릴/그리스 토큰을 라틴 매핑 비율이 높을 때만 폴딩(PG-2).

    짧은(3자) 토큰은 위장 문서(``disguise_doc``)일 때만 폴딩 — 정상 러시아어/그리스어
    문장에 우연히 섞인 confusable 단어('как')는 보존한다(과탐 방지).
    """
    scripts = token_scripts(token)
    if len(scripts) != 1:
        return token
    (script,) = tuple(scripts)
    mapping = {"CYRILLIC": CYRILLIC_TO_LATIN, "GREEK": GREEK_TO_LATIN}.get(script)
    if mapping is None:
        return token
    ratio, n = _confusable_ratio(token, mapping)
    if ratio < _CONFUSABLE_RATIO_GATE:
        return token
    if n < _MIN_CONFUSABLE_LEN or (n < 4 and not disguise_doc):
        return token
    return "".join(mapping.get(c, c) for c in token)


def _fold_token(token: str, *, fold_hangul: bool, disguise_doc: bool) -> str:
    # 라틴 confusable(희귀 IPA/소문자) 은 단일 스크립트라도 무조건 폴딩(mixed 게이팅 밖).
    if any(c in LATIN_CONFUSABLE for c in token):
        token = "".join(LATIN_CONFUSABLE.get(c, c) for c in token)
    if not is_mixed_script(token):
        # 단일 스크립트라도 전부-confusable 키릴/그리스 위장이면 폴딩(PG-2).
        return _fold_single_script(token, disguise_doc=disguise_doc)
    out: list[str] = []
    for ch in token:
        if ch in HOMOGLYPH_TO_LATIN:
            out.append(HOMOGLYPH_TO_LATIN[ch])
        elif ch in LATIN_CONFUSABLE_GATED:  # ı/ł: mixed-script 일 때만 폴딩(PG-4)
            out.append(LATIN_CONFUSABLE_GATED[ch])
        elif fold_hangul and ch in HANGUL_TO_LATIN:
            out.append(HANGUL_TO_LATIN[ch])
        else:
            out.append(ch)
    return "".join(out)


def fold_homoglyphs(text: str, *, fold_hangul: bool = False) -> str:
    """텍스트를 공백 토큰 단위로 조건부 폴딩. mixed-script 토큰만 변형한다."""
    disguise_doc = _is_disguise_doc(text)
    parts = _WS_SPLIT.split(text)
    for i in range(0, len(parts), 2):
        parts[i] = _fold_token(parts[i], fold_hangul=fold_hangul, disguise_doc=disguise_doc)
    return "".join(parts)
