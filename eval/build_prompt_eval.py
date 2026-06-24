"""task #14 prep — 한국어 인젝션 난독 평가셋 빌더.

차별점 실험: 같은 한국어 인젝션을 (평문) + (난독 변형 5종)으로 만들어, EN 인젝션 가드
(Prompt-Guard-86M/protectai)가 난독에서 recall 붕괴하는 반면 ko-prompt-guard는 normalize()로
펴서 recall 유지함을 보인다. 난독은 ko-prompt-guard가 *되돌릴 수 있는* family만 사용.

출력: prompt_eval_sets.json = {variant: [[text,label], ...]}  (label 1=injection,0=benign)
"""
from __future__ import annotations

import json
import unicodedata

KO_INJ = "/data1/mk04/eval_external/ko_injection_eval.jsonl"
DEEPSET_KO = "/data1/mk04/projects/ko-pii/experiments/ko-output-guard/eval/external/deepset_ko.jsonl"
OUT = "/data1/mk04/eval_external/prompt_eval_sets.json"

CHO = "ㄱㄲㄴㄷㄸㄹㅁㅂㅃㅅㅆㅇㅈㅉㅊㅋㅌㅍㅎ"
JUNG = "ㅏㅐㅑㅒㅓㅔㅕㅖㅗㅘㅙㅚㅛㅜㅝㅞㅟㅠㅡㅢㅣ"
JONG = " ㄱㄲㄳㄴㄵㄶㄷㄹㄺㄻㄼㄽㄾㄿㅀㅁㅂㅄㅅㅆㅇㅈㅊㅋㅌㅍㅎ"
ZW = "​"


def jamo_split(s: str) -> str:
    """자모분리: 각 한글 음절을 호환자모로 분해 (무시→ㅁㅜㅅㅣ). normalize.combine_jamo가 되돌림."""
    out = []
    for c in s:
        o = ord(c)
        if 0xAC00 <= o <= 0xD7A3:
            code = o - 0xAC00
            cho, jung, jong = code // (21 * 28), (code % (21 * 28)) // 28, code % 28
            out.append(CHO[cho] + JUNG[jung] + (JONG[jong] if jong else ""))
        else:
            out.append(c)
    return "".join(out)


def space_split(s: str) -> str:
    """칸별분리: 글자 사이 공백 (무시해→무 시 해). normalize.collapse_separators가 되돌림."""
    return " ".join(list(s))


def dot_split(s: str) -> str:
    """점 구분: 무.시.해."""
    return ".".join(list(s))


def zero_width(s: str) -> str:
    """제로폭 삽입: 무​시​해. normalize.strip_invisible이 되돌림."""
    return ZW.join(list(s))


def fullwidth(s: str) -> str:
    """전각화: ASCII→전각 (영문/숫자 부분). normalize.nfkc_fold가 되돌림."""
    out = []
    for c in s:
        o = ord(c)
        if 0x21 <= o <= 0x7E:
            out.append(chr(o + 0xFEE0))
        elif c == " ":
            out.append("　")
        else:
            out.append(c)
    return "".join(out)


# 키릴 호몰로그 (라틴 닮은꼴) — 영문 토큰 위장. normalize.fold_homoglyphs가 되돌림.
_HOMO = {"a": "а", "c": "с", "e": "е", "o": "о", "p": "р", "y": "у", "x": "х",
         "A": "А", "C": "С", "E": "Е", "O": "О", "P": "Р", "y2": "у"}


def homoglyph(s: str) -> str:
    return "".join(_HOMO.get(c, c) for c in s)


OBF = {"jamo": jamo_split, "space": space_split, "dot": dot_split,
       "zerowidth": zero_width, "fullwidth": fullwidth, "homoglyph": homoglyph}


def load_ko_inj():
    rows = [json.loads(l) for l in open(KO_INJ) if l.strip()]
    return [(r["ko"], 1 if r["injection"] else 0) for r in rows]


def load_deepset_ko():
    rows = [json.loads(l) for l in open(DEEPSET_KO) if l.strip()]
    return [(r["text_ko"], int(r["label"])) for r in rows]


def main():
    ko = load_ko_inj()
    sets = {"plain_ko": ko, "deepset_ko": load_deepset_ko()}
    # 난독 변형: ko_injection_eval 전체(공격+정상)에 적용 → variant별 recall(공격)+FPR(정상)
    for name, fn in OBF.items():
        sets[f"obf_{name}"] = [(fn(t), y) for t, y in ko]
    json.dump(sets, open(OUT, "w"), ensure_ascii=False)
    print(f"saved → {OUT}")
    for k, v in sets.items():
        pos = sum(y for _, y in v)
        print(f"  {k:16} n={len(v)} (inj {pos}/{len(v)})")
    # 샘플 — 난독이 실제로 적용됐는지
    print("\n예시(plain → jamo):", ko[1][0][:30], "→", jamo_split(ko[1][0])[:40])


if __name__ == "__main__":
    main()
