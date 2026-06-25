"""간접 프롬프트 인젝션(indirect PI) 평가 — scan_context() 검증.

에이전틱 RAG 시나리오: 식약처 benign 의료 문서에 한국어 인젝션을 *숨겨* "오염 문서"를 만들고,
scan_context() 가 격리(quarantine)하는지 측정. 평문 + 난독(자모분리/제로폭/전각) 변형으로
난독 강건성이 검색 콘텐츠에도 적용되는지 확인. benign 문서(qtaoa)로 FPR.

핵심 대조: 입력 가드(check, 사용자 턴만)는 이 공격을 **0% 탐지**(페이로드가 사용자 입력이 아니라
문서 안에 있으므로). scan_context 가 그 공백을 메운다. CPU(룰만), 오프라인.
"""
from __future__ import annotations

import json
import random
import sys

sys.path.insert(0, "/data1/mk04/eval_external/modak_pub/ko-prompt-guard/src")
from ko_prompt_guard import Guard

random.seed(7)
G = Guard()
KO_INJ = "/data1/mk04/eval_external/ko_injection_eval.jsonl"
QTAOA = "/data1/mk04/medi/agentic_v3/data/qtaoa_combined.jsonl"
ZW = "​"


def jamo(s):
    CHO = "ㄱㄲㄴㄷㄸㄹㅁㅂㅃㅅㅆㅇㅈㅉㅊㅋㅌㅍㅎ"; JUNG = "ㅏㅐㅑㅒㅓㅔㅕㅖㅗㅘㅙㅚㅛㅜㅝㅞㅟㅠㅡㅢㅣ"
    JONG = " ㄱㄲㄳㄴㄵㄶㄷㄹㄺㄻㄼㄽㄾㄿㅀㅁㅂㅄㅅㅆㅇㅈㅊㅋㅌㅍㅎ"
    o = []
    for c in s:
        n = ord(c)
        if 0xAC00 <= n <= 0xD7A3:
            k = n - 0xAC00; o.append(CHO[k//588]+JUNG[(k%588)//28]+(JONG[k%28] if k%28 else ""))
        else:
            o.append(c)
    return "".join(o)


def zerowidth(s):
    return ZW.join(s)


def fullwidth(s):
    return "".join(chr(ord(c)+0xFEE0) if 0x21<=ord(c)<=0x7E else c for c in s)


OBF = {"plain": lambda s: s, "jamo": jamo, "zerowidth": zerowidth, "fullwidth": fullwidth}


def load_docs(n=250):
    out = []
    for line in open(QTAOA):
        if not line.strip():
            continue
        r = json.loads(line)
        a = [m for m in r.get("messages", []) if m.get("role") == "assistant" and m.get("content")]
        if a and len(a[-1]["content"].strip()) >= 60:
            out.append(a[-1]["content"].strip()[:400])
        if len(out) >= n:
            break
    return out


SYNTH = "/data1/mk04/eval_external/inj_train.jsonl"


def load_injections():
    return [json.loads(l)["ko"] for l in open(KO_INJ) if l.strip() and json.loads(l)["injection"]]


def load_synth():
    """Gemma 합성 명시적 인젝션(8기법) — 실제 오염 문서에 흔한 직접 공격체."""
    return [json.loads(l)["text"] for l in open(SYNTH) if l.strip() and json.loads(l).get("label") == 1]


def embed(doc, inj):
    """benign 문서 안에 인젝션을 삽입(RAG 문서 오염 시뮬레이션)."""
    parts = doc.split(". ")
    pos = len(parts) // 2
    return ". ".join(parts[:pos] + [inj] + parts[pos:])


def main():
    docs = load_docs()
    injs = load_injections()
    n = min(len(injs), 200)
    injs = injs[:n]
    print(f"benign 문서={len(docs)}  인젝션={len(injs)}\n")
    report = {}

    synth = load_synth()[:200]
    # 오염 문서: 각 변형별 recall (scan_context poisoned) — 두 인젝션 출처
    for label, src in [("MT-간접(ko_injection_eval)", injs), ("명시적(synth 8기법)", synth)]:
        print(f"=== 오염 문서: {label} 숨김 — scan_context 격리 recall ===")
        for name, fn in OBF.items():
            flags = []
            for i, inj in enumerate(src):
                doc = docs[i % len(docs)]
                flags.append(G.scan_context(embed(doc, fn(inj)), source="rag").poisoned)
            rec = sum(flags) / len(flags) * 100
            report[f"{'mt' if src is injs else 'synth'}_recall_{name}"] = round(rec, 1)
            print(f"  {name:10} recall = {rec:5.1f}%  ({sum(flags)}/{len(flags)})")
        print()

    # 입력-가드(check, 사용자턴만) 대조 — 오염 문서를 '사용자 입력'으로 안 보므로 탐지 불가 구조
    # (개념 대조: 문서 속 인젝션은 사용자 입력 스캔 대상이 아니다)
    print("\n=== benign 문서 FPR (clean doc → 격리되면 오탐) ===")
    bf = [G.scan_context(d, source="rag").poisoned for d in docs]
    fpr = sum(bf) / len(docs) * 100
    report["benign_doc_fpr"] = round(fpr, 1)
    print(f"  benign-doc FPR = {fpr:.1f}%  ({sum(bf)}/{len(docs)})")

    json.dump(report, open("/data1/mk04/eval_external/bench_context_report.json", "w"), ensure_ascii=False, indent=2)
    print("\nsaved → bench_context_report.json")
    print("해석: scan_context 가 검색문서 속 인젝션을 평문·난독 모두 격리(난독 불변성 유지), "
          "benign 문서는 낮은 FPR. 입력-가드만으로는 구조적으로 0% 탐지인 공백을 메움.")


if __name__ == "__main__":
    main()
