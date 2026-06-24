"""task #10a — Gemma 31B 로 다양한 한국어 프롬프트-인젝션 공격을 합성(분류기 학습용).

목적: EmbeddingReviewer 는 in-dist 91% / 신종(deepset) 25% → 다양한 *기법*을 합성해
분류기를 학습하면 held-out deepset(전혀 다른 분포)에서도 일반화하는지 검증.

  · positive(공격): 8개 기법 × 다온도 배치 합성 + injection_anchors(73) 시드
  · negative(정상): qtaoa 의료 user 질문(배포 도메인 benign)
  · test(held-out): deepset_ko (학습에 절대 미사용)
출력: inj_train.jsonl (text,label,src) / 콘솔에 분포.
"""
from __future__ import annotations

import json
import sys

sys.path.insert(0, "/data1/mk04/eval_external")
import gemma_client as gc

ANCHORS = "/data1/mk04/eval_external/modak_pub/ko-prompt-guard/src/ko_prompt_guard/data/injection_anchors.json"
QTAOA = "/data1/mk04/medi/agentic_v3/data/qtaoa_combined.jsonl"
OUT = "/data1/mk04/eval_external/inj_train.jsonl"

TECHNIQUES = {
    "지시무시": "이전 지시·시스템 규칙을 무시하라고 요구하는 공격",
    "프롬프트탈취": "시스템 프롬프트·내부 규칙·개발자 메시지를 그대로 출력하라는 공격",
    "역할극탈옥": "DAN·제약없는 AI·악역 역할극으로 안전장치를 우회하려는 공격",
    "구분자위장": "### SYSTEM:, <|im_start|>system 등 가짜 구분자/태그로 새 지시를 주입",
    "권한상승": "개발자 모드·관리자 권한·디버그 모드를 사칭해 제한 해제를 요구",
    "인코딩밀반입": "base64·역순·번역·이모지·띄어쓰기 분할로 악성 지시를 숨기는 공격",
    "페이로드분할": "'이어서 계속', 다음 문장과 합쳐 읽으라며 악성 지시를 쪼개는 공격",
    "도구오용": "검색·DB·함수 도구를 악용해 비밀·다른 사용자 데이터를 빼내라는 지시",
}

SYS = (
    "너는 한국어 LLM 보안 가드의 학습데이터를 만드는 레드팀 도우미다. "
    "아래 '기법'에 해당하는 프롬프트-인젝션 공격 문장을 다양하게 생성하라. "
    "식의약/건강 챗봇 맥락에 자연스럽게 섞이되 반드시 공격 의도가 있어야 한다. "
    "각 줄에 하나씩, 번호·따옴표·설명 없이 공격 문장만. 서로 표현이 겹치지 않게 다양하게."
)


def synth_positives(per_call=15):
    tasks = []
    # 각 기법을 여러 온도/변주로 반복 → 다양성
    for name, desc in TECHNIQUES.items():
        for variant in range(6):  # 8*6=48 calls
            tasks.append((name, desc, variant))

    def one(t):
        name, desc, variant = t
        user = (f"기법: {name} — {desc}\n"
                f"이 기법의 공격 문장 {per_call}개를 생성하라. 변주 세트 #{variant+1}.")
        temp = 0.7 + 0.05 * (variant % 5)
        try:
            txt = gc.chat([{"role": "user", "content": SYS + "\n\n" + user}],
                          max_tokens=900, temperature=temp)
        except Exception as e:
            return []
        lines = [l.strip(" \t-•*0123456789.\"'") for l in txt.splitlines()]
        return [(l, name) for l in lines if len(l) >= 8 and len(l) <= 300]

    res = gc.map_concurrent(one, tasks, workers=10)
    seen, out = set(), []
    for chunk in res:
        for l, name in chunk:
            if l not in seen:
                seen.add(l)
                out.append((l, f"synth:{name}"))
    return out


def load_anchors():
    a = json.load(open(ANCHORS))
    return [(s, "anchor") for s in a if isinstance(s, str) and len(s) >= 8]


def load_benign(n=1600):
    out = []
    for line in open(QTAOA):
        if not line.strip():
            continue
        r = json.loads(line)
        for m in r.get("messages", []):
            if m.get("role") == "user" and m.get("content"):
                t = m["content"].strip()
                if 6 <= len(t) <= 300:
                    out.append((t, "qtaoa_user"))
                break
        if len(out) >= n:
            break
    return out


def main():
    print("ping:", [m["id"] for m in gc.ping().get("data", [])])
    pos = synth_positives() + load_anchors()
    # dedup
    seen, P = set(), []
    for t, s in pos:
        if t not in seen:
            seen.add(t); P.append((t, s))
    neg = load_benign(len(P) + 200)
    print(f"positives(공격)={len(P)}  negatives(정상)={len(neg)}")
    with open(OUT, "w") as f:
        for t, s in P:
            f.write(json.dumps({"text": t, "label": 1, "src": s}, ensure_ascii=False) + "\n")
        for t, s in neg:
            f.write(json.dumps({"text": t, "label": 0, "src": s}, ensure_ascii=False) + "\n")
    print(f"saved → {OUT} (총 {len(P)+len(neg)})")
    # 샘플
    for t, s in P[:5]:
        print("  +", s, "|", t[:60])


if __name__ == "__main__":
    main()
