"""over-defense hard-negative 합성 — 인젝션 트리거 단어를 포함하지만 *정상*인 한국어 프롬프트.

v3 분류기는 NotInject(트리거단어 benign)를 95.6% 과탐. NotInject 은 테스트셋이라 학습 불가 →
같은 분포(공격처럼 보이지만 정상)를 Gemma 로 합성해 hard-negative 로 추가한다. 카테고리는
NotInject 류를 한국어로 미러링: 코딩질문·AI보안 메타질문·업무맥락·교육.

출력: hard_neg.jsonl (label 0). Gemma 31B(serve_gemma4_31b_local) 필요.
"""
from __future__ import annotations

import json
import re
import sys

import gemma_client as gc
from _paths import eval_path

OUT = eval_path("hard_neg.jsonl")

# 인젝션 트리거 단어가 들어가되 정상 의도인 benign 프롬프트를 생성할 맥락
CATEGORIES = {
    "코딩질문": "프로그래밍/IT 질문인데 '무시/시스템/명령/권한/디버그/모드/설정' 같은 단어가 자연스럽게 들어간 정상 질문 (예: '이 컴파일 경고를 무시해도 되나요?', '시스템 환경변수 설정 방법 알려줘', 'sudo 권한 없이 실행하는 법')",
    "AI보안메타": "AI/LLM 보안을 *공부·설명*하려는 정상 질문 (예: '프롬프트 인젝션이 뭐야?', '탈옥 공격은 어떻게 방어하나요?', 'LLM 시스템 프롬프트는 어떻게 설계해?', '재일브레이크 사례 연구 자료 추천')",
    "업무일상": "회의·업무·일상 맥락에 '무시/이전 지시/규칙/관리자/역할' 단어가 든 정상 문장 (예: '이전 회의 안건은 무시하고 새 주제로 진행해요', '관리자 권한 신청 절차 알려줘', '내 역할이 뭔지 정리해줘')",
    "교육설명": "용어·개념을 알려달라는 정상 요청 (예: '개발자 모드가 뭔지 설명해줘', '시스템 콜이 무엇인가요?', '제약 조건 충족 문제 푸는 법', '프롬프트 엔지니어링 강의 추천')",
    "식의약맥락": "식약처/건강 맥락에 트리거 단어가 우연히 든 정상 질문 (예: '이 약의 시스템상 분류 알려줘', '복용 제약 사항이 뭐야?', '이전 처방은 무시하고 새 처방 기준으로 설명해줘')",
}

SYS = (
    "너는 한국어 LLM 보안 분류기의 hard-negative 학습데이터를 만드는 도우미다. "
    "프롬프트 인젝션 *트리거 단어*(무시/시스템/프롬프트/지시/명령/규칙/제약/역할/권한/개발자/관리자/"
    "탈옥/우회/모드/설정 등)를 포함하지만 **실제로는 공격 의도가 전혀 없는 정상 프롬프트**를 만든다. "
    "AI 를 탈취하거나 규칙을 무력화하려는 의도가 있으면 안 된다 — 어디까지나 일반 사용자의 정상 질문/요청이다. "
    "각 줄에 하나씩, 번호·따옴표·설명 없이 문장만. 서로 표현이 겹치지 않게 다양하게."
)


def synth(per_call=15):
    tasks = []
    for name, desc in CATEGORIES.items():
        for v in range(8):  # 5*8=40 calls
            tasks.append((name, desc, v))

    def one(t):
        name, desc, v = t
        user = f"맥락: {name} — {desc}\n이 맥락의 정상 프롬프트 {per_call}개. 변주 #{v+1}."
        temp = 0.7 + 0.04 * (v % 5)
        try:
            txt = gc.chat([{"role": "user", "content": SYS + "\n\n" + user}], max_tokens=900, temperature=temp)
        except Exception:
            return []
        out = []
        for line in txt.splitlines():
            s = line.strip(" \t-•*0123456789.\"'")
            if 6 <= len(s) <= 200:
                out.append((s, name))
        return out

    res = gc.map_concurrent(one, tasks, workers=10)
    seen, flat = set(), []
    for chunk in res:
        for s, name in chunk:
            if s not in seen:
                seen.add(s); flat.append((s, name))
    return flat


_TRIG = re.compile(r"무시|시스템|프롬프트|지시|명령|규칙|제약|역할|개발자|관리자|탈옥|우회|출력|설정|권한|모드|해제|초기화|디버그")


def main():
    print("ping:", [m["id"] for m in gc.ping().get("data", [])])
    hn = synth()
    # 트리거 단어가 실제로 든 것만(hard-negative 자격) 유지
    hn = [(s, c) for s, c in hn if _TRIG.search(s)]
    with open(OUT, "w") as f:
        for s, c in hn:
            f.write(json.dumps({"text": s, "label": 0, "src": f"hardneg:{c}"}, ensure_ascii=False) + "\n")
    from collections import Counter
    print(f"hard-negative: {len(hn)}건 {Counter(c for _, c in hn)}")
    for s, c in hn[:6]:
        print("  -", c, "|", s[:55])


if __name__ == "__main__":
    main()
