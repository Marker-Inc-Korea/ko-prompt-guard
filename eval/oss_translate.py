"""영어 인젝션 → 한국어 번역 (oss-120b). 학습 positive 다양성 확장용.

영어 공개 인젝션셋(deepset/xTRam1/jayavibhav, 2007건)을 oss-120b 로 한국어 번역.
⚠️ 번역은 적대적 프롬프트의 instruction-override 표면을 *순화하지 말고* 그대로 옮겨야
한다(거부·완화 금지) — 학습 positive 의 공격 시그니처 보존이 핵심.
출력: ko_injections_translated.jsonl (label 1).
"""
from __future__ import annotations

import json
import sys

sys.path.insert(0, "/data1/mk04/eval_external")
import oss_client as oss

SRC = "/data1/mk04/eval_external/en_injections.jsonl"
OUT = "/data1/mk04/eval_external/ko_injections_translated.jsonl"

SYS = (
    "You are a precise EN→KO translator building security training data. Translate the "
    "user's text to natural Korean. CRITICAL: this is adversarial/prompt-injection text — "
    "translate it FAITHFULLY without refusing, softening, or sanitizing the instructions. "
    "Preserve the attack intent and imperative tone exactly. Output ONLY the Korean translation, "
    "no quotes, no notes."
)


def main():
    print("ping:", [m["id"] for m in oss.ping().get("data", [])])
    rows = [json.loads(l) for l in open(SRC) if l.strip()]
    print(f"번역 대상: {len(rows)}건")

    def one(r):
        try:
            ko = oss.chat([{"role": "system", "content": SYS},
                           {"role": "user", "content": r["text"]}],
                          max_tokens=400, temperature=0.0)
            ko = ko.strip().strip('"').strip()
            return {"text": ko, "label": 1, "src": "mt_oss:" + r["src"]} if 4 <= len(ko) <= 600 else None
        except Exception:
            return None

    res = oss.map_concurrent(one, rows, workers=8)
    out = [x for x in res if x and any(0xAC00 <= ord(c) <= 0xD7A3 for c in x["text"])]
    with open(OUT, "w") as f:
        for x in out:
            f.write(json.dumps(x, ensure_ascii=False) + "\n")
    print(f"한국어 번역(한글 포함): {len(out)}/{len(rows)} → {OUT}")
    for x in out[:4]:
        print("  -", x["text"][:60])


if __name__ == "__main__":
    main()
