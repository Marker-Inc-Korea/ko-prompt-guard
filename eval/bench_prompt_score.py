"""task #14 score — ko-prompt-guard 룰 + GPU 예측 결합 → 경쟁 표.

sqlguard venv(pydantic)에서: ko-prompt-guard Guard().check(룰, normalize 포함) 실행 →
GPU 예측(prompt_preds_gpu.json)과 합쳐 per-variant per-system recall/FPR/F1.

스토리: 난독 변형에서 EN 가드(Prompt-Guard-86M/protectai) recall 붕괴 vs ko-prompt-guard
(normalize로 펴서) 유지. ko-pii의 F1 95.2 vs 55.6 에 대응하는 '난독 recall delta'.
"""
from __future__ import annotations

import json
import sys

sys.path.insert(0, "/data1/mk04/eval_external/modak_pub/ko-prompt-guard/src")
from ko_prompt_guard import Guard, Verdict

SETS = "/data1/mk04/eval_external/prompt_eval_sets.json"
PREDS = "/data1/mk04/eval_external/prompt_preds_gpu.json"
OUT = "/data1/mk04/eval_external/bench_prompt_report.json"
G = Guard()
THR = 0.5


def metrics(pred_pos, labels):
    tp = sum(1 for p, y in zip(pred_pos, labels) if p and y == 1)
    fp = sum(1 for p, y in zip(pred_pos, labels) if p and y == 0)
    fn = sum(1 for p, y in zip(pred_pos, labels) if not p and y == 1)
    tn = sum(1 for p, y in zip(pred_pos, labels) if not p and y == 0)
    rec = tp / (tp + fn) * 100 if tp + fn else 0.0
    fpr = fp / (fp + tn) * 100 if fp + tn else 0.0
    prec = tp / (tp + fp) * 100 if tp + fp else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"recall": round(rec, 1), "fpr": round(fpr, 1), "f1": round(f1, 1)}


def main():
    sets = json.load(open(SETS))
    preds = json.load(open(PREDS))
    report = {}
    SYS = ["ko_rules", "ko_hybrid", "prompt_guard_86m", "prompt_guard_2_86m", "qualifire_sentinel", "protectai_deberta", "ko_classifier"]
    print(f"{'variant':14} | " + " | ".join(f"{s:>10}" for s in SYS) + "   (recall%, 괄호 FPR%)")
    for variant, rows in sets.items():
        texts = [t for t, _ in rows]
        labels = preds["_labels"][variant]
        # ko-prompt-guard 룰 (normalize 포함)
        ko_rule_pos = [G.check(t).verdict is not Verdict.ALLOW for t in texts]
        clf = preds[variant]["ko_classifier"]
        ko_hybrid_pos = [r or (c > THR) for r, c in zip(ko_rule_pos, clf)]
        cols = {
            "ko_rules": ko_rule_pos,
            "ko_hybrid": ko_hybrid_pos,
            "prompt_guard_86m": [p > THR for p in preds[variant]["prompt_guard_86m"]],
            "prompt_guard_2_86m": [p > THR for p in preds[variant]["prompt_guard_2_86m"]],
            "qualifire_sentinel": [p > THR for p in preds[variant]["qualifire_sentinel"]],
            "protectai_deberta": [p > THR for p in preds[variant]["protectai_deberta"]],
            "ko_classifier": [p > THR for p in clf],
        }
        report[variant] = {s: metrics(cols[s], labels) for s in SYS}
        line = f"{variant:14} | "
        line += " | ".join(f"{report[variant][s]['recall']:5.1f}({report[variant][s]['fpr']:4.1f})" for s in SYS)
        print(line)
    json.dump(report, open(OUT, "w"), ensure_ascii=False, indent=2)
    print(f"\nsaved → {OUT}")
    # 헤드라인: 난독 평균 recall
    obf = [v for v in sets if v.startswith("obf_")]
    print("\n=== 난독 변형 평균 injection recall (핵심) ===")
    for s in SYS:
        avg = sum(report[v][s]["recall"] for v in obf) / len(obf)
        print(f"  {s:18} {avg:5.1f}%")


if __name__ == "__main__":
    main()
