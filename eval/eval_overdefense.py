"""v3 vs v4 over-defense 비교 — 올바른 *한국어* over-defense 테스트로.

NotInject 은 영어/중국어(한글 0%)라 한국어 klue/roberta 엔 over-defense 를 못 잰다(언어혼동으로
~100% 무차별). 대신 한국어 트리거-단어 benign 으로 측정:
  · synth_holdout: hard_neg 의 20%(학습 미사용분) — 분포 일치 held-out
  · mined: 실제 corpus 트리거-단어 benign(ko_overdefense_test) — 자연 분포
recall(native_test)도 함께 봐 trade-off 확인. 두 모델(v3, v4) 동일 채점.
"""
from __future__ import annotations

import json
import random

import numpy as np
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from _paths import EVAL_ROOT

random.seed(13)
D = str(EVAL_ROOT)
DEV = "cuda" if torch.cuda.is_available() else "cpu"

# hard_neg 를 train/test 분리 (v4 가 학습에 쓴 것과 동일 seed 가정 — 여기선 단순 20% holdout 표본)
hard = [json.loads(l)["text"] for l in open(f"{D}/hard_neg.jsonl") if l.strip()]
random.shuffle(hard)
hold = hard[:int(len(hard) * 0.2)]   # held-out 표본(분포 일치)
mined = [json.loads(l)["text"] for l in open(f"{D}/ko_overdefense_test.jsonl") if l.strip()]
nat = json.load(open(f"{D}/native_ko_test.json"))
nat_inj = [r["text"] for r in nat if r["label"] == 1]


@torch.no_grad()
def pinj(mdir, texts, bs=64):
    tok = AutoTokenizer.from_pretrained(mdir)
    net = AutoModelForSequenceClassification.from_pretrained(mdir).eval().to(DEV)
    o = []
    for i in range(0, len(texts), bs):
        e = tok(texts[i:i+bs], padding=True, truncation=True, max_length=128, return_tensors="pt").to(DEV)
        o.append(torch.softmax(net(**e).logits, -1)[:, 1].cpu().numpy())
    del net; torch.cuda.empty_cache()
    return np.concatenate(o)


def fpr(probs, thr=0.5):
    return float((np.array(probs) > thr).mean() * 100)


print(f"한국어 over-defense 셋: synth-holdout {len(hold)} / mined {len(mined)} | native recall: {len(nat_inj)} inj")
print(f"\n{'model':18} | synth_holdout 과탐 | mined 과탐 | native recall")
for tag, mdir in [("v3 (hard-neg 없음)", f"{D}/inj_clf_v3/final"), ("v4 (hard-neg 추가)", f"{D}/inj_clf_v4/final")]:
    od_h = fpr(pinj(mdir, hold))
    od_m = fpr(pinj(mdir, mined))
    rec = fpr(pinj(mdir, nat_inj))  # positives → "flag율"=recall
    print(f"{tag:18} | {od_h:5.1f}%            | {od_m:5.1f}%     | {rec:5.1f}%")
print("\n(과탐=한국어 정상문을 인젝션으로 오판, 낮을수록 좋음 / native recall 높을수록 좋음)")
