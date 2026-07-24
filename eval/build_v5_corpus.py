"""v5 인젝션 분류기 학습 코퍼스 병합 — 대규모 다출처.

positives:
  · native_ko train(483, test 130 제외 — 누출 방지)
  · MT 번역 영어셋(oss-120b, ko_injections_translated)
  · oss-120b 합성(ko_injections_synth_oss) + Gemma synth(inj_train label1, 721)
negatives:
  · 다양한 한국어 benign(qtaoa+unsmile clean+kmhas/apeach normal, inj_train_v3 재사용분)
  · hard-negative(트리거단어 benign, hard_neg 574)

native_ko test 130 은 절대 학습에 안 들어감(held-out). 출력: inj_train_v5.jsonl.
"""
from __future__ import annotations

import csv
import json
import random

from _paths import EVAL_ROOT, KO_PII_EVAL_ROOT

random.seed(13)
D = str(EVAL_ROOT)
EVAL = str(KO_PII_EVAL_ROOT)


def jl(p):
    return [json.loads(l) for l in open(p) if l.strip()]


# --- test 누출 방지 ---
test_texts = {r["text"] for r in json.load(open(f"{D}/native_ko_test.json"))}

pos, neg = [], []

# native train (test 제외)
alln = jl(f"{D}/korean_injection_native.jsonl")
for r in alln:
    if r["text"] in test_texts:
        continue
    (pos if r["label"] == 1 else neg).append((r["text"], "native"))

# MT 번역 (oss) — 있으면
import os
if os.path.exists(f"{D}/ko_injections_translated.jsonl"):
    for r in jl(f"{D}/ko_injections_translated.jsonl"):
        if r["text"] not in test_texts:
            pos.append((r["text"], r.get("src", "mt_oss")))

# oss 합성 — 있으면
if os.path.exists(f"{D}/ko_injections_synth_oss.jsonl"):
    for r in jl(f"{D}/ko_injections_synth_oss.jsonl"):
        if r["text"] not in test_texts:
            pos.append((r["text"], r.get("src", "synth_oss")))

# Gemma synth (기존 inj_train label 1) + qtaoa benign(label 0)
for r in jl(f"{D}/inj_train.jsonl"):
    t = r["text"]
    if t in test_texts:
        continue
    (pos if r["label"] == 1 else neg).append((t, r.get("src", "gemma")))

# 다양 한국어 benign 보강 (unsmile clean + kmhas/apeach normal)
us = list(csv.DictReader(open(f"{D}/unsmile_train_v1.0.tsv", encoding="utf-8"), delimiter="\t"))
clean = [(r["문장"], "unsmile_clean") for r in us if r.get("clean") == "1" and r["문장"] not in test_texts]
random.shuffle(clean); neg += clean[:800]
for f, tag in [("tox_kmhas", "kmhas_n"), ("tox_apeach", "apeach_n")]:
    rows = jl(f"{EVAL}/{f}.jsonl")
    nn = [(r["text"], tag) for r in rows if int(r["label"]) == 0 and r["text"] not in test_texts]
    random.shuffle(nn); neg += nn[:300]

# hard-negative (트리거단어 benign)
if os.path.exists(f"{D}/hard_neg.jsonl"):
    for r in jl(f"{D}/hard_neg.jsonl"):
        if r["text"] not in test_texts:
            neg.append((r["text"], "hardneg"))

# dedup (positive/negative 내부)
def dedup(rows):
    seen, out = set(), []
    for t, s in rows:
        if t not in seen:
            seen.add(t); out.append((t, s))
    return out


pos = dedup(pos); neg = dedup(neg)
# positive에 든 텍스트가 negative에도 있으면 negative에서 제거(라벨 충돌 방지)
pset = {t for t, _ in pos}
neg = [(t, s) for t, s in neg if t not in pset]

with open(f"{D}/inj_train_v5.jsonl", "w") as f:
    for t, s in pos:
        f.write(json.dumps({"text": t, "label": 1, "src": s}, ensure_ascii=False) + "\n")
    for t, s in neg:
        f.write(json.dumps({"text": t, "label": 0, "src": s}, ensure_ascii=False) + "\n")

from collections import Counter
print(f"v5 코퍼스: pos={len(pos)} neg={len(neg)} 총 {len(pos)+len(neg)}")
print("pos 출처:", Counter(s.split(':')[0] for _, s in pos))
print("neg 출처:", Counter(s.split(':')[0] for _, s in neg))
