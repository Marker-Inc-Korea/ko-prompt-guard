"""ClassifierReviewer v4 — v3(native+synth) + hard-negative 로 over-defense 완화.

v3 는 native recall 98.6% 지만 NotInject 과탐 95.6%(트리거단어 benign 과탐). NotInject 은
테스트라 학습 불가 → 같은 분포의 hard-negative 를 Gemma 합성(synth_hard_neg.py)해 학습 negative
에 추가. NotInject 은 여전히 held-out 평가.

학습: v3 positives + (v3 negatives + hard_neg + mined). 평가: native_test, deepset, NotInject(held).
출력: inj_clf_v4/final.
"""
from __future__ import annotations

import json
import random

import numpy as np
import torch
from transformers import (AutoModelForSequenceClassification, AutoTokenizer,
                          Trainer, TrainingArguments)

from _paths import EVAL_ROOT, pii_path

random.seed(13)
D = str(EVAL_ROOT)
MODEL = "klue/roberta-base"
DEEPSET = pii_path("deepset_ko.jsonl")


def load(p, tk, lk):
    return [(json.loads(l)[tk], int(json.loads(l)[lk])) for l in open(p) if l.strip()]


# v3 데이터 + hard-negative
base = load(f"{D}/inj_train_v3.jsonl", "text", "label")
hard = [(json.loads(l)["text"], 0) for l in open(f"{D}/hard_neg.jsonl") if l.strip()]
data = base + hard
random.shuffle(data)
nv = int(len(data) * 0.1)
val, train = data[:nv], data[nv:]
nat_test = [(r["text"], r["label"]) for r in json.load(open(f"{D}/native_ko_test.json"))]
deepset = load(DEEPSET, "text_ko", "label")
notinject = [(json.loads(l)["prompt"], 0) for l in open(f"{D}/notinject.jsonl") if l.strip()]
print(f"train={len(train)} (hard-neg {len(hard)} 포함) val={len(val)} "
      f"native_test={len(nat_test)} deepset={len(deepset)} notinject={len(notinject)}")

tok = AutoTokenizer.from_pretrained(MODEL)


class DS(torch.utils.data.Dataset):
    def __init__(s, rows):
        s.y = [l for _, l in rows]; s.e = tok([t for t, _ in rows], truncation=True, max_length=128)
    def __len__(s): return len(s.y)
    def __getitem__(s, i):
        d = {k: v[i] for k, v in s.e.items()}; d["labels"] = s.y[i]; return d


def collate(f):
    y = torch.tensor([x.pop("labels") for x in f]); b = tok.pad(f, padding=True, return_tensors="pt")
    b["labels"] = y; return b


model = AutoModelForSequenceClassification.from_pretrained(MODEL, num_labels=2)
args = TrainingArguments(output_dir=f"{D}/inj_clf_v4", per_device_train_batch_size=16,
                        num_train_epochs=3, learning_rate=2e-5, fp16=True, logging_steps=50,
                        save_strategy="no", report_to=[])
Trainer(model=model, args=args, train_dataset=DS(train), data_collator=collate).train()
model.save_pretrained(f"{D}/inj_clf_v4/final"); tok.save_pretrained(f"{D}/inj_clf_v4/final")


@torch.no_grad()
def P(texts, bs=64):
    model.eval(); o = []
    for i in range(0, len(texts), bs):
        e = tok(texts[i:i+bs], padding=True, truncation=True, max_length=128, return_tensors="pt").to(model.device)
        o.append(torch.softmax(model(**e).logits, -1)[:, 1].cpu().numpy())
    return np.concatenate(o)


def metrics(name, rows, thr=0.5):
    y = np.array([l for _, l in rows]); p = P([t for t, _ in rows]); yp = (p > thr).astype(int)
    tp = int(((yp==1)&(y==1)).sum()); fp = int(((yp==1)&(y==0)).sum())
    fn = int(((yp==0)&(y==1)).sum()); tn = int(((yp==0)&(y==0)).sum())
    rec = tp/(tp+fn)*100 if tp+fn else None; fpr = fp/(fp+tn)*100 if fp+tn else None
    print(f"[{name:16}] recall={None if rec is None else round(rec,1)} FPR={None if fpr is None else round(fpr,1)} (n={len(rows)})")
    return {"recall": rec and round(rec,1), "fpr": fpr and round(fpr,1)}


print("\n=== v4 평가 (v3: native 98.6/FPR5.1, deepset 59.3, NotInject 과탐 95.6) ===")
rep = {"native_test": metrics("native_test", nat_test),
       "deepset": metrics("deepset(MT)", deepset),
       "notinject": metrics("NotInject(과탐)", notinject)}
# NotInject 스윕 (과탐 낮출 threshold 찾기)
ni_p = P([t for t, _ in notinject]); nt_p = P([t for t, _ in nat_test]); nt_y = np.array([l for _, l in nat_test])
print("\n=== threshold 스윕 (native recall vs NotInject 과탐) ===")
sweep = {}
for thr in (0.5, 0.7, 0.9, 0.95):
    yp = (nt_p > thr).astype(int)
    rec = ((yp==1)&(nt_y==1)).sum()/(nt_y==1).sum()*100
    nfpr = (ni_p > thr).mean()*100
    sweep[thr] = {"native_recall": round(rec,1), "notinject_fpr": round(nfpr,1)}
    print(f"  thr={thr}: native recall={rec:.1f} | NotInject 과탐={nfpr:.1f}")
rep["sweep"] = sweep
json.dump(rep, open(f"{D}/inj_train_v4_report.json", "w"), ensure_ascii=False, indent=2)
print("\nsaved → inj_clf_v4/final + inj_train_v4_report.json")
