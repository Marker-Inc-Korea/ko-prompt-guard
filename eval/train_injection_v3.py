"""ClassifierReviewer v3 — native-KO 인젝션을 학습 positive 로 추가, 37% 한계 재검.

가설: v2 의 deepset recall 37% 한계는 synth(Gemma) positive ↔ 테스트 분포 격차 때문.
이제 native-KO 인젝션(xxxjjhhh, 281 train)을 positive 에 추가하면 깨지는가?

학습: positives = native_train(281) + synth(721), negatives = 다양한 한국어 benign(2257,
ko_inj_benign 제외). 평가:
  · native_test (130 held-out) — 핵심: native 분포 recall
  · deepset_ko (MT cross-dist) — 일반화
  · NotInject (over-defense FPR)
임계값 스윕(native_test) 포함. 출력: inj_clf_v3/final.
"""
from __future__ import annotations

import json
import random

import numpy as np
import torch
from transformers import (AutoModelForSequenceClassification, AutoTokenizer,
                          Trainer, TrainingArguments)

random.seed(13)
D = "/data1/mk04/eval_external"
MODEL = "klue/roberta-base"
DEEPSET = "/data1/mk04/projects/ko-pii/experiments/ko-output-guard/eval/external/deepset_ko.jsonl"


def load(p, tk, lk):
    return [(json.loads(l)[tk], int(json.loads(l)[lk])) for l in open(p) if l.strip()]


data = load(f"{D}/inj_train_v3.jsonl", "text", "label")
random.shuffle(data)
nv = int(len(data) * 0.1)
val, train = data[:nv], data[nv:]
nat_test = [(r["text"], r["label"]) for r in json.load(open(f"{D}/native_ko_test.json"))]
deepset = load(DEEPSET, "text_ko", "label")
notinject = [(json.loads(l)["prompt"], 0) for l in open(f"{D}/notinject.jsonl") if l.strip()]
print(f"train={len(train)} val={len(val)} native_test={len(nat_test)} deepset={len(deepset)} notinject={len(notinject)}")

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
args = TrainingArguments(output_dir=f"{D}/inj_clf_v3", per_device_train_batch_size=16,
                        num_train_epochs=3, learning_rate=2e-5, fp16=True, logging_steps=50,
                        save_strategy="no", report_to=[])
Trainer(model=model, args=args, train_dataset=DS(train), data_collator=collate).train()
model.save_pretrained(f"{D}/inj_clf_v3/final"); tok.save_pretrained(f"{D}/inj_clf_v3/final")


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
    f1 = (2*tp/(2*tp+fp+fn)*100) if (2*tp+fp+fn) else None
    print(f"[{name:16}] recall={None if rec is None else round(rec,1)} FPR={None if fpr is None else round(fpr,1)} F1={None if f1 is None else round(f1,1)} (n={len(rows)})")
    return {"recall": rec and round(rec,1), "fpr": fpr and round(fpr,1), "f1": f1 and round(f1,1)}


print("\n=== v3 평가 (v1: deepset 99.6/FPR82, v2: deepset 37/FPR0; 룰 native 40.3) ===")
rep = {"in_dist_val": metrics("in-dist val", val),
       "native_test": metrics("native_test", nat_test),
       "deepset_novel": metrics("deepset(MT)", deepset),
       "notinject": metrics("NotInject(과탐)", notinject)}

print("\n=== native_test 임계값 스윕 ===")
nt_t = [t for t, _ in nat_test]; nt_y = np.array([l for _, l in nat_test]); nt_p = P(nt_t)
ni_p = P([t for t, _ in notinject])
sweep = {}
for thr in (0.3, 0.5, 0.7, 0.9):
    yp = (nt_p > thr).astype(int)
    tp = int(((yp==1)&(nt_y==1)).sum()); fp = int(((yp==1)&(nt_y==0)).sum())
    fn = int(((yp==0)&(nt_y==1)).sum()); tn = int(((yp==0)&(nt_y==0)).sum())
    rec = tp/(tp+fn)*100 if tp+fn else 0; fpr = fp/(fp+tn)*100 if fp+tn else 0
    nfpr = (ni_p > thr).mean()*100
    sweep[thr] = {"native_recall": round(rec,1), "native_fpr": round(fpr,1), "notinject_fpr": round(nfpr,1)}
    print(f"  thr={thr}: native recall={rec:.1f} FPR={fpr:.1f} | NotInject 과탐={nfpr:.1f}")
rep["native_sweep"] = sweep
json.dump(rep, open(f"{D}/inj_train_v3_report.json", "w"), ensure_ascii=False, indent=2)
print("\nsaved → inj_clf_v3/final + inj_train_v3_report.json")
