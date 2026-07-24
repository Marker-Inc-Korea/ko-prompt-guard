"""ClassifierReviewer 재학습 v2 — 도메인밖 과탐(over-defense) 완화.

기존 inj_clf 는 negative 가 의료(qtaoa)뿐이라 일반 한국어 benign 을 과탐(deepset FPR 82%,
NotInject 100%). v2 는 negative 를 **다양한 한국어 benign**(의료+unsmile clean+kmhas/apeach
normal+일반 번역프롬프트, 2271)으로 확장. positive 는 동일 synth 공격(721, deepset과 무관).

자연 불균형(1:3)이 분류기를 보수적으로 만들어 FPR↓ 기대. 평가: deepset(신종 held-out, recall+FPR)
+ NotInject(과탐 over-defense) + in-dist val. 출력: inj_clf_v2/final.
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
TRAIN = f"{D}/inj_train_v2.jsonl"
DEEPSET = pii_path("deepset_ko.jsonl")
NOTINJECT = f"{D}/notinject.jsonl"


def load_jsonl(p, tk, lk):
    return [(json.loads(l)[tk], int(json.loads(l)[lk])) for l in open(p) if l.strip()]


data = load_jsonl(TRAIN, "text", "label")
random.shuffle(data)
nv = int(len(data) * 0.12)
val, train = data[:nv], data[nv:]
deepset = load_jsonl(DEEPSET, "text_ko", "label")
notinject = [(json.loads(l)["prompt"], 0) for l in open(NOTINJECT) if l.strip()]  # 전부 benign
print(f"train={len(train)} val={len(val)} deepset={len(deepset)} notinject={len(notinject)}")

tok = AutoTokenizer.from_pretrained(MODEL)


class DS(torch.utils.data.Dataset):
    def __init__(s, rows):
        s.x = [t for t, _ in rows]; s.y = [l for _, l in rows]; s.e = tok(s.x, truncation=True, max_length=128)
    def __len__(s): return len(s.y)
    def __getitem__(s, i):
        d = {k: v[i] for k, v in s.e.items()}; d["labels"] = s.y[i]; return d


def collate(f):
    labels = torch.tensor([x.pop("labels") for x in f]); b = tok.pad(f, padding=True, return_tensors="pt")
    b["labels"] = labels; return b


model = AutoModelForSequenceClassification.from_pretrained(MODEL, num_labels=2)
args = TrainingArguments(output_dir=f"{D}/inj_clf_v2", per_device_train_batch_size=16,
                        num_train_epochs=3, learning_rate=2e-5, fp16=True, logging_steps=50,
                        save_strategy="no", report_to=[])
Trainer(model=model, args=args, train_dataset=DS(train), data_collator=collate).train()
model.save_pretrained(f"{D}/inj_clf_v2/final"); tok.save_pretrained(f"{D}/inj_clf_v2/final")


@torch.no_grad()
def predict(texts, bs=64):
    model.eval(); o = []
    for i in range(0, len(texts), bs):
        e = tok(texts[i:i+bs], padding=True, truncation=True, max_length=128, return_tensors="pt").to(model.device)
        o.append(torch.softmax(model(**e).logits, -1)[:, 1].cpu().numpy())
    return np.concatenate(o)


def metrics(name, rows, thr=0.5):
    y = np.array([l for _, l in rows]); p = predict([t for t, _ in rows]); yp = (p > thr).astype(int)
    tp = int(((yp==1)&(y==1)).sum()); fp = int(((yp==1)&(y==0)).sum())
    fn = int(((yp==0)&(y==1)).sum()); tn = int(((yp==0)&(y==0)).sum())
    rec = tp/(tp+fn)*100 if tp+fn else None; fpr = fp/(fp+tn)*100 if fp+tn else None
    print(f"[{name:16}] recall={rec if rec is None else round(rec,1)} FPR={fpr if fpr is None else round(fpr,1)} (n={len(rows)})")
    return {"recall": None if rec is None else round(rec,1), "fpr": None if fpr is None else round(fpr,1)}


print("\n=== v2 평가 (기존 inj_clf: deepset recall 99.6/FPR 82, NotInject FPR 100) ===")
rep = {"in_dist_val": metrics("in-dist val", val),
       "deepset_novel": metrics("deepset(신종)", deepset),
       "notinject_overdefense": metrics("NotInject(과탐)", notinject)}
json.dump(rep, open(f"{D}/inj_train_v2_report.json", "w"), ensure_ascii=False, indent=2)
print("\nsaved → inj_clf_v2/final + inj_train_v2_report.json")
