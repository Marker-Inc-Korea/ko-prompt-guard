"""ko-injection-guard v5 — 대규모 다출처 한국어 인젝션 분류기 (공개 준비용).

학습: inj_train_v6.jsonl (native train + MT번역(oss) + oss합성 + Gemma synth positives,
다양 한국어 benign + hard-neg negatives). base=klue/roberta-base.
평가: native_test(130 held-out) + deepset(MT) + KO over-defense(합성 holdout + corpus mined).
출력: ko_injection_guard_v6/final (+ 리포트). 공개 모델 카드용 메트릭 생성.
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
OUTDIR = f"{D}/ko_injection_guard_v6"


def jl(p, tk, lk):
    return [(json.loads(l)[tk], int(json.loads(l)[lk])) for l in open(p) if l.strip()]


data = jl(f"{D}/inj_train_v6.jsonl", "text", "label")
random.shuffle(data)
nv = int(len(data) * 0.1)
val, train = data[:nv], data[nv:]
nat_test = [(r["text"], r["label"]) for r in json.load(open(f"{D}/native_ko_test.json"))]
deepset = jl(DEEPSET, "text_ko", "label")
import os
ovd_mined = [(json.loads(l)["text"], 0) for l in open(f"{D}/ko_overdefense_test.jsonl")] if os.path.exists(f"{D}/ko_overdefense_test.jsonl") else []
from collections import Counter
print(f"train={len(train)} val={len(val)} | 라벨 {Counter(l for _,l in train)}")
print(f"native_test={len(nat_test)} deepset={len(deepset)} over-defense_mined={len(ovd_mined)}")

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
args = TrainingArguments(output_dir=OUTDIR, per_device_train_batch_size=32, num_train_epochs=3,
                        learning_rate=2e-5, fp16=True, logging_steps=50, save_strategy="no", report_to=[])
Trainer(model=model, args=args, train_dataset=DS(train), data_collator=collate).train()
model.save_pretrained(f"{OUTDIR}/final"); tok.save_pretrained(f"{OUTDIR}/final")


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
    f1 = 2*tp/(2*tp+fp+fn)*100 if (2*tp+fp+fn) else None
    print(f"[{name:18}] recall={None if rec is None else round(rec,1)} FPR={None if fpr is None else round(fpr,1)} F1={None if f1 is None else round(f1,1)} (n={len(rows)})")
    return {"recall": rec and round(rec,1), "fpr": fpr and round(fpr,1), "f1": f1 and round(f1,1)}


print("\n=== v6 평가 (v4: native 94.4/FPR1.7, deepset 69.2, KO over-defense 0) ===")
rep = {"base_model": MODEL, "train_size": len(train), "label_dist": dict(Counter(l for _,l in train)),
       "in_dist_val": metrics("in-dist val", val),
       "native_test": metrics("native_test(held)", nat_test),
       "deepset_mt": metrics("deepset(MT)", deepset)}
if ovd_mined:
    rep["ko_overdefense_mined"] = metrics("KO over-defense", ovd_mined)
# native_test 임계값 스윕
nt_t=[t for t,_ in nat_test]; nt_y=np.array([l for _,l in nat_test]); nt_p=P(nt_t)
sweep={}
for thr in (0.3,0.5,0.7,0.9):
    yp=(nt_p>thr).astype(int)
    rec=((yp==1)&(nt_y==1)).sum()/(nt_y==1).sum()*100; fpr=((yp==1)&(nt_y==0)).sum()/(nt_y==0).sum()*100
    sweep[thr]={"recall":round(rec,1),"fpr":round(fpr,1)}
rep["native_sweep"]=sweep
json.dump(rep, open(f"{D}/v6_report.json","w"), ensure_ascii=False, indent=2)
print(f"\nsaved → {OUTDIR}/final + v6_report.json")
