"""task #10b — 한국어 프롬프트-인젝션 분류기 (klue/roberta-base) 학습 + 신종 일반화 평가.

학습: inj_train.jsonl (Gemma 합성 공격 721 + qtaoa benign 921), in-dist val 분리.
**신종(held-out) 테스트**: deepset_ko.jsonl (학습에 절대 미사용, 전혀 다른 분포) —
  EmbeddingReviewer 가 이 분포에서 25% 였던 것 대비, 분류기가 얼마나 일반화하는지가 핵심.

출력: inj_clf/final (모델) + inj_train_report.json (in-dist + deepset 신종 metric).
실행(GPU sbatch): HF_HOME=$KO_GUARD_EVAL_ROOT/.cache/huggingface python train_injection.py
"""
from __future__ import annotations

import json
import random

import numpy as np
import torch
import torch.nn.functional as Fnn
from transformers import (AutoModelForSequenceClassification, AutoTokenizer,
                          Trainer, TrainingArguments)

from _paths import EVAL_ROOT, pii_path

random.seed(13)
D = str(EVAL_ROOT)
MODEL = "klue/roberta-base"
TRAIN = f"{D}/inj_train.jsonl"
DEEPSET = pii_path("deepset_ko.jsonl")


def load_jsonl(p, tkey, lkey):
    out = []
    for line in open(p):
        if line.strip():
            r = json.loads(line)
            out.append((r[tkey], int(r[lkey])))
    return out


# --- 데이터 ---
data = load_jsonl(TRAIN, "text", "label")
random.shuffle(data)
n_val = int(len(data) * 0.12)
val = data[:n_val]
train = data[n_val:]
deepset = load_jsonl(DEEPSET, "text_ko", "label")  # 신종 held-out
print(f"train={len(train)} val={len(val)} deepset(신종)={len(deepset)} "
      f"(pos {sum(l for _,l in deepset)}/{len(deepset)})")

tok = AutoTokenizer.from_pretrained(MODEL)


class DS(torch.utils.data.Dataset):
    def __init__(s, rows):
        s.x = [t for t, _ in rows]
        s.y = [l for _, l in rows]
        s.e = tok(s.x, truncation=True, max_length=128)

    def __len__(s):
        return len(s.y)

    def __getitem__(s, i):
        d = {k: v[i] for k, v in s.e.items()}
        d["labels"] = s.y[i]
        return d


def collate(feats):
    labels = torch.tensor([f.pop("labels") for f in feats])
    batch = tok.pad(feats, padding=True, return_tensors="pt")
    batch["labels"] = labels
    return batch


model = AutoModelForSequenceClassification.from_pretrained(MODEL, num_labels=2)
args = TrainingArguments(output_dir=f"{D}/inj_clf", per_device_train_batch_size=16,
                        num_train_epochs=3, learning_rate=2e-5, fp16=True,
                        logging_steps=50, save_strategy="no", report_to=[])
trn = Trainer(model=model, args=args, train_dataset=DS(train), data_collator=collate)
trn.train()
model.save_pretrained(f"{D}/inj_clf/final")
tok.save_pretrained(f"{D}/inj_clf/final")


@torch.no_grad()
def predict(texts, bs=64):
    model.eval()
    out = []
    for i in range(0, len(texts), bs):
        e = tok(texts[i:i + bs], padding=True, truncation=True, max_length=128, return_tensors="pt").to(model.device)
        p = torch.softmax(model(**e).logits, -1)[:, 1].cpu().numpy()
        out.append(p)
    return np.concatenate(out)


def metrics(name, rows, thr=0.5):
    texts = [t for t, _ in rows]
    y = np.array([l for _, l in rows])
    p = predict(texts)
    yp = (p > thr).astype(int)
    tp = int(((yp == 1) & (y == 1)).sum()); fp = int(((yp == 1) & (y == 0)).sum())
    fn = int(((yp == 0) & (y == 1)).sum()); tn = int(((yp == 0) & (y == 0)).sum())
    rec = tp / (tp + fn) * 100 if tp + fn else 0
    prec = tp / (tp + fp) * 100 if tp + fp else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    fpr = fp / (fp + tn) * 100 if fp + tn else 0
    print(f"[{name:16}] F1={f1:5.1f} recall={rec:5.1f} precision={prec:5.1f} FPR={fpr:5.1f} (n={len(rows)})")
    return {"f1": f1, "recall": rec, "precision": prec, "fpr": fpr, "n": len(rows)}


print("\n=== 평가 ===")
rep = {"in_dist_val": metrics("in-dist val", val),
       "deepset_novel": metrics("deepset(신종)", deepset)}
rep["note"] = "EmbeddingReviewer 는 deepset(신종)에서 recall ~25% — 분류기 deepset recall 과 비교"
json.dump(rep, open(f"{D}/inj_train_report.json", "w"), ensure_ascii=False, indent=2)
print("\nsaved → inj_train_report.json + inj_clf/final")
