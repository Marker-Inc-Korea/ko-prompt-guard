"""task #14 GPU — EN 인젝션 가드 + 자사 분류기를 prompt_eval_sets 전체에 추론.

ner_env(torch+transformers)에서 실행. ko-prompt-guard 룰(pydantic)은 ner_env에 없으므로
별도 CPU 스텝(bench_prompt_score.py)에서. 여기선 P(injection)만 뽑아 저장.

  · meta-llama/Prompt-Guard-86M : 3클래스 {0 BENIGN,1 INJECTION,2 JAILBREAK} → P=P1+P2
  · protectai/deberta-v3-base-prompt-injection-v2 : {0 SAFE,1 INJECTION} → P=P1
  · inj_clf/final (자사 ClassifierReviewer 백본) : {0,1} → P=P1
출력: prompt_preds_gpu.json = {variant: {model: [P,...]}, _labels: {variant:[...]}}
"""
from __future__ import annotations

import json

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

SETS = "/data1/mk04/eval_external/prompt_eval_sets.json"
OUT = "/data1/mk04/eval_external/prompt_preds_gpu.json"
MODELS = {
    "prompt_guard_86m": ("meta-llama/Prompt-Guard-86M", "multi"),     # v1: P1+P2
    "prompt_guard_2_86m": ("project-free-llama/Llama-Prompt-Guard-2-86M", "binary1"),  # v2(2025)=LlamaFirewall 엔진, binary P1
    "qualifire_sentinel": ("qualifire/prompt-injection-sentinel", "binary1"),  # ModernBERT 2025 SOTA, {0 benign,1 jailbreak}
    "protectai_deberta": ("protectai/deberta-v3-base-prompt-injection-v2", "binary1"),
    "ko_classifier": ("/data1/mk04/eval_external/inj_clf_v4/final", "binary1"),
}
DEV = "cuda" if torch.cuda.is_available() else "cpu"


@torch.no_grad()
def pinj(model_dir, mode, texts, bs=32):
    tok = AutoTokenizer.from_pretrained(model_dir, use_fast=True)
    net = AutoModelForSequenceClassification.from_pretrained(model_dir).eval().to(DEV)
    out = []
    for i in range(0, len(texts), bs):
        b = texts[i:i + bs]
        enc = tok(b, padding=True, truncation=True, max_length=256, return_tensors="pt").to(DEV)
        p = torch.softmax(net(**enc).logits, -1).cpu()
        if mode == "multi":          # INJECTION + JAILBREAK
            out.extend((p[:, 1] + p[:, 2:].sum(-1)).tolist() if p.shape[1] > 2 else p[:, 1].tolist())
        else:                         # binary: class 1
            out.extend(p[:, 1].tolist())
    del net
    torch.cuda.empty_cache()
    return out


def main():
    sets = json.load(open(SETS))
    preds = {"_labels": {}}
    for variant, rows in sets.items():
        texts = [t for t, _ in rows]
        preds["_labels"][variant] = [y for _, y in rows]
        preds[variant] = {}
        for key, (md, mode) in MODELS.items():
            preds[variant][key] = pinj(md, mode, texts)
        print(f"[{variant}] done (n={len(texts)})", flush=True)
    json.dump(preds, open(OUT, "w"))
    print(f"saved → {OUT}")


if __name__ == "__main__":
    main()
