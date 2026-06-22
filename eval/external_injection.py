"""External-dataset validation for ko-prompt-guard (INPUT-side guard).

The only credible prior result is a normalization ABLATION (+93% recall on the
author's own obfuscation corpus). The end-to-end F1=1.0 in eval/measure.py is
SELF-PLAY: the same author wrote the regex patterns *and* the attack/benign
corpus. This script measures GENERALIZATION on INDEPENDENT public data.

    PYTHONPATH=src python eval/external_injection.py

Datasets (stdlib-only HF datasets-server REST; no datasets/pandas needed):
  - deepset/prompt-injections          (label 1=injection, 0=legit; EN/multiling)
  - xTRam1/safe-guard-prompt-injection (label 1=injection, 0=legit; EN)
  - jason9693/APEACH                   (class 1=toxic, 0=normal; KOREAN benign source)

Metrics:
  recall = fraction of label==1 (true injections) the guard FLAGs or BLOCKs.
  fpr    = fraction of benign (label==0 / Korean normal) the guard FLAGs/BLOCKs.

HONEST FRAMING: this guard is KOREAN-SPECIALIZED. Low recall on English
injections is an EXPECTED limitation (its value-add is Korean obfuscation
normalization, which English text never triggers), NOT proof it is broken. The
load-bearing generalization signal is the BENIGN FPR, especially on real Korean
normal text (APEACH class==0): does it spuriously block ordinary Korean? There
is NO public Korean prompt-injection set, so true Korean injection recall is
UNMEASURED here — stated explicitly, never inferred.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ko_prompt_guard import check, Verdict  # noqa: E402


def _get(url: str, retries: int = 9) -> dict:
    """GET with capped exponential backoff on HTTP 429 (datasets-server limit)."""
    for i in range(retries):
        try:
            return json.load(urllib.request.urlopen(url, timeout=60))
        except urllib.error.HTTPError as e:
            if e.code == 429 and i < retries - 1:
                time.sleep(min(2 ** i, 30))
                continue
            raise
    raise RuntimeError("unreachable")


_CACHE = Path(__file__).resolve().parent / "_extcache"


def fetch(dataset: str, config: str, split: str, n: int = 2000) -> list[dict]:
    # disk cache: independent data is static, avoids hammering datasets-server (429).
    _CACHE.mkdir(exist_ok=True)
    cf = _CACHE / (f"{dataset}__{config}__{split}__{n}".replace("/", "_") + ".json")
    if cf.exists():
        return json.loads(cf.read_text())
    out: list[dict] = []
    off = 0
    ds = urllib.parse.quote(dataset, safe="")
    while len(out) < n:
        u = (
            f"https://datasets-server.huggingface.co/rows?dataset={ds}"
            f"&config={config}&split={split}&offset={off}&length=100"
        )
        d = _get(u)
        rows = [r["row"] for r in d["rows"]]
        if not rows:
            break
        out += rows
        off += len(rows)
        time.sleep(0.3)  # gentle pacing — datasets-server rate-limits aggressively
        if len(rows) < 100:
            break
    out = out[:n]
    cf.write_text(json.dumps(out, ensure_ascii=False))
    return out


def flagged(text: str) -> bool:
    """True if the guard does NOT allow (i.e. FLAG or BLOCK)."""
    if not isinstance(text, str) or not text.strip():
        return False
    return check(text).verdict is not Verdict.ALLOW


def _has_hangul(s: str) -> bool:
    return any("가" <= c <= "힣" or "ᄀ" <= c <= "ᇿ" or
               "㄰" <= c <= "㆏" for c in s)


def evaluate(rows: list[dict], text_key: str, label_key: str,
             positive_label: str) -> dict:
    """Split rows into positives/negatives by label; measure flag rate on each."""
    pos_flag = pos_n = neg_flag = neg_n = 0
    pos_ko_flag = pos_ko_n = neg_ko_flag = neg_ko_n = 0
    pos_miss_samples: list[str] = []
    neg_fp_samples: list[str] = []
    for r in rows:
        text = r.get(text_key)
        if not isinstance(text, str):
            continue
        label = str(r.get(label_key))
        f = flagged(text)
        ko = _has_hangul(text)
        if label == positive_label:
            pos_n += 1
            pos_flag += f
            if ko:
                pos_ko_n += 1
                pos_ko_flag += f
            if not f and len(pos_miss_samples) < 5:
                pos_miss_samples.append(text[:90])
        else:
            neg_n += 1
            neg_flag += f
            if ko:
                neg_ko_n += 1
                neg_ko_flag += f
            if f and len(neg_fp_samples) < 8:
                neg_fp_samples.append(text[:90])
    return {
        "pos_n": pos_n, "pos_flag": pos_flag,
        "neg_n": neg_n, "neg_flag": neg_flag,
        "pos_ko_n": pos_ko_n, "pos_ko_flag": pos_ko_flag,
        "neg_ko_n": neg_ko_n, "neg_ko_flag": neg_ko_flag,
        "pos_miss_samples": pos_miss_samples,
        "neg_fp_samples": neg_fp_samples,
    }


def pct(a: int, b: int) -> str:
    return f"{a}/{b} = {a / b:.1%}" if b else "n/a"


def main() -> None:
    N = 2000
    print("=" * 74)
    print("ko-prompt-guard — EXTERNAL generalization eval (independent data)")
    print("self-play baseline (eval/measure.py): P=1.000 R=1.000 F1=1.000 FPR=0%")
    print("=" * 74)

    results: dict[str, dict] = {}

    # 1+2) Injection datasets: label 1 = injection (positive), 0 = legit (benign).
    for ds in ["deepset/prompt-injections", "xTRam1/safe-guard-prompt-injection"]:
        for split in ["train", "test"]:
            rows = fetch(ds, "default", split, n=N)
            labels = Counter(str(r.get("label")) for r in rows)
            r = evaluate(rows, "text", "label", positive_label="1")
            key = f"{ds}:{split}"
            results[key] = r
            print(f"\n[{key}]  n={len(rows)}  label dist={dict(labels)}")
            print(f"  INJECTION recall (label=1 flagged): {pct(r['pos_flag'], r['pos_n'])}")
            print(f"  BENIGN    fpr    (label=0 flagged): {pct(r['neg_flag'], r['neg_n'])}")
            if r["pos_ko_n"]:
                print(f"    (of which Korean-containing injections: "
                      f"recall {pct(r['pos_ko_flag'], r['pos_ko_n'])})")
            if r["pos_miss_samples"]:
                print(f"  missed-injection sample: {r['pos_miss_samples'][0]!r}")
            if r["neg_fp_samples"]:
                print(f"  benign false-positive sample: {r['neg_fp_samples'][0]!r}")

    # 3) APEACH: Korean text. class 0 = normal (benign). The KEY benign-FPR probe.
    rows = fetch("jason9693/APEACH", "default", "test", n=N)
    labels = Counter(str(r.get("class")) for r in rows)
    # Treat as benign-only test: count flag rate on class==0 (normal Korean).
    ape = evaluate(rows, "text", "class", positive_label="1")  # 1=toxic, 0=normal
    results["jason9693/APEACH:test"] = ape
    print(f"\n[jason9693/APEACH:test]  n={len(rows)}  class dist={dict(labels)}")
    print(f"  KOREAN normal-text fpr (class=0 flagged): {pct(ape['neg_flag'], ape['neg_n'])}")
    print(f"  (toxic-Korean flag rate, class=1 — NOT injection, informational only: "
          f"{pct(ape['pos_flag'], ape['pos_n'])})")
    if ape["neg_fp_samples"]:
        print(f"  Korean-normal false-positive samples: {ape['neg_fp_samples']}")

    # ---- Aggregate the headline numbers across the injection sets ----
    inj_keys = [k for k in results if k.startswith(("deepset", "xTRam1"))]
    tp = sum(results[k]["pos_flag"] for k in inj_keys)
    pos = sum(results[k]["pos_n"] for k in inj_keys)
    fp_inj = sum(results[k]["neg_flag"] for k in inj_keys)
    neg_inj = sum(results[k]["neg_n"] for k in inj_keys)
    # benign FPR aggregate = injection-set legit rows + APEACH normal Korean rows
    fp_all = fp_inj + ape["neg_flag"]
    neg_all = neg_inj + ape["neg_n"]

    recall = tp / pos if pos else 0.0
    fpr = fp_all / neg_all if neg_all else 0.0
    # precision over the injection-set rows only (where we have both classes)
    prec = tp / (tp + fp_inj) if (tp + fp_inj) else 0.0

    print("\n" + "=" * 74)
    print("AGGREGATE (external)")
    print(f"  injection recall (EN/multiling, all injection sets): {tp}/{pos} = {recall:.1%}")
    print(f"  benign FPR (legit injection-set rows + APEACH normal KR): "
          f"{fp_all}/{neg_all} = {fpr:.1%}")
    print(f"  precision (injection sets, both classes present):    {prec:.3f}")
    print("  NOTE: recall is on ENGLISH/multilingual injections; this is a "
          "Korean-specialized\n        guard, so this UNDER-states its intended "
          "(Korean) capability.")
    print("  NOTE: NO public Korean injection set exists — true Korean recall is "
          "UNMEASURED.")
    print("=" * 74)


if __name__ == "__main__":
    main()
