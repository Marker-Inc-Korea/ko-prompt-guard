"""외부 평가셋 다운로드 (datasets-server REST, stdlib만) — 재현용.

- leolee99/NotInject       : 339 트리거단어 benign (과탐/over-defense 평가). NotInject_one/two/three.
- humane-lab/K-HATERS       : native 한국어 hate(2023). test split 균형 샘플(normal vs offensive/hate).

HF_TOKEN 필요(환경변수). 출력: notinject.jsonl / khaters_test.jsonl.
"""
from __future__ import annotations

import json
import os
import random
import urllib.request

TOK = os.environ.get("HF_TOKEN", "")
OUT = "/data1/mk04/eval_external"


def rows(ds, config, split, n=4000):
    out, off = [], 0
    while off < n:
        url = (f"https://datasets-server.huggingface.co/rows?dataset={ds}"
               f"&config={config}&split={split}&offset={off}&length=100")
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {TOK}"})
        d = json.loads(urllib.request.urlopen(req, timeout=30).read())
        rs = [r["row"] for r in d.get("rows", [])]
        if not rs:
            break
        out += rs
        off += len(rs)
        if len(rs) < 100:
            break
    return out


def main():
    # NotInject (전부 benign)
    ni = []
    for sp in ["NotInject_one", "NotInject_two", "NotInject_three"]:
        ni += [{"prompt": x["prompt"], "split": sp} for x in rows("leolee99/NotInject", "default", sp)]
    with open(f"{OUT}/notinject.jsonl", "w") as f:
        for x in ni:
            f.write(json.dumps(x, ensure_ascii=False) + "\n")
    print(f"NotInject: {len(ni)} (benign)")

    # K-HATERS test → 균형 샘플
    kh = rows("humane-lab/K-HATERS", "default", "test", n=4000)
    norm = [x for x in kh if x["label"] == "normal"]
    tox = [x for x in kh if x["label"] != "normal"]
    random.seed(1); random.shuffle(norm); random.shuffle(tox)
    m = min(len(norm), len(tox), 500)
    sample = ([{"text": x["text"], "label": 0} for x in norm[:m]]
              + [{"text": x["text"], "label": 1} for x in tox[:m]])
    random.shuffle(sample)
    with open(f"{OUT}/khaters_test.jsonl", "w") as f:
        for x in sample:
            f.write(json.dumps(x, ensure_ascii=False) + "\n")
    print(f"K-HATERS: {len(sample)} (balanced)")


if __name__ == "__main__":
    main()
