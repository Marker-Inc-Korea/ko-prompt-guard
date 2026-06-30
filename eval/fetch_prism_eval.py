"""prismdata/guardrail-ko-11class-dataset → 외부 일반화 평가셋 추출 (학습 미사용).

INJECTION/SAFE 라벨만 추출해 balanced 3000 외부 평가셋. v6 가 학습 안 한 별개 분포에
99.9% recall → 작은 native test 과적합이 아님을 검증. GPL-3.0 데이터(학습 비추천, 평가용).
HF_HOME 설정 후: python fetch_prism_eval.py
"""
import os, json, glob, random
from huggingface_hub import snapshot_download
import pyarrow.parquet as pq
random.seed(7)
p = snapshot_download("prismdata/guardrail-ko-11class-dataset", repo_type="dataset", allow_patterns=["*.parquet"])
rows = []
for f in glob.glob(p + "/**/*.parquet", recursive=True):
    rows += pq.read_table(f).to_pylist()
inj = [r["text"] for r in rows if r.get("label") == "INJECTION"]
safe = [r["text"] for r in rows if r.get("label") == "SAFE"]
random.shuffle(inj); random.shuffle(safe)
out = [{"text": t, "label": 1} for t in inj[:1500]] + [{"text": t, "label": 0} for t in safe[:1500]]
random.shuffle(out)
with open("prism_ext_test.jsonl", "w") as fo:
    for x in out:
        fo.write(json.dumps(x, ensure_ascii=False) + "\n")
print(f"prism 외부평가셋: {len(out)} (INJECTION 138K / SAFE 97K 중 balanced 3000)")
