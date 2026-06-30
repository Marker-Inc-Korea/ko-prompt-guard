"""v6 코퍼스 = v5(4495) + v6 타겟 합성(문맥혼동 hard-neg + 간접공격 pos)."""
import json
D="/data1/mk04/eval_external"
test_texts={r["text"] for r in json.load(open(f"{D}/native_ko_test.json"))}
def jl(p): return [json.loads(l) for l in open(p) if l.strip()]
rows=jl(f"{D}/inj_train_v5.jsonl")
for f in ["v6_hardneg.jsonl","v6_pos.jsonl"]:
    import os
    if os.path.exists(f"{D}/{f}"):
        for r in jl(f"{D}/{f}"):
            if r["text"] not in test_texts: rows.append(r)
# dedup + 라벨충돌 제거
seen={}; 
for r in rows:
    seen[r["text"]]=r  # 마지막 라벨 우선(v6가 뒤라 타겟 라벨 반영)
rows=list(seen.values())
with open(f"{D}/inj_train_v6.jsonl","w") as fo:
    for r in rows: fo.write(json.dumps(r,ensure_ascii=False)+"\n")
from collections import Counter
print(f"v6 코퍼스: {len(rows)} 라벨{Counter(r['label'] for r in rows)}")
