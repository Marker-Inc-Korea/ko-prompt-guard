"""gpt-oss-120b (vLLM, SLURM) OpenAI 호환 클라이언트 — 데이터 합성/번역용.

endpoint.txt(서빙 sbatch가 기록)에서 base URL 자동 로드. oss-120b 는 OpenAI chat 포맷.
의존성 0(urllib). 로그인 노드는 compute 호스트명 미해석 → IP 치환.
"""
from __future__ import annotations

import json
import urllib.request
from concurrent.futures import ThreadPoolExecutor

EP_FILE = "/data1/mk04/eval_external/oss_endpoint.txt"
MODEL = "openai/gpt-oss-120b"


def endpoint() -> str:
    base = open(EP_FILE).read().strip()
    return base.replace("marker-ThinkStation-P620", "192.168.0.193")


def chat(messages, max_tokens=512, temperature=0.0, base=None, timeout=180) -> str:
    base = base or endpoint()
    body = {"model": MODEL, "messages": messages, "max_tokens": max_tokens, "temperature": temperature}
    req = urllib.request.Request(
        base + "/chat/completions",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())["choices"][0]["message"]["content"]


def ping(base=None) -> dict:
    base = base or endpoint()
    with urllib.request.urlopen(base + "/models", timeout=10) as r:
        return json.loads(r.read())


def map_concurrent(fn, items, workers=8):
    with ThreadPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(fn, items))
