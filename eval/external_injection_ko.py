"""Korean prompt-injection eval via machine-translation PROXY.

There is no public *native* Korean prompt-injection dataset, so Korean injection recall
would otherwise be unmeasured. This translates third-party English injection benchmarks
(deepset, xTRam1) to Korean with a dedicated MT endpoint and measures ko-prompt-guard on
the Korean text.

Why MT (not an LLM): a translation engine renders the adversarial payloads VERBATIM. An
LLM translator tends to refuse or sanitize injection/jailbreak prompts, corrupting the proxy.

⚠️ PROXY caveat: results depend on MT fidelity and are NOT native Korean. This is a measured,
caveated lower bound — translation can also smooth out the exact Korean instruction-override
surface the deterministic guard keys on, so recall here is conservative.

    PYTHONPATH=src python eval/external_injection_ko.py
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ko_prompt_guard import Verdict, check  # noqa: E402

CACHE = Path(__file__).resolve().parent / "_cache"
TX = CACHE / "ko_tx.json"


def _get(url: str, retries: int = 8) -> dict:
    for i in range(retries):
        try:
            return json.load(urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}), timeout=30))
        except urllib.error.HTTPError as e:
            if e.code == 429 and i < retries - 1:
                time.sleep(min(2 ** i, 20))
                continue
            raise
    raise RuntimeError("unreachable")


def fetch_rows(dataset: str, split: str, n: int) -> list[dict]:
    CACHE.mkdir(exist_ok=True)
    cf = CACHE / (dataset.replace("/", "_") + f"__{split}.json")
    if cf.exists():
        return json.loads(cf.read_text())
    out: list[dict] = []
    off = 0
    ds = urllib.parse.quote(dataset)
    while off < n:
        d = _get(f"https://datasets-server.huggingface.co/rows?dataset={ds}&config=default&split={split}&offset={off}&length=100")
        rows = [r["row"] for r in d.get("rows", [])]
        if not rows:
            break
        out += rows
        off += len(rows)
        if len(rows) < 100:
            break
    cf.write_text(json.dumps(out, ensure_ascii=False))
    return out


_tx: dict[str, str] = json.loads(TX.read_text()) if TX.exists() else {}


def translate(text: str) -> str | None:
    if text in _tx:
        return _tx[text]
    q = urllib.parse.quote(text[:1800])
    for i in range(6):
        try:
            d = _get(f"https://translate.googleapis.com/translate_a/single?client=gtx&sl=en&tl=ko&dt=t&q={q}")
            ko = "".join(seg[0] for seg in d[0] if seg[0])
            _tx[text] = ko
            return ko
        except Exception:  # noqa: BLE001
            time.sleep(min(2 ** i, 20))
    return None


def _flagged(t: str) -> bool:
    return check(t).verdict is not Verdict.ALLOW


def main() -> None:
    inj, ben = [], []
    plan = [
        ("deepset/prompt-injections", "train", 2000, "label", "1"),
        ("deepset/prompt-injections", "test", 2000, "label", "1"),
        ("xTRam1/safe-guard-prompt-injection", "test", 700, "label", "1"),
    ]
    seen: set[str] = set()
    done = 0
    for ds, split, n, lk, pos in plan:
        for r in fetch_rows(ds, split, n):
            en = r.get("text") or r.get("prompt")
            if not en or en in seen:
                continue
            seen.add(en)
            ko = translate(en)
            if not ko:
                continue
            (inj if str(r.get(lk)) == pos else ben).append(ko)
            done += 1
            if done % 50 == 0:
                TX.write_text(json.dumps(_tx, ensure_ascii=False))
            time.sleep(0.12)
    TX.write_text(json.dumps(_tx, ensure_ascii=False))
    ir = sum(_flagged(t) for t in inj)
    br = sum(_flagged(t) for t in ben)
    print(f"KO injection recall (MT proxy): {ir}/{len(inj)} = {ir / max(len(inj), 1):.4f}")
    print(f"KO benign FPR       (MT proxy): {br}/{len(ben)} = {br / max(len(ben), 1):.4f}")


if __name__ == "__main__":
    main()
