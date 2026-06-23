"""Opt-in semantic reviewers — implement the ``SemanticReviewer`` seam (semantic.py).

The deterministic ``check()`` stays pure (no ML, no network). It catches obfuscated
and *explicit* injection/jailbreak patterns at high precision but misses *semantic*
attacks (role-play, hypothetical framing, novel paraphrase) — external injection
sets show rule recall ~17% at 0% FPR. ``EmbeddingReviewer`` closes that gap: encode
the (de-obfuscated) input with an embedding model and score risk by similarity to a
set of known-attack anchors. Hybrid (rule OR reviewer) reaches ~91% recall at <1%
FPR in-distribution (see README "하이브리드"). Advisory by design — use as a FLAG
layer, never the sole gate.

The embedding backend is *injectable* (``encode=``) so the logic is unit-testable
without ML deps. The default backend (bge-m3) requires ``pip install
ko-prompt-guard[embedding]`` (torch + transformers) and is imported lazily.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from pathlib import Path

from .result import Category, GuardResult, Severity, Verdict, Violation

# encode(list[str]) -> 2D float array (n, d) of L2-normalized embeddings.
Encoder = Callable[[Sequence[str]], "list[list[float]]"]

_ANCHOR_FILE = Path(__file__).resolve().parent / "data" / "injection_anchors.json"


def default_anchors() -> list[str]:
    """Bundled representative injection/jailbreak anchors (EN + KO, family-diverse).

    Hand-authored attack *patterns* (not dataset excerpts) — license-free. Extend
    with your own red-team corpus via ``EmbeddingReviewer(anchors=...)`` for higher
    novel-attack recall.
    """
    return list(json.loads(_ANCHOR_FILE.read_text("utf-8"))["anchors"])


def _cosine_topk_mean(vec: list[float], mat: list[list[float]], k: int) -> float:
    # vec, mat rows assumed L2-normalized → dot product == cosine. Pure-python so the
    # reviewer's scoring logic needs no numpy; the *encoder* may use numpy/torch.
    sims = [sum(a * b for a, b in zip(vec, row)) for row in mat]
    if not sims:
        return 0.0
    sims.sort(reverse=True)
    k = max(1, min(k, len(sims)))
    return sum(sims[:k]) / k


class EmbeddingReviewer:
    """``SemanticReviewer``: risk = top-k cosine similarity to known-attack anchors.

    Parameters
    ----------
    anchors:  known-attack texts; defaults to the bundled set.
    encode:   embedding backend ``(list[str]) -> normalized vectors``. If None, a
              lazy bge-m3 backend is built on first use (needs the ``embedding`` extra).
    top_k:    average the k highest anchor similarities (k>1 is steadier than max).
    model:    HF model id for the default backend.
    """

    def __init__(
        self,
        anchors: Sequence[str] | None = None,
        *,
        encode: Encoder | None = None,
        top_k: int = 3,
        model: str = "BAAI/bge-m3",
        max_length: int = 256,
    ) -> None:
        self.anchors: list[str] = list(anchors) if anchors is not None else default_anchors()
        if not self.anchors:
            raise ValueError("EmbeddingReviewer needs at least one anchor")
        self.top_k = top_k
        self._model = model
        self._max_length = max_length
        self._encode = encode
        self._anchor_emb: list[list[float]] | None = None

    def _ensure(self) -> None:
        if self._encode is None:
            self._encode = make_bge_encoder(self._model, max_length=self._max_length)
        if self._anchor_emb is None:
            self._anchor_emb = [list(map(float, v)) for v in self._encode(self.anchors)]

    def review(self, text: str, deterministic_result: GuardResult | None = None) -> float:
        """0..1 risk for ``text`` (use the de-obfuscated ``normalized_text`` if available)."""
        if not isinstance(text, str) or not text.strip():
            return 0.0
        self._ensure()
        assert self._encode is not None and self._anchor_emb is not None
        vec = list(map(float, self._encode([text])[0]))
        risk = _cosine_topk_mean(vec, self._anchor_emb, self.top_k)
        return max(0.0, min(1.0, risk))


def make_bge_encoder(
    model: str = "BAAI/bge-m3",
    *,
    device: str | None = None,
    max_length: int = 256,
    batch_size: int = 64,
) -> Encoder:
    """Lazy bge-m3 encoder → L2-normalized dense (CLS) embeddings. Needs torch+transformers.

    Kept out of import path so ``import ko_prompt_guard`` stays ML-free; only building
    a reviewer with the *default* backend pulls these in.
    """
    try:
        import torch
        from transformers import AutoModel, AutoTokenizer
    except ImportError as e:  # pragma: no cover - exercised only without the extra
        raise ImportError(
            "EmbeddingReviewer's default backend needs torch+transformers: "
            "pip install ko-prompt-guard[embedding] (or pass your own encode=...)."
        ) from e

    dev = device or ("cuda" if torch.cuda.is_available() else "cpu")
    tok = AutoTokenizer.from_pretrained(model)
    net = AutoModel.from_pretrained(model).eval().to(dev)

    @torch.no_grad()
    def encode(texts: Sequence[str]) -> list[list[float]]:
        out: list[list[float]] = []
        texts = list(texts)
        for i in range(0, len(texts), batch_size):
            b = texts[i : i + batch_size]
            enc = tok(b, padding=True, truncation=True, max_length=max_length,
                      return_tensors="pt").to(dev)
            h = net(**enc).last_hidden_state[:, 0]            # CLS = bge-m3 dense
            h = torch.nn.functional.normalize(h, dim=-1)
            out.extend(h.float().cpu().tolist())
        return out

    return encode


def hybrid_check(
    text: str,
    reviewer: EmbeddingReviewer,
    *,
    threshold: float = 0.62,
    context: str | None = None,
) -> GuardResult:
    """Deterministic ``check()`` + advisory reviewer, combined into one GuardResult.

    If rules already FLAG/BLOCK, returns that untouched (reviewer not called — fast
    path). Otherwise scores the normalized text; if ``risk > threshold`` upgrades a
    SAFE result to **FLAG** (advisory) with a SEMANTIC violation carrying the score.
    Never hard-BLOCKs on the reviewer alone (semantic.py contract).
    """
    from .guard import check

    r = check(text, context)
    if r.verdict is not Verdict.ALLOW:
        return r
    risk = reviewer.review(r.normalized_text or text, r)
    if risk <= threshold:
        return r
    v = Violation(
        code="semantic_similarity",
        category=Category.SEMANTIC,
        severity=Severity.MEDIUM,
        reason=f"semantic similarity to known attacks (risk={risk:.2f} > {threshold})",
    )
    return r.model_copy(update={"verdict": Verdict.FLAG, "violations": r.violations + (v,)})
