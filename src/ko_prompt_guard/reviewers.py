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
    sims = [sum(a * b for a, b in zip(vec, row, strict=False)) for row in mat]
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

    def encode(texts: Sequence[str]) -> list[list[float]]:
        out: list[list[float]] = []
        texts = list(texts)
        with torch.no_grad():
            for i in range(0, len(texts), batch_size):
                b = texts[i : i + batch_size]
                enc = tok(
                    b,
                    padding=True,
                    truncation=True,
                    max_length=max_length,
                    return_tensors="pt",
                ).to(dev)
                h = net(**enc).last_hidden_state[:, 0]  # CLS = bge-m3 dense
                h = torch.nn.functional.normalize(h, dim=-1)
                out.extend(h.float().cpu().tolist())
        return out

    return encode


# scorer(list[str]) -> list[float], 각 텍스트의 P(injection) (0..1).
Scorer = Callable[[Sequence[str]], "list[float]"]


class ClassifierReviewer:
    """``SemanticReviewer``: risk = fine-tuned 분류기의 P(injection).

    ``EmbeddingReviewer`` (anchor 유사도) 는 in-distribution 91% 지만 *신종*(전혀 다른
    분포의 cross-dataset) 에서 recall ~25%. 다양한 공격 *기법*을 합성해 학습한
    klue/roberta 분류기는 신종 held-out(deepset) recall **~99.6%** 로 일반화가 크게
    낫다. 다만 학습 negative 도메인 밖 정상문에선 precision 이 낮아질 수 있어 **advisory
    FLAG** 로(룰의 정밀도와 결합) 쓴다. 배포 도메인의 정상문을 negative 로 충분히 학습하고
    threshold 를 그 도메인 FPR 로 정할 것.

    ``scorer`` 주입으로 ML 없이 단위테스트 가능. 기본 backend 는 lazy torch+transformers.
    가중치는 bring-your-own(레시피만 배포). 사용:

        from ko_prompt_guard.reviewers import ClassifierReviewer, hybrid_check
        rv = ClassifierReviewer("/path/inj_clf/final", threshold=0.9)
        r = hybrid_check(user_input, rv, threshold=0.9)
    """

    def __init__(
        self,
        model_dir: str | None = None,
        *,
        scorer: Scorer | None = None,
        positive_index: int = 1,
        max_length: int = 128,
    ) -> None:
        if scorer is None and model_dir is None:
            raise ValueError("ClassifierReviewer needs model_dir= or scorer=")
        self._model_dir = model_dir
        self._positive_index = positive_index
        self._max_length = max_length
        self._scorer = scorer

    def _ensure(self) -> None:
        if self._scorer is None:
            assert self._model_dir is not None
            self._scorer = make_roberta_classifier(
                self._model_dir, positive_index=self._positive_index, max_length=self._max_length
            )

    def review(self, text: str, deterministic_result: GuardResult | None = None) -> float:
        """0..1 injection 확률 (de-obfuscated ``normalized_text`` 사용 권장)."""
        if not isinstance(text, str) or not text.strip():
            return 0.0
        self._ensure()
        assert self._scorer is not None
        return max(0.0, min(1.0, float(self._scorer([text])[0])))


def make_roberta_classifier(
    model_dir: str,
    *,
    device: str | None = None,
    positive_index: int = 1,
    max_length: int = 128,
    batch_size: int = 64,
) -> Scorer:
    """Lazy 시퀀스 분류기 backend → 각 텍스트의 P(positive). Needs torch+transformers.

    ``import ko_prompt_guard`` 를 ML-free 로 유지하려 import 경로 밖에 둔다.
    """
    try:
        import torch
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
        )
    except ImportError as e:  # pragma: no cover
        raise ImportError(
            "ClassifierReviewer's default backend needs torch+transformers: "
            "pip install ko-prompt-guard[embedding] (or pass your own scorer=...)."
        ) from e

    dev = device or ("cuda" if torch.cuda.is_available() else "cpu")
    tok = AutoTokenizer.from_pretrained(model_dir)
    net = AutoModelForSequenceClassification.from_pretrained(model_dir).eval().to(dev)

    def score(texts: Sequence[str]) -> list[float]:
        out: list[float] = []
        texts = list(texts)
        with torch.no_grad():
            for i in range(0, len(texts), batch_size):
                b = texts[i : i + batch_size]
                enc = tok(
                    b,
                    padding=True,
                    truncation=True,
                    max_length=max_length,
                    return_tensors="pt",
                ).to(dev)
                p = torch.softmax(net(**enc).logits, dim=-1)[:, positive_index]
                out.extend(p.float().cpu().tolist())
        return out

    return score


def hybrid_check(
    text: str,
    reviewer: EmbeddingReviewer | ClassifierReviewer,
    *,
    threshold: float = 0.62,
    context: str | None = None,
) -> GuardResult:
    """Deterministic ``check()`` + advisory reviewer, combined into one GuardResult.

    ``reviewer`` 는 ``SemanticReviewer`` 면 무엇이든(EmbeddingReviewer/ClassifierReviewer).

    If rules already FLAG/BLOCK, returns that untouched (reviewer not called — fast
    path). Otherwise scores the normalized text; if ``risk > threshold`` upgrades a
    SAFE result to **FLAG** (advisory) with a SEMANTIC violation carrying the score.
    Never hard-BLOCKs on the reviewer alone (semantic.py contract).

    ``context`` (검색문서·도구출력 등 비-사용자 콘텐츠)가 주어지면 ``scan_context`` 로 간접
    프롬프트 인젝션을 함께 스캔해, 오염되면 advisory **FLAG** 로 접고 그 신호를 violations 에
    합친다(컨텍스트만으로 hard-BLOCK 하지 않음).
    """
    from .guard import check, scan_context

    # NOTE: 이전엔 check(text, context) 로 호출해 context 가 policy 슬롯에 들어가 크래시(또는
    # 무시)되는 dead/footgun 파라미터였다. 이제 scan_context 로 실제 배선한다.
    r = check(text)
    ctx_pi: tuple[Violation, ...] = ()
    if context is not None:
        cs = scan_context(context)
        if cs.poisoned:
            ctx_pi = cs.violations

    if r.verdict is not Verdict.ALLOW:
        # 룰이 이미 잡았으면 그대로 — 단 context 오염 신호가 있으면 합쳐 반환.
        return r.model_copy(update={"violations": r.violations + ctx_pi}) if ctx_pi else r

    risk = reviewer.review(r.normalized_text or text, r)
    if risk <= threshold and not ctx_pi:
        return r
    new_viol = r.violations + ctx_pi
    if risk > threshold:
        new_viol = new_viol + (
            Violation(
                code="semantic_similarity",
                category=Category.SEMANTIC,
                severity=Severity.MEDIUM,
                reason=f"semantic similarity to known attacks (risk={risk:.2f} > {threshold})",
            ),
        )
    return r.model_copy(update={"verdict": Verdict.FLAG, "violations": new_viol})
