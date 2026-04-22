#!/usr/bin/env python3
"""
Portable model-scorer for engineered Wazuh feature CSVs.

Loads a serialised anomaly-detection artifact (joblib / pickle / cloudpickle),
resolves it to an sklearn-compatible estimator or pipeline even if nested
inside a dict or list, infers per-row anomaly scores, and writes:

  - `scored_features.csv`               : full input + `anomaly_score` column
  - `topK_features_at_<pct>pct.csv`     : Top-K rows at the operating p%

Usage:
  python src/score/inference.py \
    --csv data/splits/T3_feat.csv \
    --model artifacts/knn.joblib \
    --meta  artifacts/knn.meta.json
"""

import argparse
import io
import json
import math
import os

import numpy as np
import pandas as pd
from pandas.api.types import is_numeric_dtype
from sklearn.pipeline import Pipeline


SCORER_ATTRS = ("score_samples", "decision_function", "predict_proba", "kneighbors", "predict")


# ---------------------------------------------------------------------------
# Robust model loading
# ---------------------------------------------------------------------------

def safe_load_model(path_or_bytes):
    """Load a serialised model via joblib -> pickle -> cloudpickle in that order."""
    if isinstance(path_or_bytes, (bytes, bytearray)):
        raw = path_or_bytes
    else:
        with open(path_or_bytes, "rb") as f:
            raw = f.read()
    buf = io.BytesIO(raw)

    for loader_name in ("joblib", "pickle", "cloudpickle"):
        try:
            module = __import__(loader_name)
            buf.seek(0)
            return module.load(buf)
        except Exception:
            continue
    raise RuntimeError("Could not load model with joblib/pickle/cloudpickle.")


def _is_estimator(x) -> bool:
    return any(hasattr(x, attr) for attr in SCORER_ATTRS)


def _is_pipeline(x) -> bool:
    return isinstance(x, Pipeline) or (
        getattr(x, "__class__", None).__name__ == "Pipeline" and hasattr(x, "steps")
    )


def _resolve_from_dict(d):
    est = None
    feats = None
    for k in ("model", "estimator", "pipeline", "clf", "nn", "iforest"):
        if k in d:
            est = d[k]
            break
    for k in ("features", "feature_names", "feature_list"):
        v = d.get(k)
        if isinstance(v, (list, tuple)) and all(isinstance(s, str) for s in v):
            feats = list(v)
            break
    return est, feats


def _gather_from_iterable(items):
    transformers = []
    estimator = None
    features = None
    for x in items:
        if isinstance(x, dict):
            e, f = _resolve_from_dict(x)
            estimator = estimator or e
            features = features or f
        elif isinstance(x, (list, tuple)):
            t2, e2, f2 = _gather_from_iterable(x)
            transformers += t2
            estimator = estimator or e2
            features = features or f2
        elif _is_estimator(x):
            estimator = estimator or x
        elif hasattr(x, "transform"):
            transformers.append(x)
    return transformers, estimator, features


def resolve_artifact_to_model_and_features(artifact):
    """Return (model_like, features_override_or_None) from a loaded artifact."""
    if _is_pipeline(artifact) or _is_estimator(artifact):
        return artifact, None

    if isinstance(artifact, dict):
        est, feats = _resolve_from_dict(artifact)
        if est is not None:
            return est, feats
        transformers, estimator, features = _gather_from_iterable(list(artifact.values()))
    elif isinstance(artifact, (list, tuple)):
        transformers, estimator, features = _gather_from_iterable(artifact)
    else:
        raise RuntimeError(f"Unsupported artifact type: {type(artifact).__name__}")

    if estimator is None:
        raise RuntimeError("Artifact does not contain a usable estimator.")
    if transformers:
        steps = [(f"pre{i+1}", t) for i, t in enumerate(transformers)] + [("est", estimator)]
        return Pipeline(steps), features
    return estimator, features


def unwrap_pipeline_for_scoring(model_like):
    """Return (preproc_callable, final_estimator) for any estimator or Pipeline."""
    if not _is_pipeline(model_like):
        return (lambda X: X, model_like)
    steps = model_like.steps or []
    if len(steps) <= 1:
        return (lambda X: X, steps[-1][1] if steps else model_like)

    def _preproc(X):
        Xt = X
        for _, step in steps[:-1]:
            if hasattr(step, "transform"):
                Xt = step.transform(Xt)
            elif hasattr(step, "fit_transform"):
                Xt = step.fit_transform(Xt)
        return Xt

    return _preproc, steps[-1][1]


def labels_to_scores(y):
    """Coerce arbitrary predict() output into a numeric score vector."""
    y = np.asarray(y)
    try:
        return y.astype(float)
    except (TypeError, ValueError):
        pass
    tokens = ("anom", "outlier", "attack", "malicious", "fraud", "bad", "novel")
    return np.array(
        [1.0 if any(tok in str(label).lower() for tok in tokens) else 0.0 for label in y],
        dtype=float,
    )


def infer_scores(model_like, X):
    """Produce an anomaly score per row, plus a tag describing how the score was derived."""
    preproc, est = unwrap_pipeline_for_scoring(model_like)
    Xt = preproc(X)

    # LOF guard: without novelty=True, LOF can only score the training data.
    if est.__class__.__name__ == "LocalOutlierFactor" and not getattr(est, "novelty", False):
        raise RuntimeError(
            "LocalOutlierFactor was trained with novelty=False, so it cannot score "
            "unseen data. Retrain with novelty=True."
        )

    if hasattr(est, "score_samples"):
        return -est.score_samples(Xt), "score_samples (inverted)"
    if hasattr(est, "decision_function"):
        return -est.decision_function(Xt), "decision_function (inverted)"
    if hasattr(est, "predict_proba"):
        proba = est.predict_proba(Xt)
        if proba.shape[1] == 2:
            return proba[:, 1], "predict_proba[:,1]"
    if hasattr(est, "kneighbors"):
        dists, _ = est.kneighbors(Xt)
        return dists.mean(axis=1), "kneighbors -> mean distance"
    if hasattr(est, "predict"):
        y = est.predict(Xt)
        y = np.asarray(y)
        if y.dtype.kind in ("U", "S", "O"):
            return labels_to_scores(y), "predict (labels_to_scores)"
        return y.astype(float), "predict (numeric)"
    raise ValueError("No usable scoring method found on the estimator.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--csv", required=True, help="Engineered features CSV (e.g. T3_feat.csv)")
    parser.add_argument("--model", required=True, help="Trained model (.joblib/.pkl)")
    parser.add_argument("--meta", help="Optional meta.json with 'features' and/or 'PRIMARY_P'")
    args = parser.parse_args()

    print(f"== Load features: {args.csv} ==")
    df = pd.read_csv(args.csv)
    print(f"Rows: {len(df):,}  Cols: {len(df.columns)}")

    feat_list = [c for c in df.columns if is_numeric_dtype(df[c])]
    primary_p = 0.01

    if args.meta and os.path.exists(args.meta):
        try:
            with open(args.meta, "r", encoding="utf-8") as f:
                meta = json.load(f)
            if isinstance(meta.get("features"), list):
                feat_list = [f for f in meta["features"] if f in df.columns]
                print(f"Using features from meta.json ({len(feat_list)})")
            if "PRIMARY_P" in meta:
                primary_p = float(meta["PRIMARY_P"])
                print(f"PRIMARY_P from meta: {primary_p}")
        except (OSError, ValueError) as err:
            print(f"Meta load failed: {err}")

    X = df[feat_list].apply(pd.to_numeric, errors="coerce").to_numpy(dtype=float)

    print(f"\n== Load model: {args.model} ==")
    artifact = safe_load_model(args.model)
    model_like, feats_override = resolve_artifact_to_model_and_features(artifact)

    if feats_override:
        embedded = [f for f in feats_override if f in df.columns]
        if embedded:
            feat_list = embedded
            X = df[feat_list].apply(pd.to_numeric, errors="coerce").to_numpy(dtype=float)
            print(f"Using embedded artifact features ({len(feat_list)})")

    scores, method = infer_scores(model_like, X)
    scores = np.asarray(scores, dtype=float).ravel()
    print(f"[OK] Scored via: {method}")
    print(f"min={scores.min():.6f}  max={scores.max():.6f}  mean={scores.mean():.6f}")
    print("Head(10):", np.round(scores[:10], 6))

    df_out = df.copy()
    df_out["anomaly_score"] = scores
    out_full = "scored_features.csv"
    df_out.to_csv(out_full, index=False)

    k = max(1, int(math.ceil(max(0.0001, min(1.0, primary_p)) * len(df_out))))
    out_topk = f"topK_features_at_{primary_p:.3f}pct.csv"
    df_out.nlargest(k, "anomaly_score").to_csv(out_topk, index=False)

    print(f"\nSaved scored dataset -> {out_full}")
    print(f"Saved top-K anomalies (K={k}, p={primary_p:.3f}%) -> {out_topk}")


if __name__ == "__main__":
    main()
