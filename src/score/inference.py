# === test_model_on_features.py (robust) ===
import argparse, os, io, json, math
import numpy as np
import pandas as pd
from pandas.api.types import is_numeric_dtype

# ---------------- I/O ----------------
parser = argparse.ArgumentParser()
parser.add_argument("--csv", required=True, help="Engineered features CSV (e.g., features_T3.csv)")
parser.add_argument("--model", required=True, help="Trained model (.joblib/.pkl)")
parser.add_argument("--meta", help="Optional meta.json (PRIMARY_P, features)")
args = parser.parse_args()

# ---------------- Safe loaders & resolvers ----------------
def safe_load_model(path_or_bytes):
    if isinstance(path_or_bytes, (bytes, bytearray)):
        raw = path_or_bytes
    else:
        with open(path_or_bytes, "rb") as f:
            raw = f.read()
    bio = io.BytesIO(raw)
    # joblib
    try:
        import joblib
        bio.seek(0); return joblib.load(bio)
    except Exception:
        pass
    # pickle
    try:
        import pickle
        bio.seek(0); return pickle.load(bio)
    except Exception:
        pass
    # cloudpickle
    try:
        import cloudpickle as cp
        bio.seek(0); return cp.load(bio)
    except Exception as e:
        raise RuntimeError("Could not load model with joblib/pickle/cloudpickle.") from e

from sklearn.pipeline import Pipeline
SCORER_ATTRS = ("score_samples","decision_function","predict_proba","kneighbors","predict")
def _is_estimator(x): return any(hasattr(x, a) for a in SCORER_ATTRS)
def _is_pipeline(x):  return isinstance(x, Pipeline) or (getattr(x, "__class__", None).__name__ == "Pipeline" and hasattr(x, "steps"))

def _resolve_from_dict(d):
    est = None; feats = None
    for k in ("model","estimator","pipeline","clf","nn","iforest"):
        if k in d: est = d[k]; break
    for k in ("features","feature_names","feature_list"):
        v = d.get(k)
        if isinstance(v, (list, tuple)) and all(isinstance(s, str) for s in v):
            feats = list(v); break
    return est, feats

def _gather_from_iterable(it):
    transformers, estimator, features = [], None, None
    for x in it:
        if isinstance(x, dict):
            e, f = _resolve_from_dict(x); estimator = estimator or e; features = features or f
        elif isinstance(x, (list, tuple)):
            t2, e2, f2 = _gather_from_iterable(x); transformers += t2; estimator = estimator or e2; features = features or f2
        else:
            if _is_estimator(x): estimator = estimator or x
            elif hasattr(x, "transform"): transformers.append(x)
            elif isinstance(x, (list, tuple)) and all(isinstance(s, str) for s in x): features = features or list(x)
    return transformers, estimator, features

def resolve_artifact_to_model_and_features(artifact):
    """Return (model_like, features_override or None)."""
    # already usable?
    if _is_pipeline(artifact) or _is_estimator(artifact):
        return artifact, None
    # dict?
    if isinstance(artifact, dict):
        est, feats = _resolve_from_dict(artifact)
        if est is not None:
            return est, feats
        transformers, estimator, features = _gather_from_iterable(list(artifact.values()))
    # tuple/list?
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
    """Return (preproc_callable, final_estimator). Identity if not a Pipeline."""
    if not _is_pipeline(model_like):
        return (lambda X: X, model_like)
    steps = model_like.steps or []
    if len(steps) <= 1:
        return (lambda X: X, steps[-1][1] if steps else model_like)
    def _preproc(X):
        Xt = X
        for _, step in steps[:-1]:
            if hasattr(step, "transform"): Xt = step.transform(Xt)
            elif hasattr(step, "fit_transform"): Xt = step.fit_transform(Xt)
        return Xt
    return _preproc, steps[-1][1]

def labels_to_scores(y):
    y = np.asarray(y)
    try:
        return y.astype(float)
    except Exception:
        ys = y.astype(str)
        toks = ("anom","outlier","attack","malicious","fraud","bad","novel")
        return np.array([1.0 if any(t in s.lower() for t in toks) else 0.0 for s in ys], dtype=float)

def infer_scores(model_like, X):
    preproc, est = unwrap_pipeline_for_scoring(model_like)
    Xt = preproc(X)

    # LOF guard
    if est.__class__.__name__ == "LocalOutlierFactor" and not getattr(est, "novelty", False):
        raise RuntimeError("LocalOutlierFactor novelty=False (cannot score unseen data). Retrain with novelty=True.")

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
        return dists.mean(axis=1), "kneighbors → mean distance"
    if hasattr(est, "predict"):
        y = est.predict(Xt)
        return (labels_to_scores(y) if np.asarray(y).dtype.kind in ("U","S","O") else y.astype(float)), "predict"
    raise ValueError("No usable scoring method found on the estimator.")

# ---------------- Load data ----------------
print(f"== Load features: {args.csv} ==")
df = pd.read_csv(args.csv)
print(f"Rows: {len(df):,}  Cols: {len(df.columns)}")

# Default: all numeric columns
feat_list = [c for c in df.columns if is_numeric_dtype(df[c])]
PRIMARY_P = 0.01

# Meta overrides
if args.meta and os.path.exists(args.meta):
    try:
        meta = json.load(open(args.meta, "r", encoding="utf-8"))
        feats_meta = meta.get("features")
        if isinstance(feats_meta, list):
            feat_list = [f for f in feats_meta if f in df.columns]
            print(f"Using features from meta.json ({len(feat_list)})")
        if "PRIMARY_P" in meta:
            PRIMARY_P = float(meta["PRIMARY_P"])
            print(f"PRIMARY_P from meta: {PRIMARY_P}")
    except Exception as e:
        print("Meta load failed:", e)

X = df[feat_list].apply(pd.to_numeric, errors="coerce").to_numpy(dtype=float)

# ---------------- Load model & resolve ----------------
print(f"\n== Load model: {args.model} ==")
artifact = safe_load_model(args.model)
model_like, feats_override = resolve_artifact_to_model_and_features(artifact)

# If artifact carries a feature list, prefer it (but only those present in CSV)
if feats_override:
    feat_from_art = [f for f in feats_override if f in df.columns]
    if feat_from_art:
        feat_list = feat_from_art
        X = df[feat_list].apply(pd.to_numeric, errors="coerce").to_numpy(dtype=float)
        print(f"Using embedded artifact features ({len(feat_list)})")

# ---------------- Inference ----------------
scores, method = infer_scores(model_like, X)
scores = np.asarray(scores, dtype=float).ravel()
print(f"✓ Scored via: {method}")
print(f"min={scores.min():.6f}  max={scores.max():.6f}  mean={scores.mean():.6f}")
print("Head(10):", np.round(scores[:10], 6))

# ---------------- Persist outputs ----------------
df_out = df.copy()
df_out["anomaly_score"] = scores
out_full = "scored_features.csv"
df_out.to_csv(out_full, index=False)

K = max(1, int(math.ceil(max(0.0001, min(1.0, PRIMARY_P)) * len(df_out))))
out_topk = f"topK_features_at_{PRIMARY_P:.3f}pct.csv"
df_out.nlargest(K, "anomaly_score").to_csv(out_topk, index=False)

print(f"\nSaved scored dataset → {out_full}")
print(f"Saved top-K anomalies (K={K}, p={PRIMARY_P:.3f}%) → {out_topk}")
