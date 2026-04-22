#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wazuh Anomaly Scoring — Gradio (single process) + Explainability

Purpose of this UI:
- Visualize the ML model's data-processing pipeline & inference results,
  and demonstrate them when needed during thesis writing (NOT a production UI).
"""

import os, io, json, math, zipfile
from typing import List, Optional, Tuple

import numpy as np
import pandas as pd
from pandas.api.types import is_numeric_dtype
import matplotlib.pyplot as plt
import gradio as gr

# =========================== Helpers: model loading ===========================

def safe_load_model(model_bytes_or_path):
    """
    Robust loader: joblib -> pickle -> cloudpickle.
    Accepts raw bytes or filesystem path.
    """
    if isinstance(model_bytes_or_path, (bytes, bytearray)):
        raw = model_bytes_or_path
    else:
        with open(model_bytes_or_path, "rb") as f:
            raw = f.read()
    bio = io.BytesIO(raw)

    # joblib
    try:
        import joblib
        bio.seek(0)
        return joblib.load(bio)
    except Exception:
        pass

    # pickle
    try:
        import pickle
        bio.seek(0)
        return pickle.load(bio)
    except Exception:
        pass

    # cloudpickle
    try:
        import cloudpickle as cp
        bio.seek(0)
        return cp.load(bio)
    except Exception as e:
        raise RuntimeError(
            "Could not load model with joblib/pickle/cloudpickle. "
            "Re-save it with joblib in the training environment."
        ) from e


from sklearn.pipeline import Pipeline
SCORER_ATTRS = ("score_samples","decision_function","predict_proba","kneighbors","predict")

def _is_estimator(x) -> bool:
    return any(hasattr(x, a) for a in SCORER_ATTRS)

def _is_pipeline(x) -> bool:
    return isinstance(x, Pipeline) or (getattr(x, "__class__", None).__name__ == "Pipeline" and hasattr(x, "steps"))

def _resolve_from_dict(d):
    est = None; feats = None
    for k in ("model","estimator","pipeline","clf","nn","iforest"):
        if k in d:
            est = d[k]; break
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
            elif isinstance(x, (list, tuple)) and all(isinstance(s, str) for s in x):
                features = features or list(x)
    return transformers, estimator, features

def resolve_artifact_to_model_and_features(artifact):
    """
    Return (model_like, features_override or None).
    Accepts: estimator, Pipeline, dict, tuple/list (possibly nested).
    If we find transformers + estimator, build a temporary Pipeline.
    """
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
    """Return (preproc_callable, final_estimator). Identity if not a Pipeline."""
    if not _is_pipeline(model_like):
        return (lambda X: X, model_like)
    steps = model_like.steps or []
    if len(steps) <= 1:
        return (lambda X: X, steps[-1][1] if steps else model_like)
    def _preproc(X_df: pd.DataFrame):
        Xt = X_df
        for _, step in steps[:-1]:
            if hasattr(step, "transform"):
                Xt = step.transform(Xt)
            elif hasattr(step, "fit_transform"):
                Xt = step.fit_transform(Xt)
        return Xt
    return _preproc, steps[-1][1]

def labels_to_scores(y):
    y = np.asarray(y)
    try:
        return y.astype(float)
    except Exception:
        ys = y.astype(str)
        toks = ("anom","outlier","attack","malicious","fraud","bad","novel")
        return np.array([1.0 if any(t in s.lower() for s in [ys_i] for t in toks) else 0.0 for ys_i in ys], dtype=float)

def infer_scores(model_like, X_df: pd.DataFrame):
    """
    Score with the final estimator:
      - kNN → mean distance
      - score_samples / decision_function (inverted)
      - predict_proba[:,1] for binary classifiers
      - predict → numeric or mapped labels
    """
    preproc, est = unwrap_pipeline_for_scoring(model_like)
    Xt = preproc(X_df)

    # LOF guard
    if est.__class__.__name__ == "LocalOutlierFactor" and not getattr(est, "novelty", False):
        raise RuntimeError("LocalOutlierFactor novelty=False (cannot score unseen data). Retrain with novelty=True.")

    if hasattr(est, "kneighbors"):
        dists, _ = est.kneighbors(Xt)
        return dists.mean(axis=1), "kneighbors_mean_distance"

    if hasattr(est, "score_samples"):
        return -est.score_samples(Xt), "score_samples_inverted"

    if hasattr(est, "decision_function"):
        return -est.decision_function(Xt), "decision_function_inverted"

    if hasattr(est, "predict_proba"):
        proba = est.predict_proba(Xt)
        if proba.shape[1] == 2:
            return proba[:, 1], "predict_proba[:,1]"

    if hasattr(est, "predict"):
        y = est.predict(Xt)
        y = np.asarray(y)
        if y.dtype.kind in ("U","S","O"):
            return labels_to_scores(y), "predict_labels_to_scores"
        return y.astype(float), "predict_float"

    raise ValueError("Could not derive anomaly scores from the provided model.")


# ============================ Canonicalization & FE ============================

CANON = ["event_id", "timestamp", "agent", "rule_id", "rule_level", "decoder"]
CANDIDATES = {
    "event_id":  ["event_id", "_id", "id"],
    "timestamp": ["timestamp", "_source.timestamp", "@timestamp", "_source.@timestamp"],
    "agent":     ["agent", "_source.agent.name", "_source.agent.id", "agent.name", "agent.id"],
    "rule_id":   ["rule_id", "_source.rule.id", "rule.id"],
    "rule_level":["rule_level", "_source.rule.level", "rule.level"],
    "decoder":   ["decoder", "_source.decoder.name", "decoder.name"],
}

def _first_present(df: pd.DataFrame, names: List[str]) -> Optional[str]:
    for n in names:
        if n in df.columns:
            return n
    return None

def _to_ts(s: pd.Series) -> pd.Series:
    ts = pd.to_datetime(s, format="%b %d, %Y @ %H:%M:%S.%f", errors="coerce", utc=True)
    miss = ts.isna()
    if miss.any():
        ts2 = pd.to_datetime(s[miss], errors="coerce", utc=True)
        ts.loc[miss] = ts2
    return ts

def normalize_to_canon(df_raw: pd.DataFrame) -> Tuple[pd.DataFrame, dict, list]:
    mapping = {k: _first_present(df_raw, CANDIDATES[k]) for k in CANON}

    event_id = (df_raw[mapping["event_id"]].astype("string")
                if mapping["event_id"] else df_raw.index.astype(str).astype("string"))

    if mapping["timestamp"] is None:
        raise ValueError("No timestamp-like column found. Provide '_source.timestamp' or 'timestamp'.")
    ts = _to_ts(df_raw[mapping["timestamp"]])

    if mapping["agent"] is None:
        raise ValueError("No agent-like column found. Provide '_source.agent.name' or 'agent'.")
    agent = df_raw[mapping["agent"]].astype("string")

    if mapping["rule_id"] is None:
        raise ValueError("No rule_id-like column found. Provide '_source.rule.id' or 'rule_id'.")
    rule_id = df_raw[mapping["rule_id"]].astype("string")

    if mapping["rule_level"] is None:
        raise ValueError("No rule_level-like column found. Provide '_source.rule.level' or 'rule_level'.")
    rule_level = pd.to_numeric(df_raw[mapping["rule_level"]], errors="coerce").astype("Float64")

    if mapping["decoder"] is None:
        raise ValueError("No decoder-like column found. Provide '_source.decoder.name' or 'decoder'.")
    decoder = df_raw[mapping["decoder"]].astype("string")

    out = pd.DataFrame({
        "event_id": event_id,
        "timestamp": ts,
        "agent": agent,
        "rule_id": rule_id,
        "rule_level": rule_level,
        "decoder": decoder
    })

    out = out.dropna(subset=["timestamp"]).reset_index(drop=True)
    out = out.drop_duplicates(subset=["event_id"], keep="first")

    return out, mapping, []


import hashlib  # <-- make sure this import exists

def engineer_features(df: pd.DataFrame) -> Tuple[pd.DataFrame, list]:
    """
    Thesis features with parity to the notebook:
    - keeps existing engineered features
    - ADDS: seconds_in_hour_bucketed, agent_rule_hour_hash01, agent_rule_hour_freq_log1p, recency_x_rule_level
    """
    g = df.copy()

    # --- time basics (no timezone conversion) ---
    g["ts_local"] = g["timestamp"]
    g["hour_local"] = g["ts_local"].dt.hour.astype(int)
    g["day_of_week"] = g["ts_local"].dt.dayofweek.astype(int)  # Mon=0
    g["is_weekend"] = (g["day_of_week"] >= 5).astype(int)
    g["is_off_hours"] = g["hour_local"].isin(list(range(0, 7))).astype(int)

    # second within hour, and a bucketed version (minute bucket: 0..59)
    g["second_in_hour"] = g["ts_local"].dt.minute * 60 + g["ts_local"].dt.second
    g["seconds_in_hour_bucketed"] = (g["second_in_hour"] // 60).astype(int)

    # 2-hour bucket (0,2,4,...,22)
    g["hour_bucket"] = (np.floor(g["hour_local"] / 2.0) * 2).astype(int)

    # --- host-relative level z-score ---
    mu = g.groupby("agent", dropna=False)["rule_level"].transform("mean")
    sd = g.groupby("agent", dropna=False)["rule_level"].transform("std").fillna(0.0)
    sd = sd.replace(0, np.nan)
    g["rule_level_z_host"] = ((g["rule_level"] - mu) / sd).fillna(0.0)

    # --- host recency features ---
    g = g.sort_values(["agent", "timestamp"])
    g["rule_time_since_last_host"] = g.groupby("agent", dropna=False)["timestamp"].diff().dt.total_seconds()
    g["rule_time_since_last_host"] = g["rule_time_since_last_host"].fillna(
        g["rule_time_since_last_host"].median()
    ).clip(lower=0)
    g["rule_time_since_last_host_log1p"] = np.log1p(g["rule_time_since_last_host"])

    # Crosses
    g["offhours_x_rule_level"]   = g["is_off_hours"] * g["rule_level"].astype(float)
    g["offhours_x_rule_level_z"] = g["is_off_hours"] * g["rule_level_z_host"]
    g["weekend_x_rule_level_z"]  = g["is_weekend"]   * g["rule_level_z_host"]

    # NEW: recency × rule_level
    g["recency_x_rule_level"] = g["rule_time_since_last_host_log1p"] * g["rule_level"].astype(float)

    # --- combo features on (agent, rule_id, hour_bucket) ---
    combo = (
        g["agent"].astype(str)
        + "||"
        + g["rule_id"].astype(str)
        + "||"
        + g["hour_bucket"].astype(str)
    )

    # NEW: stable hash ∈ [0,1] for the combo
    def _hash01(s: str) -> float:
        h = hashlib.blake2b(s.encode("utf-8"), digest_size=8).hexdigest()  # 64-bit hex
        v = int(h, 16) & ((1 << 32) - 1)  # lower 32 bits
        return v / float((1 << 32) - 1)

    g["agent_rule_hour_hash01"] = combo.apply(_hash01).astype(float)

    # NEW: frequency of the combo (log1p)
    freq = combo.value_counts()                             # Series: combo -> count
    g["agent_rule_hour_freq_log1p"] = np.log1p(combo.map(freq).astype(float))

    # --- default feature list (parity with training) ---
    FEATURES_DEFAULT = [
        # time & calendar
        "hour_local", "is_off_hours", "day_of_week", "is_weekend",
        "second_in_hour", "seconds_in_hour_bucketed", "hour_bucket",

        # rule intensity & recency
        "rule_level", "rule_level_z_host", "rule_time_since_last_host_log1p",
        "recency_x_rule_level",

        # crosses
        "offhours_x_rule_level", "offhours_x_rule_level_z", "weekend_x_rule_level_z",

        # combo embeddings
        "agent_rule_hour_hash01", "agent_rule_hour_freq_log1p",
    ]
    return g, FEATURES_DEFAULT

# ================================ Explainability ================================

def parse_features_json(text: Optional[str]) -> Optional[list]:
    if not text:
        return None
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and "features" in obj and isinstance(obj["features"], list):
            if all(isinstance(s, str) for s in obj["features"]):
                return obj["features"]
        if isinstance(obj, list) and all(isinstance(s, str) for s in obj):
            return obj
    except Exception:
        return None
    return None


def occlusion_contributions(model_like, X_df: pd.DataFrame, baseline_series: pd.Series) -> np.ndarray:
    """
    Occlusion using the SAME scoring path (preprocessing included inside infer_scores).
    contrib_j = score(x) - score(x with feature j := baseline_j)
    """
    base_scores, _ = infer_scores(model_like, X_df)
    contrib = np.zeros((len(X_df), X_df.shape[1]), dtype=float)
    for j, col in enumerate(X_df.columns):
        X_mod = X_df.copy()
        X_mod[col] = baseline_series[col]
        scores_mod, _ = infer_scores(model_like, X_mod)
        contrib[:, j] = base_scores - scores_mod
    return contrib


def build_explain_outputs(df_top: pd.DataFrame, feat_list, contrib: np.ndarray, baseline_series: pd.Series, out_dir: str):
    """
    Save long-form CSV (alert × feature × contribution) and per-alert bar charts (Top-10 features).
    Return (csv_path or None, zip_path or None, [img_paths]).
    """
    X_top = df_top[feat_list]
    rows = []
    for i, (_, r) in enumerate(df_top.iterrows()):
        for j, f in enumerate(feat_list):
            rows.append({
                "rank": int(r.get("rank", i+1)),
                "event_id": r.get("event_id", ""),
                "agent": r.get("agent", ""),
                "score": float(r.get("score", np.nan)),
                "feature": f,
                "value": float(pd.to_numeric(X_top.iloc[i][f], errors="coerce")),
                "baseline": float(pd.to_numeric(baseline_series[f], errors="coerce")),
                "contribution": float(contrib[i, j]),
                "abs_contribution": float(abs(contrib[i, j])),
            })
    df_long = pd.DataFrame(rows).sort_values(["rank", "abs_contribution"], ascending=[True, False])

    os.makedirs(out_dir, exist_ok=True)
    contrib_csv = os.path.join(out_dir, "explanations_top_slice.csv")
    df_long.to_csv(contrib_csv, index=False)

    # Per-alert bar charts
    img_paths = []
    for rnk in sorted(df_long["rank"].unique()):
        sub = df_long[df_long["rank"] == rnk].nlargest(10, "abs_contribution")
        plt.figure(figsize=(8, 4.5))
        plt.barh(sub["feature"], sub["contribution"])
        plt.title(f"Top 10 feature contributions — rank {rnk} (event_id={sub.iloc[0]['event_id']})")
        plt.xlabel("contribution to anomaly score (+ raises, − lowers)")
        plt.gca().invert_yaxis()
        fpath = os.path.join(out_dir, f"explain_rank_{rnk}.png")
        plt.tight_layout()
        plt.savefig(fpath, bbox_inches="tight")
        plt.close()
        img_paths.append(fpath)

    zip_path = None
    if img_paths:
        zip_path = os.path.join(out_dir, "explain_charts.zip")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
            for p in img_paths:
                z.write(p, arcname=os.path.basename(p))

    return contrib_csv, zip_path, img_paths


# ================================== Pipeline ==================================

def _pct_str(pct_float: float) -> str:
    """Format a percent value (e.g., 1.0) → '1', 1.25 → '1.25'."""
    s = f"{pct_float:.3f}"
    s = s.rstrip("0").rstrip(".")
    return s

def pipeline_run(input_csv_path: str,
                 model_ref: Optional[str],
                 features_json_path: Optional[str],
                 top_p_percent: float,
                 do_explain: bool = True,
                 explain_top_n: int = 10):
    """
    Return 8 outputs (file paths or None) + gallery list:
      cleaned_preview.csv, features_preview.csv,
      scored_full.csv, top_slice.csv, score_hist.png,
      explanations_top_slice.csv, explain_charts.zip,
      [image paths].
    """
    # Load data
    try:
        raw = pd.read_csv(input_csv_path)
    except Exception as e:
        raise RuntimeError(f"Failed to read CSV '{input_csv_path}': {e}")

    # Canonicalize & engineer
    clean, _, _ = normalize_to_canon(raw)
    with_feats, default_feats = engineer_features(clean)

    # Feature selection (start with default)
    feat_list = list(default_feats)

    # Option 1: from features.json
    if features_json_path:
        try:
            with open(features_json_path, "r", encoding="utf-8") as f:
                feats_text = f.read()
            user_feats = parse_features_json(feats_text)
            if user_feats:
                filtered = [f for f in user_feats if f in with_feats.columns and is_numeric_dtype(with_feats[f])]
                if filtered:
                    feat_list = filtered
        except Exception:
            pass

    # Initialize outputs (must be None if missing for Gradio)
    scored_full_path = None
    top_slice_path   = None
    hist_path        = None
    explain_csv_path = None
    explain_zip_path = None
    explain_imgs     = []

    # Optional inference
    if model_ref:
        # Load artifact and resolve to model + (optional) embedded features
        artifact = safe_load_model(model_ref)
        model_like, feats_override = resolve_artifact_to_model_and_features(artifact)

        # If artifact carries a feature list, prefer it
        if feats_override:
            filtered = [f for f in feats_override if f in with_feats.columns and is_numeric_dtype(with_feats[f])]
            if filtered:
                feat_list = filtered

        # Build X as DataFrame (preserve names for transformers)
        X_df = with_feats[feat_list].copy()
        for c in X_df.columns:
            X_df[c] = pd.to_numeric(X_df[c], errors="coerce")

        scores, method = infer_scores(model_like, X_df)
        with_feats["score"] = np.asarray(scores, dtype=float)

        # Top p%
        p = max(0.0001, min(100.0, top_p_percent))  # p as percent (0.01..100)
        k = max(1, int(math.ceil((p / 100.0) * len(with_feats))))
        top_df = with_feats.nlargest(k, "score").copy()
        top_df["rank"] = np.arange(1, len(top_df) + 1)

        out_dir = "outputs"
        os.makedirs(out_dir, exist_ok=True)

        # Save scored and slice
        pct_str = _pct_str(p)
        scored_full_path = os.path.join(out_dir, "scored_full.csv")
        top_slice_path   = os.path.join(out_dir, f"top_{k}_at_{pct_str}pct.csv")
        with_feats.to_csv(scored_full_path, index=False)
        top_df.to_csv(top_slice_path, index=False)

        # Histogram
        if "score" in with_feats.columns:
            plt.figure()
            with_feats["score"].dropna().hist(bins=50)
            plt.title(f"Anomaly score distribution (method={method})")
            plt.xlabel("score"); plt.ylabel("count")
            hist_path = os.path.join(out_dir, "score_hist.png")
            plt.savefig(hist_path, bbox_inches="tight")
            plt.close()

        # Explainability on Top-N
        if do_explain and len(top_df) > 0:
            n = min(int(explain_top_n), len(top_df))
            top_head = top_df.head(n).copy()

            # Baseline = median over full X
            X_all = with_feats[feat_list].copy()
            for c in X_all.columns:
                X_all[c] = pd.to_numeric(X_all[c], errors="coerce")
            baseline = X_all.median(numeric_only=True)
            # Rebuild X_df for top rows
            X_top_df = top_head[feat_list].copy()
            for c in X_top_df.columns:
                X_top_df[c] = pd.to_numeric(X_top_df[c], errors="coerce")

            contrib = occlusion_contributions(model_like, X_top_df, baseline)
            explain_csv_path, explain_zip_path, explain_imgs = build_explain_outputs(
                top_head, feat_list, contrib, baseline, out_dir
            )

    # Previews (always)
    out_dir = "outputs"
    os.makedirs(out_dir, exist_ok=True)
    cleaned_preview_path = os.path.join(out_dir, "cleaned_preview.csv")
    feats_preview_path   = os.path.join(out_dir, "features_preview.csv")
    clean.head(50).to_csv(cleaned_preview_path, index=False)
    with_feats.head(50).to_csv(feats_preview_path, index=False)

    return (cleaned_preview_path, feats_preview_path,
            scored_full_path, top_slice_path, hist_path,
            explain_csv_path, explain_zip_path, explain_imgs)


# ====================================== UI ======================================

def _ui_run(csv_path, model_path, features_path, top_p_percent, do_explain, explain_top_n):
    return pipeline_run(
        input_csv_path=csv_path,
        model_ref=model_path,                # file path or None
        features_json_path=features_path,    # file path or None
        top_p_percent=top_p_percent,
        do_explain=bool(do_explain),
        explain_top_n=int(explain_top_n),
    )

with gr.Blocks(title="Wazuh Anomaly Scoring — Demo UI") as demo:
    gr.Markdown(
        "## Wazuh Anomaly Scoring — Demo UI\n"
        "Interactive walkthrough of the data-processing pipeline and ML inference results. "
        "Built for thesis demonstrations and exploratory review; not a production interface."
    )

    with gr.Row():
        csv_in   = gr.File(label="Input CSV (Wazuh export)", file_types=[".csv"], type="filepath")
        model_in = gr.File(label="Model (.pkl/.joblib, optional)", file_types=[".pkl", ".joblib"], type="filepath")
        feats_in = gr.File(label="features.json (optional)", file_types=[".json"], type="filepath")

    p_slider = gr.Slider(0.01, 5.0, value=1.0, step=0.01, label="Top p% for review")

    with gr.Row():
        explain_chk = gr.Checkbox(value=True, label="Explain Top-N")
        explain_n   = gr.Slider(1, 50, value=10, step=1, label="Top-N to explain")

    run_btn = gr.Button("Run Pipeline", variant="primary")

    with gr.Row():
        cleaned_out = gr.File(label="Cleaned preview")
        feats_out   = gr.File(label="Features preview")

    with gr.Row():
        scored_out  = gr.File(label="Scored full CSV")
        top_out     = gr.File(label="Top-p% slice CSV")

    hist_img = gr.Image(label="Score histogram", type="filepath")

    with gr.Row():
        explain_csv_out = gr.File(label="Explanations CSV")
        explain_zip_out = gr.File(label="Explanation charts (ZIP)")

    gr.Markdown("### Inline explainability preview (Top-N alerts)")
    explain_gallery_out = gr.Gallery(label="Explanation charts", columns=5, rows=2, height="auto")

    run_btn.click(
        fn=_ui_run,
        inputs=[csv_in, model_in, feats_in, p_slider, explain_chk, explain_n],
        outputs=[cleaned_out, feats_out, scored_out, top_out, hist_img, explain_csv_out, explain_zip_out, explain_gallery_out]
    )

if __name__ == "__main__":
    demo.launch()  # set share=True to expose a public link