#!/usr/bin/env python3
"""
Inject curated synthetic anomalies into a validation window (T2) so downstream
evaluation has a controlled ground truth. Kept intentionally minimal: four
stylised surrogates for MITRE-ATT&CK-adjacent scenarios.

Anomaly families (v1 scope):
  - offhours     : shift timestamp into 00:00-06:59
  - rule_new     : replace rule.id with one never seen on this host
  - decoder_new  : replace decoder.name with one never seen on this host
  - level_out    : bump rule.level into a host-relative outlier

Outputs two CSVs:
  1) --out-window : only the validation window rows, with labels
  2) --out-for-fe : history (T1) + labelled window concatenated, for FE runs

Label columns:
  - split          : 'T1' for history rows, 'T2_synth' for window rows
  - is_synth_anom  : 0/1 (window only; history forced to 0)
  - y_true_synth   : same as is_synth_anom (NaN for history)
  - y_mask_eval    : 1 for window rows, 0 for history rows (useful for filtering)
  - synth_usecase  : {offhours, rule_new, decoder_new, level_out, ''}

Usage:
  python src/pipeline/05_inject_synthetic.py \
    --input data/synthetic/wazuh.csv \
    --history-cutoff 2025-07-31 \
    --window-start 2025-08-01 --window-end 2025-08-07 \
    --out-window data/splits/T2_synth_window.csv \
    --out-for-fe data/splits/T2_synth_for_fe.csv \
    --rate-total 0.03 \
    --weights "offhours:1,rule_new:1,decoder_new:1,level_out:1"
"""

import argparse
import json
import math
import os

import numpy as np
import pandas as pd


AGENT_COL = "_source.agent.name"
RULE_COL = "_source.rule.id"
LEVEL_COL = "_source.rule.level"
DECODER_COL = "_source.decoder.name"
TS_COL = "_source.timestamp"

FAMILIES = ["offhours", "rule_new", "decoder_new", "level_out"]


# ---------------------------------------------------------------------------
# Utils
# ---------------------------------------------------------------------------

def ensure_dir_for(path: str) -> None:
    """Create the parent directory for `path` if needed."""
    if path:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)


def parse_local_ts(series: pd.Series) -> pd.Series:
    """Parse a Kibana-style local timestamp ('Aug 11, 2025 @ 08:12:11.194')."""
    cleaned = series.astype(str).str.replace(" @ ", " ", regex=False)
    return pd.to_datetime(cleaned, errors="coerce")


def fmt_kibana_local(dt: pd.Timestamp) -> str:
    """Format back into the Kibana local-time string the rest of the pipeline expects."""
    if pd.isna(dt):
        return ""
    formatted = pd.to_datetime(dt).strftime("%b %d, %Y @ %H:%M:%S.%f")
    return formatted[:-3]  # trim to millisecond resolution


def ensure_object_column(df: pd.DataFrame, col: str) -> None:
    """Ensure `col` accepts string writes — pandas 3.0 is strict about dtype coercion."""
    if col in df.columns and df[col].dtype != object:
        df[col] = df[col].astype(object)


# ---------------------------------------------------------------------------
# History profile (drives what counts as "new" or "outlier" per host)
# ---------------------------------------------------------------------------

def build_host_history(df_hist: pd.DataFrame) -> dict:
    """Build per-host sets of seen rule_ids / decoders, plus mean rule_level."""
    seen_rule: dict = {}
    seen_dec: dict = {}
    lvl_mean: dict = {}

    if RULE_COL in df_hist.columns:
        seen_rule = (
            df_hist.groupby(AGENT_COL)[RULE_COL]
            .apply(lambda s: set(s.dropna().astype(str)))
            .to_dict()
        )
    if DECODER_COL in df_hist.columns:
        seen_dec = (
            df_hist.groupby(AGENT_COL)[DECODER_COL]
            .apply(lambda s: set(s.dropna().astype(str)))
            .to_dict()
        )
    if LEVEL_COL in df_hist.columns:
        levels = pd.to_numeric(df_hist[LEVEL_COL], errors="coerce")
        lvl_mean = levels.groupby(df_hist[AGENT_COL]).mean().to_dict()

    return {"seen_rule": seen_rule, "seen_dec": seen_dec, "lvl_mean": lvl_mean}


# ---------------------------------------------------------------------------
# Injections
# ---------------------------------------------------------------------------

def synth_offhours_shift(dfw: pd.DataFrame, idx, rng) -> pd.DataFrame:
    """Shift the timestamp into 00:00-06:59 (off-hours)."""
    if len(idx) == 0 or TS_COL not in dfw.columns:
        return dfw

    ts = parse_local_ts(dfw.loc[idx, TS_COL])
    new_ts = []
    for t in ts:
        if pd.isna(t):
            new_ts.append(t)
            continue
        hh = int(rng.integers(0, 7))
        mm = int(rng.integers(0, 60))
        ss = int(rng.integers(0, 60))
        ms = int(rng.integers(0, 1000))
        new_ts.append(t.replace(hour=hh, minute=mm, second=ss, microsecond=ms * 1000))
    ensure_object_column(dfw, TS_COL)
    dfw.loc[idx, TS_COL] = [fmt_kibana_local(x) for x in new_ts]
    return dfw


def synth_rule_new(dfw: pd.DataFrame, idx, rng, seen_rule_host, global_rules) -> pd.DataFrame:
    """Replace rule_id with one never observed on this host."""
    if len(idx) == 0 or RULE_COL not in dfw.columns:
        return dfw

    ensure_object_column(dfw, RULE_COL)
    for i in idx:
        host = dfw.at[i, AGENT_COL] if AGENT_COL in dfw.columns else None
        seen = seen_rule_host.get(host, set()) if host is not None else set()
        candidates = [r for r in global_rules if r not in seen] or [
            f"9{rng.integers(10**6, 10**7 - 1)}"
        ]
        dfw.at[i, RULE_COL] = str(rng.choice(candidates))
    return dfw


def synth_decoder_new(dfw: pd.DataFrame, idx, rng, seen_dec_host, global_decs) -> pd.DataFrame:
    """Replace decoder.name with one never observed on this host."""
    if len(idx) == 0 or DECODER_COL not in dfw.columns:
        return dfw

    ensure_object_column(dfw, DECODER_COL)
    for i in idx:
        host = dfw.at[i, AGENT_COL] if AGENT_COL in dfw.columns else None
        seen = seen_dec_host.get(host, set()) if host is not None else set()
        candidates = [d for d in global_decs if d not in seen] or [
            f"dec_{rng.integers(10**6, 10**7 - 1)}"
        ]
        dfw.at[i, DECODER_COL] = str(rng.choice(candidates))
    return dfw


def synth_level_outlier(dfw: pd.DataFrame, idx, host_lvl_mean, rng) -> pd.DataFrame:
    """Set rule.level to a host-relative severity outlier."""
    if len(idx) == 0 or LEVEL_COL not in dfw.columns:
        return dfw

    # Level is numeric, but to keep the injection robust against any dtype we
    # promote to object first (the column round-trips through CSV anyway).
    ensure_object_column(dfw, LEVEL_COL)
    for i in idx:
        host = dfw.at[i, AGENT_COL] if AGENT_COL in dfw.columns else None
        mu = float(host_lvl_mean.get(host, 3.0))
        outlier = int(min(15, max(0, math.ceil(mu + 4 + rng.integers(0, 2)))))
        dfw.at[i, LEVEL_COL] = outlier
    return dfw


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------

def parse_weights(spec: str) -> np.ndarray:
    """Parse 'offhours:1,rule_new:1,...' into a normalised probability vector."""
    weight_map = {family: 1.0 for family in FAMILIES}
    for part in (p.strip() for p in spec.split(",") if p.strip()):
        name, val = part.split(":")
        name = name.strip()
        if name in FAMILIES:
            weight_map[name] = float(val)
    weights = np.array([weight_map[k] for k in FAMILIES], dtype=float)
    return weights / weights.sum()


def plan_counts(n_window: int, rate_total: float, weights: np.ndarray) -> np.ndarray:
    """Allocate the total injection budget across families, rounding up if needed."""
    n_total = max(1, int(round(n_window * max(0.0, rate_total))))
    counts = (weights * n_total).astype(int)
    # Distribute any shortfall from rounding to the highest-weighted families.
    while counts.sum() < n_total:
        for i in np.argsort(-weights):
            counts[i] += 1
            if counts.sum() == n_total:
                break
    return counts


def allocate_buckets(n_window: int, counts: np.ndarray, rng) -> dict:
    """Partition window row indices into per-family index arrays."""
    pool = np.arange(n_window)
    rng.shuffle(pool)
    buckets: dict = {}
    cursor = 0
    for family, c in zip(FAMILIES, counts):
        end = min(cursor + c, len(pool))
        buckets[family] = pool[cursor:end].copy()
        cursor = end
    return buckets


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument("--input", required=True)
    ap.add_argument("--out-window", required=True)
    ap.add_argument("--out-for-fe", required=True)
    ap.add_argument("--history-cutoff", required=True)
    ap.add_argument("--window-start", required=True)
    ap.add_argument("--window-end", required=True)
    ap.add_argument("--rate-total", type=float, default=0.03)
    ap.add_argument("--weights", type=str,
                    default="offhours:1,rule_new:1,decoder_new:1,level_out:1")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    ensure_dir_for(args.out_window)
    ensure_dir_for(args.out_for_fe)
    rng = np.random.default_rng(args.seed)

    df = pd.read_csv(args.input, low_memory=False)
    if TS_COL not in df.columns:
        raise ValueError(f"Input must contain '{TS_COL}' (local-like string).")

    # Date-partition the raw data into history and window.
    df["__date"] = parse_local_ts(df[TS_COL]).dt.date
    history_cut = pd.to_datetime(args.history_cutoff).date()
    window_start = pd.to_datetime(args.window_start).date()
    window_end = pd.to_datetime(args.window_end).date()

    history = df[df["__date"] <= history_cut].copy()
    window = df[(df["__date"] >= window_start) & (df["__date"] <= window_end)].copy()
    if len(window) == 0:
        raise ValueError("Validation window has zero rows. Check --window-start / --window-end.")

    # Build per-host profiles from history, plus global vocabularies.
    hist_profile = build_host_history(history)
    seen_rule_host = hist_profile["seen_rule"]
    seen_dec_host = hist_profile["seen_dec"]
    host_lvl_mean = hist_profile["lvl_mean"]
    global_rules = (
        sorted(df[RULE_COL].dropna().astype(str).unique().tolist())
        if RULE_COL in df.columns else []
    )
    global_decs = (
        sorted(df[DECODER_COL].dropna().astype(str).unique().tolist())
        if DECODER_COL in df.columns else []
    )

    # Label baseline state before injection.
    history = history.reset_index(drop=True)
    history["split"] = "T1"
    history["is_synth_anom"] = 0
    history["y_true_synth"] = np.nan
    history["y_mask_eval"] = 0
    history["synth_usecase"] = ""

    window = window.reset_index(drop=True)
    window["split"] = "T2_synth"
    window["is_synth_anom"] = 0
    window["synth_usecase"] = ""

    # Plan and apply injections.
    weights = parse_weights(args.weights)
    counts = plan_counts(len(window), args.rate_total, weights)
    buckets = allocate_buckets(len(window), counts, rng)

    window = synth_offhours_shift(window, buckets["offhours"], rng)
    window.loc[buckets["offhours"], "is_synth_anom"] = 1
    window.loc[buckets["offhours"], "synth_usecase"] = "offhours"

    window = synth_rule_new(window, buckets["rule_new"], rng, seen_rule_host, global_rules)
    window.loc[buckets["rule_new"], "is_synth_anom"] = 1
    window.loc[buckets["rule_new"], "synth_usecase"] = "rule_new"

    window = synth_decoder_new(window, buckets["decoder_new"], rng, seen_dec_host, global_decs)
    window.loc[buckets["decoder_new"], "is_synth_anom"] = 1
    window.loc[buckets["decoder_new"], "synth_usecase"] = "decoder_new"

    window = synth_level_outlier(window, buckets["level_out"], host_lvl_mean, rng)
    window.loc[buckets["level_out"], "is_synth_anom"] = 1
    window.loc[buckets["level_out"], "synth_usecase"] = "level_out"

    # Finalise labels on the window.
    window["y_true_synth"] = window["is_synth_anom"].astype(int)
    window["y_mask_eval"] = 1

    window.to_csv(args.out_window, index=False)
    pd.concat([history, window], ignore_index=True).to_csv(args.out_for_fe, index=False)

    print(json.dumps({
        "n_history": int(len(history)),
        "n_window": int(len(window)),
        "n_injected_total": int(window["is_synth_anom"].sum()),
        "split_counts_per_type": dict(zip(FAMILIES, counts.astype(int).tolist())),
        "rate_total": float(args.rate_total),
        "dates": {
            "history_cutoff": args.history_cutoff,
            "window_start": args.window_start,
            "window_end": args.window_end,
        },
    }, indent=2))


if __name__ == "__main__":
    main()
