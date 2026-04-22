#!/usr/bin/env python3
"""
Feature engineering with a fit-on-T1 / freeze-for-T2-T3 discipline.

This enforces the no-leakage invariant: every statistic used at inference
(per-host z-score means/stdevs, combo frequency tables, recency medians) is
computed ONCE on T1 and then serialised to a stats JSON. The `apply` mode
reads that JSON and applies the frozen statistics to T2 or T3 without ever
recomputing them on validation data.

Feature families:
  - Temporal: hour, off-hours flag, weekend flag, 2-hour bucket, second-in-hour
  - Severity: per-host z-score of rule_level
  - Rarity:   time-since-last-rule-on-host (log1p), agent×rule×hour combo
              as a stable blake2b hash in [0,1] and a log1p frequency
  - Crosses:  off-hours × severity, weekend × severity, recency × severity

Usage:
  # 1) Fit on T1 (saves stats.json AND writes T1_feat.csv)
  python 06_engineer_features.py fit \
    --input data/splits/T1.csv \
    --out   data/splits/T1_feat.csv \
    --stats-out data/splits/fe_stats.json

  # 2) Apply to T2 (and T3) using frozen stats
  python 06_engineer_features.py apply \
    --input data/splits/T2.csv \
    --stats data/splits/fe_stats.json \
    --out   data/splits/T2_feat.csv
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd

FEATURES = [
    "hour_local", "is_off_hours", "day_of_week", "is_weekend",
    "second_in_hour", "seconds_in_hour_bucketed", "hour_bucket",
    "rule_level", "rule_level_z_host",
    "rule_time_since_last_host_log1p", "recency_x_rule_level",
    "offhours_x_rule_level", "offhours_x_rule_level_z", "weekend_x_rule_level_z",
    "agent_rule_hour_hash01", "agent_rule_hour_freq_log1p",
]


def _hash01(s: str) -> float:
    h = hashlib.blake2b(s.encode("utf-8"), digest_size=8).hexdigest()
    v = int(h, 16) & ((1 << 32) - 1)
    return v / float((1 << 32) - 1)


def _temporal_features(df: pd.DataFrame) -> pd.DataFrame:
    g = df.copy()
    g["timestamp"] = pd.to_datetime(g["timestamp"], errors="coerce")
    g["hour_local"] = g["timestamp"].dt.hour.fillna(0).astype(int)
    g["day_of_week"] = g["timestamp"].dt.dayofweek.fillna(0).astype(int)
    g["is_weekend"] = (g["day_of_week"] >= 5).astype(int)
    g["is_off_hours"] = g["hour_local"].isin(list(range(0, 7))).astype(int)
    g["second_in_hour"] = (g["timestamp"].dt.minute.fillna(0) * 60
                           + g["timestamp"].dt.second.fillna(0)).astype(int)
    g["seconds_in_hour_bucketed"] = (g["second_in_hour"] // 60).astype(int)
    g["hour_bucket"] = (np.floor(g["hour_local"] / 2.0) * 2).astype(int)
    return g


def _fit_stats(df: pd.DataFrame) -> dict:
    """Fit all reusable statistics on a training frame (T1)."""
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["rule_level"] = pd.to_numeric(df["rule_level"], errors="coerce")

    # per-host rule_level statistics
    g = df.groupby("agent", dropna=False)["rule_level"]
    host_mu = g.mean()
    host_sd = g.std().fillna(0.0)

    # recency median per host (seconds)
    df_sorted = df.sort_values(["agent", "timestamp"])
    rec = df_sorted.groupby("agent", dropna=False)["timestamp"].diff().dt.total_seconds()
    global_recency_median = float(rec.dropna().median()) if rec.notna().any() else 0.0

    # agent × rule × hour_bucket combo frequency (from training only)
    hour_bucket = (np.floor(df["timestamp"].dt.hour.fillna(0).astype(int) / 2.0) * 2).astype(int)
    combo = (df["agent"].astype(str) + "||" + df["rule_id"].astype(str) + "||" + hour_bucket.astype(str))
    combo_freq = combo.value_counts().to_dict()

    return {
        "host_rule_level_mean": host_mu.to_dict(),
        "host_rule_level_std": host_sd.to_dict(),
        "global_recency_median": global_recency_median,
        "combo_freq": {str(k): int(v) for k, v in combo_freq.items()},
    }


def _apply_features(df: pd.DataFrame, stats: dict) -> pd.DataFrame:
    """Apply all features using frozen statistics from `stats`."""
    g = _temporal_features(df)
    g["rule_level"] = pd.to_numeric(g["rule_level"], errors="coerce")

    # per-host z-score using frozen mean/std
    mu = g["agent"].map(stats["host_rule_level_mean"]).astype(float)
    sd = g["agent"].map(stats["host_rule_level_std"]).astype(float).replace(0, np.nan)
    g["rule_level_z_host"] = ((g["rule_level"] - mu) / sd).fillna(0.0)

    # recency computed within this frame per host (local to this batch is OK:
    # the MEDIAN-fallback is the frozen statistic, not the per-row recency)
    g_sorted = g.sort_values(["agent", "timestamp"])
    recency = g_sorted.groupby("agent", dropna=False)["timestamp"].diff().dt.total_seconds()
    recency = recency.fillna(stats["global_recency_median"]).clip(lower=0)
    g.loc[g_sorted.index, "rule_time_since_last_host"] = recency.values
    g["rule_time_since_last_host_log1p"] = np.log1p(g["rule_time_since_last_host"].astype(float))

    # combo features using FROZEN frequency table (unseen combos → 0 freq)
    combo = (g["agent"].astype(str) + "||" + g["rule_id"].astype(str)
             + "||" + g["hour_bucket"].astype(str))
    g["agent_rule_hour_hash01"] = combo.map(_hash01).astype(float)
    g["agent_rule_hour_freq_log1p"] = np.log1p(
        combo.map(lambda k: stats["combo_freq"].get(k, 0)).astype(float)
    )

    # crosses
    g["offhours_x_rule_level"] = g["is_off_hours"] * g["rule_level"].astype(float)
    g["offhours_x_rule_level_z"] = g["is_off_hours"] * g["rule_level_z_host"]
    g["weekend_x_rule_level_z"] = g["is_weekend"] * g["rule_level_z_host"]
    g["recency_x_rule_level"] = g["rule_time_since_last_host_log1p"] * g["rule_level"].astype(float)

    return g


def main() -> None:
    ap = argparse.ArgumentParser(description="Fit or apply frozen feature transformers.")
    sub = ap.add_subparsers(dest="mode", required=True)

    fit_p = sub.add_parser("fit", help="Fit stats on training frame (T1) and emit features.")
    fit_p.add_argument("--input", required=True)
    fit_p.add_argument("--out", required=True, help="Output features CSV.")
    fit_p.add_argument("--stats-out", required=True, help="Where to save the fitted stats JSON.")

    app_p = sub.add_parser("apply", help="Apply stats to a validation/hold-out frame.")
    app_p.add_argument("--input", required=True)
    app_p.add_argument("--stats", required=True, help="Stats JSON produced by `fit`.")
    app_p.add_argument("--out", required=True, help="Output features CSV.")

    args = ap.parse_args()

    if args.mode == "fit":
        df = pd.read_csv(args.input, low_memory=False)
        stats = _fit_stats(df)
        feats = _apply_features(df, stats)
        Path(args.stats_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        with open(args.stats_out, "w", encoding="utf-8") as f:
            json.dump(stats, f)
        feats.to_csv(args.out, index=False)
        print(f"[OK] Fitted stats -> {args.stats_out}")
        print(f"[OK] T1 features -> {args.out} ({len(feats)} rows, {len(FEATURES)} feature cols)")

    elif args.mode == "apply":
        df = pd.read_csv(args.input, low_memory=False)
        with open(args.stats, "r", encoding="utf-8") as f:
            stats = json.load(f)
        feats = _apply_features(df, stats)
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        feats.to_csv(args.out, index=False)
        print(f"[OK] Features written -> {args.out} ({len(feats)} rows)")


if __name__ == "__main__":
    main()
