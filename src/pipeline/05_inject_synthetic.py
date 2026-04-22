#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Minimal synthetic injector aligned with v1 scope.
- Keeps only: offhours, rule_new, decoder_new, level_out
- Skips other anomaly families by default

Outputs two CSVs:
  1) --out-window: only the validation window (T2_synth) with labels
  2) --out-for-fe: history (T1) + labeled window (T2_synth) for FE

Label columns:
  - split: 'T1' for history rows, 'T2_synth' for window rows
  - is_synth_anom: 0/1 (window only; history forced to 0)
  - y_true_synth: same as is_synth_anom (NaN for history)
  - y_mask_eval: 1 for window rows, 0 for history rows (useful to filter eval)
  - synth_usecase: {offhours, rule_new, decoder_new, level_out, ''}

Usage:
  python make_validation_synthetic_min.py \
    --input cleaned.csv \
    --history-cutoff 2025-07-31 --window-start 2025-08-01 --window-end 2025-08-07 \
    --out-window window_synth.csv --out-for-fe history_plus_window.csv \
    --rate-total 0.03 \
    --weights "offhours:1,rule_new:1,decoder_new:1,level_out:1"
"""

import argparse, os, json, math
import numpy as np
import pandas as pd

# ------------ utils ------------

def ensure_dir_for(path: str):
    if path:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

def parse_local_ts(series: pd.Series) -> pd.Series:
    return pd.to_datetime(series.astype(str).str.replace(" @ ", " ", regex=False), errors="coerce")

def fmt_kibana_local(dt: pd.Timestamp) -> str:
    if pd.isna(dt): return ""
    s = pd.to_datetime(dt).strftime("%b %d, %Y @ %H:%M:%S.%f")
    return s[:-3]

# ------------ history ------------

def build_host_history(df_hist: pd.DataFrame):
    seen_rule = df_hist.groupby("_source.agent.name")["_source.rule.id"].apply(lambda s: set(s.dropna().astype(str))).to_dict() if "_source.rule.id" in df_hist.columns else {}
    seen_dec  = df_hist.groupby("_source.agent.name")["_source.decoder.name"].apply(lambda s: set(s.dropna().astype(str))).to_dict() if "_source.decoder.name" in df_hist.columns else {}
    lvl_mean = {}
    if "_source.rule.level" in df_hist.columns:
        lvl = pd.to_numeric(df_hist["_source.rule.level"], errors="coerce")
        g = df_hist["_source.agent.name"]
        lvl_mean = lvl.groupby(g).mean().to_dict()
    return {"seen_rule": seen_rule, "seen_dec": seen_dec, "lvl_mean": lvl_mean}

# ------------ injections ------------

def synth_offhours_shift(dfw, idx, rng):
    if len(idx)==0 or "_source.timestamp" not in dfw.columns: return dfw
    ts = parse_local_ts(dfw.loc[idx, "_source.timestamp"])  # local-like
    new_ts = []
    for t in ts:
        if pd.isna(t): new_ts.append(t); continue
        hh = int(rng.integers(0,7)); mm = int(rng.integers(0,60)); ss = int(rng.integers(0,60)); ms = int(rng.integers(0,1000))
        new_ts.append(t.replace(hour=hh, minute=mm, second=ss, microsecond=ms*1000))
    dfw.loc[idx, "_source.timestamp"] = [fmt_kibana_local(x) for x in new_ts]
    return dfw

def synth_rule_new(dfw, idx, rng, seen_rule_host, global_rules):
    if len(idx)==0 or "_source.rule.id" not in dfw.columns: return dfw
    for i in idx:
        h = dfw.at[i, "_source.agent.name"] if "_source.agent.name" in dfw.columns else None
        seen = seen_rule_host.get(h, set()) if h is not None else set()
        cands = [r for r in global_rules if r not in seen] or [f"9{rng.integers(10**6, 10**7-1)}"]
        dfw.at[i, "_source.rule.id"] = str(rng.choice(cands))
    return dfw

def synth_decoder_new(dfw, idx, rng, seen_dec_host, global_decs):
    if len(idx)==0 or "_source.decoder.name" not in dfw.columns: return dfw
    for i in idx:
        h = dfw.at[i, "_source.agent.name"] if "_source.agent.name" in dfw.columns else None
        seen = seen_dec_host.get(h, set()) if h is not None else set()
        cands = [d for d in global_decs if d not in seen] or [f"dec_{rng.integers(10**6, 10**7-1)}"]
        dfw.at[i, "_source.decoder.name"] = str(rng.choice(cands))
    return dfw

def synth_level_outlier(dfw, idx, host_lvl_mean, rng):
    if len(idx)==0 or "_source.rule.level" not in dfw.columns: return dfw
    for i in idx:
        h = dfw.at[i, "_source.agent.name"] if "_source.agent.name" in dfw.columns else None
        mu = float(host_lvl_mean.get(h, 3.0))
        dfw.at[i, "_source.rule.level"] = int(min(15, max(0, math.ceil(mu + 4 + rng.integers(0,2)))))
    return dfw

# ------------ main ------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--out-window", required=True)
    ap.add_argument("--out-for-fe", required=True)
    ap.add_argument("--history-cutoff", required=True)
    ap.add_argument("--window-start", required=True)
    ap.add_argument("--window-end", required=True)
    ap.add_argument("--rate-total", type=float, default=0.03)
    ap.add_argument("--weights", type=str, default="offhours:1,rule_new:1,decoder_new:1,level_out:1")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    ensure_dir_for(args.out_window); ensure_dir_for(args.out_for_fe)
    rng = np.random.default_rng(args.seed)

    df = pd.read_csv(args.input, low_memory=False)
    if "_source.timestamp" not in df.columns:
        raise ValueError("Input must contain '_source.timestamp' (local-like string).")

    ts = parse_local_ts(df["_source.timestamp"])
    df["__date"] = pd.to_datetime(ts, errors="coerce").dt.date
    t1 = pd.to_datetime(args.history_cutoff).date()
    ws = pd.to_datetime(args.window_start).date()
    we = pd.to_datetime(args.window_end).date()
    hist = df[df["__date"] <= t1].copy()
    wnd  = df[(df["__date"] >= ws) & (df["__date"] <= we)].copy()

    if len(wnd) == 0: raise ValueError("Validation window has zero rows. Check dates.")

    H = build_host_history(hist)
    seen_rule_host = H["seen_rule"]; seen_dec_host = H["seen_dec"]; host_lvl_mean = H["lvl_mean"]
    global_rules = sorted(df["_source.rule.id"].dropna().astype(str).unique().tolist()) if "_source.rule.id" in df.columns else []
    global_decs  = sorted(df["_source.decoder.name"].dropna().astype(str).unique().tolist()) if "_source.decoder.name" in df.columns else []

    # init labels
    hist = hist.reset_index(drop=True)
    hist["split"] = "T1"
    hist["is_synth_anom"] = 0
    hist["y_true_synth"] = np.nan
    hist["y_mask_eval"] = 0
    hist["synth_usecase"] = ""

    wnd = wnd.reset_index(drop=True)
    wnd["split"] = "T2_synth"
    wnd["is_synth_anom"], wnd["synth_usecase"] = 0, ""

    # Plan injections
    parts = [p.strip() for p in args.weights.split(",") if p.strip()]
    order = ["offhours","rule_new","decoder_new","level_out"]
    w_map = {k:1.0 for k in order}
    for p in parts:
        name, val = p.split(":"); name=name.strip(); val=float(val)
        if name in order: w_map[name] = val
    weights = np.array([w_map[k] for k in order], dtype=float)
    weights = weights / weights.sum()

    n_total = max(1, int(round(len(wnd) * max(0.0, args.rate_total))))
    counts = (weights * n_total).astype(int)
    while counts.sum() < n_total:
        for i in np.argsort(-weights):
            counts[i]+=1
            if counts.sum()==n_total: break

    pool = np.arange(len(wnd)); rng.shuffle(pool)
    start=0; buckets={}
    for k,c in zip(order, counts):
        end = min(start+c, len(pool))
        buckets[k] = pool[start:end].copy()
        start = end

    # Apply
    wnd = synth_offhours_shift(wnd, buckets["offhours"], rng);                    wnd.loc[buckets["offhours"], "is_synth_anom"] = 1; wnd.loc[buckets["offhours"], "synth_usecase"] = "offhours"
    wnd = synth_rule_new(wnd, buckets["rule_new"], rng, seen_rule_host, global_rules); wnd.loc[buckets["rule_new"], "is_synth_anom"] = 1; wnd.loc[buckets["rule_new"], "synth_usecase"] = "rule_new"
    wnd = synth_decoder_new(wnd, buckets["decoder_new"], rng, seen_dec_host, global_decs);  wnd.loc[buckets["decoder_new"], "is_synth_anom"] = 1; wnd.loc[buckets["decoder_new"], "synth_usecase"] = "decoder_new"
    wnd = synth_level_outlier(wnd, buckets["level_out"], host_lvl_mean, rng);     wnd.loc[buckets["level_out"], "is_synth_anom"] = 1; wnd.loc[buckets["level_out"], "synth_usecase"] = "level_out"

    # finalize labels for window
    wnd["y_true_synth"] = wnd["is_synth_anom"].astype(int)
    wnd["y_mask_eval"] = 1

    out_window = wnd.copy()
    out_for_fe = pd.concat([hist, wnd], ignore_index=True)

    out_window.to_csv(args.out_window, index=False)
    out_for_fe.to_csv(args.out_for_fe, index=False)

    summary = {
        "n_history": int(len(hist)),
        "n_window": int(len(out_window)),
        "n_injected_total": int(out_window["is_synth_anom"].sum()),
        "split_counts_per_type": {k:int(v) for k,v in zip(order, counts)},
        "rate_total": float(args.rate_total),
        "dates": {"history_cutoff": args.history_cutoff, "window_start": args.window_start, "window_end": args.window_end}
    }
    print(json.dumps(summary, indent=2))

if __name__ == "__main__":
    main()