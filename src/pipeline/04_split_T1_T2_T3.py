#!/usr/bin/env python3
"""
Temporal split into T1 (training) / T2 (validation) / T3 (hold-out).

Reads a cleaned Wazuh CSV (output of 03_clean.py) and splits it by date into three
disjoint windows. The splits are temporal — never random — to mirror how a SOC
deployment moves forward in time: models are trained on past data, validated on
a near-past window with synthetic injections, and evaluated on a truly-unseen
future window.

Usage:
  python 04_split_T1_T2_T3.py \
    --input data/cleaned.csv \
    --out-dir data/splits \
    --history-cutoff 2025-08-02 \
    --window-start   2025-08-03 \
    --window-end     2025-08-07
    # T3 is everything after --window-end.
"""

import argparse
import json
import os
from pathlib import Path

import pandas as pd


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Split cleaned Wazuh alerts into T1/T2/T3 windows.")
    ap.add_argument("--input", required=True, help="Cleaned CSV (must contain a 'timestamp' column).")
    ap.add_argument("--out-dir", required=True, help="Directory to write T1.csv, T2.csv, T3.csv, summary.json.")
    ap.add_argument("--history-cutoff", required=True,
                    help="T1 training window is timestamp <= this date (inclusive). ISO date.")
    ap.add_argument("--window-start", required=True,
                    help="T2 validation window start date (inclusive). ISO date.")
    ap.add_argument("--window-end", required=True,
                    help="T2 validation window end date (inclusive). ISO date.")
    ap.add_argument("--timestamp-col", default="timestamp",
                    help="Name of timestamp column in the input (default: 'timestamp').")
    return ap.parse_args()


def main() -> None:
    args = parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(args.input, low_memory=False)
    if args.timestamp_col not in df.columns:
        raise SystemExit(f"[!] Timestamp column '{args.timestamp_col}' not found in {args.input}.")

    df[args.timestamp_col] = pd.to_datetime(df[args.timestamp_col], errors="coerce")
    dropped_nat = int(df[args.timestamp_col].isna().sum())
    if dropped_nat:
        print(f"[i] Dropping {dropped_nat} rows with unparseable timestamps.")
        df = df.dropna(subset=[args.timestamp_col]).reset_index(drop=True)

    df["__date"] = df[args.timestamp_col].dt.date

    t1_cut = pd.to_datetime(args.history_cutoff).date()
    ws = pd.to_datetime(args.window_start).date()
    we = pd.to_datetime(args.window_end).date()

    if not (t1_cut < ws <= we):
        raise SystemExit("[!] Require history-cutoff < window-start <= window-end.")

    t1 = df[df["__date"] <= t1_cut].drop(columns="__date")
    t2 = df[(df["__date"] >= ws) & (df["__date"] <= we)].drop(columns="__date")
    t3 = df[df["__date"] > we].drop(columns="__date")

    t1.to_csv(out_dir / "T1.csv", index=False)
    t2.to_csv(out_dir / "T2.csv", index=False)
    t3.to_csv(out_dir / "T3.csv", index=False)

    summary = {
        "input": str(Path(args.input).resolve()),
        "history_cutoff": str(t1_cut),
        "window_start": str(ws),
        "window_end": str(we),
        "counts": {"T1": int(len(t1)), "T2": int(len(t2)), "T3": int(len(t3))},
        "date_range": {
            "min": str(df[args.timestamp_col].min()),
            "max": str(df[args.timestamp_col].max()),
        },
    }
    with open(out_dir / "summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(json.dumps(summary, indent=2))
    print(f"[OK] Wrote splits to {out_dir}/")


if __name__ == "__main__":
    main()
