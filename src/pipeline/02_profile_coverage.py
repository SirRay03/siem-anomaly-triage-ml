#!/usr/bin/env python3
"""
Extract the most-complete Wazuh features from many CSVs (or one big CSV),
generate a completeness report, and write a reduced dataset + optional sample.

- Unions columns across files
- Computes non-null percentage per column in streaming mode (chunks)
- Keeps only columns above --min-pct (e.g., 0.85 = 85% filled)
- Parses '_source.@timestamp' like 'Aug 12, 2025 @ 16:03:14.261'
- Writes:
    1) <out_prefix>_feature_report.csv (completeness + quick stats)
    2) <out_prefix>_reduced.csv (only high-coverage columns)
    3) <out_prefix>_sample.csv (optional; random sample of reduced)

Usage:
  python extract_top_features.py --input-dir /data --out-prefix wazuh_top --min-pct 0.85 --sample 50000
  python extract_top_features.py --input-file combined_wazuh.csv --out-prefix wazuh_top --min-pct 0.9
"""

import argparse
import glob
import os
import random
import sys
from collections import defaultdict

import pandas as pd

TIMESTAMP_COL = "_source.@timestamp"

def parse_args():
    ap = argparse.ArgumentParser(description="Extract most-complete features from Wazuh CSV logs.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--input-dir", type=str, help="Directory with CSV/.csv.gz files to merge/scan.")
    g.add_argument("--input-file", type=str, help="Single CSV file to scan.")
    ap.add_argument("--pattern", type=str, default="*.csv*",
                    help="Glob for --input-dir (default: *.csv*; matches .csv and .csv.gz).")
    ap.add_argument("--chunksize", type=int, default=250_000, help="Rows per chunk (streaming).")
    ap.add_argument("--min-pct", type=float, default=0.85,
                    help="Minimum non-null ratio to keep a column (0.0–1.0).")
    ap.add_argument("--top-n", type=int, default=0,
                    help="Optional cap: keep only top-N columns by coverage (after threshold). 0=off.")
    ap.add_argument("--out-prefix", type=str, default="wazuh_top",
                    help="Prefix for outputs (report/reduced/sample).")
    ap.add_argument("--sample", type=int, default=0,
                    help="Optional random sample size from reduced data. 0=off.")
    ap.add_argument("--dedupe", action="store_true", help="Drop duplicate rows in reduced output.")
    ap.add_argument("--seed", type=int, default=42, help="RNG seed for sampling.")
    return ap.parse_args()

def iter_files(args):
    if args.input_file:
        if not os.path.isfile(args.input_file):
            sys.exit(f"[!] File not found: {args.input_file}")
        return [args.input_file]
    else:
        pattern = os.path.join(args.input_dir, args.pattern)
        files = sorted(f for f in glob.glob(pattern) if os.path.isfile(f))
        if not files:
            sys.exit(f"[!] No files in {args.input_dir!r} matching {args.pattern!r}")
        return files

def read_csv_iter(path, chunksize):
    return pd.read_csv(
        path,
        chunksize=chunksize,
        low_memory=False,
        encoding="utf-8",
        on_bad_lines="skip",
        dtype_backend="pyarrow" if pd.__version__ >= "2.0.0" else None,
    )

def normalize_timestamp_inplace(df):
    if TIMESTAMP_COL in df.columns:
        ts = df[TIMESTAMP_COL].astype("string").str.replace(" @ ", " ", regex=False)
        parsed = pd.to_datetime(ts, format="%b %d, %Y %H:%M:%S.%f", errors="coerce", utc=True)
        miss = parsed.isna()
        if miss.any():
            parsed2 = pd.to_datetime(ts[miss], format="%b %d, %Y %H:%M:%S", errors="coerce", utc=True)
            parsed[miss] = parsed2
        df[TIMESTAMP_COL] = parsed

def update_profile(col, s, prof):
    nn = s.notna()
    prof[col]["non_null"] += int(nn.sum())
    prof[col]["total"] += len(s)

    # quick stats on a small sample of non-nulls
    sample_vals = s[nn]
    if not sample_vals.empty:
        # Save up to a few example values
        if len(prof[col]["examples"]) < 5:
            for v in sample_vals.head(5).tolist():
                if len(prof[col]["examples"]) >= 5: break
                prof[col]["examples"].append(v)

        # Unique counts on a capped sample for performance
        cap = min(50_000, len(sample_vals))
        uniques = sample_vals.head(cap).nunique(dropna=True)
        prof[col]["nunique_sample"] = prof[col].get("nunique_sample", 0) + int(uniques)

        # Type-specific extras
        if pd.api.types.is_numeric_dtype(sample_vals):
            zeros = (sample_vals == 0).sum()
            prof[col]["zeros"] += int(zeros)

def first_pass_profile(file_list, chunksize):
    profile = defaultdict(lambda: {
        "non_null": 0,
        "total": 0,
        "nunique_sample": 0,
        "zeros": 0,
        "examples": []
    })

    for path in file_list:
        print(f"[i] Scanning (pass 1): {os.path.basename(path)}")
        for chunk in read_csv_iter(path, chunksize):
            normalize_timestamp_inplace(chunk)
            for col in chunk.columns:
                update_profile(col, chunk[col], profile)

    # finalize coverage
    rows = []
    for col, st in profile.items():
        total = st["total"] if st["total"] else 1
        coverage = st["non_null"] / total
        rows.append({
            "column": col,
            "non_null": st["non_null"],
            "total": st["total"],
            "coverage": round(coverage, 6),
            "nunique_sample": st["nunique_sample"],
            "zeros_sample": st["zeros"],
            "examples": "; ".join(map(lambda x: str(x)[:120], st["examples"]))
        })
    report_df = pd.DataFrame(rows).sort_values("coverage", ascending=False)
    return report_df

def select_columns(report_df, min_pct, top_n):
    keep = report_df[report_df["coverage"] >= min_pct].copy()
    if top_n and top_n > 0 and len(keep) > top_n:
        keep = keep.sort_values(["coverage","non_null"], ascending=[False,False]).head(top_n)
    # Keep timestamp if it exists even if below threshold
    if TIMESTAMP_COL in report_df["column"].values and TIMESTAMP_COL not in keep["column"].values:
        keep = pd.concat([pd.DataFrame([{"column": TIMESTAMP_COL}]), keep], ignore_index=True)
    cols = keep["column"].tolist()
    # ensure timestamp first
    if TIMESTAMP_COL in cols:
        cols = [TIMESTAMP_COL] + [c for c in cols if c != TIMESTAMP_COL]
    return cols, keep

def write_report(report_df, out_prefix):
    out = f"{out_prefix}_feature_report.csv"
    report_df.to_csv(out, index=False)
    print(f"[OK] Wrote feature report: {out} ({len(report_df)} cols profiled)")

def second_pass_write(file_list, cols_to_keep, out_prefix, chunksize, dedupe=False, sample_n=0, seed=42):
    reduced_path = f"{out_prefix}_reduced.csv"
    sample_path  = f"{out_prefix}_sample.csv"
    rng = random.Random(seed)

    # Streaming write
    header_written = False
    sample_buf = []

    for path in file_list:
        print(f"[i] Extracting (pass 2): {os.path.basename(path)}")
        for chunk in read_csv_iter(path, chunksize):
            normalize_timestamp_inplace(chunk)
            # Align columns (add missing)
            for c in cols_to_keep:
                if c not in chunk.columns:
                    chunk[c] = pd.NA
            # Reorder & trim
            chunk = chunk[cols_to_keep]

            # Sort by timestamp if present
            if TIMESTAMP_COL in chunk.columns:
                chunk = chunk.sort_values(by=TIMESTAMP_COL, kind="stable")

            # Append to reduced CSV
            mode = "a"
            if not header_written:
                mode = "w"
                header_written = True
            chunk.to_csv(reduced_path, mode=mode, header=(mode=="w"), index=False)

            # Reservoir sampling for optional sample output
            if sample_n and sample_n > 0:
                for _, row in chunk.iterrows():
                    if len(sample_buf) < sample_n:
                        sample_buf.append(row)
                    else:
                        j = rng.randint(0, len(sample_buf))
                        if j < sample_n:
                            sample_buf[j] = row

    # Optional dedupe for reduced (can be heavy on very large data)
    if dedupe:
        print("[i] Deduping reduced data (this may take a while)...")
        df = pd.read_csv(reduced_path, low_memory=False)
        before = len(df)
        df = df.drop_duplicates()
        after = len(df)
        df.to_csv(reduced_path, index=False)
        print(f"[i] Deduped rows: {before - after}")

    print(f"[OK] Wrote reduced data: {reduced_path}")

    # Write sample if requested
    if sample_n and sample_n > 0:
        if sample_buf:
            sample_df = pd.DataFrame(sample_buf)
            sample_df.to_csv(sample_path, index=False)
            print(f"[OK] Wrote sample ({len(sample_df)} rows): {sample_path}")
        else:
            print("[!] No rows collected for sample.")

def main():
    args = parse_args()
    files = iter_files(args)

    # Pass 1: profile coverage
    report_df = first_pass_profile(files, args.chunksize)
    write_report(report_df, args.out_prefix)

    # Decide columns to keep
    cols_to_keep, kept_df = select_columns(report_df, args.min_pct, args.top_n)
    print(f"[i] Keeping {len(cols_to_keep)} columns (min_pct={args.min_pct}, top_n={args.top_n})")
    if not cols_to_keep:
        sys.exit("[!] No columns met the criteria. Try lowering --min-pct or increasing --top-n.")

    # Pass 2: write reduced + optional sample
    second_pass_write(
        file_list=files,
        cols_to_keep=cols_to_keep,
        out_prefix=args.out_prefix,
        chunksize=args.chunksize,
        dedupe=args.dedupe,
        sample_n=args.sample,
        seed=args.seed
    )

if __name__ == "__main__":
    main()
