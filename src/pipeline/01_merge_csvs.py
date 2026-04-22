#!/usr/bin/env python3
"""
Merge Wazuh weekly CSVs with varying columns into a single time-sorted CSV.

Columns across the input files may differ. The union schema is used, missing
columns are left empty, and `_source.@timestamp` is parsed (Kibana format)
and used as the sort key. Optional Parquet twin output.

Usage:
  python src/pipeline/01_merge_csvs.py \
    --input-dir data/raw --out data/combined.csv --parquet
"""

import argparse
import glob
import os
import sys
import pandas as pd

TIMESTAMP_COL = "_source.@timestamp"

def parse_args():
    ap = argparse.ArgumentParser(description="Merge Wazuh CSVs with differing columns.")
    ap.add_argument("--input-dir", type=str, required=True,
                    help="Directory containing weekly CSVs (e.g., /data).")
    ap.add_argument("--pattern", type=str, default="*.csv*",
                    help="Glob pattern inside input-dir (default: *.csv*; also matches .csv.gz).")
    ap.add_argument("--out", type=str, default="combined_wazuh.csv",
                    help="Output CSV path (default: combined_wazuh.csv).")
    ap.add_argument("--parquet", action="store_true",
                    help="Also write a Parquet file next to the CSV.")
    ap.add_argument("--dedupe", action="store_true",
                    help="Drop exact duplicate rows after concat.")
    ap.add_argument("--chunksize", type=int, default=0,
                    help="Read in chunks (rows) to reduce memory; 0 = read whole file.")
    return ap.parse_args()

def find_files(input_dir, pattern):
    path = os.path.join(input_dir, pattern)
    files = sorted(glob.glob(path))
    return [f for f in files if os.path.isfile(f)]

def read_csv_any(path, chunksize=0):
    common_kwargs = dict(
        low_memory=False,
        encoding="utf-8",
        on_bad_lines="skip",   # skip malformed lines instead of crashing
        dtype_backend="pyarrow" if pd.__version__ >= "2.0.0" else None,
    )
    if chunksize and chunksize > 0:
        return pd.read_csv(path, chunksize=chunksize, **common_kwargs)
    else:
        return pd.read_csv(path, **common_kwargs)

def normalize_timestamp(df):
    if TIMESTAMP_COL not in df.columns:
        return df, False

    # Normalize the literal " @ " to a space to simplify parsing
    ts = df[TIMESTAMP_COL].astype("string").str.replace(" @ ", " ", regex=False)

    # Try with fractional seconds first, then without
    parsed = pd.to_datetime(ts, format="%b %d, %Y %H:%M:%S.%f", errors="coerce", utc=True)
    missing = parsed.isna()
    if missing.any():
        parsed2 = pd.to_datetime(ts[missing], format="%b %d, %Y %H:%M:%S", errors="coerce", utc=True)
        parsed[missing] = parsed2

    df[TIMESTAMP_COL] = parsed
    return df, True

def concat_frames(frames):
    if not frames:
        return pd.DataFrame()

    # Align on union of columns; pandas handles by concat with sort=True
    combined = pd.concat(frames, ignore_index=True, sort=True)
    return combined

def main():
    args = parse_args()
    files = find_files(args.input_dir, args.pattern)
    if not files:
        print(f"[!] No files found in {args.input_dir!r} matching {args.pattern!r}", file=sys.stderr)
        sys.exit(1)

    print(f"[i] Found {len(files)} file(s):")
    for f in files:
        print("   -", os.path.basename(f))

    frames = []
    for path in files:
        print(f"[i] Reading: {path}")
        obj = read_csv_any(path, chunksize=args.chunksize)

        if isinstance(obj, pd.DataFrame):
            df = obj
            df, had_col = normalize_timestamp(df)
            if had_col:
                # keep original order but ensure timestamp first when possible
                cols = [TIMESTAMP_COL] + [c for c in df.columns if c != TIMESTAMP_COL]
                df = df[cols]
            frames.append(df)
        else:
            # Chunked iterator
            chunk_list = []
            for i, chunk in enumerate(obj, start=1):
                chunk, had_col = normalize_timestamp(chunk)
                chunk_list.append(chunk)
                if i % 50 == 0:
                    print(f"    ... {i} chunks read")
            df = pd.concat(chunk_list, ignore_index=True, sort=True) if chunk_list else pd.DataFrame()
            frames.append(df)

    combined = concat_frames(frames)

    if combined.empty:
        print("[!] Combined DataFrame is empty. Nothing to write.", file=sys.stderr)
        sys.exit(2)

    # Optional de-duplication
    if args.dedupe:
        before = len(combined)
        combined = combined.drop_duplicates()
        after = len(combined)
        print(f"[i] Deduped rows: {before - after}")

    # Sort by timestamp if present
    if TIMESTAMP_COL in combined.columns:
        # Some rows may have NaT; sort with them last
        combined = combined.sort_values(by=TIMESTAMP_COL, kind="stable")
    else:
        print(f"[!] {TIMESTAMP_COL!r} not found in any file; output will not be time-sorted.", file=sys.stderr)

    # Write CSV
    out_csv = args.out
    os.makedirs(os.path.dirname(out_csv) or ".", exist_ok=True)
    combined.to_csv(out_csv, index=False)
    print(f"[OK] Wrote CSV: {out_csv} ({len(combined)} rows, {combined.shape[1]} cols)")

    # Optionally write Parquet (smaller & faster to load)
    if args.parquet:
        base, _ = os.path.splitext(out_csv)
        out_parquet = base + ".parquet"
        try:
            combined.to_parquet(out_parquet, index=False)
            print(f"[OK] Wrote Parquet: {out_parquet}")
        except Exception as e:
            print(f"[!] Failed to write Parquet ({e}). Install pyarrow or fastparquet.", file=sys.stderr)

if __name__ == "__main__":
    main()
