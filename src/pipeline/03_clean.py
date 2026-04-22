#!/usr/bin/env python3
"""
clean_wazuh_v1.py
=================
Minimal data cleaning for Wazuh alerts tailored to anomaly detection use-cases.

Kept canonical columns:
- event_id     : unique identifier (from _id if available, else row_index)
- timestamp    : event time (datetime64[ns]), parsed from "_source.timestamp"
- agent        : agent.name or agent.id (string)
- rule_id      : rule identifier (string)
- rule_level   : severity (nullable Int64)
- decoder      : decoder name (string)

Outputs:
- Cleaned CSV
- Cleaning report (Markdown + JSON)

Usage:
  python clean_wazuh_v1.py --input data/combined_wazuh.csv --output data/cleaned_wazuh.csv --report-dir reports/clean_v1
"""

import argparse
import os
import json
from datetime import datetime
import pandas as pd

# Candidate mappings
CANDIDATES = {
    "event_id": ["_id", "event_id", "id"],
    "timestamp": ["_source.timestamp", "timestamp", "@timestamp", "event.timestamp"],
    "agent_name": ["agent.name", "_source.agent.name", "agentName"],
    "agent_id": ["agent.id", "_source.agent.id", "agentId"],
    "rule_id": ["rule.id", "_source.rule.id", "ruleId"],
    "rule_level": ["rule.level", "_source.rule.level", "ruleLevel", "level"],
    "decoder": ["decoder.name", "_source.decoder.name", "decoder"],
}

CANON = ["event_id", "timestamp", "agent", "rule_id", "rule_level", "decoder"]

def find_first(df: pd.DataFrame, candidates: list[str]) -> str | None:
    for c in candidates:
        if c in df.columns:
            return c
    return None

def normalize_columns(df: pd.DataFrame, mapping: dict) -> pd.DataFrame:
    # event_id
    src = mapping.get("event_id")
    if src:
        df["event_id"] = df[src].astype("string")
    else:
        df["event_id"] = df.index.astype(str)

    # timestamp (fixed format parsing)
    ts_src = mapping["timestamp"]
    df["timestamp"] = pd.to_datetime(
        df[ts_src],
        format="%b %d, %Y @ %H:%M:%S.%f",  # e.g., "Aug 11, 2025 @ 08:12:11.194"
        errors="coerce"
    )

    # agent
    agent_src = mapping.get("agent_name") or mapping.get("agent_id")
    df["agent"] = df[agent_src].astype("string")

    # rule_id
    df["rule_id"] = df[mapping["rule_id"]].astype("string")

    # rule_level
    df["rule_level"] = pd.to_numeric(df[mapping["rule_level"]], errors="coerce").astype("Int64")

    # decoder
    df["decoder"] = df[mapping["decoder"]].astype("string")

    return df[CANON]

def build_report(df_raw, df_clean, mapping, report_dir, dropped, dedup_info):
    os.makedirs(report_dir, exist_ok=True)
    md_path = os.path.join(report_dir, "cleaning_report.md")
    json_path = os.path.join(report_dir, "cleaning_report.json")

    report = {
        "started_at": datetime.now().isoformat(timespec="seconds"),
        "rows_raw": len(df_raw),
        "cols_raw": len(df_raw.columns),
        "rows_clean": len(df_clean),
        "cols_clean": len(df_clean.columns),
        "mapping": mapping,
        "dropped_columns": dropped,
        "deduplication": dedup_info,
        "dtypes": df_clean.dtypes.apply(str).to_dict(),
        "null_counts": df_clean.isna().sum().to_dict(),
    }

    # Markdown summary
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# Cleaning Report\n\n")
        f.write(f"- Raw shape: {df_raw.shape}\n")
        f.write(f"- Clean shape: {df_clean.shape}\n\n")
        f.write("## Column Mapping\n")
        for k, v in mapping.items():
            f.write(f"- {k}: {v}\n")
        f.write("\n## Dropped Columns\n")
        for c in dropped:
            f.write(f"- {c}\n")
        f.write("\n## Deduplication\n")
        f.write(f"- Duplicates removed: {dedup_info['removed']}\n")
        f.write(f"- Keys used: {dedup_info['keys']}\n")
        f.write("\n## Dtypes\n")
        for k, v in report["dtypes"].items():
            f.write(f"- {k}: {v}\n")
        f.write("\n## Null Counts\n")
        for k, v in report["null_counts"].items():
            f.write(f"- {k}: {v}\n")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[OK] Cleaning report written to {md_path} and {json_path}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--report-dir", required=True)
    args = ap.parse_args()

    # Load raw CSV as strings to avoid dtype issues
    df_raw = pd.read_csv(args.input, dtype=str, low_memory=False)

    # Map columns
    mapping = {}
    missing = []
    for key, candidates in CANDIDATES.items():
        src = find_first(df_raw, candidates)
        if src:
            mapping[key] = src
        else:
            if key == "event_id":  # optional
                mapping[key] = None
            else:
                missing.append(key)
    if missing:
        raise SystemExit(f"Missing required columns: {missing}")

    # Normalize
    df_clean = normalize_columns(df_raw, mapping)

    # Deduplication
    before = len(df_clean)
    df_clean = df_clean.drop_duplicates(subset=["event_id"])
    after = len(df_clean)
    removed = before - after
    dedup_info = {"removed": removed, "keys": ["event_id"]}

    # Save
    df_clean.to_csv(args.output, index=False)

    # Build report
    dropped = [c for c in df_raw.columns if c not in (list(mapping.values()) if mapping else [])]
    build_report(df_raw, df_clean, mapping, args.report_dir, dropped, dedup_info)

    print(f"[OK] Cleaned data saved to {args.output} ({len(df_clean)} rows).")

if __name__ == "__main__":
    main()
