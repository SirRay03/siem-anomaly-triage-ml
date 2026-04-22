#!/usr/bin/env python3
"""
Synthetic Wazuh alert generator.

Produces CSV output with the same schema the pipeline expects, so anyone can
clone this repository and run the whole pipeline end-to-end without access to
the real production dataset.

The generator simulates realistic Wazuh alert distributions:

  - Business-hour heavy arrival pattern (with a minority off-hours tail)
  - Rule levels skewed toward 3-7 (medium severity) with rare high-severity rules
  - Realistic agent x rule co-occurrence (a handful of agents, dozens of rules,
    long-tail combinations)
  - Timestamps in the Wazuh export format:  "Aug 12, 2025 @ 16:03:14.261"

Note: this generator does NOT inject anomalies. Anomaly injection is handled
separately by  src/pipeline/05_inject_synthetic.py  so the fit/apply split
of generation vs labelling stays clean.

Usage:
  python data/synthetic/generate.py --n 50000 --out data/synthetic/wazuh.csv --seed 42
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd


AGENTS = [f"agent-{i:02d}" for i in range(1, 6)]  # 5 agents
RULE_IDS = [str(10_000 + i) for i in range(60)]    # 60 rule ids
DECODERS = ["auth", "syscheck", "web", "ossec", "sudo", "pam_unix",
            "sshd", "systemd", "cron", "apache2-access", "nginx-access"]


def _rule_level_sample(rng: np.random.Generator, n: int) -> np.ndarray:
    """Rule levels ~ discretised mixture: peak in 3-7, tail up to 12."""
    base = rng.normal(loc=5.0, scale=1.5, size=n)
    tail_mask = rng.random(n) < 0.04  # 4% high-severity tail
    base[tail_mask] = rng.normal(loc=11.0, scale=0.8, size=tail_mask.sum())
    levels = np.clip(np.rint(base), 1, 15).astype(int)
    return levels


def _business_hour_biased_hours(rng: np.random.Generator, n: int) -> np.ndarray:
    """~80% of hours land in 08:00-19:00; the rest is overnight tail."""
    is_business = rng.random(n) < 0.80
    business_h = rng.integers(low=8, high=20, size=n)
    offhours_h = rng.integers(low=0, high=24, size=n)
    return np.where(is_business, business_h, offhours_h)


def generate(n: int, start_date: str, days: int, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)

    # Spread events uniformly across `days` starting from start_date, then
    # overlay business-hour-biased time-of-day.
    start = pd.Timestamp(start_date)
    day_offsets = rng.integers(low=0, high=days, size=n)
    hours = _business_hour_biased_hours(rng, n)
    minutes = rng.integers(low=0, high=60, size=n)
    seconds = rng.integers(low=0, high=60, size=n)
    millis = rng.integers(low=0, high=1000, size=n)

    ts = (start
          + pd.to_timedelta(day_offsets, unit="D")
          + pd.to_timedelta(hours, unit="h")
          + pd.to_timedelta(minutes, unit="m")
          + pd.to_timedelta(seconds, unit="s")
          + pd.to_timedelta(millis, unit="ms"))

    # agent / rule assignment: each agent has a preferred set of rules; some
    # rules are globally common, most are local to one or two agents.
    agent_pref_rules: dict = {a: rng.choice(RULE_IDS, size=rng.integers(10, 25), replace=False).tolist()
                              for a in AGENTS}

    agents = rng.choice(AGENTS, size=n, p=[0.35, 0.25, 0.18, 0.14, 0.08])
    rules = np.empty(n, dtype=object)
    for i, a in enumerate(agents):
        if rng.random() < 0.10:  # 10% globally common rules (any agent)
            rules[i] = rng.choice(RULE_IDS)
        else:
            rules[i] = rng.choice(agent_pref_rules[a])

    levels = _rule_level_sample(rng, n)
    decoders = rng.choice(DECODERS, size=n)

    ts_fmt = ts.strftime("%b %d, %Y @ %H:%M:%S.") + ts.strftime("%f").str[:3]

    df = pd.DataFrame({
        "_id": [f"evt-{i:010d}" for i in range(n)],
        "_source.@timestamp": ts_fmt,
        "_source.timestamp": ts_fmt,
        "_source.agent.name": agents,
        "_source.agent.id": [f"a{a.split('-')[-1]}" for a in agents],
        "_source.rule.id": rules,
        "_source.rule.level": levels,
        "_source.decoder.name": decoders,
    })
    # Ensure time-ordered output (matches how real Wazuh CSVs export)
    df = df.sort_values("_source.timestamp").reset_index(drop=True)
    return df


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate a synthetic Wazuh-alert CSV.")
    ap.add_argument("--n", type=int, default=50_000, help="Number of rows (default: 50,000).")
    ap.add_argument("--start-date", default="2025-07-10", help="First day of the simulated window.")
    ap.add_argument("--days", type=int, default=33, help="Number of days to span (default: 33).")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", required=True, help="Output CSV path.")
    args = ap.parse_args()

    df = generate(args.n, args.start_date, args.days, args.seed)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)
    print(f"[OK] Wrote {len(df):,} synthetic alerts to {out_path}")
    print(f"     agents={df['_source.agent.name'].nunique()}  "
          f"rules={df['_source.rule.id'].nunique()}  "
          f"date_range=[{df['_source.timestamp'].iloc[0]} .. {df['_source.timestamp'].iloc[-1]}]")


if __name__ == "__main__":
    main()
