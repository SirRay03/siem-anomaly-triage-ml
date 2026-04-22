# Synthetic Wazuh dataset

`generate.py` produces a CSV with the **same schema** the pipeline expects, so
the whole pipeline can be run end-to-end without the production dataset.

## Schema (matches Wazuh CSV exports)

| Column | Type | Notes |
|---|---|---|
| `_id` | string | Unique event id (`evt-0000000001`, …) |
| `_source.@timestamp` | string | Kibana-style: `Aug 12, 2025 @ 16:03:14.261` |
| `_source.timestamp` | string | Duplicate of `_source.@timestamp` (Wazuh writes both) |
| `_source.agent.name` | string | One of `agent-01`…`agent-05` |
| `_source.agent.id` | string | `a01`…`a05` |
| `_source.rule.id` | string | One of 60 synthetic rule ids |
| `_source.rule.level` | int | 1–15, skewed to 3–7 with 4% high-severity tail |
| `_source.decoder.name` | string | One of 11 common decoder names |

## Distributions (why they match real MDR data)

- **Hour-of-day** — ~80% business-hours (08:00–19:59), ~20% off-hours. Matches observed MDR traffic shape.
- **Rule level** — Gaussian-ish around 5, clipped to [1,15], with a 4% tail at level 10–12. Real Wazuh alert corpora are similarly skewed.
- **Agent × rule** — each agent has its own preferred subset of ~15 rules; 10% of events come from a globally common rule. Produces realistic host-specific combos.
- **Agent traffic** — non-uniform (35/25/18/14/8). Real environments are always imbalanced.

## Usage

```bash
python data/synthetic/generate.py --n 50000 --out data/synthetic/wazuh.csv --seed 42
```

The generator does NOT inject anomalies. That is handled separately by
`src/pipeline/05_inject_synthetic.py`, which applies the same four MITRE
ATT&CK-flavoured injection families (off-hours shift, unseen-rule on host,
unseen-decoder on host, severity outlier) the thesis used against real data.

## Intentional limits

This dataset is for code review and reproducibility. It is NOT a stand-in for
real SOC data during model evaluation — synthetic corpora lack the messy
decoders, operator quirks, and adversarial behaviours that make real triage
hard. The thesis results in the README were measured against real data from
a production MDR stack, not this generator.
