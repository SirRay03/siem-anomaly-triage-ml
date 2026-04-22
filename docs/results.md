# Results

All numbers below are measured on real Wazuh SIEM data from a production
CSOC index. The published code produces the same numbers when pointed at
the same data; the synthetic data generator in this repository produces
a similarly-shaped but much smaller dataset, so absolute numbers there
will differ.

## Corpus

| Metric | Value |
|---|---|
| Date range | 10 Jul 2025 – 12 Aug 2025 |
| Total alerts | 277,499 |
| Distinct agents | 5 |
| Distinct source IPs | 2,359 |

## Split sizes

| Split | Rows | Role |
|---|---|---|
| T1 | 214,538 | Training window — transformers fit here |
| T2 | 36,022 | Validation window with 1–3%/day synthetic injections |
| T3 | 26,880 | Prospective hold-out (true future) |

## Model comparison at p = 1% daily operating budget

| Model | Config | Precision@1% | Recall@1% | Lift@1% | FPR@1% |
|-------|--------|--------------|-----------|---------|--------|
| **k-NN** | k=35 | **0.6801** | **0.2340** | **23.34×** | **0.0033** |
| Isolation Forest | 600 trees, 0.5 sample fraction | 0.4032 | 0.1388 | 13.84× | 0.0061 |
| LOF | k=20, novelty=True | 0.3010 | 0.1036 | 10.33× | 0.0072 |

- k-NN beats Isolation Forest by ~1.69× on precision and ~1.69× on lift.
- k-NN beats LOF by ~2.26× on precision and ~2.26× on lift.
- All three models produce FPR@1% below 1%, meaning even the weakest
  baseline would not flood an analyst queue. The question at 1% is
  *who hands the analyst the right items*, not *who floods the queue*.

## Operating-point summary on T3

At p = 1% per day on the T3 hold-out, the k-NN model yields:

- **253 true positives** captured inside the 1% slice
- **119 false positives** inside the same slice
- **TP : FP ≈ 2.13 : 1** — more than two true anomalies per false one

This is the interpretable SOC metric: *when an analyst commits an hour
to the top-K list, the signal-to-noise floor is 2:1*, vs approximately
1:40 for random sampling at the same budget.

## Per-day stability

A brittle ranker shows wide per-day swings in precision@p and lift@p —
great on some days, useless on others. The k-NN scorer's daily
precision and lift remain in a tight interquartile range across the
full T3 window without re-tuning:

- Per-day precision@1% stays within roughly ±15% of the mean
- Lift@1% stays within roughly ±10% of the mean

The practical implication: once deployed, the model does not need
daily re-calibration to remain useful. Drift monitoring only has to
watch for sustained departures from this baseline, not per-day noise.

## What these numbers do and do not mean

The thesis evaluation measures whether *synthetic-but-ATT&CK-shaped*
anomalies can be pulled to the top of a 1%-per-day slice. They are
strong evidence that the pipeline architecture works, that k-NN is the
right family for this feature space, and that the T1/T2/T3 + frozen-
transformer methodology produces reproducible numbers.

They are **not** evidence that the system catches all real-world
insider threats, zero-day campaigns, or adversarial evasion — that
requires either a longer prospective deployment study or a red-team
engagement. The "Context-Aware and Agentic Anomaly Detection" MSc
extension proposed in the companion brief is the path toward those
harder evaluations.
