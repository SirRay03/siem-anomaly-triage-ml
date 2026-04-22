# Methodology

This document explains *why* the pipeline is built the way it is. It is meant
for readers who have seen the results table in the main README and want to
know how the numbers were produced.

## Reframing detection as ranking under a budget

A naïve formulation is *binary classification*: label every alert as
"anomaly" or "normal" and report precision/recall globally. In a real SOC
that breaks down in two ways:

1. **Analyst capacity is fixed.** A SOC analyst can triage roughly *k*
   alerts per day. If the classifier produces 10× that many "positives",
   the analyst silently reverts to sorting by severity — the model
   contributes nothing.
2. **Threshold drift is undetectable.** As traffic shape changes over
   time, a fixed decision threshold drifts: yesterday's "90% precision"
   quietly becomes today's "40% precision" without anyone noticing.

The reframing is simple: fix the budget *p* (e.g. 1% of daily events) and
optimise metrics *inside that slice*. The operating point is explicit in
the metric name, so drift is observable day over day.

- **precision@p** — fraction of the top-*p* slice that are true positives
- **recall@p** — fraction of all true positives captured inside the slice
- **lift@p** — ratio vs random sampling at the same budget
- **FPR@p** — false-positive rate inside the slice

At p = 1%, random sampling gives lift ≈ 1.0; anything above that is
genuine triage value.

## Temporal T1 / T2 / T3 split

All splits are strictly temporal. The order matches how a SOC deployment
moves forward in time: train on the past, validate on the near past, hold
out the true future.

| Split | Role | Rows (thesis) | Time relation |
|-------|------|---------------|---------------|
| **T1** | Training window | 214,538 | `timestamp ≤ history-cutoff` |
| **T2** | Validation with synthetic injection | 36,022 | `window-start ≤ timestamp ≤ window-end` |
| **T3** | Prospective hold-out | 26,880 | `timestamp > window-end` |

A random K-fold split would allow a model to cheat by memorising per-host
habits that change across days. Temporal splitting forbids this, matching
the deployment reality where yesterday's patterns drive tomorrow's
scoring.

### No-leakage invariant

Feature transformers — per-host `rule_level` mean/stdev, recency median,
agent × rule × hour combo frequency table — are **fit once on T1** and
**frozen** as a JSON statistics file. At T2 and T3 time, the `apply` mode
reads that JSON and evaluates features against the frozen statistics.
See `src/pipeline/06_engineer_features.py`.

This guarantees three things:

1. No statistic derived from validation/hold-out data reaches the model.
2. Results are reproducible: re-running `apply` against the same stats
   file always produces the same features.
3. Deployment parity: the service loads the same stats at inference time
   that were used to measure validation performance.

## Synthetic injection for validation

Real anomaly labels at scale are impossible to obtain in a SOC — analysts
confirm or dismiss alerts under time pressure, and most true positives
never get an "anomaly" label flipped on them. To generate a meaningful
validation signal, this work injects MITRE ATT&CK-flavoured anomalies
into the T2 window at 1–3%/day and evaluates the ranker against those
known positives.

Four injection families, mapped to ATT&CK thinking:

| Family | What it does | ATT&CK analogue |
|---|---|---|
| `offhours_shift` | Shift timestamp of a genuine alert into 00:00–06:59 | Unusual access time (T1078, T1110) |
| `rule_new` | Replace `rule.id` with a rule never seen on this host | Novel tooling / sub-technique (T1059, T1105) |
| `decoder_new` | Replace `decoder.name` with one never seen on this host | New source / unusual log channel |
| `level_out` | Set `rule.level` to roughly host-mean + 5 (severity outlier) | Privilege escalation / impact signals |

Weights for each family are tunable via `--weights` (see script). The
injections preserve existing row structure except for the targeted fields,
so the ranker has to find them using the same features it would use
against real anomalies.

## Model selection rationale

Three unsupervised baselines were compared:

- **k-NN** — mean distance to the *k* nearest neighbours, scored per row
- **Isolation Forest** — path-length-based anomaly score from random trees
- **Local Outlier Factor (LOF)** — local density ratio vs neighbourhood

k-NN won on precision, recall, and lift at p = 1%. The interpretation is
straightforward: Wazuh alerts cluster tightly in feature space when they
are normal (same agent, same rule, similar hour), so *distance to near
neighbours* is a sharper signal than either global tree path-length
(Isolation Forest) or local density (LOF). LOF also requires explicit
`novelty=True` to score unseen data, which adds a tripwire to deployment.

## Explainability layer

For every top-K row the service returns a `reason` payload with:

1. **Top contributing features** — per-feature delta `Δscore` if the
   value were replaced with the training-set median. Features whose
   replacement collapses the score the most are the "reasons" the alert
   ranked high.
2. **Neighbour-median comparator** — what the nearest-neighbour group
   looks like for this host on each feature. Gives the analyst a local
   "what's normal here" reference.
3. **Context flags** — human-readable tags: `off-hours × high severity`,
   `new rule on this host`, etc.

Reference: `build_explain_outputs` and `occlusion_contributions` in
`src/service/gradio_app.py`.
