# Results

This document mirrors Chapter V.2 of the thesis (*Hasil Evaluasi* —
Evaluation Results). All numbers below are measured on real Wazuh SIEM
data from a production CSOC index (Telkom Indonesia, acknowledged in the
published thesis). The published code produces the same numbers when
pointed at the same data; the synthetic data generator in this repository
produces a similarly-shaped but much smaller dataset, so absolute numbers
there will differ.

## Corpus

| Metric | Value |
|---|---|
| Date range | 10 Jul 2025 17:40 – 12 Aug 2025 15:44 (Asia/Jakarta) |
| Total alerts (raw) | 277,499 |
| Total alerts (after dedup) | 277,440 |
| Distinct agents | 5 |
| Distinct source IPs | 2,359 |

## Split sizes

| Split | Rows | Role |
|---|---|---|
| T1 | 214,538 | Training window — transformers fit here |
| T2 | 36,022 | Validation window with 1–3%/day synthetic injections |
| T3 | 26,880 | Prospective hold-out (true future) |

## Hyperparameter tuning and model selection (V.2.1)

Three unsupervised algorithms were tuned on T2 (with synthetic
injections) at the operating budget p = 1%. Best-of-each:

| Model | Config | Precision@1% | Recall@1% | Lift@1% | FPR@1% |
|-------|--------|--------------|-----------|---------|--------|
| **k-NN** | k=35 | **0.6801** | **0.2340** | **23.34×** | **0.0033** |
| Isolation Forest | 600 trees, 0.5 sample fraction, 0.8 max_features, bootstrap=True | 0.4032 | 0.1388 | 13.84× | 0.0061 |
| LOF | k=20, `novelty=True` | 0.3010 | 0.1036 | 10.33× | 0.0072 |

- k-NN beats Isolation Forest by ~1.69× on precision and ~1.69× on lift.
- k-NN beats LOF by ~2.26× on precision and ~2.26× on lift.
- All three produce FPR@1% below 1%, so even the weakest baseline would
  not flood an analyst queue. At p = 1% the question is *who hands the
  analyst the right items*, not *who floods the queue*.

### Reason codes — why the top-ranked alerts are top-ranked

The ranker's output is paired with **reason codes**: a per-alert
attribution that shows which features pushed the score up, and what the
"normal neighbour" baseline looks like on each of those features. This is
what converts a score into something an analyst can act on in seconds.

![Figure 5.1 — Reason codes for rank #1](figures/fig-5-1-reason-codes-rank1.png)

*Figure 5.1 (thesis): Top feature contributions for the #1-ranked alert
on T3. The dominant driver is `rule_time_since_last_host` (an extremely
long gap since this rule last fired on this host), with `rule_level_z`
interactions contributing secondary weight.*

![Figure 5.2 — Reason codes for rank #3](figures/fig-5-2-reason-codes-rank3.png)

*Figure 5.2 (thesis): For the #3-ranked alert, the driver shifts: the
`weekend × rule_level_z` and `offhours × rule_level_z` interactions
dominate. The same model surfaces different explanation patterns for
different classes of anomaly.*

These explanations aren't a separate post-hoc tool; they fall out of the
k-NN distance computation directly, which is why explainability is cheap
and consistent with the scoring path.

## Operating-point analysis — Top-p sweep (V.2.2)

For the winning k-NN configuration, precision, recall, and lift were
measured across a range of operating budgets *p*. The pattern matches the
canonical tradeoff of budgeted triage: tighter budget → higher precision,
wider budget → higher recall.

### Precision vs p

![Figure 5.3 — Precision vs p](figures/fig-5-3-precision-vs-p-knn.png)

*Figure 5.3 (thesis): `precision@p` as the budget widens. Drops gently
from ~0.78 at p = 0.5% to ~0.50 at p = 3%, with a clear "shoulder" near
p = 1%.*

### Recall vs p

![Figure 5.4 — Recall vs p](figures/fig-5-4-recall-vs-p-knn.png)

*Figure 5.4 (thesis): `recall@p` rises approximately linearly as the
slice widens, from ~0.14 at p = 0.5% to ~0.51 at p = 3%.*

### Lift vs p

![Figure 5.5 — Lift vs p](figures/fig-5-5-lift-vs-p-knn.png)

*Figure 5.5 (thesis): `lift@p` starts near 27× at p = 0.5% and settles at
~17× at p = 3%. Even at the widest budget, the ranker is more than an
order of magnitude better than random sampling.*

### k sweep at p = 1%

| k  | Precision@1% | Recall@1% | Lift@1% | FPR@1% |
|----|--------------|-----------|---------|--------|
| 5  | 0.6640 | 0.2285 | 22.79× | 0.0035 |
| 10 | 0.6694 | 0.2303 | 22.97× | 0.0034 |
| 20 | 0.6720 | 0.2313 | 23.07× | 0.0034 |
| **35** | **0.6801** | **0.2340** | **23.34×** | **0.0033** |
| 50 | 0.6747 | 0.2322 | 23.16× | 0.0034 |
| 100| 0.6586 | 0.2266 | 22.61× | 0.0035 |

k = 35 is the precision peak; k ≤ 10 under-smooths, k ≥ 75 over-smooths
the locality that k-NN is exploiting.

### Best-of-k at different p

| p | best k | Precision@p | Recall@p | Lift@p | FPR@p |
|---|--------|-------------|----------|--------|-------|
| 0.5% | 5  | 0.8118 | 0.1397 | 27.86× | 0.0010 |
| **1%** | **35** | **0.6801** | **0.2340** | **23.34×** | **0.0033** |
| 2% | 50 | 0.5034 | 0.3460 | 17.28× | 0.0102 |
| 3% | 35 | 0.4982 | 0.5134 | 17.10× | 0.0155 |

**p = 1% is chosen as the primary operating point** because it balances
high precision (0.68) with useful recall (0.23) and delivers > 23× lift
with < 0.33% FPR.

## Fixed-K operating points — capacity planning (V.2.3)

SOC capacity is often expressed as "alerts per analyst per shift", a fixed
*K*, rather than a proportion. The same model is therefore also evaluated
at three fixed-K budgets so a manager can translate the ranker directly to
headcount.

| Top-K | Precision@K | Recall@K | Lift@K | FPR@K | TP | FP | FN | TN |
|-------|-------------|----------|--------|-------|----|----|----|----|
| 25 | **0.84** | 0.0194 | 28.83× | 0.0001 | 21 | 4 | 1,060 | 36,018 |
| 50 | **0.84** | 0.0388 | 28.83× | 0.0002 | 42 | 8 | 1,039 | 36,014 |
| 100 | 0.64 | 0.0592 | 21.97× | 0.0009 | 64 | 36 | 1,017 | 35,986 |

### Precision@K

![Figure 5.6 — Precision@K](figures/fig-5-6-precision-at-k.png)

*Figure 5.6 (thesis): Precision stays at 0.84 for K ≤ 50 and drops to
0.64 at K = 100. Ranking remains sharp even when the slice widens.*

### Recall@K

![Figure 5.7 — Recall@K](figures/fig-5-7-recall-at-k.png)

*Figure 5.7 (thesis): Recall rises monotonically with K. K = 50 gives a
meaningful bump over K = 25 with the precision penalty still small.*

### Lift@K

![Figure 5.8 — Lift@K](figures/fig-5-8-lift-at-k.png)

*Figure 5.8 (thesis): Lift stays at 28.83× through K ≤ 50 and settles at
21.97× at K = 100 — still far above 1×, so prioritisation is
operationally meaningful.*

### FPR@K

![Figure 5.9 — FPR@K](figures/fig-5-9-fpr-at-k.png)

*Figure 5.9 (thesis): FPR grows with K as expected, but stays below 0.1%
even at K = 100 — noise remains well within analyst tolerance.*

### Confusion counts at fixed K

![Figure 5.10 — Confusion matrix counts](figures/fig-5-10-confusion-at-k.png)

*Figure 5.10 (thesis): TP / FP / TN / FN counts across K = 25, 50, 100.
Most mass stays in TN (non-anomalous and correctly un-selected); FP
scales predictably with K.*

### Practical capacity translation

A three-analyst shift with a 50-alert quota per analyst can expect
roughly **126 true positives per day** (3 × 42) against **24 false
positives**, for a ~5:1 signal-to-noise ratio inside the queue.

## What these numbers do and do not mean

The thesis evaluation measures whether *synthetic-but-ATT&CK-shaped*
anomalies can be pulled to the top of a 1%-per-day slice. They are strong
evidence that:

- the pipeline architecture works,
- k-NN is the right algorithm family for this feature space,
- the T1/T2/T3 + frozen-transformer methodology produces reproducible
  numbers.

They are **not** evidence that the system catches all real-world insider
threats, zero-day campaigns, or adversarial evasion — that requires
either a longer prospective deployment study or a red-team engagement.
The production roadmap documented in the main README (closed-loop RL /
active learning, real-incident labels replacing synthetic) is the path
toward those harder evaluations.
