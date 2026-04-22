# Architecture

## Data-processing pipeline

```mermaid
flowchart TB
    subgraph INGEST["Ingest"]
        CSV["Weekly Wazuh CSVs<br/>(varying schemas)"]
        CSV -->|"01_merge_csvs"| COMBINED["combined.csv<br/>union schema, time-sorted"]
    end

    subgraph PREP["Preparation"]
        COMBINED -->|"02_profile_coverage"| COV["coverage report<br/>keeps cols &geq; 80% non-null"]
        COV -->|"03_clean"| CLEAN["cleaned.csv<br/>canonical columns:<br/>event_id, timestamp, agent,<br/>rule_id, rule_level, decoder"]
    end

    subgraph SPLIT["Temporal split"]
        CLEAN -->|"04_split_T1_T2_T3"| T1["T1.csv<br/>training"]
        CLEAN -->|"04_split_T1_T2_T3"| T2["T2.csv<br/>validation"]
        CLEAN -->|"04_split_T1_T2_T3"| T3["T3.csv<br/>hold-out"]
    end

    subgraph LABEL["Synthetic labelling"]
        T2 -->|"05_inject_synthetic<br/>(history = T1)"| T2S["T2_synth.csv<br/>+ is_synth_anom<br/>+ synth_usecase"]
    end

    subgraph FE["Feature engineering<br/>(fit-on-T1, freeze)"]
        T1 -->|"06_engineer_features fit"| STATS["fe_stats.json<br/>frozen transformers"]
        T1 -->|"06_engineer_features fit"| T1F["T1_feat.csv"]
        STATS --> APPLY1["06_engineer_features apply"]
        STATS --> APPLY2["06_engineer_features apply"]
        T2S --> APPLY1
        T3 --> APPLY2
        APPLY1 --> T2F["T2_feat.csv"]
        APPLY2 --> T3F["T3_feat.csv"]
    end

    subgraph SCORE["Scoring"]
        T1F --> MODEL["k-NN model<br/>k=35"]
        MODEL --> T3F_SCORED["T3 scored<br/>+ anomaly_score<br/>+ reason payload"]
        T3F --> MODEL
    end

    style STATS fill:#fff4e1,stroke:#d99900
    style MODEL fill:#e8f4ff,stroke:#0066cc
    style T3F_SCORED fill:#e8f4ff,stroke:#0066cc
```

The orange block is the **no-leakage invariant**: every reusable statistic
(per-host z-score parameters, recency median, combo frequency table) is
computed once on T1 and frozen into a JSON file. T2 and T3 apply the same
frozen statistics — they never recompute on validation data.

## Service layer

```mermaid
flowchart LR
    SCORED["scored CSV<br/>(anomaly_score +<br/>explanations)"]

    subgraph SERVICE["Scoring service"]
        API["FastAPI<br/>/anomalies/top<br/>/anomalies/file<br/>/health /upload /datasets"]
        GR["Gradio demo UI<br/>(thesis / exploration)"]
    end

    SCORED --> API
    SCORED --> GR

    API -->|"Top-K JSON"| QUEUE["Analyst queue<br/>(Top-K per day)"]
    API -->|"CSV download"| FEED["SOAR / ticketing<br/>feed (e.g. n8n)"]
    API -->|"reason codes"| EXPLAIN["Per-alert<br/>explanation payload"]

    style API fill:#e8f4ff,stroke:#0066cc
    style GR fill:#f3e6ff,stroke:#8040c0
```

### Endpoints (FastAPI)

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/health` | Liveness probe |
| `GET` | `/datasets` | Enumerate CSVs in `DATA_DIR` |
| `POST` | `/upload` | Upload a scored CSV |
| `POST` | `/anomalies/top` | Return Top-K ranked rows as JSON |
| `GET` | `/anomalies/file` | Return Top-K as a downloadable CSV |

If the uploaded CSV already contains an `anomaly_score` column, the
service uses it directly. If not, a lightweight fallback scorer
(`z(rule_level) + off_hours + rarity(agent×rule)`) is applied so the
service remains useful even without a trained model. This is intentional:
the portfolio version of this repo does not ship binary model artifacts,
but the service still demonstrates end-to-end behaviour.

### Deployment path (thesis)

In the thesis deployment, the FastAPI service ran as a Uvicorn worker
with frozen feature transformers pickled alongside the k-NN estimator.
It plugged into a wider Managed Detection & Response stack:

- **Wazuh SIEM** → alert source
- **Suricata NIDS** → parallel detection channel
- **DFIR-IRIS** → case management, consuming the Top-K output
- **YARA / ClamAV / VirusTotal** → threat-intel enrichment
- **n8n** → SOAR automation, reading the CSV download endpoint

Top-K rankings feed analyst queues as ranked, explainable shortlists.
At the 1%-per-day operating point, analysts working from this list see
23× more true positives than random sampling across the same budget.
