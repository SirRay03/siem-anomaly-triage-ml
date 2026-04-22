"""
FastAPI service for the SIEM anomaly pipeline

What it does
------------
- Lists available CSV datasets (e.g., T3 / T3_scored).
- Accepts dataset path or uploaded file.
- If the CSV already has `anomaly_score`, it uses that.
- If not, computes a **simple fallback score** from common Wazuh fields
  (rule_level z-score + off-hours flag + agent×rule rarity).
- Returns the **Top-K anomalies** and can also write a CSV artifact.

How to run
----------
1) pip install -U fastapi uvicorn pydantic pandas numpy python-multipart
2) uvicorn fastapi_anomaly_service:app --host 0.0.0.0 --port 8000 --reload

Optional env vars
-----------------
DATA_DIR: directory where datasets live (default: ./data)
OUTPUT_DIR: where to write artifacts (default: ./artifacts)

Notes
-----
- This file is **standalone**; plug your real model later by replacing
  `score_with_fallback` with your saved artifacts' scorer.
- Expected columns (if present): event_id, timestamp, agent, rule_id,
  decoder, rule_level, anomaly_score, explanations.
"""
from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

import numpy as np
import pandas as pd
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, validator

# -----------------------------------------------------------------------------
# Config & logging
# -----------------------------------------------------------------------------
DATA_DIR = Path(os.getenv("DATA_DIR", "./data"))
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "./artifacts"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
)
log = logging.getLogger("anomaly-api")

# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------
CSV_PATTERNS = (
    "T3_scored.csv",
    "T3.csv",
    "*T3*scored*.csv",
    "*T3*.csv",
)


def find_dataset_path(dataset: Optional[str] = None, path: Optional[str] = None) -> Path:
    """Resolve dataset path from name or explicit path.

    Priority: explicit path > dataset name patterns > raise.
    """
    if path:
        p = Path(path)
        if not p.exists():
            raise HTTPException(404, detail=f"Dataset not found at path: {path}")
        return p

    if dataset:
        # Exact file name first
        candidate = DATA_DIR / dataset
        if candidate.exists():
            return candidate
        # Try common patterns
        pats = [dataset] + [pat.replace("T3", dataset) for pat in CSV_PATTERNS]
        for pat in pats:
            for fp in DATA_DIR.glob(pat):
                if fp.is_file():
                    return fp

    # Fallback: try T3 patterns
    for pat in CSV_PATTERNS:
        for fp in DATA_DIR.glob(pat):
            if fp.is_file():
                return fp

    raise HTTPException(404, detail="Could not resolve dataset path. Pass `path` or `dataset`.")


def _to_datetime(s: pd.Series) -> pd.Series:
    try:
        return pd.to_datetime(s, errors="coerce")
    except Exception:
        return pd.to_datetime(pd.Series([None] * len(s)))


def load_csv(fp: Path, usecols: Optional[List[str]] = None) -> pd.DataFrame:
    """Load CSV with safe defaults and minimal dtype enforcement."""
    if not fp.exists():
        raise HTTPException(404, detail=f"File not found: {fp}")
    log.info("Loading CSV: %s", fp)
    try:
        df = pd.read_csv(fp, low_memory=False, usecols=usecols)
    except ValueError:
        # usecols may not match; reload without it
        df = pd.read_csv(fp, low_memory=False)

    # Normalize common columns if present
    if "timestamp" in df.columns:
        df["timestamp"] = _to_datetime(df["timestamp"])  # type: ignore
    for c in ("rule_level",):
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")
    return df


def parse_explanations_cell(x: Any) -> Optional[Dict[str, Any]]:
    """Parse the `explanations` column if it contains JSON (stringified)."""
    if x is None or (isinstance(x, float) and np.isnan(x)):
        return None
    if isinstance(x, dict):
        return x
    if isinstance(x, str):
        s = x.strip()
        if not s:
            return None
        try:
            return json.loads(s)
        except Exception:
            # Try to salvage JSON-like by removing trailing quotes/escapes
            try:
                s2 = re.sub(r"\\'", '"', s)
                return json.loads(s2)
            except Exception:
                return {"raw": s}
    return None


def score_with_fallback(df: pd.DataFrame) -> pd.Series:
    """Compute a simple anomaly score if `anomaly_score` not provided.

    score = 0.5 * z(rule_level) + 1.0 * off_hours + 2.0 * rarity(agent×rule)
    """
    n = len(df)
    score = pd.Series(np.zeros(n, dtype=float), index=df.index)

    # z-score of rule_level
    if "rule_level" in df.columns:
        rl = pd.to_numeric(df["rule_level"], errors="coerce").fillna(0)
        mu, sig = rl.mean(), rl.std(ddof=0) or 1.0
        z = (rl - mu) / sig
        score = score + 0.5 * z

    # off-hours flag from timestamp (00:00–06:59)
    if "timestamp" in df.columns and np.issubdtype(df["timestamp"].dtype, np.datetime64):
        hrs = df["timestamp"].dt.hour.fillna(0)
        off = ((hrs >= 0) & (hrs <= 6)).astype(float)
        score = score + 1.0 * off

    # agent×rule rarity (inverse frequency)
    if "agent" in df.columns and "rule_id" in df.columns:
        grp = df.groupby(["agent", "rule_id"], dropna=False)["rule_id"].transform("count")
        rarity = 1.0 / (1.0 + grp.astype(float))
        score = score + 2.0 * rarity

    # Final normalization to 0..1 for readability
    s = (score - score.min()) / (score.max() - score.min() + 1e-9)
    return s


def ensure_anomaly_score(df: pd.DataFrame) -> pd.DataFrame:
    if "anomaly_score" not in df.columns:
        df = df.copy()
        df["anomaly_score"] = score_with_fallback(df)
    return df


def summarise_reasons(parsed: Optional[Dict[str, Any]]) -> Optional[str]:
    """Flatten a parsed explanations dict into a 'feature:delta' summary string.

    Expected structure: `{"top_features": [{"feature": str, "delta_score_...": float}, ...]}`.
    Returns None for anything else.
    """
    if not isinstance(parsed, dict):
        return None
    parts = []
    for entry in parsed.get("top_features", [])[:3]:
        feature = entry.get("feature")
        delta = entry.get("delta_score_if_replaced_by_train_median", 0)
        try:
            parts.append(f"{feature}:{round(float(delta), 3)}")
        except (TypeError, ValueError):
            continue
    return ", ".join(parts) if parts else None


def jsonable_records(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Convert a DataFrame slice to JSON-ready dicts.

    pandas Timestamps and numpy NaNs are not stdlib-JSON-serialisable; this
    helper coerces timestamp columns to ISO-8601 strings and replaces NaN
    with None, then returns plain dicts.
    """
    if df.empty:
        return []
    out = df.copy()
    for col in out.columns:
        if pd.api.types.is_datetime64_any_dtype(out[col]):
            out[col] = out[col].dt.strftime("%Y-%m-%dT%H:%M:%S")
    out = out.where(pd.notna(out), None)
    return out.to_dict(orient="records")


def choose_output_columns(df: pd.DataFrame) -> List[str]:
    pref = [
        "rank",
        "event_id",
        "timestamp",
        "agent",
        "rule_id",
        "decoder",
        "rule_level",
        "anomaly_score",
        "explanations",
    ]
    return [c for c in pref if c in df.columns]


def topk(df: pd.DataFrame, k: int = 50, sort_by: str = "anomaly_score", descending: bool = True) -> pd.DataFrame:
    if sort_by not in df.columns:
        raise HTTPException(400, detail=f"sort_by '{sort_by}' not in columns")
    d = df.sort_values(by=sort_by, ascending=not descending).head(k).copy()
    d.insert(0, "rank", range(1, len(d) + 1))
    return d


# -----------------------------------------------------------------------------
# Pydantic models
# -----------------------------------------------------------------------------
class TopRequest(BaseModel):
    dataset: Optional[str] = Field(None, description="Dataset name, e.g., 'T3' or filename in DATA_DIR")
    path: Optional[str] = Field(None, description="Explicit CSV path; overrides dataset name if set")
    top_k: int = Field(50, ge=1, le=1000)
    sort_by: str = Field("anomaly_score")
    descending: bool = True
    write_artifact: bool = Field(True, description="Write CSV of the top-k selection to OUTPUT_DIR")
    artifact_name: Optional[str] = Field(None, description="Override output filename for the artifact")

    @validator("artifact_name")
    def _safe_name(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if not re.match(r"^[A-Za-z0-9_.-]+$", v):
            raise ValueError("artifact_name contains invalid characters")
        return v


# -----------------------------------------------------------------------------
# FastAPI app & endpoints
# -----------------------------------------------------------------------------
app = FastAPI(title="Anomaly Top-K Service", version="1.0.0")


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "time": datetime.utcnow().isoformat() + "Z"}


class ListDatasetsResponse(BaseModel):
    count: int
    files: List[str]

@app.get("/datasets", response_model=ListDatasetsResponse)
def list_datasets(pattern: str = Query("*.csv", description="Glob pattern inside DATA_DIR")) -> ListDatasetsResponse:
    files = sorted([str(p) for p in DATA_DIR.glob(pattern) if p.is_file()])
    return ListDatasetsResponse(count=len(files), files=files)


@app.post("/upload")
def upload(file: UploadFile = File(...)) -> Dict[str, str]:
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(400, detail="Only .csv files are accepted")
    dest = DATA_DIR / file.filename
    with dest.open("wb") as f:
        f.write(file.file.read())
    return {"saved_to": str(dest.resolve())}


@app.post("/anomalies/top")
def anomalies_top(req: TopRequest) -> JSONResponse:
    fp = find_dataset_path(dataset=req.dataset, path=req.path)

    # Minimal columns for fallback scorer
    needed = [
        "event_id",
        "timestamp",
        "agent",
        "rule_id",
        "decoder",
        "rule_level",
        "anomaly_score",
        "explanations",
    ]
    df = load_csv(fp, usecols=None)  # allow auto-discovery; fallback will subset

    # Ensure anomaly_score exists (compute fallback if missing)
    df = ensure_anomaly_score(df)

    # Parse explanations if present (optional)
    if "explanations" in df.columns:
        try:
            df["reason_summary"] = df["explanations"].map(parse_explanations_cell).map(summarise_reasons)
        except Exception:
            pass

    # Build Top-K
    cols = list({*needed, *df.columns})  # include all; we'll slice after sorting
    dtop = topk(df, k=req.top_k, sort_by=req.sort_by, descending=req.descending)
    out_cols = choose_output_columns(dtop)
    dresp = dtop[out_cols]

    # Persist artifact
    artifact_path = None
    if req.write_artifact:
        name = req.artifact_name or f"top{req.top_k}_{fp.stem}_{req.sort_by}.csv"
        artifact_path = OUTPUT_DIR / name
        dresp.to_csv(artifact_path, index=False)

    payload: Dict[str, Any] = {
        "dataset": str(fp),
        "rows": len(dresp),
        "columns": out_cols,
        "artifact": str(artifact_path) if artifact_path else None,
        "items": jsonable_records(dresp),
    }
    return JSONResponse(payload)


@app.get("/anomalies/file")
def anomalies_file(dataset: Optional[str] = None, path: Optional[str] = None,
                   top_k: int = 50, sort_by: str = "anomaly_score", descending: bool = True):
    fp = find_dataset_path(dataset=dataset, path=path)
    df = load_csv(fp)
    df = ensure_anomaly_score(df)
    dtop = topk(df, k=top_k, sort_by=sort_by, descending=descending)
    out_cols = choose_output_columns(dtop)
    dresp = dtop[out_cols]

    # Stream CSV in-memory
    csv_bytes = dresp.to_csv(index=False).encode("utf-8")
    return StreamingResponse(
        iter([csv_bytes]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=top{top_k}_{fp.stem}_{sort_by}.csv"
        },
    )


# -----------------------------------------------------------------------------
# Local dev helper
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
