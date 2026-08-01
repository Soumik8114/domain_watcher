"""app.py — lightweight FastAPI wrapper for domain_watch CLI logic.

Usage (development):
    pip install -r requirements.txt
    uvicorn app:app --reload --host 0.0.0.0 --port 8000

POST /scan JSON body example:
    {
      "domains": ["acme.com"],
      "min_score": 30
    }

Returns JSON with a `job_id` immediately, then expose results through
`GET /scan/{job_id}` once processing finishes.
"""
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Dict, List
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

from fastapi import FastAPI
from pydantic import BaseModel

import domain_watch

app = FastAPI(title="Domain Watch API")
executor = ThreadPoolExecutor(max_workers=4)
job_store: Dict[str, Dict[str, Any]] = {}
job_store_lock = Lock()

class ScanRequest(BaseModel):
    domains: List[str]
    min_score: int = 0


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _set_job(job_id: str, **updates: Any) -> None:
    with job_store_lock:
        job_store[job_id].update(updates)


def _run_scan_job(job_id: str, domains: List[str], min_score: int) -> None:
    try:
        results_lists = [domain_watch.scan_domain(domain, min_score) for domain in domains]
        results = [item for sub in results_lists for item in sub]
        _set_job(
            job_id,
            status="completed",
            completed_at=_utc_now_iso(),
            count=len(results),
            results=results,
        )
    except Exception as exc:
        _set_job(
            job_id,
            status="failed",
            completed_at=_utc_now_iso(),
            error=str(exc),
        )


@app.get("/")
async def root():
    return {
        "ok": True,
        "info": "POST /scan with JSON {domains:[...], min_score:int}; poll GET /scan/{job_id}",
    }


@app.post("/scan")
async def scan(req: ScanRequest):
    job_id = uuid4().hex
    with job_store_lock:
        job_store[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "created_at": _utc_now_iso(),
            "completed_at": None,
            "count": None,
            "results": None,
            "error": None,
        }

    executor.submit(_run_scan_job, job_id, req.domains, req.min_score)
    return {
        "job_id": job_id,
        "status": "queued",
        "detail": "Scan accepted. Poll GET /scan/{job_id} for results.",
    }


@app.get("/scan/{job_id}")
async def scan_status(job_id: str):
    with job_store_lock:
        job = job_store.get(job_id)

    if not job:
        return {"job_id": job_id, "status": "not_found"}

    return job


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
