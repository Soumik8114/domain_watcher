"""app.py — lightweight FastAPI wrapper for domain_watch CLI logic.

Usage (development):
    pip install -r requirements.txt
    uvicorn app:app --reload --host 0.0.0.0 --port 8000

POST /scan JSON body example:
    {
      "domains": ["acme.com"],
      "min_score": 30
    }

Returns JSON with a `count` and `results` list (same dicts produced by `scan_domain`).
"""
from typing import List
import asyncio
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI
from pydantic import BaseModel

import domain_watch

app = FastAPI(title="Domain Watch API")
executor = ThreadPoolExecutor(max_workers=4)

class ScanRequest(BaseModel):
    domains: List[str]
    min_score: int = 0


@app.get("/")
async def root():
    return {"ok": True, "info": "POST /scan with JSON {domains:[...], min_score:int}"}


@app.post("/scan")
async def scan(req: ScanRequest):
    loop = asyncio.get_event_loop()
    tasks = [loop.run_in_executor(executor, domain_watch.scan_domain, d, req.min_score) for d in req.domains]
    results_lists = await asyncio.gather(*tasks)
    # flatten
    results = [item for sub in results_lists for item in sub]
    return {"count": len(results), "results": results}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
