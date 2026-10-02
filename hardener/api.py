from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
import uvicorn

from .engine import audit
from .db import Database

app = FastAPI(title="Linux Hardener API", version="0.6.0")
db = Database("./hardener-api.db")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "linux-hardener-api"}


@app.get("/api/scan")
def scan():
    report = audit()
    db.save_scan(report)
    return report.to_dict()


@app.post("/api/scans")
def ingest(report: dict):
    if "hostname" not in report or "results" not in report:
        raise HTTPException(400, "Invalid report")
    class Stored:
        pass
    obj = Stored()
    obj.hostname = report["hostname"]
    obj.score = int(report.get("score", 0))
    obj.to_dict = lambda: report
    db.save_scan(obj)
    return {"accepted": True}


@app.get("/api/scans")
def scans():
    return db.recent()


@app.get("/")
def dashboard():
    return FileResponse(Path(__file__).with_name("static") / "index.html")


def main():
    uvicorn.run("hardener.api:app", host="0.0.0.0", port=8000, reload=False)
