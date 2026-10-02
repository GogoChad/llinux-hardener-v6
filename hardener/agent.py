import argparse
import time
import urllib.request
import json

from .engine import audit
from .db import Database


def send_report(url: str, report):
    body = json.dumps(report.to_dict()).encode()
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.status


def main():
    parser = argparse.ArgumentParser(description="Linux Hardener agent")
    parser.add_argument("--interval", type=int, default=900)
    parser.add_argument("--server", help="API endpoint, e.g. http://127.0.0.1:8000/api/scans")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    db = Database("./agent.db")
    while True:
        report = audit()
        db.save_scan(report)
        print(f"Agent scan: {report.hostname} score={report.score}")
        if args.server:
            try:
                print(f"Server response: {send_report(args.server, report)}")
            except Exception as exc:
                print(f"Server error: {exc}")
        if args.once:
            break
        time.sleep(max(10, args.interval))
