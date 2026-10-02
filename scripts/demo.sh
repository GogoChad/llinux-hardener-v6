#!/bin/sh
set -eu
python -m hardener doctor
python -m hardener audit --html report.html --json report.json --sarif report.sarif
python -m hardener baseline --output baseline.json
python -m hardener drift baseline.json || true
python -m hardener remediate --dry-run
