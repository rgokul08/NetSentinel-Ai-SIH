#!/usr/bin/env python3
"""
Seed the CyberForecast AI database for demos and development.

Creates the role accounts, trains + activates real models on the bundled sample
dataset, generates 24h of labelled simulated traffic through the normal analysis
pipeline, runs a forecast and initialises the integrity ledger.

Usage:
    python backend/scripts/seed_database.py [--force] [--traffic 900] [--algorithm random_forest]
"""

from __future__ import annotations

import argparse
import json
import os
import sys

BACKEND_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND_ROOT)

from app.core.config import settings  # noqa: E402
from app.storage.orm import init_db  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed CyberForecast AI demo data")
    parser.add_argument("--force", action="store_true", help="Re-seed even when data exists")
    parser.add_argument("--traffic", type=int, default=settings.seed_traffic_records,
                        help="number of historical simulated flows to generate")
    parser.add_argument("--algorithm", default=settings.default_classifier)
    args = parser.parse_args()

    if args.traffic:
        settings.seed_traffic_records = args.traffic
    settings.default_classifier = args.algorithm

    init_db()
    from app.services import seed_service

    result = seed_service.seed_all(force=args.force)
    print(json.dumps(result, indent=2))
    if result.get("status") != "complete":
        sys.exit(1)


if __name__ == "__main__":
    main()
