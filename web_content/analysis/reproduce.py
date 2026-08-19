#!/usr/bin/env python3
"""Reproduce the Web Content section outputs from the packaged databases."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


ARTIFACT_ROOT = Path(__file__).resolve().parent.parent
ANALYSIS_DIR = ARTIFACT_ROOT / "analysis"
DATA_DIR = ARTIFACT_ROOT / "data"
ARCHIVE = DATA_DIR / "raw_data.tar.zst"
RAW_DATA = DATA_DIR / "raw_data"
OUTPUTS = ARTIFACT_ROOT / "outputs"
REFERENCE_OUTPUTS = ARTIFACT_ROOT / "reference_outputs"


def run(command):
    print("+", " ".join(str(part) for part in command), flush=True)
    subprocess.run([str(part) for part in command], cwd=ARTIFACT_ROOT, check=True, env=os.environ)


def extract_data():
    if RAW_DATA.is_dir():
        return
    if not ARCHIVE.is_file():
        raise SystemExit(f"Missing data archive: {ARCHIVE}")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    run(["tar", "--use-compress-program=unzstd", "-xf", ARCHIVE, "-C", DATA_DIR])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--extract-only", action="store_true", help="Extract the data archive without running analyses.")
    args = parser.parse_args()

    extract_data()
    if args.extract_only:
        return

    blocking_out = OUTPUTS / "blocking_analysis"
    blocking_out.mkdir(parents=True, exist_ok=True)

    run([
        sys.executable,
        ANALYSIS_DIR / "third_party_web_resources_report.py",
        "--crawl-dir", RAW_DATA / "crawl_blocked_paper",
        "--domains-csv", RAW_DATA / "domains" / "domains.csv",
        "--output-dir", blocking_out,
    ])
    run([
        sys.executable,
        ANALYSIS_DIR / "reproduce_web_content.py",
        "--crawl-dir", RAW_DATA / "crawl_blocked_paper",
        "--domains-csv", RAW_DATA / "domains" / "domains.csv",
        "--output-dir", blocking_out,
    ])

    generated_summary = json.loads((blocking_out / "web_content_summary.json").read_text(encoding="utf-8"))
    reference_summary = json.loads((REFERENCE_OUTPUTS / "web_content_summary.json").read_text(encoding="utf-8"))
    if generated_summary != reference_summary:
        raise SystemExit("Generated web_content_summary.json differs from the reference values")
    expected_figure = blocking_out / "resource_type_location_probability_by_sector_barcols_sorted_dom_doc.pdf"
    if not expected_figure.is_file():
        raise SystemExit(f"Missing section figure: {expected_figure}")
    print("Verified Web Content summary and figure filename")
    print(f"Outputs written to {OUTPUTS}")


if __name__ == "__main__":
    main()
