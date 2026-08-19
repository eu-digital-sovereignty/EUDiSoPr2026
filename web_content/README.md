# Web Content reproducibility artifact

The file `reference_outputs/section.tex` is the result of this artifact. 
The code and data reproduce its values and figures. It covers
both parts of the Web Content measurement:

1. the blocked-phase interception log used for outside-EU request shares,
   resource types, request destinations, and country/sector Web Layer scores;
   this log records both allowed EU and attempted outside-EU subrequests; and
2. comparison of the blocked rendering with two normal loads, used to measure
   visual, rendered-HTML, and visible-text changes while accounting for dynamic
   variation. The first normal load also determines crawl inclusion.

No paths containing a local user name or checkout location are required.

## Reproduce the analysis

Requirements are Python 3.10 or newer, `tar`, and `zstd`/`unzstd`.

```bash
python3 -m venv .venv
.venv/bin/pip install -r analysis/requirements.txt
.venv/bin/python analysis/reproduce.py
```

The runner extracts `data/raw_data.tar.zst` if necessary and writes all generated
CSV, JSON, TeX, and PDF files to `outputs/blocking_analysis/`. 

## Contents

- `analysis/third_party_web_resources_report.py` performs retained-domain
  filtering and generates the classified resource-type and destination results.
- `analysis/reproduce_web_content.py` generates the exact denominators, failure counts,
  request shares, raw visual-loss values, and `_doc.pdf` filename cited by the
  current section.
- `analysis/analyze_eu_check.py` documents the screenshot/HTML/text comparison
  that populated the derived metrics in the SQLite files. Re-running this stage
  requires the optional screenshots and HTML package.
- `crawler/` contains the Node.js/Puppeteer crawler and its dependency manifest.
- `reference_outputs/` contains section inputs.

## Packaged data

The main compressed archive contains `raw_data/crawl_blocked_paper/`, with one
sanitized SQLite database per crawl target, and `raw_data/domains/domains.csv`.
Each database includes statuses and captures for all three phases, the
blocked-phase request-decision log, and the stored comparison metrics. 

Screenshots, HARs, rendered HTML, and JavaScript are omitted from this repository
to keep the public artifact compact. Screenshots and HAR files
are available from the authors on request. The exact derived visual metrics
needed by the paper are retained in the packaged SQLite databases.

## Country sovereignty scores

`in_eu_request_summary.json` includes the section's all-event Web Layer results
by country-sector and is 
the web-content input available to combined sovereignty visualizations. The
country-ranking PDF currently included later in the paper.

All 1,988 input domains have a crawl record; 1,517 met the inclusion criteria.
All 17 Lithuanian government domains returned HTTP 403 challenge responses, so
that country-sector Web Layer score is unavailable.

## Manuscript counting note

The section's “Google Fonts and CSS on 83 government domains” is the sum of 74
CSS-pattern domain detections and 9 font-file-pattern domain detections. Six
domains occur in both groups, so the unique-domain union is 77. Both the summed
manuscript value and the deduplicated union are recorded in
`reference_outputs/web_content_summary.json`.
