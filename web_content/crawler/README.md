# Crawler

This directory contains the data-collection code separately from the analysis.
It records three loads per target (`normal_1`, `blocked`, and `normal_2`) in a
SQLite database and optionally saves screenshots, rendered HTML, and HAR files.

Requires Node.js 22 or newer:

```bash
npm install
npm run crawl -- --urls-file urls.txt --storage-dir crawl_output
```

The crawler uses the CAIDA AS Rank API and, when available, a MaxMind-compatible
country database configured with `MMDB_PATH`. Its command-line options are
defined in `parseArgs()` near the beginning of `crawler_eu_check.js`.

