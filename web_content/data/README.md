# Packaged Web Content data

`raw_data.tar.zst` contains the sanitized SQLite databases and domain metadata
needed by `../analysis/reproduce.py`. It extracts to `data/raw_data/`:

```bash
tar --use-compress-program=unzstd -xf data/raw_data.tar.zst -C data
```

The archive retains page records for all three load phases, the blocked-phase
request-decision log, and the derived comparison metrics used by the paper.

Large capture files are intentionally not included in this repository. Reduced
screenshots and sanitized HAR files are available from the authors on request.
Rendered HTML and JavaScript are also omitted. The stored SQLite metrics are
sufficient to reproduce the Web Content section's reported results and figure.

SHA-256:

```text
2e4514b228ee3fea9472bf41d7acc9bd15ba18a785b5009295b759f37ab8c450  raw_data.tar.zst
```
