#!/usr/bin/env python3
"""Generate the appendix SaaS-rules table from lookup_tables + latest analyzed_results.

Outputs two files (both in paper/tables/):
  - saas_rules.csv  (clean, human-readable: literal regex patterns)
  - saas_rules.tex  (full \\begin{tabular}...\\end{tabular} with LaTeX-escaped patterns)

All vendors with any detection are included. The 'Crit.' column shows 'X' if any of
the vendor's patterns is marked critical=yes in lookup_tables, blank otherwise.
Counts are deduped per domain.
"""

import csv
import glob
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SECTORS = ["government", "universities", "banks", "newspapers"]
COL = {"government": "Gov", "universities": "Uni", "banks": "Banks", "newspapers": "News"}


def tex_escape(s):
    """Escape LaTeX special chars present in our regex patterns (texttt-safe)."""
    return (s.replace("\\", "\\textbackslash{}")
             .replace("^", "\\^{}")
             .replace("_", "\\_")
             .replace("$", "\\$")
             .replace("&", "\\&")
             .replace("%", "\\%"))


def load_rules():
    """Return {vendor: {'hq': hq, 'critical': bool, 'rules': [(prefix, regex), ...]}}."""
    out = defaultdict(lambda: {"hq": "", "critical": False, "rules": []})
    for fname, prefix in [("txt_patterns.csv", "TXT"), ("mx_patterns.csv", "MX")]:
        with open(ROOT / "lookup_tables" / fname) as f:
            for r in csv.DictReader(f):
                v = r["vendor"]
                if not out[v]["hq"]:
                    out[v]["hq"] = r["hq"]
                if r.get("critical", "").strip().lower() == "yes":
                    out[v]["critical"] = True
                out[v]["rules"].append((prefix, r["regex"]))
    return out


def load_latest(sector):
    paths = sorted(f for f in glob.glob(str(ROOT / "results" / sector / "analyzed_results*.json"))
                   if "BEFORE" not in f)
    with open(paths[-1]) as f:
        return json.load(f)


def count_per_sector(vendors):
    counts = {v: {s: 0 for s in SECTORS} for v in vendors}
    totals = {}
    for s in SECTORS:
        entries = load_latest(s)
        totals[s] = len(entries)
        for e in entries:
            seen = set()
            for svc in e.get("detected_services", []):
                v = svc.get("vendor")
                if v in vendors and v not in seen:
                    counts[v][s] += 1
                    seen.add(v)
    pct = {v: {s: 100 * counts[v][s] / totals[s] for s in SECTORS} for v in counts}
    return pct, totals


def write_csv(rows, path):
    # Column header 'Rules' must match \Rules reference in main.tex template.
    # Multi-rule cells joined with ';' (not ',') to avoid csvsimple-l3 splitting on
    # quoted commas. Cells are LaTeX-escaped because main.tex wraps them in \texttt{}.
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Vendor", "HQ", "Crit", "Rules"] + [COL[s] for s in SECTORS])
        for vendor, hq, crit, rule_list, p in rows:
            rules_cell = "; ".join(f"{pre}: {tex_escape(rx)}" for pre, rx in rule_list)
            w.writerow([vendor, hq, "X" if crit else "", rules_cell]
                       + [f"{p[s]:.1f}" for s in SECTORS])


def write_tex(rows, path):
    lines = [
        "\\begin{tabular}{llc p{0.5\\textwidth} rrrr}",
        "\\toprule",
        "Vendor & HQ & Crit. & Rule(s) & Gov & News & Banks & Uni \\\\",
        "\\midrule",
    ]
    for vendor, hq, crit, rule_list, p in rows:
        rules_tex = "; ".join(f"{pre}: {tex_escape(rx)}" for pre, rx in rule_list)
        cells = [
            vendor.replace("&", "\\&"),
            hq,
            "X" if crit else "",
            f"\\texttt{{{rules_tex}}}",
            f"{p['government']:.1f}",
            f"{p['newspapers']:.1f}",
            f"{p['banks']:.1f}",
            f"{p['universities']:.1f}",
        ]
        lines.append(" & ".join(cells) + " \\\\")
    lines += ["\\bottomrule", "\\end{tabular}"]
    path.write_text("\n".join(lines) + "\n")


def main():
    rules = load_rules()
    pct, totals = count_per_sector(set(rules))

    rows = [(v, rules[v]["hq"], rules[v]["critical"], rules[v]["rules"], pct[v])
            for v in rules if sum(pct[v].values()) > 0]
    # Sort: critical first, then by total prevalence descending
    rows.sort(key=lambda r: (not r[2], -sum(r[4].values())))

    tables = ROOT / "paper" / "tables"
    write_csv(rows, tables / "saas_rules.csv")
    write_tex(rows, tables / "saas_rules.tex")
    print(f"Wrote {tables/'saas_rules.csv'} and {tables/'saas_rules.tex'} ({len(rows)} vendors)")
    print(f"Sector totals: {totals}")


if __name__ == "__main__":
    main()
