#!/usr/bin/env python3
"""Export top-10 provider tables from analyzed_results into paper/tables/."""

import csv
import glob
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TABLES_DIR = ROOT / "paper" / "tables"

EU = set("AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE".split())


def load_entries():
    entries = []
    for sector in ["government", "banks", "newspapers", "universities"]:
        path = sorted(
            f for f in glob.glob(f"{ROOT}/results/{sector}/analyzed_results*.json")
            if "BEFORE" not in f
        )[-1]
        with open(path) as f:
            entries.extend(json.load(f))
    return entries


def load_ssl():
    with open(ROOT / "results" / "ssl_collection.json") as f:
        return [r for r in json.load(f)["results"] if not r.get("error")]


def load_ca_overrides():
    rows = []
    with open(ROOT / "lookup_tables" / "ca_database.csv") as f:
        for row in csv.reader(f):
            if row and not row[0].startswith("#") and row[0] != "pattern":
                rows.append((row[0].lower(), row[2]))
    return rows


def load_critical_vendors():
    vendors = set()
    for fname in ("txt_patterns.csv", "mx_patterns.csv"):
        with open(ROOT / "lookup_tables" / fname) as f:
            for row in csv.DictReader(f):
                if row.get("critical", "").strip().lower() == "yes":
                    vendors.add(row["vendor"])
    return vendors


def apply_ca_override(issuer, country, overrides):
    issuer_l = (issuer or "").lower()
    for pattern, cc in overrides:
        if pattern in issuer_l:
            return cc
    return country


def ns_group_key(ns_host):
    parts = ns_host.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return ns_host


NS_ALIASES = {
    "akam.net": "Akamai",
    "akamaiedge.net": "Akamai",
    "awsdns-53.org": "Amazon",
    "awsdns-53.co.uk": "Amazon",
    "awsdns-53.com": "Amazon",
    "awsdns-53.net": "Amazon",
    "ultradns.biz": "UltraDNS",
    "ultradns.com": "UltraDNS",
    "ultradns.net": "UltraDNS",
    "ultradns.org": "UltraDNS",
    "cw.net": "Centurylink",
    "ARUBA-ASN, IT": "Aruba",
}


def count_nameservers(entries):
    counter = Counter()
    country_for = {}
    for e in entries:
        seen = set()
        for p in e.get("ns_providers", []):
            raw = p.get("provider") or ns_group_key(p.get("ns", ""))
            name = NS_ALIASES.get(raw, raw)
            if not name or name in seen:
                continue
            seen.add(name)
            counter[name] += 1
            country_for.setdefault(name, p.get("hq") or "—")
    return counter, country_for


def count_hosting(entries):
    counter = Counter()
    country_for = {}
    for e in entries:
        name = e.get("hosting_provider")
        if not name:
            continue
        counter[name] += 1
        country_for.setdefault(name, e.get("hosting_provider_hq") or "—")
    return counter, country_for


def count_email(entries):
    counter = Counter()
    country_for = {}
    for e in entries:
        name = e.get("email_provider")
        if not name:
            continue
        counter[name] += 1
        country_for.setdefault(name, e.get("email_provider_hq") or "—")
    return counter, country_for


def count_certificates(ssl_ok, overrides):
    counter = Counter()
    country_for = {}
    for r in ssl_ok:
        name = r.get("ssl_issuer_org")
        if not name:
            continue
        counter[name] += 1
        country_for.setdefault(
            name, apply_ca_override(name, r.get("ssl_issuer_country"), overrides) or "—"
        )
    return counter, country_for


def count_saas(entries, critical_vendors):
    counter = Counter()
    country_for = {}
    for e in entries:
        seen = set()
        for s in e.get("detected_services", []):
            name = s.get("vendor")
            if not name or name not in critical_vendors or name in seen:
                continue
            seen.add(name)
            counter[name] += 1
            country_for.setdefault(name, s.get("hq_country") or "—")
    return counter, country_for


def write_top10(out_path, counter, country_for, total, caption, label):
    rows = counter.most_common(20)
    lines = [
        "\\begin{tabular}{rElrr}",
        "\\toprule",
        " & Name & Country & Count & \\% \\\\",
        "\\midrule",
    ]
    for rank, (name, count) in enumerate(rows, 1):
        pct = 100 * count / total
        name_tex = name.replace("&", "\\&").replace("_", "\\_")
        country = country_for.get(name, "—")
        lines.append(f"{rank} & {name_tex} & {country} & {count} & {pct:.1f} \\\\")
    lines.extend(["\\bottomrule", "\\end{tabular}"])
    out_path.write_text("\n".join(lines) + "\n")
    print(f"Wrote {out_path} ({len(rows)} rows)")


def main():
    entries = load_entries()
    ssl_ok = load_ssl()
    overrides = load_ca_overrides()
    total = len(entries)
    print(f"Total domains: {total}, TLS certs: {len(ssl_ok)}")

    ns_cnt, ns_cc = count_nameservers(entries)
    host_cnt, host_cc = count_hosting(entries)
    email_cnt, email_cc = count_email(entries)
    cert_cnt, cert_cc = count_certificates(ssl_ok, overrides)
    saas_cnt, saas_cc = count_saas(entries, load_critical_vendors())

    TABLES_DIR.mkdir(parents=True, exist_ok=True)

    write_top10(TABLES_DIR / "tab_nameserver_top.tex",   ns_cnt,   ns_cc,   total, "", "")
    write_top10(TABLES_DIR / "tab_hosting_top.tex",      host_cnt, host_cc, total, "", "")
    write_top10(TABLES_DIR / "tab_certificates_top.tex", cert_cnt, cert_cc, total, "", "")
    write_top10(TABLES_DIR / "tab_email_top.tex",        email_cnt, email_cc, total, "", "")
    write_top10(TABLES_DIR / "tab_saas_top.tex",         saas_cnt, saas_cc, total, "", "")


if __name__ == "__main__":
    main()
