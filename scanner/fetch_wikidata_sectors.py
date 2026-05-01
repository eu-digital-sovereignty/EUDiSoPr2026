#!/usr/bin/env python3
"""Fetch EU domain lists by sector from Wikidata SPARQL.

Sectors: newspapers, banks, universities.
Each sector queries Wikidata per EU-27 country, with a fallback to broader
entity types for countries below a minimum threshold.
"""

import argparse
import json
import time
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

WIKIDATA_ENDPOINT = "https://query.wikidata.org/sparql"
USER_AGENT = "EU-Gov-Infrastructure-Research/1.0 (academic research)"

EU_COUNTRIES = [
    ("AT", "Q40",  "Austria"),
    ("BE", "Q31",  "Belgium"),
    ("BG", "Q219", "Bulgaria"),
    ("HR", "Q224", "Croatia"),
    ("CY", "Q229", "Cyprus"),
    ("CZ", "Q213", "Czechia"),
    ("DK", "Q35",  "Denmark"),
    ("EE", "Q191", "Estonia"),
    ("FI", "Q33",  "Finland"),
    ("FR", "Q142", "France"),
    ("DE", "Q183", "Germany"),
    ("GR", "Q41",  "Greece"),
    ("HU", "Q28",  "Hungary"),
    ("IE", "Q27",  "Ireland"),
    ("IT", "Q38",  "Italy"),
    ("LV", "Q211", "Latvia"),
    ("LT", "Q37",  "Lithuania"),
    ("LU", "Q32",  "Luxembourg"),
    ("MT", "Q233", "Malta"),
    ("NL", "Q55",  "Netherlands"),
    ("PL", "Q36",  "Poland"),
    ("PT", "Q45",  "Portugal"),
    ("RO", "Q218", "Romania"),
    ("SK", "Q214", "Slovakia"),
    ("SI", "Q215", "Slovenia"),
    ("ES", "Q29",  "Spain"),
    ("SE", "Q34",  "Sweden"),
]

SECTORS = {
    "newspapers": {
        "types": [("Q1110794", "daily newspaper"), ("Q11032", "newspaper")],
        "category": "newspaper",
        "min_per_country": 3,
    },
    "banks": {
        "types": [("Q22687", "bank"), ("Q837171", "commercial bank")],
        "category": "bank",
        "min_per_country": 2,
    },
    "universities": {
        "types": [("Q3918", "university"), ("Q875538", "public university")],
        "category": "university",
        "min_per_country": 3,
    },
}


def query_wikidata(sparql: str) -> list[dict]:
    data = urllib.parse.urlencode({"query": sparql}).encode()
    req = urllib.request.Request(
        WIKIDATA_ENDPOINT,
        data=data,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/sparql-results+json",
        },
    )
    with urllib.request.urlopen(req, timeout=45) as resp:
        return json.loads(resp.read())["results"]["bindings"]


def fetch_entities(country_qid: str, type_qid: str) -> list[dict]:
    sparql = f"""
    SELECT ?entity ?entityLabel ?website WHERE {{
      ?entity wdt:P31 wd:{type_qid} .
      ?entity wdt:P17 wd:{country_qid} .
      ?entity wdt:P856 ?website .
      SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en" . }}
    }}
    """
    return query_wikidata(sparql)


def extract_domain(url: str) -> str:
    domain = urlparse(url).netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def fetch_sector(sector_name: str, cfg: dict, delay: float) -> list[dict]:
    types = cfg["types"]
    category = cfg["category"]
    min_per_country = cfg["min_per_country"]
    entries = []
    seen = set()

    for i, (type_qid, type_label) in enumerate(types):
        if i == 0:
            countries = EU_COUNTRIES
            print(f"\n  Primary: {type_label} ({type_qid})")
        else:
            cc_counts = Counter(e["country_code"] for e in entries)
            countries = [(cc, qid, name) for cc, qid, name in EU_COUNTRIES
                         if cc_counts.get(cc, 0) < min_per_country]
            if not countries:
                break
            print(f"\n  Fallback: {type_label} ({type_qid}) for {len(countries)} countries")

        for cc, qid, country_name in countries:
            try:
                results = fetch_entities(qid, type_qid)
                count = 0
                for r in results:
                    domain = extract_domain(r["website"]["value"])
                    if domain and domain not in seen and "." in domain and " " not in domain:
                        seen.add(domain)
                        entries.append({
                            "domain": domain,
                            "name": r["entityLabel"]["value"],
                            "country": country_name,
                            "country_code": cc,
                            "category": category,
                        })
                        count += 1
                prefix = "+" if i > 0 else ""
                print(f"    {cc} ({country_name:15}): {prefix}{count:3}")
            except Exception as e:
                print(f"    {cc} ({country_name:15}): ERROR - {e}")
            time.sleep(delay)

    entries.sort(key=lambda e: (e["country_code"], e["domain"]))
    return entries


def print_summary(entries: list[dict], sector_name: str):
    cc_counts = Counter(e["country_code"] for e in entries)
    if not entries:
        print("  No results found!")
        return
    lo = min(cc_counts, key=cc_counts.get)
    hi = max(cc_counts, key=cc_counts.get)
    print(f"\n  {sector_name}: {len(entries)} domains, {len(cc_counts)}/27 countries")
    print(f"  Min: {cc_counts[lo]} ({lo}), Max: {cc_counts[hi]} ({hi})")
    for cc in sorted(cc_counts):
        print(f"    {cc}: {cc_counts[cc]:3}")


def main():
    parser = argparse.ArgumentParser(
        description="Fetch EU domain lists by sector from Wikidata")
    parser.add_argument("sectors", nargs="*", default=list(SECTORS.keys()),
                        choices=list(SECTORS.keys()),
                        help="Sectors to fetch (default: all)")
    parser.add_argument("--delay", type=float, default=2.0,
                        help="Delay between requests in seconds")
    parser.add_argument("--output-dir", default="data",
                        help="Output directory (default: data)")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    for name in args.sectors:
        cfg = SECTORS[name]
        print(f"\n{'#' * 60}")
        print(f"# {name}")
        print(f"{'#' * 60}")

        entries = fetch_sector(name, cfg, args.delay)
        print_summary(entries, name)

        path = out_dir / f"{name}.json"
        path.write_text(json.dumps(entries, indent=2, ensure_ascii=False) + "\n")
        print(f"  Saved to {path}")


if __name__ == "__main__":
    main()
