#!/usr/bin/env python3
"""Generate the Web Content measurement summary."""

import argparse
import json
import shutil
from collections import Counter
from pathlib import Path
from statistics import mean

import third_party_web_resources_report as report


SECTOR_LABELS = {
    "government": "Government",
    "university": "University",
    "bank": "Bank",
    "newspaper": "Newspaper",
}


def failure_summary(pages):
    counts = Counter()
    status_counts = Counter()
    for page in pages:
        if report.normal_load_success(page):
            counts["successful"] += 1
            continue
        status = page.get("normal_1_status")
        blank = page.get("normal_1_blank_white")
        status_counts[str(status) if status is not None else "none"] += 1
        if status is None:
            counts["no_main_document_http_status"] += 1
        elif 400 <= int(status) < 500:
            counts["http_4xx"] += 1
        elif int(status) in (200, 202) and blank == 1:
            counts["http_200_202_blank_screenshot"] += 1
        else:
            counts["other_excluded"] += 1

    lt_government = [
        page for page in pages
        if page["category"] == "government" and page["country_code"] == "LT"
    ]
    return {
        "input_domain_count": len(pages),
        "successful_domain_count": counts["successful"],
        "excluded_domain_count": len(pages) - counts["successful"],
        "exclusion_reasons": {
            "no_main_document_http_status": counts["no_main_document_http_status"],
            "http_200_202_blank_screenshot": counts["http_200_202_blank_screenshot"],
            "http_4xx": counts["http_4xx"],
            "http_403": status_counts["403"],
            "other_excluded": counts["other_excluded"],
        },
        "normal_1_status_counts_among_excluded": dict(sorted(status_counts.items())),
        "lithuania_government": {
            "input_domain_count": len(lt_government),
            "http_403_count": sum(page.get("normal_1_status") == 403 for page in lt_government),
        },
    }


def raw_blocking_by_sector(pages):
    rows = []
    for sector in report.SECTOR_ORDER:
        sector_pages = [page for page in pages if page["category"] == sector]

        def metric(field, transform=lambda value: value):
            values = [report.safe_float(page.get(field)) for page in sector_pages]
            values = [transform(value) for value in values if value is not None]
            return round(mean(values), 6) if values else None

        rows.append({
            "category": sector,
            "domain_count": len(sector_pages),
            "visual_loss_mean_pct": metric("blocked_diff_pct"),
            "visual_loss_n": sum(page.get("blocked_diff_pct") is not None for page in sector_pages),
            "html_loss_mean_pct": metric("blocked_html_similarity_ratio", lambda value: 100 * (1 - value)),
            "html_loss_n": sum(page.get("blocked_html_similarity_ratio") is not None for page in sector_pages),
        })
    return rows


def by_vendor(rows, vendor, sector=None):
    for row in rows:
        if row["vendor"] == vendor and (sector is None or row.get("category") == sector):
            return row
    raise KeyError((sector, vendor))


def pattern_government_domains(patterns, name):
    for pattern in patterns:
        if pattern["pattern"] == name:
            return {
                row["domain"] for row in pattern["domains"]
                if row["category"] == "government"
            }
    raise KeyError(name)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main():
    artifact_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--crawl-dir", type=Path, default=artifact_root / "data/raw_data/crawl_blocked_paper")
    parser.add_argument("--domains-csv", type=Path, default=artifact_root / "data/raw_data/domains/domains.csv")
    parser.add_argument("--output-dir", type=Path, default=artifact_root / "outputs/blocking_analysis")
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    meta = report.load_domain_meta(args.domains_csv)
    pages, requests, _ = report.load_rows(args.crawl_dir, meta)
    pages, requests, _ = report.deduplicate_to_one_run_per_domain(pages, requests)
    failures = failure_summary(pages)
    retained_pages, retained_requests, retained_meta = report.filter_to_successful_normal_loads(pages, requests, meta)
    classified = report.classified_subrequests(retained_requests)

    # The current section uses every recorded blocked-phase event as the request
    # denominator. A row is outside EU when row_external() says so; all remaining
    # events are counted as not outside EU. Resource-type and destination analyses
    # remain restricted to classified subrequests.
    any_outside = report.summarize_any_outside_by_sector_country(retained_meta, retained_requests)
    in_eu = report.summarize_in_eu_by_sector_country(retained_meta, retained_requests)
    in_eu.pop("per_domain", None)
    in_eu["request_population"] = "all recorded blocked-phase request events"
    in_eu["classification_note"] = (
        "Outside-EU events satisfy row_external(); all other recorded events are "
        "included as not outside EU for the manuscript's all-event denominator."
    )

    pattern_evidence = report.resource_pattern_domain_evidence(classified)
    patterns = pattern_evidence["patterns"]
    vendors, vendors_by_sector = report.any_asn_org_domain_share(retained_meta, classified)
    blocking = raw_blocking_by_sector(retained_pages)

    font_css_domains = pattern_government_domains(patterns, "Google Fonts CSS")
    font_file_domains = pattern_government_domains(patterns, "Google Fonts files")
    font_domains = font_css_domains | font_file_domains
    named_patterns = [
        "Google Tag Manager", "Google Analytics", "jsDelivr CDN",
        "Cloudflare cdnjs", "Facebook events/SDK", "Cloudflare Insights",
        "Matomo/Piwik",
    ]
    pattern_counts = {
        name: len(pattern_government_domains(patterns, name))
        for name in named_patterns
    }
    pattern_counts["Google Fonts CSS"] = len(font_css_domains)
    pattern_counts["Google Fonts files"] = len(font_file_domains)
    pattern_counts["Google Fonts CSS plus files (summed pattern counts)"] = (
        len(font_css_domains) + len(font_file_domains)
    )
    pattern_counts["Google Fonts CSS or files (unique-domain union)"] = len(font_domains)

    domain_vendors = {
        label: by_vendor(vendors, vendor)["domain_share_pct"]
        for label, vendor in {
            "Google": "Google LLC",
            "Cloudflare": "Cloudflare, Inc.",
            "Amazon": "Amazon.com, Inc.",
            "Fastly": "Fastly, Inc.",
            "Microsoft": "Microsoft Corporation",
        }.items()
    }
    request_vendors = {
        label: by_vendor(vendors, vendor)["request_share_pct"]
        for label, vendor in {
            "Amazon": "Amazon.com, Inc.",
            "Cloudflare": "Cloudflare, Inc.",
            "Akamai": "Akamai International B.V.",
            "Google": "Google LLC",
            "Microsoft": "Microsoft Corporation",
            "Fastly": "Fastly, Inc.",
        }.items()
    }
    government_vendors = {
        label: by_vendor(vendors_by_sector, vendor, "government")["domain_share_pct"]
        for label, vendor in {
            "Google": "Google LLC",
            "Cloudflare": "Cloudflare, Inc.",
            "Amazon": "Amazon.com, Inc.",
        }.items()
    }

    summary = {
        "crawl": failures,
        "request_share": {
            "overall": any_outside["overall"],
            "mean_domain_in_eu_request_share_pct_by_sector": {
                SECTOR_LABELS[row["category"]]: row["mean_domain_in_eu_request_share_pct"]
                for row in in_eu["by_sector"]
            },
            "domains_only_in_eu_share_pct_by_sector": {
                SECTOR_LABELS[row["category"]]: row["domains_only_in_eu_share_pct"]
                for row in in_eu["by_sector"]
            },
        },
        "government_named_resource_domain_counts": pattern_counts,
        "request_destinations": {
            "domain_share_pct": domain_vendors,
            "request_share_pct": request_vendors,
            "government_domain_share_pct": government_vendors,
        },
        "blocking_effect_by_sector": blocking,
    }

    write_json(args.output_dir / "failure_reasons_summary.json", failures)
    write_json(args.output_dir / "any_outside_request_summary.json", any_outside)
    write_json(args.output_dir / "in_eu_request_summary.json", in_eu)
    write_json(args.output_dir / "web_content_summary.json", summary)
    report.write_csv(args.output_dir / "blocking_effect_by_sector.csv", blocking)

    source_pdf = args.output_dir / "resource_type_location_probability_by_sector_barcols_sorted_dom.pdf"
    if source_pdf.exists():
        shutil.copy2(source_pdf, args.output_dir / "resource_type_location_probability_by_sector_barcols_sorted_dom_doc.pdf")

    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
