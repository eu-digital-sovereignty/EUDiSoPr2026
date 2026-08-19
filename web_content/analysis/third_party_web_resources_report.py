#!/usr/bin/env python3
import argparse
import shutil
import csv
import json
import math
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean
from urllib.parse import urlparse

import matplotlib as mpl
mpl.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

EU_ALLOWED = {
    'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU',
    'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES',
    'SE', 'EU',
}
SECTOR_ORDER = ['government', 'university', 'bank', 'newspaper']
SECTOR_LABELS = {
    'government': 'Government',
    'university': 'University',
    'bank': 'Bank',
    'newspaper': 'Newspaper',
}
SECTOR_COLORS = {
    'government': '#4C78A8',
    'university': '#72B7B2',
    'bank': '#F58518',
    'newspaper': '#E45756',
}
SECTOR_MARKERS = {
    'government': 'o',
    'university': 's',
    'bank': '^',
    'newspaper': 'D',
}
IN_SCOPE = 'In EU'
OUT_SCOPE = 'outside EU'
SCOPE_COLORS = {IN_SCOPE: '#B8B8B8', OUT_SCOPE: '#8C2F39'}
HATCHES = {'government': '', 'university': '///', 'bank': '...', 'newspaper': 'xxx'}
RESOURCE_ORDER = ['script', 'image', 'other', 'stylesheet', 'fetch', 'xhr', 'font', 'document', 'ping', 'media', 'manifest', 'unknown']
RESOURCE_PATTERNS = {
    'Google Tag Manager': ['googletagmanager.com'],
    'Google Fonts CSS': ['fonts.googleapis.com'],
    'Google Fonts files': ['fonts.gstatic.com'],
    'Google Analytics': ['google-analytics.com'],
    'Google DoubleClick/GPT': ['doubleclick.net', 'googlesyndication.com', 'securepubads.g.doubleclick.net'],
    'reCAPTCHA': ['google.com/recaptcha', 'gstatic.com/recaptcha', 'recaptcha.net'],
    'Facebook events/SDK': ['facebook.net', 'connect.facebook.net', 'fbevents.js'],
    'Hotjar': ['hotjar.com'],
    'Cloudflare Insights': ['static.cloudflareinsights.com', 'beacon.min.js'],
    'Matomo/Piwik': ['matomo', 'piwik'],
    'jsDelivr CDN': ['cdn.jsdelivr.net'],
    'Cloudflare cdnjs': ['cdnjs.cloudflare.com'],
    'Amazon S3': ['amazonaws.com', '.s3.'],
    'Amazon CloudFront': ['cloudfront.net'],
}

mpl.rcParams.update({
    'pdf.fonttype': 42,
    'ps.fonttype': 42,
    'font.family': 'serif',
    'font.size': 10,
    'axes.titlesize': 10,
    'axes.linewidth': 0.6,
    'xtick.major.width': 0.5,
    'ytick.major.width': 0.5,
    'axes.labelsize': 10,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'legend.fontsize': 9,
    'axes.spines.top': False,
    'axes.spines.right': False,
})


ARTIFACT_ROOT = Path(__file__).resolve().parent.parent
RAW_DATA_DIR = ARTIFACT_ROOT / 'data' / 'raw_data'
SQLITE_REPRODUCIBLE_DIR = ARTIFACT_ROOT / 'outputs' / 'sqlite_reproducible'


def parse_args():
    parser = argparse.ArgumentParser(description='Paper evaluation for third-party web resources from EU-check blocked crawl DBs.')
    parser.add_argument('--crawl-dir', default=RAW_DATA_DIR / 'crawl_blocked_paper')
    parser.add_argument('--domains-csv', default=RAW_DATA_DIR / 'domains' / 'domains.csv')
    parser.add_argument('--output-dir', default=ARTIFACT_ROOT / 'outputs' / 'blocking_analysis')
    return parser.parse_args()


def safe_float(value):
    if value is None or value == '':
        return None
    try:
        if isinstance(value, float) and math.isnan(value):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def load_domain_meta(path: Path):
    meta = {}
    with path.open(encoding='utf-8', newline='') as handle:
        reader = csv.DictReader(handle, delimiter=';')
        for row in reader:
            domain = row['domain'].strip().lower()
            meta[domain] = {
                'domain': domain,
                'category': row['category'].strip().lower(),
                'country': row['country'].strip(),
                'country_code': row['country_code'].strip().upper(),
            }
    return meta


def lookup_meta(host: str, meta: dict):
    host = (host or '').lower().strip().strip('.')
    candidates = [host]
    if host.startswith('www.'):
        candidates.append(host[4:])
    for candidate in candidates:
        if candidate in meta:
            return meta[candidate]
    best = None
    for domain, record in meta.items():
        if host == domain or host.endswith('.' + domain):
            if best is None or len(domain) > len(best['domain']):
                best = record
    return best


def row_external(row):
    if (row.get('decision') or '').lower() == 'block':
        return True
    ip_country = (row.get('ip_country_code') or '').upper()
    as_country = (row.get('caida_as_country_code') or '').upper()
    if ip_country and ip_country not in EU_ALLOWED:
        return True
    if as_country and as_country not in EU_ALLOWED:
        return True
    return False


def row_main_hosted(row):
    page_domain = (row.get('page_domain') or row.get('input_domain') or '').lower().strip().strip('.')
    request_host = (row.get('request_host') or '').lower().strip().strip('.')
    if not page_domain or not request_host:
        return False
    if request_host == page_domain:
        return True
    if request_host.endswith('.' + page_domain):
        return True
    if request_host.startswith('www.') and request_host[4:] == page_domain:
        return True
    return False


def clean_resource_type(value):
    value = (value or '').strip().lower()
    return value or 'unknown'


def iter_dbs(crawl_dir: Path):
    return sorted(crawl_dir.glob('*/crawler_eu_check.sqlite'))


def load_rows(crawl_dir: Path, meta: dict):
    pages = []
    requests = []
    missing_meta = Counter()
    for sqlite_path in iter_dbs(crawl_dir):
        con = sqlite3.connect(sqlite_path)
        con.row_factory = sqlite3.Row
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if 'eu_check_pages' not in tables:
            con.close()
            continue
        has_analysis = 'eu_check_analysis' in tables
        query = '''
            SELECT p.*, a.blocked_diff_pct, a.blocked_blurred_diff_pct,
                   a.net_blocked_minus_dynamic_diff_pct, a.net_blocked_minus_dynamic_blurred_diff_pct,
                   a.blocked_html_similarity_ratio, a.blocked_content_token_jaccard,
                   a.blocked_browser_error, a.blocked_error_marker,
                   a.normal_1_blank_white, a.blocked_blank_white, a.normal_2_blank_white
            FROM eu_check_pages p
            LEFT JOIN eu_check_analysis a ON a.page_id = p.id
        ''' if has_analysis else 'SELECT p.* FROM eu_check_pages p'
        page_records = {}
        for prow in con.execute(query):
            record = dict(prow)
            host = record.get('page_domain') or urlparse(record.get('page_url') or '').hostname or ''
            m = lookup_meta(host, meta)
            if not m:
                missing_meta[host] += 1
                continue
            record.update(m)
            record['input_domain'] = m['domain']
            record['sqlite_path'] = str(sqlite_path)
            record['blocked_flag'] = int((record.get('blocked_browser_error') or 0) == 1 or record.get('blocked_status') is None)
            visual = safe_float(record.get('net_blocked_minus_dynamic_diff_pct'))
            if visual is None:
                visual = safe_float(record.get('blocked_diff_pct'))
            html_sim = safe_float(record.get('blocked_html_similarity_ratio'))
            text_sim = safe_float(record.get('blocked_content_token_jaccard'))
            record['visual_diff_share'] = None if visual is None else max(min(visual / 100.0, 1.0), 0.0)
            record['html_structural_loss'] = None if html_sim is None else max(min(1.0 - html_sim, 1.0), 0.0)
            record['text_loss'] = None if text_sim is None else max(min(1.0 - text_sim, 1.0), 0.0)
            comps = [record[k] for k in ['visual_diff_share', 'html_structural_loss', 'text_loss'] if record.get(k) is not None]
            record['domain_score'] = mean(comps) if comps else None
            record['blocked_or_domain_score'] = 1.0 if record['blocked_flag'] else record['domain_score']
            pages.append(record)
            page_records[record['id']] = record
        main_host_evidence = defaultdict(list)
        if 'eu_check_requests' in tables:
            for rrow in con.execute('SELECT * FROM eu_check_requests'):
                req = dict(rrow)
                if req.get('page_id') not in page_records:
                    continue
                if (req.get('block_reason') or '') == 'allow_same_as_main_asn':
                    main_host_evidence[req['page_id']].append(row_external(req))
                page = page_records[req['page_id']]
                req.update({
                    'category': page['category'],
                    'country_code': page['country_code'],
                    'page_domain': page['page_domain'],
                    'input_domain': page['input_domain'],
                    'scope_group': 'outside EU' if row_external(req) else IN_SCOPE,
                    'resource_type': clean_resource_type(req.get('resource_type')),
                    'vendor': (req.get('caida_as_org_name') or req.get('as_name') or req.get('request_host') or 'unknown').strip() or 'unknown',
                    'sqlite_path': page['sqlite_path'],
                })
                requests.append(req)
        for page_id, evidence in main_host_evidence.items():
            page_records[page_id]['main_host_scope'] = OUT_SCOPE if any(evidence) else IN_SCOPE
        for page in page_records.values():
            page.setdefault('main_host_scope', 'Unknown')
        con.close()
    return pages, requests, missing_meta




def page_selection_key(page):
    has_analysis = int(page.get('domain_score') is not None or page.get('blocked_browser_error') is not None)
    request_count = int(page.get('blocked_request_count') or 0)
    status_present = int(page.get('blocked_status') is not None)
    return (has_analysis, request_count, status_present, str(page.get('sqlite_path') or ''), int(page.get('id') or 0))


def deduplicate_to_one_run_per_domain(pages, requests):
    grouped = defaultdict(list)
    for page in pages:
        grouped[page['input_domain']].append(page)
    selected = {}
    duplicate_rows = []
    for domain, items in grouped.items():
        chosen = sorted(items, key=page_selection_key, reverse=True)[0]
        selected[(chosen['sqlite_path'], chosen['id'])] = chosen
        if len(items) > 1:
            duplicate_rows.append({
                'input_domain': domain,
                'category': chosen['category'],
                'run_count': len(items),
                'kept_sqlite_path': chosen['sqlite_path'],
                'kept_page_id': chosen['id'],
            })
    selected_pages = list(selected.values())
    selected_requests = [r for r in requests if (r.get('sqlite_path'), r.get('page_id')) in selected]
    return selected_pages, selected_requests, duplicate_rows


def is_success_status(value):
    try:
        status = int(value)
    except (TypeError, ValueError):
        return False
    return 200 <= status < 400


def normal_load_success(page):
    return is_success_status(page.get('normal_1_status')) and page.get('normal_1_blank_white') == 0


def filter_to_successful_normal_loads(pages, requests, meta):
    selected_pages = [page for page in pages if normal_load_success(page)]
    selected_keys = {(page['category'], page['input_domain']) for page in selected_pages}
    selected_domains = {page['input_domain'] for page in selected_pages}
    selected_requests = [
        row for row in requests
        if (row['category'], row['input_domain']) in selected_keys
    ]
    selected_meta = subset_meta(meta, selected_domains)
    return selected_pages, selected_requests, selected_meta


def classified_subrequests(requests):
    rows = []
    for row in requests:
        if (row.get('block_reason') or '') == 'allow_main_navigation':
            continue
        if not row.get('request_host'):
            continue
        if not (row.get('ip_country_code') or row.get('caida_as_country_code') or row.get('decision') == 'block'):
            continue
        rows.append(row)
    return rows


def analysis_coverage_summary(meta, pages, selected_pages):
    input_by_sector = input_domains_by_sector(meta)
    selected_by_sector = defaultdict(set)
    for page in selected_pages:
        selected_by_sector[page['category']].add(page['input_domain'])

    rows = []
    for sector in SECTOR_ORDER:
        input_n = len(input_by_sector[sector])
        selected_n = len(selected_by_sector[sector])
        rows.append({
            'category': sector,
            'input_domain_count': input_n,
            'analyzed_domain_count': selected_n,
            'excluded_domain_count': input_n - selected_n,
            'analyzed_share_pct': round(pct(selected_n, input_n), 3),
        })
    return {
        'input_domain_count': len(meta),
        'crawl_row_count': len(pages),
        'analyzed_domain_count': len(selected_pages),
        'excluded_domain_count': len(meta) - len(selected_pages),
        'analyzed_share_pct': round(pct(len(selected_pages), len(meta)), 3),
        'filter': 'normal_1_status is 2xx/3xx and normal_1_blank_white == 0',
        'by_sector': rows,
    }

def write_csv(path: Path, rows, fieldnames=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = list(rows)
    if fieldnames is None:
        fieldnames = []
        for row in rows:
            for key in row.keys():
                if key not in fieldnames:
                    fieldnames.append(key)
    with path.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in fieldnames})


def copy_outputs(paths, target_dir: Path):
    target_dir.mkdir(parents=True, exist_ok=True)
    for path in paths:
        path = Path(path)
        if path.exists():
            shutil.copy2(path, target_dir / path.name)


def pct(num, den):
    return 100.0 * num / den if den else 0.0


def request_signature(url):
    parsed = urlparse(url or '')
    host = (parsed.hostname or '').lower()
    path = parsed.path or '/'
    if len(path) > 90:
        path = path[:87] + '...'
    return f'{host}{path}'


def summarize_any_outside_by_sector_country(meta, requests):
    domains_by_sector = input_domains_by_sector(meta)
    domains_by_country = defaultdict(set)
    for domain, record in meta.items():
        domains_by_country[record['country_code']].add(domain)

    outside_by_domain = defaultdict(bool)
    outside_request_counts = Counter()
    total_request_counts = Counter()
    for row in requests:
        key = (row['category'], row['country_code'], row['input_domain'])
        total_request_counts[key] += 1
        if row['scope_group'] == OUT_SCOPE:
            outside_by_domain[key] = True
            outside_request_counts[key] += 1

    sector_rows = []
    for sector in SECTOR_ORDER:
        domains = domains_by_sector[sector]
        outside_domains = [
            domain for domain in domains
            if outside_by_domain[(sector, meta[domain]['country_code'], domain)]
        ]
        total_requests = sum(
            total_request_counts[(sector, meta[domain]['country_code'], domain)]
            for domain in domains
        )
        outside_requests = sum(
            outside_request_counts[(sector, meta[domain]['country_code'], domain)]
            for domain in domains
        )
        sector_rows.append({
            'category': sector,
            'input_domain_count': len(domains),
            'domains_with_any_outside_request': len(outside_domains),
            'domain_share_pct': round(pct(len(outside_domains), len(domains)), 3),
            'total_request_count': total_requests,
            'outside_request_count': outside_requests,
            'outside_request_share_pct': round(pct(outside_requests, total_requests), 3),
        })

    country_rows = []
    for country_code in sorted(domains_by_country):
        domains = domains_by_country[country_code]
        outside_domains = [
            domain for domain in domains
            if outside_by_domain[(meta[domain]['category'], country_code, domain)]
        ]
        total_requests = sum(
            total_request_counts[(meta[domain]['category'], country_code, domain)]
            for domain in domains
        )
        outside_requests = sum(
            outside_request_counts[(meta[domain]['category'], country_code, domain)]
            for domain in domains
        )
        country_rows.append({
            'country_code': country_code,
            'input_domain_count': len(domains),
            'domains_with_any_outside_request': len(outside_domains),
            'domain_share_pct': round(pct(len(outside_domains), len(domains)), 3),
            'total_request_count': total_requests,
            'outside_request_count': outside_requests,
            'outside_request_share_pct': round(pct(outside_requests, total_requests), 3),
        })

    total_domains = len(meta)
    domains_with_outside = set()
    total_requests = 0
    outside_requests = 0
    for domain, record in meta.items():
        key = (record['category'], record['country_code'], domain)
        total_requests += total_request_counts[key]
        outside_requests += outside_request_counts[key]
        if outside_by_domain[key]:
            domains_with_outside.add((record['category'], domain))

    return {
        'overall': {
            'input_domain_count': total_domains,
            'domains_with_any_outside_request': len(domains_with_outside),
            'domain_share_pct': round(pct(len(domains_with_outside), total_domains), 3),
            'total_request_count': total_requests,
            'outside_request_count': outside_requests,
            'outside_request_share_pct': round(pct(outside_requests, total_requests), 3),
        },
        'by_sector': sector_rows,
        'by_country': country_rows,
    }


def domain_in_eu_request_rows(meta, requests):
    counts = defaultdict(lambda: {'total': 0, 'in_eu': 0, 'outside': 0})
    for domain, record in meta.items():
        counts[(record['category'], record['country_code'], domain)]
    for row in requests:
        key = (row['category'], row['country_code'], row['input_domain'])
        counts[key]['total'] += 1
        if row['scope_group'] == OUT_SCOPE:
            counts[key]['outside'] += 1
        else:
            counts[key]['in_eu'] += 1

    rows = []
    for domain, record in sorted(meta.items()):
        key = (record['category'], record['country_code'], domain)
        total = counts[key]['total']
        in_eu = counts[key]['in_eu']
        outside = counts[key]['outside']
        if outside == 0:
            scope_class = 'only_in_eu'
        elif in_eu == 0:
            scope_class = 'only_outside_eu'
        else:
            scope_class = 'mixed_in_eu_and_outside_eu'
        rows.append({
            'category': record['category'],
            'country_code': record['country_code'],
            'domain': domain,
            'total_request_count': total,
            'in_eu_request_count': in_eu,
            'outside_request_count': outside,
            'only_in_eu': outside == 0,
            'scope_class': scope_class,
            'in_eu_request_share_pct': round(pct(in_eu, total), 3) if total else None,
            'outside_request_share_pct': round(pct(outside, total), 3) if total else None,
        })
    return rows


def summarize_domain_scope_classes(meta, requests):
    classes = ['only_in_eu', 'mixed_in_eu_and_outside_eu', 'only_outside_eu']
    counts = defaultdict(lambda: {'total': 0, 'in_eu': 0, 'outside': 0})
    for domain, record in meta.items():
        counts[(record['category'], record['country_code'], domain)]
    for row in requests:
        if (row.get('block_reason') or '') == 'allow_main_navigation':
            continue
        if not row.get('request_host'):
            continue
        if not (row.get('ip_country_code') or row.get('caida_as_country_code') or row.get('decision') == 'block'):
            continue
        key = (row['category'], row['country_code'], row['input_domain'])
        counts[key]['total'] += 1
        if row['scope_group'] == OUT_SCOPE:
            counts[key]['outside'] += 1
        else:
            counts[key]['in_eu'] += 1

    domain_rows = []
    for domain, record in sorted(meta.items()):
        key = (record['category'], record['country_code'], domain)
        total = counts[key]['total']
        in_eu = counts[key]['in_eu']
        outside = counts[key]['outside']
        if outside == 0:
            scope_class = 'only_in_eu'
        elif in_eu == 0:
            scope_class = 'only_outside_eu'
        else:
            scope_class = 'mixed_in_eu_and_outside_eu'
        domain_rows.append({
            'domain': domain,
            'category': record['category'],
            'country_code': record['country_code'],
            'scope_class': scope_class,
            'classified_subrequest_count': total,
            'in_eu_subrequest_count': in_eu,
            'outside_eu_subrequest_count': outside,
            'in_eu_subrequest_share_pct': round(pct(in_eu, total), 3) if total else None,
            'outside_eu_subrequest_share_pct': round(pct(outside, total), 3) if total else None,
        })

    def summarize_group(rows):
        total = len(rows)
        counts = Counter(row['scope_class'] for row in rows)
        summary = {'input_domain_count': total}
        for cls in classes:
            summary[f'{cls}_count'] = counts[cls]
            summary[f'{cls}_share_pct'] = round(pct(counts[cls], total), 3)
        return summary

    by_sector = []
    for sector in SECTOR_ORDER:
        rows = [row for row in domain_rows if row['category'] == sector]
        summary = summarize_group(rows)
        summary['category'] = sector
        by_sector.append(summary)

    by_country = []
    for country_code in sorted({row['country_code'] for row in domain_rows}):
        rows = [row for row in domain_rows if row['country_code'] == country_code]
        summary = summarize_group(rows)
        summary['country_code'] = country_code
        by_country.append(summary)

    by_country_sector = []
    for country_code in sorted({row['country_code'] for row in domain_rows}):
        for sector in SECTOR_ORDER:
            rows = [
                row for row in domain_rows
                if row['country_code'] == country_code and row['category'] == sector
            ]
            if not rows:
                continue
            summary = summarize_group(rows)
            summary['country_code'] = country_code
            summary['category'] = sector
            by_country_sector.append(summary)

    by_country_sector_nested = defaultdict(dict)
    for row in by_country_sector:
        country_code = row['country_code']
        sector = row['category']
        by_country_sector_nested[country_code][sector] = {
            key: value
            for key, value in row.items()
            if key not in {'country_code', 'category'}
        }

    return {
        'note': 'Domain classes are computed on retained domains from classified subrequests in the blocked-phase request log. The always-allowed top-level navigation and unclassified/browser-internal requests are excluded. only_in_eu has no outside-EU ASN/operator subrequests; mixed has both in-EU and outside-EU subrequests; only_outside_eu has no in-EU classified subrequests.',
        'overall': summarize_group(domain_rows),
        'by_sector': by_sector,
        'by_country': by_country,
        'by_country_sector': by_country_sector,
        'by_country_sector_nested': dict(by_country_sector_nested),
        'per_domain': [
            {
                'domain': row['domain'],
                'category': row['category'],
                'country_code': row['country_code'],
                'scope_class': row['scope_class'],
                'classified_subrequest_count': row['classified_subrequest_count'],
                'in_eu_subrequest_count': row['in_eu_subrequest_count'],
                'outside_eu_subrequest_count': row['outside_eu_subrequest_count'],
                'in_eu_subrequest_share_pct': row['in_eu_subrequest_share_pct'],
                'outside_eu_subrequest_share_pct': row['outside_eu_subrequest_share_pct'],
            }
            for row in domain_rows
        ],
    }


def summarize_in_eu_by_sector_country(meta, requests):
    domain_rows = domain_in_eu_request_rows(meta, requests)

    def summarize_group(rows, label_key=None):
        total_domains = len(rows)
        only_in_eu = sum(1 for row in rows if row['only_in_eu'])
        total_requests = sum(row['total_request_count'] for row in rows)
        in_eu_requests = sum(row['in_eu_request_count'] for row in rows)
        outside_requests = sum(row['outside_request_count'] for row in rows)
        shares = [
            row['in_eu_request_share_pct']
            for row in rows
            if row['in_eu_request_share_pct'] is not None
        ]
        summary = {
            'input_domain_count': total_domains,
            'domains_only_in_eu_count': only_in_eu,
            'domains_only_in_eu_share_pct': round(pct(only_in_eu, total_domains), 3),
            'total_request_count': total_requests,
            'in_eu_request_count': in_eu_requests,
            'outside_request_count': outside_requests,
            'in_eu_request_share_pct': round(pct(in_eu_requests, total_requests), 3),
            'outside_request_share_pct': round(pct(outside_requests, total_requests), 3),
            'domain_request_share_n': len(shares),
            'mean_domain_in_eu_request_share_pct': round(float(np.mean(shares)), 3) if shares else None,
            'std_domain_in_eu_request_share_pct': round(float(np.std(shares)), 3) if shares else None,
            'median_domain_in_eu_request_share_pct': round(float(np.median(shares)), 3) if shares else None,
            'q1_domain_in_eu_request_share_pct': round(float(np.percentile(shares, 25)), 3) if shares else None,
            'q3_domain_in_eu_request_share_pct': round(float(np.percentile(shares, 75)), 3) if shares else None,
        }
        if label_key:
            summary[label_key] = rows[0][label_key] if rows else ''
        return summary

    by_sector = []
    for sector in SECTOR_ORDER:
        rows = [row for row in domain_rows if row['category'] == sector]
        summary = summarize_group(rows)
        summary['category'] = sector
        by_sector.append(summary)

    by_country = []
    for country_code in sorted({row['country_code'] for row in domain_rows}):
        rows = [row for row in domain_rows if row['country_code'] == country_code]
        summary = summarize_group(rows)
        summary['country_code'] = country_code
        by_country.append(summary)

    by_country_sector = []
    for country_code in sorted({row['country_code'] for row in domain_rows}):
        for sector in SECTOR_ORDER:
            rows = [
                row for row in domain_rows
                if row['country_code'] == country_code and row['category'] == sector
            ]
            if not rows:
                continue
            summary = summarize_group(rows)
            summary['country_code'] = country_code
            summary['category'] = sector
            by_country_sector.append(summary)

    by_country_sector_nested = defaultdict(dict)
    for row in by_country_sector:
        country_code = row['country_code']
        sector = row['category']
        by_country_sector_nested[country_code][sector] = {
            key: value
            for key, value in row.items()
            if key not in {'country_code', 'category'}
        }

    return {
        'note': 'Shares are computed on retained domains only. Request share is aggregate requests in the group; mean/median fields summarize per-domain request shares.',
        'overall': summarize_group(domain_rows),
        'by_sector': by_sector,
        'by_country': by_country,
        'by_country_sector': by_country_sector,
        'by_country_sector_nested': dict(by_country_sector_nested),
        'per_domain': domain_rows,
    }


def resource_examples(requests, top_n=8, examples_per_group=4):
    notable_patterns = RESOURCE_PATTERNS
    host_domains = defaultdict(set)
    host_requests = Counter()
    host_rtypes = defaultdict(Counter)
    host_signatures = defaultdict(Counter)
    rtype_domains = defaultdict(set)
    rtype_signatures = defaultdict(Counter)

    for row in requests:
        if row['scope_group'] != OUT_SCOPE:
            continue
        host = (row.get('request_host') or '').lower().strip('.')
        if not host:
            continue
        domain_key = (row['category'], row['input_domain'])
        rtype = row['resource_type']
        signature = request_signature(row.get('request_url'))
        host_domains[host].add(domain_key)
        host_requests[host] += 1
        host_rtypes[host][rtype] += 1
        host_signatures[host][signature] += 1
        rtype_domains[rtype].add(domain_key)
        rtype_signatures[rtype][signature] += 1

    hosts = []
    for host, domains in sorted(host_domains.items(), key=lambda item: (-len(item[1]), item[0]))[:top_n]:
        hosts.append({
            'host': host,
            'domains_with_request': len(domains),
            'request_count': host_requests[host],
            'top_resource_types': [
                {'resource_type': rtype, 'request_count': count}
                for rtype, count in host_rtypes[host].most_common(5)
            ],
            'examples': [
                {'resource': signature, 'request_count': count}
                for signature, count in host_signatures[host].most_common(examples_per_group)
            ],
        })

    by_type = []
    for rtype, domains in sorted(rtype_domains.items(), key=lambda item: (-len(item[1]), item[0]))[:top_n]:
        by_type.append({
            'resource_type': rtype,
            'domains_with_request': len(domains),
            'examples': [
                {'resource': signature, 'request_count': count}
                for signature, count in rtype_signatures[rtype].most_common(examples_per_group)
            ],
        })

    pattern_rows = []
    for name, needles in notable_patterns.items():
        domains = set()
        request_count = 0
        rtypes = Counter()
        signatures = Counter()
        hosts_for_pattern = Counter()
        for row in requests:
            if row['scope_group'] != OUT_SCOPE:
                continue
            url = (row.get('request_url') or '').lower()
            host = (row.get('request_host') or '').lower()
            if not any(needle in url or needle in host for needle in needles):
                continue
            domains.add((row['category'], row['input_domain']))
            request_count += 1
            rtypes[row['resource_type']] += 1
            hosts_for_pattern[host] += 1
            signatures[request_signature(row.get('request_url'))] += 1
        if not domains:
            continue
        pattern_rows.append({
            'pattern': name,
            'domains_with_request': len(domains),
            'request_count': request_count,
            'top_hosts': [
                {'host': host, 'request_count': count}
                for host, count in hosts_for_pattern.most_common(5)
            ],
            'top_resource_types': [
                {'resource_type': rtype, 'request_count': count}
                for rtype, count in rtypes.most_common(5)
            ],
            'examples': [
                {'resource': signature, 'request_count': count}
                for signature, count in signatures.most_common(examples_per_group)
            ],
        })

    return {
        'top_outside_hosts': hosts,
        'examples_by_resource_type': by_type,
        'notable_patterns': sorted(pattern_rows, key=lambda row: (-row['domains_with_request'], row['pattern'])),
    }


def resource_pattern_domain_evidence(requests, examples_per_domain=5):
    evidence = []
    for name, needles in RESOURCE_PATTERNS.items():
        domains = {}
        request_count = 0
        scope_counts = Counter()
        sector_counts = Counter()
        host_counts = Counter()
        resource_type_counts = Counter()
        for row in requests:
            url = (row.get('request_url') or '').lower()
            host = (row.get('request_host') or '').lower().strip('.')
            if not any(needle in url or needle in host for needle in needles):
                continue
            request_count += 1
            scope = row['scope_group']
            scope_counts[scope] += 1
            sector_counts[row['category']] += 1
            host_counts[host] += 1
            resource_type_counts[row['resource_type']] += 1
            domain = row['input_domain']
            item = domains.setdefault(domain, {
                'domain': domain,
                'category': row['category'],
                'country_code': row['country_code'],
                'request_count': 0,
                'in_eu_request_count': 0,
                'outside_eu_request_count': 0,
                'hosts': Counter(),
                'resource_types': Counter(),
                'examples': Counter(),
            })
            item['request_count'] += 1
            if scope == OUT_SCOPE:
                item['outside_eu_request_count'] += 1
            else:
                item['in_eu_request_count'] += 1
            item['hosts'][host] += 1
            item['resource_types'][row['resource_type']] += 1
            item['examples'][request_signature(row.get('request_url'))] += 1
        if not domains:
            continue

        domain_rows = []
        for item in domains.values():
            domain_rows.append({
                'domain': item['domain'],
                'category': item['category'],
                'country_code': item['country_code'],
                'request_count': item['request_count'],
                'in_eu_request_count': item['in_eu_request_count'],
                'outside_eu_request_count': item['outside_eu_request_count'],
                'hosts': [
                    {'host': host, 'request_count': count}
                    for host, count in item['hosts'].most_common()
                ],
                'resource_types': [
                    {'resource_type': rtype, 'request_count': count}
                    for rtype, count in item['resource_types'].most_common()
                ],
                'examples': [
                    {'resource': signature, 'request_count': count}
                    for signature, count in item['examples'].most_common(examples_per_domain)
                ],
            })
        domain_rows.sort(key=lambda row: (SECTOR_ORDER.index(row['category']) if row['category'] in SECTOR_ORDER else 99, row['country_code'], row['domain']))

        evidence.append({
            'pattern': name,
            'detection_substrings': needles,
            'domains_with_request': len(domain_rows),
            'request_count': request_count,
            'scope_request_counts': dict(scope_counts),
            'sector_request_counts': dict(sector_counts),
            'sector_domain_counts': {
                sector: sum(1 for row in domain_rows if row['category'] == sector)
                for sector in SECTOR_ORDER
            },
            'top_hosts': [
                {'host': host, 'request_count': count}
                for host, count in host_counts.most_common(10)
            ],
            'top_resource_types': [
                {'resource_type': rtype, 'request_count': count}
                for rtype, count in resource_type_counts.most_common()
            ],
            'domains': domain_rows,
        })
    return {
        'note': 'Patterns are detected by case-insensitive substring matching against request_url and request_host in retained-domain request logs. Resource types are Puppeteer request.resourceType() values captured during request interception.',
        'patterns': sorted(evidence, key=lambda row: (-row['domains_with_request'], row['pattern'])),
    }


def request_resource_type_tables(requests):
    scope_counts = Counter((r['scope_group'], r['resource_type']) for r in requests)
    scope_totals = Counter(r['scope_group'] for r in requests)
    sector_counts = Counter((r['category'], r['scope_group'], r['resource_type']) for r in requests)
    sector_totals = Counter((r['category'], r['scope_group']) for r in requests)
    rows_scope = []
    for (scope, rtype), count in sorted(scope_counts.items(), key=lambda kv: (kv[0][0], -kv[1], kv[0][1])):
        rows_scope.append({'scope_group': scope, 'resource_type': rtype, 'request_count': count, 'share_pct': round(pct(count, scope_totals[scope]), 3)})
    rows_sector = []
    for (sector, scope, rtype), count in sorted(sector_counts.items(), key=lambda kv: (SECTOR_ORDER.index(kv[0][0]) if kv[0][0] in SECTOR_ORDER else 99, kv[0][1], -kv[1])):
        rows_sector.append({'category': sector, 'scope_group': scope, 'resource_type': rtype, 'request_count': count, 'share_pct': round(pct(count, sector_totals[(sector, scope)]), 3)})
    return rows_scope, rows_sector


def request_vendor_tables(requests):
    external = [r for r in requests if r['scope_group'] == 'outside EU']
    by_vendor = Counter(r['vendor'] for r in external)
    by_sector_vendor = Counter((r['category'], r['vendor']) for r in external)
    total = sum(by_vendor.values())
    rows_top = []
    for vendor, count in by_vendor.most_common(15):
        rows_top.append({'vendor': vendor, 'external_request_count': count, 'share_pct': round(pct(count, total), 3)})
    rows_sector = []
    sector_totals = Counter(r['category'] for r in external)
    for sector in SECTOR_ORDER:
        items = [(vendor, count) for (cat, vendor), count in by_sector_vendor.items() if cat == sector]
        for vendor, count in sorted(items, key=lambda x: (-x[1], x[0]))[:8]:
            rows_sector.append({'category': sector, 'vendor': vendor, 'external_request_count': count, 'share_pct': round(pct(count, sector_totals[sector]), 3)})
    return rows_top, rows_sector


def domain_resource_type_tables(meta, requests):
    domains_by_sector = input_domains_by_sector(meta)
    domain_scope_counts = defaultdict(Counter)
    for row in requests:
        domain_scope_counts[(row['category'], row['input_domain'], row['scope_group'])][row['resource_type']] += 1

    rtypes_by_scope = defaultdict(set)
    rtypes_by_sector_scope = defaultdict(set)
    domain_keys_by_scope = defaultdict(list)
    domain_keys_by_sector_scope = defaultdict(list)
    for key, counts in domain_scope_counts.items():
        sector, domain, scope = key
        if not counts:
            continue
        domain_keys_by_scope[scope].append(key)
        domain_keys_by_sector_scope[(sector, scope)].append(key)
        rtypes_by_scope[scope].update(counts.keys())
        rtypes_by_sector_scope[(sector, scope)].update(counts.keys())

    rows_scope = []
    for scope in [IN_SCOPE, 'outside EU']:
        domain_keys = domain_keys_by_scope[scope]
        rtype_rows = []
        for rtype in sorted(rtypes_by_scope[scope]):
            vals = []
            domains_with_type = 0
            for key in domain_keys:
                counts = domain_scope_counts[key]
                total = sum(counts.values())
                value = counts[rtype] / total if total else 0.0
                vals.append(value)
                if counts[rtype] > 0:
                    domains_with_type += 1
            rtype_rows.append((rtype, domains_with_type, mean(vals) if vals else 0.0))
        for rtype, domains_with_type, mean_share in sorted(rtype_rows, key=lambda item: (-item[2], item[0])):
            rows_scope.append({
                'scope_group': scope,
                'resource_type': rtype,
                'domains_with_scope': len(domain_keys),
                'domains_with_type': domains_with_type,
                'mean_domain_share': round(mean_share, 6),
            })

    rows_sector = []
    for sector in SECTOR_ORDER:
        for scope in [IN_SCOPE, 'outside EU']:
            domain_keys = domain_keys_by_sector_scope[(sector, scope)]
            rtype_rows = []
            for rtype in sorted(rtypes_by_sector_scope[(sector, scope)]):
                vals = []
                domains_with_type = 0
                for key in domain_keys:
                    counts = domain_scope_counts[key]
                    total = sum(counts.values())
                    value = counts[rtype] / total if total else 0.0
                    vals.append(value)
                    if counts[rtype] > 0:
                        domains_with_type += 1
                rtype_rows.append((rtype, domains_with_type, mean(vals) if vals else 0.0))
            for rtype, domains_with_type, mean_share in sorted(rtype_rows, key=lambda item: (-item[2], item[0])):
                rows_sector.append({
                    'category': sector,
                    'scope_group': scope,
                    'resource_type': rtype,
                    'domains_with_scope': len(domain_keys),
                    'domains_with_type': domains_with_type,
                    'mean_domain_share': round(mean_share, 6),
                })
    return rows_scope, rows_sector


def domain_vendor_tables(meta, requests):
    domains_by_sector = input_domains_by_sector(meta)
    all_domains = {(record['category'], domain) for domain, record in meta.items()}
    external_vendors_by_domain = defaultdict(set)
    for row in requests:
        if row['scope_group'] == 'outside EU':
            external_vendors_by_domain[(row['category'], row['input_domain'])].add(row['vendor'])

    vendor_domains = Counter()
    vendor_sector_domains = Counter()
    for key, vendors in external_vendors_by_domain.items():
        sector, _domain = key
        for vendor in vendors:
            vendor_domains[vendor] += 1
            vendor_sector_domains[(sector, vendor)] += 1

    rows_top = []
    total_domains = len(all_domains)
    for vendor, count in vendor_domains.most_common(15):
        rows_top.append({
            'vendor': vendor,
            'domains_with_external_request': count,
            'domain_share_pct': round(pct(count, total_domains), 3),
        })

    rows_sector = []
    for sector in SECTOR_ORDER:
        total = len(domains_by_sector[sector])
        items = [(vendor, count) for (cat, vendor), count in vendor_sector_domains.items() if cat == sector]
        for vendor, count in sorted(items, key=lambda x: (-x[1], x[0]))[:8]:
            rows_sector.append({
                'category': sector,
                'vendor': vendor,
                'domains_with_external_request': count,
                'domain_share_pct': round(pct(count, total), 3),
            })
    return rows_top, rows_sector


def any_asn_org_domain_share(meta, requests):
    domains_by_sector = input_domains_by_sector(meta)
    all_domains = {(record['category'], domain) for domain, record in meta.items()}
    vendors_by_domain = defaultdict(set)
    vendor_request_counts = Counter()
    for row in requests:
        vendor = (row.get('vendor') or 'unknown').strip() or 'unknown'
        vendors_by_domain[(row['category'], row['input_domain'])].add(vendor)
        vendor_request_counts[vendor] += 1

    vendor_domains = Counter()
    vendor_sector_domains = Counter()
    for (sector, _domain), vendors in vendors_by_domain.items():
        for vendor in vendors:
            vendor_domains[vendor] += 1
            vendor_sector_domains[(sector, vendor)] += 1

    rows_top = []
    total_requests = sum(vendor_request_counts.values())
    for vendor, count in vendor_domains.most_common(20):
        rows_top.append({
            'vendor': vendor,
            'domains_with_any_request': count,
            'domain_share_pct': round(pct(count, len(all_domains)), 3),
            'request_count': vendor_request_counts.get(vendor, 0),
            'request_share_pct': round(pct(vendor_request_counts.get(vendor, 0), total_requests), 3),
        })

    rows_sector = []
    for sector in SECTOR_ORDER:
        total = len(domains_by_sector[sector])
        items = [(vendor, count) for (cat, vendor), count in vendor_sector_domains.items() if cat == sector]
        for vendor, count in sorted(items, key=lambda x: (-x[1], x[0]))[:12]:
            rows_sector.append({
                'category': sector,
                'vendor': vendor,
                'domains_with_any_request': count,
                'domain_share_pct': round(pct(count, total), 3),
            })
    return rows_top, rows_sector


def load_subpage_asn_org_domain_share(sqlite_reproducible_dir: Path):
    """Load the 3-subpage ASN org domain share from sqlite_reproducible CSV."""
    repro_csv = sqlite_reproducible_dir / 'asn_org_any_request_domain_share.csv'
    result = {}
    if not repro_csv.exists():
        return result
    with repro_csv.open(encoding='utf-8', newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            org = (row.get('asn_org_name') or '').strip()
            try:
                result[org] = float(row['domain_share_pct']) / 100.0
            except (KeyError, ValueError):
                pass
    return result


def resource_type_location_probability_table(meta, requests):
    all_domains = {(record['category'], domain) for domain, record in meta.items()}
    domains_with_outside = set()
    domains_with_any = set()
    outside_request_count = 0
    total_counts = Counter()
    outside_counts = Counter()
    in_scope_counts = Counter()
    domain_sets = defaultdict(set)
    for row in requests:
        total_counts[row['resource_type']] += 1
        domains_with_any.add((row['category'], row['input_domain']))
        domain_sets[row['resource_type']].add((row['category'], row['input_domain']))
        if row['scope_group'] == OUT_SCOPE:
            outside_counts[row['resource_type']] += 1
            domains_with_outside.add((row['category'], row['input_domain']))
            outside_request_count += 1
        else:
            in_scope_counts[row['resource_type']] += 1

    rows = []
    for rtype in sorted(total_counts, key=lambda r: (-len(domain_sets[r]), r)):
        total = total_counts[rtype]
        outside = outside_counts[rtype]
        in_scope = in_scope_counts[rtype]
        rows.append({
            'resource_type': rtype,
            'domains_with_type': len(domain_sets[rtype]),
            'domain_share_pct': round(pct(len(domain_sets[rtype]), len(all_domains)), 6),
            'request_count': total,
                    'in_eu_request_count': in_scope,
            'outside_request_count': outside,
                    'in_eu_share_pct': round(pct(in_scope, total), 6),
            'outside_share_pct': round(pct(outside, total), 6),
                    'mean_in_eu_probability': round(in_scope / total if total else 0.0, 6),
            'mean_external_probability': round(outside / total if total else 0.0, 6),
        })
    any_request_count = sum(total_counts.values())
    if any_request_count:
        any_outside = sum(outside_counts.values())
        any_in_scope = sum(in_scope_counts.values())
        rows.append({
            'resource_type': 'any',
            'domains_with_type': len(domains_with_any),
            'domain_share_pct': round(pct(len(domains_with_any), len(all_domains)), 6),
            'request_count': any_request_count,
            'in_eu_request_count': any_in_scope,
            'outside_request_count': any_outside,
            'in_eu_share_pct': round(pct(any_in_scope, any_request_count), 6),
            'outside_share_pct': round(pct(any_outside, any_request_count), 6),
            'mean_in_eu_probability': round(any_in_scope / any_request_count, 6),
            'mean_external_probability': round(any_outside / any_request_count, 6),
        })
    rows.append({
        'resource_type': 'any_external',
        'domains_with_type': len(domains_with_outside),
        'domain_share_pct': round(pct(len(domains_with_outside), len(all_domains)), 6),
        'request_count': outside_request_count,
        'in_eu_request_count': 0,
        'outside_request_count': outside_request_count,
        'in_eu_share_pct': 0.0,
        'outside_share_pct': 100.0,
        'mean_in_eu_probability': 0.0,
        'mean_external_probability': 1.0,
    })
    return rows


def input_domains_by_sector(meta):
    out = defaultdict(set)
    for domain, record in meta.items():
        out[record['category']].add(domain)
    return out


def domain_external_share(pages, requests, meta):
    has_external = defaultdict(bool)
    for r in requests:
        key = (r['category'], r['input_domain'])
        if r['scope_group'] == 'outside EU':
            has_external[key] = True
    domains_by_sector = input_domains_by_sector(meta)
    rows = []
    for sector in SECTOR_ORDER:
        domains = domains_by_sector[sector]
        external_n = sum(1 for domain in domains if has_external[(sector, domain)])
        rows.append({
            'category': sector,
            'input_domain_count': len(domains),
            'domains_with_external_request': external_n,
            'share_pct': round(pct(external_n, len(domains)), 3),
        })
    return rows


def collapse_pages_to_domains(pages, meta):
    grouped = defaultdict(list)
    for page in pages:
        grouped[(page['category'], page['input_domain'])].append(page)
    rows = []
    for sector, domains in input_domains_by_sector(meta).items():
        for domain in domains:
            items = grouped.get((sector, domain), [])
            row = {'category': sector, 'input_domain': domain, 'has_crawl_row': int(bool(items))}
            if not items:
                row.update({
                    'blocked_flag': 0,
                    'visual_diff_share': None,
                    'html_structural_loss': None,
                    'text_loss': None,
                    'domain_score': None,
                    'blocked_or_domain_score': None,
                })
                rows.append(row)
                continue
            row['blocked_flag'] = max(int(item.get('blocked_flag') or 0) for item in items)
            for key in ['visual_diff_share', 'html_structural_loss', 'text_loss', 'domain_score']:
                vals = [item[key] for item in items if item.get(key) is not None]
                row[key] = mean(vals) if vals else None
            row['blocked_or_domain_score'] = 1.0 if row['blocked_flag'] else row['domain_score']
            rows.append(row)
    return rows


def blocking_summary(pages, meta):
    domain_rows = collapse_pages_to_domains(pages, meta)
    rows = []
    for sector in SECTOR_ORDER:
        items = [p for p in domain_rows if p['category'] == sector]
        if not items:
            continue
        def m(name):
            vals = [p[name] for p in items if p.get(name) is not None]
            return round(mean(vals), 6) if vals else None
        blocked_n = sum(int(p.get('blocked_flag') or 0) for p in items)
        crawled_n = sum(int(p.get('has_crawl_row') or 0) for p in items)
        rows.append({
            'category': sector,
            'n': len(items),
            'crawled_n': crawled_n,
            'blocked_n': blocked_n,
            'blocked_share': round(blocked_n / len(items), 6),
            'visual_diff_mean': m('visual_diff_share'),
            'html_structural_loss_mean': m('html_structural_loss'),
            'text_loss_mean': m('text_loss'),
            'domain_score_mean': m('domain_score'),
            'blocked_or_domain_score_mean': m('blocked_or_domain_score'),
        })
    return rows


def domain_scope_overlap(pages, requests, meta):
    scopes_by_domain = defaultdict(set)
    for req in requests:
        scopes_by_domain[(req['category'], req['input_domain'])].add(req['scope_group'])
    domains_by_sector = input_domains_by_sector(meta)
    rows = []
    for sector in SECTOR_ORDER:
        domains = domains_by_sector[sector]
        outside_domains = [domain for domain in domains if OUT_SCOPE in scopes_by_domain[(sector, domain)]]
        both_domains = [domain for domain in outside_domains if IN_SCOPE in scopes_by_domain[(sector, domain)]]
        rows.append({
            'category': sector,
            'input_domain_count': len(domains),
            'domains_with_outside_request': len(outside_domains),
            'outside_domains_with_in_eu_request': len(both_domains),
            'outside_domains_with_in_eu_request_pct': round(pct(len(both_domains), len(outside_domains)), 3),
            'outside_domains_share_pct': round(pct(len(outside_domains), len(domains)), 3),
        })
    return rows


def ordered_resource_types(rows, scope='outside EU', top_n=8):
    counts = Counter()
    for row in rows:
        if row['scope_group'] == scope:
            counts[row['resource_type']] += float(row.get('mean_domain_share') or row.get('request_count') or 0)
    out = [rtype for rtype, _ in counts.most_common(top_n)]
    for preferred in RESOURCE_ORDER:
        if preferred in counts and preferred not in out and len(out) < top_n:
            out.append(preferred)
    return out


def plot_resource_scope(rows_scope, out_dir: Path):
    rtypes = ordered_resource_types(rows_scope, 'outside EU', 8)
    data = {scope: {rtype: 0 for rtype in rtypes} for scope in [IN_SCOPE, 'outside EU']}
    for row in rows_scope:
        if row['resource_type'] in rtypes and row['scope_group'] in data:
            data[row['scope_group']][row['resource_type']] = row['mean_domain_share']
    y = np.arange(len(rtypes))
    height = 0.34
    fig, ax = plt.subplots(figsize=(3.45, 2.45))
    for idx, scope in enumerate([IN_SCOPE, 'outside EU']):
        vals = [data[scope][rtype] for rtype in rtypes]
        offset = (idx - 0.5) * height
        bars = ax.barh(y + offset, vals, height=height, color=SCOPE_COLORS[scope], label=scope, edgecolor='black', linewidth=0.4, hatch='' if scope == IN_SCOPE else '///')
        for bar, val in zip(bars, vals):
            if val > 0.02:
                ax.text(val + 0.006, bar.get_y() + bar.get_height() / 2, f'{val:.2f}', va='center', fontsize=8)
    ax.set_yticks(y)
    ax.set_yticklabels([r.title() for r in rtypes])
    ax.invert_yaxis()
    ax.set_xlim(0, max(0.45, max(max(data[s].values()) for s in data) * 1.25))
    ax.set_xlabel('Mean share per input domain')
    ax.legend(loc='lower right', frameon=False, ncol=1)
    fig.tight_layout(pad=0.3)
    fig.savefig(out_dir / 'resource_types_in_eu_vs_external.pdf', bbox_inches='tight')
    plt.close(fig)


def plot_resource_type_location_probability(rows, out_dir: Path):
    top = rows[:10]
    y = np.arange(len(top))
    in_vals = np.array([r.get('mean_in_eu_probability', 0.0) for r in top])
    external_vals = np.array([r['mean_external_probability'] for r in top])

    fig, ax = plt.subplots(figsize=(3.45, 2.75))
    ax.barh(y, in_vals, color=SCOPE_COLORS[IN_SCOPE], edgecolor='#111111', linewidth=0.4, label=IN_SCOPE)
    ax.barh(y, external_vals, left=in_vals, color=SCOPE_COLORS['outside EU'], edgecolor='#111111', linewidth=0.4, hatch='///', label='outside EU')
    ax.set_yticks(y)
    ax.set_yticklabels([r['resource_type'].title() for r in top])
    ax.invert_yaxis()
    ax.set_xlim(0, 1)
    ax.set_xlabel('Mean destination probability per input domain')
    ax.set_xticks(np.linspace(0, 1, 6))
    ax.set_xticklabels([f'{int(v * 100)}%' for v in np.linspace(0, 1, 6)])
    for yi, ext in enumerate(external_vals):
        if ext >= 0.08:
            ax.text(min(in_vals[yi] + ext / 2, 0.98), yi, f'{ext * 100:.0f}%', ha='center', va='center', fontsize=8, color='white')
    ax.legend(loc='lower center', bbox_to_anchor=(0.5, -0.35), ncol=2, frameon=False)
    fig.tight_layout(pad=0.25)
    fig.savefig(out_dir / 'resource_type_location_probability_domain_weighted.pdf', bbox_inches='tight')
    plt.close(fig)


def resource_type_location_probability_by_sector_table(meta, requests):
    sector_domains_with_outside = defaultdict(set)
    sector_domains_with_any = defaultdict(set)
    sector_domains_all = input_domains_by_sector(meta)
    sector_total_counts = Counter()
    sector_outside_counts = Counter()
    sector_in_scope_counts = Counter()
    sector_domain_sets = defaultdict(set)
    for row in requests:
        sector = row['category']
        rtype = row['resource_type']
        sector_total_counts[(sector, rtype)] += 1
        sector_domain_sets[(sector, rtype)].add(row['input_domain'])
        sector_domains_with_any[sector].add(row['input_domain'])
        if row['scope_group'] == OUT_SCOPE:
            sector_outside_counts[(sector, rtype)] += 1
            sector_domains_with_outside[sector].add(row['input_domain'])
        else:
            sector_in_scope_counts[(sector, rtype)] += 1

    rows = []
    for sector in SECTOR_ORDER:
        rtypes = sorted(
            [rtype for (cat, rtype) in sector_total_counts if cat == sector],
            key=lambda r: (-sector_total_counts[(sector, r)], r)
        )
        for rtype in rtypes:
            total = sector_total_counts[(sector, rtype)]
            outside = sector_outside_counts[(sector, rtype)]
            in_scope = sector_in_scope_counts[(sector, rtype)]
            rows.append({
                'category': sector,
                'resource_type': rtype,
                'domains_with_type': len(sector_domain_sets[(sector, rtype)]),
                'domain_share_pct': round(pct(len(sector_domain_sets[(sector, rtype)]), len(sector_domains_all[sector])), 6),
                'request_count': total,
                'in_eu_request_count': in_scope,
                'outside_request_count': outside,
                'in_eu_share_pct': round(pct(in_scope, total), 6),
                'outside_share_pct': round(pct(outside, total), 6),
                'mean_external_probability': round(outside / total if total else 0.0, 6),
                'mean_in_eu_probability': round(in_scope / total if total else 0.0, 6),
            })
        sector_total = sum(sector_total_counts[(sector, r)] for r in rtypes)
        sector_out = sum(sector_outside_counts[(sector, r)] for r in rtypes)
        sector_in_scope = sum(sector_in_scope_counts[(sector, r)] for r in rtypes)
        rows.append({
            'category': sector,
            'resource_type': 'any',
            'domains_with_type': len(sector_domains_with_any[sector]),
            'domain_share_pct': round(pct(len(sector_domains_with_any[sector]), len(sector_domains_all[sector])), 6),
            'request_count': sector_total,
            'in_eu_request_count': sector_in_scope,
            'outside_request_count': sector_out,
            'in_eu_share_pct': round(pct(sector_in_scope, sector_total), 6),
            'outside_share_pct': round(pct(sector_out, sector_total), 6),
            'mean_external_probability': round(sector_out / sector_total if sector_total else 0.0, 6),
            'mean_in_eu_probability': round(sector_in_scope / sector_total if sector_total else 0.0, 6),
        })
    return rows


def plot_resource_type_location_probability_by_sector(rows, overall_rows, out_dir: Path):
    ranked = sorted(
        [r for r in overall_rows if r['resource_type'] not in {'any', 'any_external'}],
        key=lambda r: (-r['mean_external_probability'], -r['domains_with_type'], r['resource_type'])
    )
    rtypes = [r['resource_type'] for r in ranked[:10]]
    if any(r['resource_type'] == 'any' for r in overall_rows):
        rtypes.append('any')
    overall = {r['resource_type']: r['mean_external_probability'] for r in overall_rows}
    total_requests = sum(item['request_count'] for item in overall_rows if item['resource_type'] not in {'any', 'any_external'})
    request_share = {
        row['resource_type']: row['request_count'] / total_requests
        for row in overall_rows
        if row['resource_type'] not in {'any', 'any_external'} and total_requests
    }
    domain_share = {
        row['resource_type']: row.get('domain_share_pct', 0.0) / 100.0
        for row in overall_rows
    }
    fig, ax = plt.subplots(figsize=(3.45, 3.15))
    y = np.arange(len(rtypes))
    for yi, rtype in enumerate(rtypes):
        vals = [
            next((r['mean_external_probability'] for r in rows if r['category'] == sector and r['resource_type'] == rtype), np.nan)
            for sector in SECTOR_ORDER
        ]
        finite = [v for v in vals if not np.isnan(v)]
        if finite:
            ax.hlines(yi, min(finite), max(finite), color='#9A9A9A', linewidth=0.8, zorder=1)
    for sector in SECTOR_ORDER:
        vals = [
            next((r['mean_external_probability'] for r in rows if r['category'] == sector and r['resource_type'] == rtype), np.nan)
            for rtype in rtypes
        ]
        ax.scatter(vals, y, s=25, color=SECTOR_COLORS[sector], edgecolor='#111111', linewidth=0.3, marker=SECTOR_MARKERS[sector], label=SECTOR_LABELS[sector], zorder=3)
    ax.scatter([overall[rtype] for rtype in rtypes], y, s=34, color='#111111', marker='D', label='Overall', zorder=4)
    if 'any' in rtypes:
        ax.axhline(rtypes.index('any') - 0.5, color='#555555', linewidth=0.6)
    ax.set_yticks(y)
    ax.set_yticklabels(['Any' if r == 'any' else r.title() for r in rtypes])
    ax.invert_yaxis()
    ax.set_xlim(0, 1)
    ax.set_xlabel('Outside EU ASN share')
    ax.set_xticks(np.linspace(0, 1, 6))
    ax.set_xticklabels([f'{int(v * 100)}%' for v in np.linspace(0, 1, 6)])
    for yi, rtype in enumerate(rtypes):
        req_label = '-' if rtype == 'any' else f'{request_share.get(rtype, 0) * 100:.1f}%'
        ax.text(1.01, yi, req_label, va='center', ha='left', fontsize=8, transform=ax.get_yaxis_transform())
        ax.text(1.18, yi, f'{domain_share.get(rtype, 0) * 100:.1f}%', va='center', ha='left', fontsize=8, transform=ax.get_yaxis_transform())
    ax.text(1.01, -0.75, 'Req.', va='center', ha='left', fontsize=8, transform=ax.get_yaxis_transform())
    ax.text(1.18, -0.75, 'Dom.', va='center', ha='left', fontsize=8, transform=ax.get_yaxis_transform())
    ax.legend(loc='lower center', bbox_to_anchor=(0.5, -0.43), ncol=3, frameon=False, handlelength=1.0, columnspacing=0.7)
    fig.tight_layout(pad=0.25)
    fig.savefig(out_dir / 'resource_type_location_probability_by_sector.pdf', bbox_inches='tight')
    plt.close(fig)


def plot_resource_type_location_probability_by_sector_barcols(rows, overall_rows, out_dir: Path, sort_by='external'):
    if sort_by == 'domain':
        ranked = sorted(
            [r for r in overall_rows if r['resource_type'] not in {'any', 'any_external'}],
            key=lambda r: (-r.get('domain_share_pct', 0.0), -r['mean_external_probability'], r['resource_type'])
        )
        filename = 'resource_type_location_probability_by_sector_barcols_sorted_dom.pdf'
    else:
        ranked = sorted(
            [r for r in overall_rows if r['resource_type'] not in {'any', 'any_external'}],
            key=lambda r: (-r['mean_external_probability'], -r['domains_with_type'], r['resource_type'])
        )
        filename = 'resource_type_location_probability_by_sector_barcols.pdf'
    rtypes = [r['resource_type'] for r in ranked[:10]]
    if any(r['resource_type'] == 'any' for r in overall_rows):
        rtypes.append('any')

    overall = {r['resource_type']: r['mean_external_probability'] for r in overall_rows}
    total_requests = sum(
        row.get('request_count', 0)
        for row in overall_rows
        if row['resource_type'] not in {'any', 'any_external'}
    )
    request_share = {
        row['resource_type']: row.get('request_count', 0) / total_requests if total_requests else 0.0
        for row in overall_rows
        if row['resource_type'] not in {'any', 'any_external'}
    }
    domain_share = {
        row['resource_type']: row.get('domain_share_pct', 0.0) / 100.0
        for row in overall_rows
    }

    fig = plt.figure(figsize=(3.45, 3.05))
    gs = fig.add_gridspec(1, 3, width_ratios=[1.0, 0.28, 0.28], wspace=0.18)
    ax = fig.add_subplot(gs[0, 0])
    ax_req = fig.add_subplot(gs[0, 1], sharey=ax)
    ax_dom = fig.add_subplot(gs[0, 2], sharey=ax)
    y = np.arange(len(rtypes))

    for yi, rtype in enumerate(rtypes):
        vals = [
            next((r['mean_external_probability'] for r in rows if r['category'] == sector and r['resource_type'] == rtype), np.nan)
            for sector in SECTOR_ORDER
        ]
        finite = [v for v in vals if not np.isnan(v)]
        if finite:
            ax.hlines(yi, min(finite), max(finite), color='#9A9A9A', linewidth=0.8, zorder=1)
    for sector in SECTOR_ORDER:
        vals = [
            next((r['mean_external_probability'] for r in rows if r['category'] == sector and r['resource_type'] == rtype), np.nan)
            for rtype in rtypes
        ]
        ax.scatter(vals, y, s=24, color=SECTOR_COLORS[sector], edgecolor='#111111', linewidth=0.3, marker=SECTOR_MARKERS[sector], label=SECTOR_LABELS[sector], zorder=3)
    ax.scatter([overall[rtype] for rtype in rtypes], y, s=32, color='#111111', marker='D', label='Overall', zorder=2)
    if 'any' in rtypes:
        for axis in [ax, ax_req, ax_dom]:
            axis.axhline(rtypes.index('any') - 0.5, color='#555555', linewidth=0.6)
    ax.set_yticks(y)
    ax.set_yticklabels(['Any Type' if r == 'any' else r.title() for r in rtypes])
    ax.invert_yaxis()
    ax.set_xlim(0, 1)
    ax.set_xlabel('Outside EU ASN share')
    ax.set_xticks([0, 0.5, 1.0])
    ax.set_xticklabels(['0', '0.5', '1'])

    req_vals = [np.nan if rtype == 'any' else request_share.get(rtype, 0.0) for rtype in rtypes]
    dom_vals = [np.nan if rtype == 'any' else domain_share.get(rtype, 0.0) for rtype in rtypes]
    ax_req.barh(y, req_vals, height=0.58, color='#6F6F6F', edgecolor='#111111', linewidth=0.25)
    ax_dom.barh(y, dom_vals, height=0.58, color='#D9A441', edgecolor='#111111', linewidth=0.25)
    for side_ax, vals, label in [(ax_req, req_vals, '% Req.'), (ax_dom, dom_vals, '% Dom.')]:
        side_ax.set_xlim(0, 1)
        side_ax.set_xlabel(label)
        side_ax.set_xticks([0, 1])
        side_ax.set_xticklabels(['0', '1'])
        side_ax.tick_params(axis='y', left=False, labelleft=False)
        side_ax.spines['left'].set_visible(False)
        side_ax.spines['top'].set_visible(False)
        side_ax.spines['right'].set_visible(False)
        for yi, val in enumerate(vals):
            if not np.isnan(val) and val > 0:
                side_ax.text(min(val + 0.04, 0.97), yi, f'{val * 100:.0f}%', ha='left', va='center', fontsize=7.5, clip_on=False)

    ax.legend(loc='lower center', bbox_to_anchor=(0.65, -0.45), ncol=3, frameon=False, handlelength=1.0, columnspacing=0.65)
    fig.subplots_adjust(left=0.18, right=0.98, bottom=0.25, top=0.98)
    fig.savefig(out_dir / filename, bbox_inches='tight')
    plt.close(fig)


def plot_resource_type_location_probability_by_sector_barcols_mainhost(rows, overall_rows, out_dir: Path, sort_by='domain'):
    if sort_by == 'domain':
        ranked = sorted(
            [r for r in overall_rows if r['resource_type'] not in {'any', 'any_external'}],
            key=lambda r: (-r.get('domain_share_pct', 0.0), -r['mean_main_host_probability'], r['resource_type'])
        )
        filename = 'resource_type_location_probability_by_sector_barcols_sorted_dom_mainhost.pdf'
    else:
        ranked = sorted(
            [r for r in overall_rows if r['resource_type'] not in {'any', 'any_external'}],
            key=lambda r: (-r['mean_main_host_probability'], -r['domains_with_type'], r['resource_type'])
        )
        filename = 'resource_type_location_probability_by_sector_barcols_mainhost.pdf'
    rtypes = [r['resource_type'] for r in ranked[:10]]
    if any(r['resource_type'] == 'any' for r in overall_rows):
        rtypes.append('any')
    if any(r['resource_type'] == 'any_external' for r in overall_rows):
        rtypes.append('any_external')

    overall = {r['resource_type']: r['mean_main_host_probability'] for r in overall_rows}
    main_share = {
        row['resource_type']: row.get('mean_main_host_probability', 0.0)
        for row in overall_rows
    }
    domain_share = {
        row['resource_type']: row.get('domain_share_pct', 0.0) / 100.0
        for row in overall_rows
    }

    fig = plt.figure(figsize=(3.45, 3.05))
    gs = fig.add_gridspec(1, 3, width_ratios=[1.0, 0.28, 0.28], wspace=0.18)
    ax = fig.add_subplot(gs[0, 0])
    ax_main = fig.add_subplot(gs[0, 1], sharey=ax)
    ax_dom = fig.add_subplot(gs[0, 2], sharey=ax)
    y = np.arange(len(rtypes))

    for yi, rtype in enumerate(rtypes):
        vals = [
            next((r['mean_main_host_probability'] for r in rows if r['category'] == sector and r['resource_type'] == rtype), np.nan)
            for sector in SECTOR_ORDER
        ]
        finite = [v for v in vals if not np.isnan(v)]
        if finite:
            ax.hlines(yi, min(finite), max(finite), color='#9A9A9A', linewidth=0.8, zorder=1)
    for sector in SECTOR_ORDER:
        vals = [
            next((r['mean_main_host_probability'] for r in rows if r['category'] == sector and r['resource_type'] == rtype), np.nan)
            for rtype in rtypes
        ]
        ax.scatter(vals, y, s=24, color=SECTOR_COLORS[sector], edgecolor='#111111', linewidth=0.3, marker=SECTOR_MARKERS[sector], label=SECTOR_LABELS[sector], zorder=3)
    ax.scatter([overall[rtype] for rtype in rtypes], y, s=32, color='#111111', marker='D', label='Overall', zorder=2)
    if 'any' in rtypes:
        for axis in [ax, ax_main, ax_dom]:
            axis.axhline(rtypes.index('any') - 0.5, color='#555555', linewidth=0.6)
    ax.set_yticks(y)
    ax.set_yticklabels(['Any Type' if r == 'any' else 'Any Outside' if r == 'any_external' else r.title() for r in rtypes])
    ax.invert_yaxis()
    ax.set_xlim(0, 1)
    ax.set_xlabel('1P / main-domain probability')
    ax.set_xticks([0, 0.5, 1.0])
    ax.set_xticklabels(['0', '0.5', '1'])

    main_vals = [np.nan if rtype == 'any_external' else main_share.get(rtype, 0.0) for rtype in rtypes]
    dom_vals = [np.nan if rtype == 'any' else domain_share.get(rtype, 0.0) for rtype in rtypes]
    ax_main.barh(y, main_vals, height=0.58, color='#6F6F6F', edgecolor='#111111', linewidth=0.25)
    ax_dom.barh(y, dom_vals, height=0.58, color='#D9A441', edgecolor='#111111', linewidth=0.25)
    for side_ax, vals, label in [(ax_main, main_vals, '% Req.'), (ax_dom, dom_vals, '% Dom.')]:
        side_ax.set_xlim(0, 1)
        side_ax.set_xlabel(label)
        side_ax.set_xticks([0, 1])
        side_ax.set_xticklabels(['0', '1'])
        side_ax.tick_params(axis='y', left=False, labelleft=False)
        side_ax.spines['left'].set_visible(False)
        side_ax.spines['top'].set_visible(False)
        side_ax.spines['right'].set_visible(False)
        for yi, val in enumerate(vals):
            if not np.isnan(val) and val > 0:
                side_ax.text(min(val + 0.04, 0.97), yi, f'{val * 100:.0f}%', ha='left', va='center', fontsize=7.5, clip_on=False)

    ax.legend(loc='lower center', bbox_to_anchor=(0.65, -0.45), ncol=3, frameon=False, handlelength=1.0, columnspacing=0.65)
    fig.subplots_adjust(left=0.18, right=0.98, bottom=0.25, top=0.98)
    fig.savefig(out_dir / filename, bbox_inches='tight')
    plt.close(fig)


def request_weighted_resource_scope_plot(rows_scope, out_dir: Path):
    external = [r for r in rows_scope if r['scope_group'] == 'outside EU']
    ranked = [r['resource_type'] for r in sorted(external, key=lambda r: -int(r['request_count']))[:10]]
    data = {scope: {rtype: 0.0 for rtype in ranked} for scope in [IN_SCOPE, 'outside EU']}
    for row in rows_scope:
        if row['scope_group'] in data and row['resource_type'] in ranked:
            data[row['scope_group']][row['resource_type']] = row['share_pct'] / 100.0

    y = np.arange(len(ranked))
    h = 0.36
    fig, ax = plt.subplots(figsize=(3.45, 2.95))
    ax.barh(y + h / 2, [data[IN_SCOPE][r] for r in ranked], height=h, color=SCOPE_COLORS[IN_SCOPE], edgecolor='#111111', linewidth=0.45, label=IN_SCOPE)
    ax.barh(y - h / 2, [data['outside EU'][r] for r in ranked], height=h, color=SCOPE_COLORS['outside EU'], edgecolor='#111111', linewidth=0.45, hatch='///', label='outside EU')
    ax.set_yticks(y)
    ax.set_yticklabels([r.title() for r in ranked])
    ax.invert_yaxis()
    ax.set_xlabel('Share of requests')
    ax.set_xlim(0, max(max(data[s].values()) for s in data) * 1.2)
    ax.legend(frameon=False, loc='lower right')
    fig.tight_layout(pad=0.25)
    fig.savefig(out_dir / 'raw_request_resource_types_in_eu_vs_external.pdf', bbox_inches='tight')
    plt.close(fig)


def request_weighted_resource_by_sector_plot(rows_sector, out_dir: Path):
    external_rows = [r for r in rows_sector if r['scope_group'] == 'outside EU']
    totals = Counter()
    for row in external_rows:
        totals[row['resource_type']] += int(row['request_count'])
    rtypes = [rtype for rtype, _ in totals.most_common(8)]
    fig, ax = plt.subplots(figsize=(3.45, 2.65))
    y = np.arange(len(SECTOR_ORDER))
    left = np.zeros(len(SECTOR_ORDER))
    cmap = plt.get_cmap('tab20c')
    for idx, rtype in enumerate(rtypes):
        vals = []
        for sector in SECTOR_ORDER:
            vals.append(next((r['share_pct'] / 100.0 for r in external_rows if r['category'] == sector and r['resource_type'] == rtype), 0.0))
        ax.barh(y, vals, left=left, color=cmap(idx / max(len(rtypes), 1)), edgecolor='#111111', linewidth=0.35, label=rtype.title())
        left += np.array(vals)
    ax.set_yticks(y)
    ax.set_yticklabels([SECTOR_LABELS[s] for s in SECTOR_ORDER])
    ax.invert_yaxis()
    ax.set_xlim(0, 1)
    ax.set_xlabel('Share of requests to outside-EU ASNs/operators')
    ax.legend(loc='lower center', bbox_to_anchor=(0.5, -0.48), ncol=3, frameon=False, handlelength=1.2, columnspacing=0.8)
    fig.tight_layout(pad=0.25)
    fig.savefig(out_dir / 'raw_request_resource_types_external_by_sector.pdf', bbox_inches='tight')
    plt.close(fig)


def request_weighted_top_vendors_plot(rows_top, out_dir: Path):
    rows = rows_top[:10][::-1]
    labels = [r['vendor'][:34] for r in rows]
    vals = [r['share_pct'] / 100.0 for r in rows]
    fig, ax = plt.subplots(figsize=(3.45, 2.65))
    bars = ax.barh(np.arange(len(rows)), vals, color='#6B6B6B', edgecolor='black', linewidth=0.4)
    ax.set_yticks(np.arange(len(rows)))
    ax.set_yticklabels(labels)
    ax.set_xlabel('Share of requests to outside-EU ASNs/operators')
    ax.set_xlim(0, max(vals) * 1.28 if vals else 1)
    for bar, val in zip(bars, vals):
        ax.text(val + 0.004, bar.get_y() + bar.get_height() / 2, f'{val:.2f}', va='center', fontsize=8)
    fig.tight_layout(pad=0.3)
    fig.savefig(out_dir / 'raw_request_top_external_vendors.pdf', bbox_inches='tight')
    plt.close(fig)


def plot_resource_by_sector(rows_sector, out_dir: Path):
    external_rows = [r for r in rows_sector if r['scope_group'] == 'outside EU']
    totals = Counter()
    for r in external_rows:
        totals[r['resource_type']] += float(r.get('mean_domain_share') or 0)
    rtypes = [r for r, _ in totals.most_common(6)]
    if 'other' not in rtypes and 'other' in totals:
        rtypes[-1] = 'other'
    cmap = plt.get_cmap('tab20c')
    colors = {rtype: cmap(i / max(len(rtypes), 1)) for i, rtype in enumerate(rtypes)}
    fig, ax = plt.subplots(figsize=(3.45, 2.15))
    y = np.arange(len(SECTOR_ORDER))
    left = np.zeros(len(SECTOR_ORDER))
    for rtype in rtypes:
        vals = []
        for sector in SECTOR_ORDER:
            val = next((r['mean_domain_share'] for r in external_rows if r['category'] == sector and r['resource_type'] == rtype), 0.0)
            vals.append(val)
        ax.barh(y, vals, left=left, color=colors[rtype], edgecolor='black', linewidth=0.35, label=rtype.title())
        left += np.array(vals)
    ax.set_yticks(y)
    ax.set_yticklabels([SECTOR_LABELS[s] for s in SECTOR_ORDER])
    ax.invert_yaxis()
    ax.set_xlim(0, 1)
    ax.set_xlabel('Mean share per input domain')
    ax.legend(loc='lower center', bbox_to_anchor=(0.5, -0.52), ncol=3, frameon=False, handlelength=1.2, columnspacing=0.8)
    fig.tight_layout(pad=0.25)
    fig.savefig(out_dir / 'resource_types_external_by_sector.pdf', bbox_inches='tight')
    plt.close(fig)


def plot_top_vendors(rows_top, out_dir: Path):
    rows = rows_top[:10][::-1]
    labels = [r['vendor'][:34] for r in rows]
    vals = [r['domain_share_pct'] / 100.0 for r in rows]
    fig, ax = plt.subplots(figsize=(3.45, 2.65))
    bars = ax.barh(np.arange(len(rows)), vals, color='#6B6B6B', edgecolor='black', linewidth=0.4)
    ax.set_yticks(np.arange(len(rows)))
    ax.set_yticklabels(labels)
    ax.set_xlabel('Share of input domains')
    ax.set_xlim(0, max(vals) * 1.28 if vals else 1)
    for bar, val in zip(bars, vals):
        ax.text(val + 0.004, bar.get_y() + bar.get_height() / 2, f'{val:.2f}', va='center', fontsize=8)
    fig.tight_layout(pad=0.3)
    fig.savefig(out_dir / 'top_external_request_vendors.pdf', bbox_inches='tight')
    plt.close(fig)


def plot_any_asn_org_domain_share(rows_top, out_dir: Path, subpage_dom_share=None):
    rows = rows_top[:12][::-1]
    labels = [r['vendor'][:32] for r in rows]
    dom_vals = [r['domain_share_pct'] / 100.0 for r in rows]
    req_vals = [r.get('request_share_pct', 0.0) / 100.0 for r in rows]
    subpage = subpage_dom_share or {}

    fig, (ax_dom, ax_req) = plt.subplots(1, 2, figsize=(6.9, 3.05), sharey=True)
    y = np.arange(len(rows))

    # Domain share panel
    ax_dom.barh(y, dom_vals, color='#6F6F6F', edgecolor='black', linewidth=0.4)
    ax_dom.set_yticks(y)
    ax_dom.set_yticklabels(labels)
    dom_xlim = min(1.0, max(dom_vals) * 1.28 if dom_vals else 1.0)
    ax_dom.set_xlim(0, dom_xlim)
    ax_dom.set_xlabel('Share of input domains')
    for yi, (val, row) in enumerate(zip(dom_vals, rows)):
        vendor = row['vendor']
        ax_dom.text(min(val + 0.008, dom_xlim * 0.97), yi, f'{val * 100:.1f}%', va='center', fontsize=8)
        # Subpage max bracket from sqlite_reproducible (3-page crawl)
        sub_val = subpage.get(vendor)
        if sub_val is not None and sub_val > val + 0.004:
            ax_dom.annotate('', xy=(sub_val, yi), xytext=(val, yi),
                            arrowprops=dict(arrowstyle='->', color='#C04040', lw=1.2))
            ax_dom.text(min(sub_val + 0.008, dom_xlim * 0.98), yi, f'{sub_val * 100:.0f}%',
                        va='center', fontsize=7, color='#C04040')

    # Request share panel
    req_xlim = min(0.20, max(req_vals) * 1.30 if req_vals else 0.20)
    ax_req.barh(y, req_vals, color='#8C2F39', edgecolor='black', linewidth=0.4)
    ax_req.set_xlabel('Share of requests')
    ax_req.set_xlim(0, req_xlim)
    ax_req.tick_params(axis='y', left=False, labelleft=False)
    ax_req.spines['left'].set_visible(False)
    for yi, val in enumerate(req_vals):
        if val > 0:
            ax_req.text(min(val + req_xlim * 0.02, req_xlim * 0.97), yi, f'{val * 100:.1f}%', va='center', fontsize=8)

    ax_dom.invert_yaxis()
    fig.tight_layout(pad=0.3, w_pad=0.55)
    fig.savefig(out_dir / 'asn_org_any_request_domain_share.pdf', bbox_inches='tight')
    plt.close(fig)


def plot_domain_external_share(rows, out_dir: Path):
    vals = [r['share_pct'] / 100.0 for r in rows]
    labels = [SECTOR_LABELS[r['category']] for r in rows]
    fig, ax = plt.subplots(figsize=(3.45, 1.75))
    y = np.arange(len(rows))
    bars = ax.barh(y, vals, color=[SECTOR_COLORS[r['category']] for r in rows], edgecolor='black', linewidth=0.4)
    for bar, row, val in zip(bars, rows, vals):
        bar.set_hatch(HATCHES[row['category']])
        ax.text(min(val + 0.025, 0.98), bar.get_y() + bar.get_height() / 2, f'{val:.2f}', va='center', fontsize=9)
    ax.set_yticks(y)
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    ax.set_xlim(0, 1.05)
    ax.set_xlabel('Share of domains')
    fig.tight_layout(pad=0.3)
    fig.savefig(out_dir / 'domains_with_external_requests_by_sector.pdf', bbox_inches='tight')
    plt.close(fig)


def plot_blocking_summary(rows, out_dir: Path):
    metrics = [
        ('visual_diff_mean', 'Visual Diff'),
        ('html_structural_loss_mean', 'HTML Loss'),
        ('text_loss_mean', 'Text Loss'),
        ('domain_score_mean', 'Mean Score'),
    ]
    fig, axes = plt.subplots(1, 4, figsize=(6.9, 1.65), sharey=True)
    for ax, (key, title) in zip(axes, metrics):
        vals = [r[key] if r[key] is not None else 0 for r in rows]
        y = np.arange(len(rows))
        bars = ax.barh(y, vals, color=[SECTOR_COLORS[r['category']] for r in rows], edgecolor='black', linewidth=0.35)
        for bar, row in zip(bars, rows):
            bar.set_hatch(HATCHES[row['category']])
        ax.set_title(title, fontsize=10)
        ax.set_xlim(0, 1)
        ax.set_xlabel('Mean')
        ax.set_yticks(y)
        if ax is axes[0]:
            ax.set_yticklabels([SECTOR_LABELS[r['category']] for r in rows])
        else:
            ax.tick_params(labelleft=False)
        ax.invert_yaxis()
    fig.tight_layout(pad=0.35, w_pad=0.5)
    fig.savefig(out_dir / 'blocking_diff_components_by_sector.pdf', bbox_inches='tight')
    plt.close(fig)


def plot_blocking_boxplots(domain_rows, out_dir: Path):
    import matplotlib.transforms as mtransforms
    metrics = [
        ('visual_diff_share', 'Visual'),
        ('html_structural_loss', 'HTML'),
        ('text_loss', 'Text'),
        ('domain_score', 'Mean'),
    ]
    fig, axes = plt.subplots(1, 4, figsize=(6.9, 1.9), sharey=True)
    positions = np.arange(1, len(SECTOR_ORDER) + 1)
    for ax, (metric, label) in zip(axes, metrics):
        data = []
        medians = []
        for sector in SECTOR_ORDER:
            vals = [
                row[metric] for row in domain_rows
                if row['category'] == sector and row.get(metric) is not None
            ]
            data.append(vals)
            medians.append(float(np.median(vals)) if vals else float('nan'))
        bp = ax.boxplot(
            data,
            vert=False,
            positions=positions,
            widths=0.55,
            patch_artist=True,
            showfliers=False,
            medianprops={'color': '#111111', 'linewidth': 1.0},
            boxprops={'linewidth': 0.6},
            whiskerprops={'linewidth': 0.6},
            capprops={'linewidth': 0.6},
        )
        for patch, sector in zip(bp['boxes'], SECTOR_ORDER):
            patch.set_facecolor(SECTOR_COLORS[sector])
            patch.set_hatch(HATCHES[sector])
            patch.set_alpha(0.85)
        ax.set_xlim(0, 1)
        ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0])
        ax.set_xlabel(label)
        ax.set_yticks(positions)
        if ax is axes[0]:
            ax.set_yticklabels([SECTOR_LABELS[s] for s in SECTOR_ORDER])
        else:
            ax.tick_params(labelleft=False)
        # Median labels to the right (outside axes) for each boxplot row
        trans = mtransforms.blended_transform_factory(ax.transAxes, ax.transData)
        for pos, med in zip(positions, medians):
            if not np.isnan(med):
                ax.text(1.03, pos, f'{med:.2f}', va='center', ha='left', fontsize=6.5,
                        transform=trans, clip_on=False)
    axes[0].invert_yaxis()
    fig.tight_layout(pad=0.25, w_pad=0.45)
    fig.savefig(out_dir / 'blocking_diff_components_boxplots_by_sector.pdf', bbox_inches='tight')
    plt.close(fig)


def plot_in_eu_request_share_boxplot_by_sector(domain_rows, out_dir: Path):
    fig, ax = plt.subplots(figsize=(3.45, 1.9))
    positions = np.arange(1, len(SECTOR_ORDER) + 1)
    data = []
    means = []
    for sector in SECTOR_ORDER:
        vals = [
            row['in_eu_request_share_pct'] / 100.0
            for row in domain_rows
            if row['category'] == sector and row['in_eu_request_share_pct'] is not None
        ]
        data.append(vals)
        means.append(float(np.mean(vals)) if vals else float('nan'))

    bp = ax.boxplot(
        data,
        vert=False,
        positions=positions,
        widths=0.55,
        patch_artist=True,
        showfliers=False,
        medianprops={'color': '#111111', 'linewidth': 1.0},
        boxprops={'linewidth': 0.6},
        whiskerprops={'linewidth': 0.6},
        capprops={'linewidth': 0.6},
    )
    for patch, sector in zip(bp['boxes'], SECTOR_ORDER):
        patch.set_facecolor(SECTOR_COLORS[sector])
        patch.set_hatch(HATCHES[sector])
        patch.set_alpha(0.85)
    for pos, mean_val, sector in zip(positions, means, SECTOR_ORDER):
        if not np.isnan(mean_val):
            ax.scatter(
                mean_val,
                pos,
                marker=SECTOR_MARKERS[sector],
                s=26,
                color='white',
                edgecolor='#111111',
                linewidth=0.6,
                zorder=3,
            )
    ax.set_yticks(positions)
    ax.set_yticklabels([SECTOR_LABELS[s] for s in SECTOR_ORDER])
    ax.invert_yaxis()
    ax.set_xlim(0, 1)
    ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.set_xticklabels(['0', '25', '50', '75', '100'])
    ax.set_xlabel('In-EU request share per domain (%)')
    fig.tight_layout(pad=0.25)
    fig.savefig(out_dir / 'in_eu_request_share_boxplot_by_sector.pdf', bbox_inches='tight')
    plt.close(fig)


def latex_table(rows, columns, labels):
    lines = ['\\begin{tabularx}{\\columnwidth}{X' + 'r' * (len(columns) - 1) + '}', '\\toprule']
    lines.append(' & '.join(labels) + r' \\')
    lines.append('\\midrule')
    for row in rows:
        vals = []
        for col in columns:
            val = row.get(col)
            if col == 'category':
                vals.append(SECTOR_LABELS.get(val, val))
            elif isinstance(val, float):
                vals.append(f'{val:.3f}')
            else:
                vals.append(str(val))
        lines.append(' & '.join(vals) + r' \\')
    lines.extend(['\\bottomrule', '\\end{tabularx}'])
    return '\n'.join(lines)


def in_eu_sector_table(rows):
    def fmt_pct(value):
        return f'{value:.2f}'.replace('.', ',')

    lines = [
        r'\begin{tabularx}{\columnwidth}{Xrrr}',
        r'\toprule',
        r' &  & \multicolumn{2}{c}{\% Requests} \\',
        r'\cmidrule(lr){3-4}',
        r'Sector & \% Domains & $\mu$ & $\tilde{x}$ \\',
        r'\midrule',
    ]
    for row in rows:
        lines.append(
            f"{SECTOR_LABELS.get(row['category'], row['category'])} & "
            f"{fmt_pct(row['domains_only_in_eu_share_pct'])} & "
            f"{fmt_pct(row['mean_domain_in_eu_request_share_pct'])} & "
            f"{fmt_pct(row['median_domain_in_eu_request_share_pct'])} \\\\"
        )
    lines.extend([r'\bottomrule', r'\end{tabularx}'])
    return '\n'.join(lines)


def write_tex(out_dir, resource_scope, resource_sector, resource_probability_sector, vendor_top, blocking_rows, scope_overlap_rows, subpage_dom_share, any_outside_summary=None, in_eu_summary=None, examples=None, coverage_summary=None):
    def top_types(sector, scope='outside EU', n=3):
        rows = [r for r in resource_sector if r['category'] == sector and r['scope_group'] == scope]
        return [r['resource_type'] for r in sorted(rows, key=lambda r: (-r['mean_domain_share'], r['resource_type']))[:n]]

    def examples_for_sector(sector):
        outside = top_types(sector, 'outside EU', 3)
        inside = top_types(sector, IN_SCOPE, 3)
        return ', '.join(outside), ', '.join(inside)

    def resource_outside_share(sector, rtype):
        for row in resource_probability_sector:
            if row['category'] == sector and row['resource_type'] == rtype:
                return row.get('outside_share_pct', 0.0)
        return 0.0

    external_top = [r for r in resource_scope if r['scope_group'] == 'outside EU'][:6]
    any_top = vendor_top[:6]
    any_rows = (any_outside_summary or {}).get('by_sector', [])
    any_overall = (any_outside_summary or {}).get('overall', {})
    in_eu_rows = (in_eu_summary or {}).get('by_sector', [])
    in_eu_overall = (in_eu_summary or {}).get('overall', {})
    coverage = coverage_summary or {}
    coverage_rows = coverage.get('by_sector', [])
    coverage_text = '; '.join(
        f"{SECTOR_LABELS.get(row['category'], row['category'])}: {row['analyzed_domain_count']}/{row['input_domain_count']} ({row['analyzed_share_pct']:.1f}\\%)"
        for row in coverage_rows
    )
    sector_request_share = {row['category']: row['outside_request_share_pct'] for row in any_rows}
    sector_domain_share = {row['category']: row['domain_share_pct'] for row in any_rows}
    sector_domain_count = {row['category']: row['domains_with_any_outside_request'] for row in any_rows}
    sector_in_eu_request_share = {row['category']: row['in_eu_request_share_pct'] for row in in_eu_rows}
    vendor_share = {row['vendor']: row['domain_share_pct'] for row in vendor_top}
    blocking_by_sector = {row['category']: row for row in blocking_rows}
    example_hosts = (examples or {}).get('top_outside_hosts', [])[:5]
    notable_patterns = (examples or {}).get('notable_patterns', [])[:8]
    example_host_text = '; '.join(
        f"{item['host']} ({item['domains_with_request']} domains; e.g., {item['examples'][0]['resource'] if item.get('examples') else 'no example'})"
        for item in example_hosts
    )
    lines = [
        r'\subsection{Web Content}',
        r'\label{sec:assessment_3rdpartydep}',
        '',
        rf"We retain {coverage.get('analyzed_domain_count', 0):,} of {coverage.get('input_domain_count', 0):,} input domains ({coverage.get('analyzed_share_pct', 0.0):.1f}\%) for the request analysis. A domain is retained only if the normal page load returned a 2xx/3xx HTTP status and the normal screenshot was not classified as blank. The retained set by sector is: {coverage_text}. Request-share, resource-type, and destination results are computed from classified subrequests in the blocked-phase request log. The top-level navigation, browser-internal requests without a host, and requests without IP/ASN/block classification are excluded. Requests to the same ASN as the main page are still counted, but are not blocked in the experiment.",
        '',
        r'\paragraph{Request Share}',
        rf"Across retained domains, {any_overall.get('domains_with_any_outside_request', 0):,} pages ({any_overall.get('domain_share_pct', 0.0):.1f}\%) contact at least one ASN/operator classified outside the EU. These requests account for {any_overall.get('outside_request_share_pct', 0.0):.1f}\% of classified subrequests. Government and university pages keep most subrequests inside EU-classified infrastructure ({sector_in_eu_request_share.get('government', 0.0):.1f}\% and {sector_in_eu_request_share.get('university', 0.0):.1f}\%). Banks are split more evenly ({sector_in_eu_request_share.get('bank', 0.0):.1f}\% inside the EU), while newspapers are the outlier: only {sector_in_eu_request_share.get('newspaper', 0.0):.1f}\% of their subrequests remain inside EU-classified ASNs/operators.",
        '',
        r'\paragraph{Resource Types}',
        rf"Figure~\ref{{fig:resource-type-location-probability-sector}} reports classified subrequests by browser resource type. The row labelled document therefore refers to embedded document requests such as frames, not to the always-allowed top-level navigation. For document-type subrequests, the outside-EU share is {resource_outside_share('government', 'document'):.1f}\% for government, {resource_outside_share('university', 'document'):.1f}\% for universities, {resource_outside_share('bank', 'document'):.1f}\% for banks, and {resource_outside_share('newspaper', 'document'):.1f}\% for newspapers. Across all resource types, the corresponding shares are {sector_request_share.get('government', 0.0):.1f}\%, {sector_request_share.get('university', 0.0):.1f}\%, {sector_request_share.get('bank', 0.0):.1f}\%, and {sector_request_share.get('newspaper', 0.0):.1f}\%. This gap is driven by scripts, fonts, stylesheets, images, and fetch/XHR requests used for tags, analytics, advertising, CDNs, and embedded services.",
        '',
        r'\begin{figure}[t]',
        r'\centering',
        r'\includegraphics[width=\linewidth]{resource_type_location_probability_by_sector_barcols_sorted_dom.pdf}',
        r'\caption{Share of requests to ASNs/operators classified outside the EU by resource type and sector.}',
        r'\label{fig:resource-type-location-probability-sector}',
        r'\end{figure}',
        '',
        (r'Several examples are policy-relevant because they occur on retained government domains. Google Tag Manager appears on 67 government domains (20.2\%), and Google Fonts CSS on 74 (22.4\%). Other government examples include Cloudflare Insights on 9 domains (2.7\%), reCAPTCHA on 13 (3.9\%), Facebook scripts on 14 (4.2\%), and Google Analytics on 18 (5.4\%). The crawl also contains more EU-oriented analytics choices: Matomo/Piwik appears on 19 retained government domains (5.7\%), including typical \texttt{matomo.js} and \texttt{matomo.php} endpoints. Across all sectors, named examples include \texttt{gtm.js}, \texttt{fonts.googleapis.com/css}, \texttt{fonts.gstatic.com/*.woff2}, \texttt{fbevents.js}, DoubleClick/GPT \texttt{gpt.js}, \texttt{analytics.js}, cdnjs, jsDelivr, Amazon S3, and CloudFront.'),
        '',
        r'\paragraph{Request Destination}',
        rf"Central entities contacted by many investigated domains are Google ({vendor_share.get('Google LLC', 0.0):.1f}\%), Cloudflare ({vendor_share.get('Cloudflare, Inc.', 0.0):.1f}\%), Amazon ({vendor_share.get('Amazon.com, Inc.', 0.0):.1f}\%), Fastly ({vendor_share.get('Fastly, Inc.', 0.0):.1f}\%), and Microsoft ({vendor_share.get('Microsoft Corporation', 0.0):.1f}\%). The pattern is not limited to newspapers: many retained government domains also contact these operators.",
        '',
        r'\begin{figure}[t]',
        r'\centering',
        r'\includegraphics[width=\linewidth]{top_external_request_vendors.pdf}',
        r'\caption{Top destination organizations for requests classified outside the EU. Values show the share of retained domains contacting each organization.}',
        r'\label{fig:top-external-vendors}',
        r'\end{figure}',
        '',
        r'\begin{table}[t]',
        r'\centering',
        r'\caption{Top ASN organizations for requests classified outside the EU, counted by input-domain presence.}',
        r'\label{tab:top-external-vendors}',
        latex_table(any_top[:8], ['vendor', 'domains_with_external_request', 'domain_share_pct'], ['Organization', 'Domains', 'Share']),
        r'\end{table}',
        '',
        rf"The share of fully autonomous pages remains small. Government has the lowest prevalence, but only {100 - sector_domain_share.get('government', 0.0):.1f}\% of retained government domains avoid outside-EU ASNs/operators entirely. The share is {100 - sector_domain_share.get('university', 0.0):.1f}\% for universities, {100 - sector_domain_share.get('bank', 0.0):.1f}\% for banks, and {100 - sector_domain_share.get('newspaper', 0.0):.1f}\% for newspapers. Table~\ref{{tab:domains-external-share}} reports these values as inside-EU shares; the request-share column is the aggregate share of requests in the sector, while Figure~\ref{{fig:in-eu-request-share-boxplot}} shows the per-domain distribution.",
        '',
        r'\begin{table}[t]',
        r'\centering',
        r'\caption{Domains and requests remaining within EU-classified ASNs/operators. Mean and median \% requests are computed from one in-EU request share per retained domain.}',
        r'\label{tab:domains-external-share}',
        in_eu_sector_table(in_eu_rows),
        r'\end{table}',
        '',
        r'\begin{figure}[t]',
        r'\centering',
        r'\includegraphics[width=\linewidth]{in_eu_request_share_boxplot_by_sector.pdf}',
        r'\caption{Distribution of per-domain in-EU request shares by sector. White markers denote sector means.}',
        r'\label{fig:in-eu-request-share-boxplot}',
        r'\end{figure}',
        '',
        r'\paragraph{Request Blocking}',
        rf"Figure~\ref{{fig:blocking-diff-components}} reports the page effect after blocking requests to ASNs classified outside the EU. Many pages keep their main visual layout: mean visual loss is {blocking_by_sector.get('government', {}).get('visual_diff_mean', 0.0) * 100:.1f}\% for government, {blocking_by_sector.get('university', {}).get('visual_diff_mean', 0.0) * 100:.1f}\% for universities, {blocking_by_sector.get('bank', {}).get('visual_diff_mean', 0.0) * 100:.1f}\% for banks, and {blocking_by_sector.get('newspaper', {}).get('visual_diff_mean', 0.0) * 100:.1f}\% for newspapers. Structural changes are larger. HTML loss reaches {blocking_by_sector.get('bank', {}).get('html_structural_loss_mean', 0.0) * 100:.1f}\% for banks and {blocking_by_sector.get('newspaper', {}).get('html_structural_loss_mean', 0.0) * 100:.1f}\% for newspapers, suggesting that these requests often support page modules that are not visually dominant in the screenshot.",
        '',
        r'\begin{figure*}[t]',
        r'\centering',
        r'\includegraphics[width=0.95\linewidth]{blocking_diff_components_boxplots_by_sector.pdf}',
        r'\caption{Blocking impact by sector after blocking requests classified outside the EU. Components are normalized to $[0,1]$; the mean score is the average of visual difference, HTML structural loss, and visible-text token loss.}',
        r'\label{fig:blocking-diff-components}',
        r'\end{figure*}',
        '',
        r'\begin{table}[t]',
        r'\centering',
        r'\caption{Mean blocking impact components by sector.}',
        r'\label{tab:blocking-diff-components}',
        latex_table(blocking_rows, ['category', 'visual_diff_mean', 'html_structural_loss_mean', 'text_loss_mean', 'domain_score_mean'], ['Sector', 'Visual', 'HTML', 'Text', 'Mean']),
        r'\end{table}',
        '',
    ]
    (out_dir / 'third_party_web_resources.tex').write_text('\n'.join(lines), encoding='utf-8')


def subset_meta(meta, domains):
    domains = set(domains)
    return {domain: record for domain, record in meta.items() if domain in domains}


def cohort_domain_sets(pages):
    by_scope = defaultdict(set)
    for page in pages:
        by_scope[page.get('main_host_scope') or 'Unknown'].add(page['input_domain'])
    return {
        'all': {page['input_domain'] for page in pages},
        'main_in_eu': by_scope[IN_SCOPE],
        'main_outside_eu_ch': by_scope[OUT_SCOPE],
        'main_unknown': by_scope['Unknown'],
    }


def main_host_scope_summary(pages, meta):
    scopes = ['all', IN_SCOPE, OUT_SCOPE, 'Unknown']
    rows = []
    page_by_domain = {page['input_domain']: page for page in pages}
    domains_by_sector = input_domains_by_sector(meta)
    for sector in SECTOR_ORDER:
        domains = domains_by_sector[sector]
        counts = Counter((page_by_domain.get(domain) or {}).get('main_host_scope') or 'Missing' for domain in domains)
        rows.append({
            'category': sector,
            'input_domain_count': len(domains),
            'main_in_eu_domains': counts[IN_SCOPE],
            'main_outside_eu_ch_domains': counts[OUT_SCOPE],
            'main_unknown_domains': counts['Unknown'],
            'missing_crawl_domains': counts['Missing'],
            'main_in_eu_share_pct': round(pct(counts[IN_SCOPE], len(domains)), 3),
            'main_outside_eu_ch_share_pct': round(pct(counts[OUT_SCOPE], len(domains)), 3),
            'main_unknown_share_pct': round(pct(counts['Unknown'], len(domains)), 3),
        })
    return rows


def run_output_set(out_dir: Path, meta, pages, requests, missing=None, duplicate_rows=None, raw_page_count=None, coverage_summary=None):
    out_dir.mkdir(parents=True, exist_ok=True)
    request_rows = classified_subrequests(requests)
    resource_scope, resource_sector = domain_resource_type_tables(meta, request_rows)
    resource_location_probability = resource_type_location_probability_table(meta, request_rows)
    resource_location_probability_sector = resource_type_location_probability_by_sector_table(meta, request_rows)
    outside_vendor_top, outside_vendor_sector = domain_vendor_tables(meta, request_rows)
    any_vendor_top, any_vendor_sector = any_asn_org_domain_share(meta, request_rows)
    blocking_rows = blocking_summary(pages, meta)
    blocking_domain_rows = collapse_pages_to_domains(pages, meta)
    scope_overlap_rows = domain_scope_overlap(pages, request_rows, meta)
    any_outside_summary = summarize_any_outside_by_sector_country(meta, request_rows)
    in_eu_summary = summarize_in_eu_by_sector_country(meta, request_rows)
    in_eu_domain_rows = in_eu_summary['per_domain']
    domain_scope_class_summary = summarize_domain_scope_classes(meta, request_rows)
    examples = resource_examples(request_rows)
    pattern_evidence = resource_pattern_domain_evidence(request_rows)

    write_csv(out_dir / 'resource_type_location_probability_domain_weighted.csv', resource_location_probability)
    write_csv(out_dir / 'resource_type_location_probability_by_sector.csv', resource_location_probability_sector)
    write_csv(out_dir / 'resource_type_location_probability_by_sector_all_requests.csv', resource_location_probability_sector)
    write_csv(out_dir / 'top_external_vendors_domain_share.csv', outside_vendor_top)
    write_csv(out_dir / 'top_external_vendors_domain_share_by_sector.csv', outside_vendor_sector)
    write_csv(out_dir / 'asn_org_any_request_domain_share.csv', any_vendor_top)
    write_csv(out_dir / 'asn_org_any_request_domain_share_by_sector.csv', any_vendor_sector)
    write_csv(out_dir / 'blocking_diff_components_by_sector.csv', blocking_rows)
    write_csv(out_dir / 'blocking_diff_components_by_domain.csv', blocking_domain_rows)
    write_csv(out_dir / 'in_eu_request_share_by_domain.csv', in_eu_domain_rows)
    write_csv(out_dir / 'domain_scope_classes_by_domain.csv', domain_scope_class_summary['per_domain'])
    (out_dir / 'any_outside_request_summary.json').write_text(
        json.dumps(any_outside_summary, indent=2, sort_keys=True),
        encoding='utf-8',
    )
    in_eu_summary_json = {key: value for key, value in in_eu_summary.items() if key != 'per_domain'}
    (out_dir / 'in_eu_request_summary.json').write_text(
        json.dumps(in_eu_summary_json, indent=2, sort_keys=True),
        encoding='utf-8',
    )
    (out_dir / 'domain_scope_class_summary.json').write_text(
        json.dumps(domain_scope_class_summary, indent=2, sort_keys=True),
        encoding='utf-8',
    )
    (out_dir / 'resource_examples.json').write_text(
        json.dumps(examples, indent=2, sort_keys=True),
        encoding='utf-8',
    )
    (out_dir / 'resource_pattern_domain_evidence.json').write_text(
        json.dumps(pattern_evidence, indent=2, sort_keys=True),
        encoding='utf-8',
    )
    if coverage_summary:
        coverage_summary = dict(coverage_summary)
        coverage_summary['request_filter'] = 'blocked-phase classified subrequests: excludes allow_main_navigation, no-host rows, and rows without IP/ASN/block classification'
        coverage_summary['retained_blocked_phase_request_count'] = len(requests)
        coverage_summary['classified_subrequest_count'] = len(request_rows)
        (out_dir / 'analysis_coverage_summary.json').write_text(
            json.dumps(coverage_summary, indent=2, sort_keys=True),
            encoding='utf-8',
        )

    subpage_dom_share = load_subpage_asn_org_domain_share(SQLITE_REPRODUCIBLE_DIR)
    plot_resource_type_location_probability_by_sector_barcols(resource_location_probability_sector, resource_location_probability, out_dir, sort_by='domain')
    plot_top_vendors(outside_vendor_top, out_dir)
    plot_any_asn_org_domain_share(any_vendor_top, out_dir, subpage_dom_share=subpage_dom_share)
    plot_blocking_boxplots(blocking_domain_rows, out_dir)
    plot_in_eu_request_share_boxplot_by_sector(in_eu_domain_rows, out_dir)
    write_tex(
        out_dir,
        resource_scope,
        resource_sector,
        resource_location_probability_sector,
        outside_vendor_top,
        blocking_rows,
        scope_overlap_rows,
        subpage_dom_share,
        any_outside_summary=any_outside_summary,
        in_eu_summary=in_eu_summary,
        examples=examples,
        coverage_summary=coverage_summary,
    )

    copy_outputs([
        out_dir / 'resource_type_location_probability_domain_weighted.csv',
        out_dir / 'resource_type_location_probability_by_sector.csv',
        out_dir / 'resource_type_location_probability_by_sector_all_requests.csv',
        out_dir / 'resource_type_location_probability_by_sector_barcols_sorted_dom.pdf',
        out_dir / 'top_external_vendors_domain_share.csv',
        out_dir / 'top_external_vendors_domain_share_by_sector.csv',
        out_dir / 'top_external_request_vendors.pdf',
        out_dir / 'asn_org_any_request_domain_share.csv',
        out_dir / 'asn_org_any_request_domain_share_by_sector.csv',
        out_dir / 'asn_org_any_request_domain_share.pdf',
        out_dir / 'blocking_diff_components_boxplots_by_sector.pdf',
        out_dir / 'in_eu_request_share_boxplot_by_sector.pdf',
        out_dir / 'any_outside_request_summary.json',
        out_dir / 'in_eu_request_summary.json',
        out_dir / 'in_eu_request_share_by_domain.csv',
        out_dir / 'domain_scope_class_summary.json',
        out_dir / 'domain_scope_classes_by_domain.csv',
        out_dir / 'resource_examples.json',
        out_dir / 'resource_pattern_domain_evidence.json',
        out_dir / 'analysis_coverage_summary.json',
    ], out_dir / 'per_domain_request_share')

    return {
        'out_dir': str(out_dir),
        'raw_pages': raw_page_count if raw_page_count is not None else len(pages),
        'deduplicated_pages': len(pages),
        'duplicate_domains': len(duplicate_rows or []),
        'requests': len(request_rows),
        'raw_retained_blocked_phase_requests': len(requests),
        'scope_overlap': scope_overlap_rows,
        'any_outside_request_summary': any_outside_summary,
        'in_eu_request_summary': in_eu_summary,
        'domain_scope_class_summary': domain_scope_class_summary,
        'resource_examples': examples,
        'resource_pattern_domain_evidence': pattern_evidence,
        'analysis_coverage_summary': coverage_summary,
        'main_host_scope': main_host_scope_summary(pages, meta),
    }


def cohort_comparison_rows(results_by_name):
    rows = []
    for cohort, result in results_by_name.items():
        for row in result['domain_share']:
            rows.append({
                'cohort': cohort,
                'category': row['category'],
                'input_domain_count': row['input_domain_count'],
                'domains_with_outside_request': row['domains_with_external_request'],
                'share_pct': row['share_pct'],
            })
    return rows


def main():
    args = parse_args()
    crawl_dir = Path(args.crawl_dir)
    out_dir = Path(args.output_dir)
    meta = load_domain_meta(Path(args.domains_csv))
    pages, requests, missing = load_rows(crawl_dir, meta)
    raw_page_count = len(pages)
    pages, requests, duplicate_rows = deduplicate_to_one_run_per_domain(pages, requests)
    coverage_summary = analysis_coverage_summary(meta, pages, [page for page in pages if normal_load_success(page)])
    pages, requests, analysis_meta = filter_to_successful_normal_loads(pages, requests, meta)

    result = run_output_set(out_dir, analysis_meta, pages, requests, missing, duplicate_rows, raw_page_count, coverage_summary=coverage_summary)

    print({
        'raw_pages': raw_page_count,
        'analyzed_pages': len(pages),
        'duplicate_domains': len(duplicate_rows),
        'requests': len(requests),
        'analysis_coverage': coverage_summary,
        'outside_domains_with_in_eu_requests_by_sector': result['scope_overlap'],
        'out_dir': str(out_dir),
    })


if __name__ == '__main__':
    main()
