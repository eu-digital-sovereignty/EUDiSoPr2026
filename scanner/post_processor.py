#!/usr/bin/env python3
"""
Post-Processor for EU Government Infrastructure Survey

Reads raw collected data and performs analysis:
- IP to ASN/Provider mapping
- SaaS service detection
- Email provider identification
- Tracker classification
- Security posture assessment

This separation allows:
1. Raw data to be archived for reproducibility
2. Analysis to be re-run with updated classification databases
3. Different analysis approaches on the same raw data

Usage:
    python post_processor.py raw_data/ -o results/
    python post_processor.py raw_data/all_raw_data.json.gz -o results/
"""

import json
import gzip
import re
import csv
import logging
import argparse
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional
from collections import Counter

import dns.resolver

from ip_mapper import IPMapper, LOOKUP_DIR
from saas_detector import SaaSDetector
from constants import EU_COUNTRIES, CDN_PROVIDERS

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class AnalyzedDomain:
    """Analyzed domain with interpretations"""
    domain: str
    country: str
    country_code: str
    institution_name: str
    institution_category: str

    # Timestamps
    collection_timestamp: str
    analysis_timestamp: str

    # DNS Analysis
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    mx_records: list[dict] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None
    dmarc_policy: Optional[str] = None
    dkim_selectors_found: list[str] = field(default_factory=list)

    # NS Analysis
    ns_providers: list[dict] = field(default_factory=list)  # [{ns, ip, provider, hq, is_eu}]

    # Hosting Analysis
    hosting_ips: list[dict] = field(default_factory=list)
    hosting_provider: Optional[str] = None
    hosting_provider_hq: Optional[str] = None
    hosting_is_eu: Optional[bool] = None
    # hosting_status: "direct" | "cdn_and_origin" | "cdn_only" | "no_dns" | "lookup_failed"
    #  - direct:         origin resolved, no CDN
    #  - cdn_and_origin: CDN detected AND origin resolved behind it
    #  - cdn_only:       CDN detected, origin hidden (hosting_is_eu refers to CDN HQ)
    #  - no_dns:         domain has no A/AAAA records
    #  - lookup_failed:  A records exist but ASN lookup failed
    hosting_status: Optional[str] = None
    hosting_behind_cdn: Optional[bool] = None
    hosting_cdn_provider: Optional[str] = None
    hosting_cdn_provider_hq: Optional[str] = None
    hosting_cdn_is_eu: Optional[bool] = None

    # Email Analysis
    email_provider: Optional[str] = None
    email_provider_hq: Optional[str] = None
    email_is_eu: Optional[bool] = None
    office_suite: Optional[str] = None
    mx_resolution_cache: list[dict] = field(default_factory=list)

    # SaaS Detection
    detected_services: list[dict] = field(default_factory=list)
    office_suite_hq: Optional[str] = None

    # HTTP Analysis
    http_status: Optional[int] = None
    http_server: Optional[str] = None
    http_final_url: Optional[str] = None
    cdn_detected: Optional[str] = None
    third_party_domains: list[str] = field(default_factory=list)
    trackers: list[dict] = field(default_factory=list)

    # HTTP Accessibility
    http_accessible: bool = False  # True if we got a valid response
    http_blocked: bool = False  # True if we detected blocking
    http_block_reason: Optional[str] = None  # Reason for suspected block

    # Security Analysis
    has_https: bool = False
    has_hsts: bool = False
    security_headers: dict = field(default_factory=dict)

    # DNSSEC Analysis
    dnssec_enabled: bool = False
    dnssec_validated: bool = False
    has_dnskey: bool = False
    has_ds: bool = False

    # CAA Analysis
    caa_records: list[dict] = field(default_factory=list)
    caa_authorized_cas: list[str] = field(default_factory=list)
    caa_has_eu_ca: Optional[bool] = None
    caa_has_non_eu_ca: Optional[bool] = None

    # SSL/TLS Analysis
    ssl_issuer: Optional[str] = None
    ssl_issuer_org: Optional[str] = None
    ssl_issuer_country: Optional[str] = None
    ssl_issuer_is_eu: Optional[bool] = None
    ssl_protocol: Optional[str] = None
    ssl_valid_from: Optional[str] = None
    ssl_valid_to: Optional[str] = None

    # Errors from collection
    collection_errors: list[str] = field(default_factory=list)
    analysis_errors: list[str] = field(default_factory=list)

    # Classification reasoning (for audit/reproducibility)
    classification_log: list[str] = field(default_factory=list)


class PostProcessor:
    """Processes raw collected data into analyzed results"""

    # Certificate Authority classification — loaded from lookup_tables/ca_database.csv
    # Format: CA identifier pattern -> (Name, HQ Country, Is EU)
    @staticmethod
    def _load_ca_database():
        db = {}
        csv_path = LOOKUP_DIR / 'ca_database.csv'
        with open(csv_path, newline='') as f:
            for row in csv.DictReader(f):
                db[row['pattern']] = (row['name'], row['country'], row['is_eu'] == 'True')
        return db

    CA_DATABASE = _load_ca_database()

    def __init__(self):
        self.ip_mapper = IPMapper()
        self.saas_detector = SaaSDetector()

    def _classify_ca(self, ca_identifier: str) -> Optional[tuple]:
        """Classify a CA by its identifier (domain or name)"""
        ca_lower = ca_identifier.lower()
        for pattern, info in self.CA_DATABASE.items():
            if pattern in ca_lower:
                return info
        return None

    def process_raw_data(self, raw_data: dict) -> AnalyzedDomain:
        """Process a single domain's raw data"""
        domain = raw_data['domain']
        metadata = raw_data.get('metadata', {})

        result = AnalyzedDomain(
            domain=domain,
            country=metadata.get('country', 'Unknown'),
            country_code=metadata.get('country_code', 'XX'),
            institution_name=metadata.get('name', ''),
            institution_category=metadata.get('category', ''),
            collection_timestamp=raw_data.get('collection_timestamp', ''),
            analysis_timestamp=datetime.now(timezone.utc).isoformat(),
            collection_errors=raw_data.get('errors', [])
        )

        # Process DNS data
        self._process_dns(raw_data.get('dns_queries', []), result)

        # Perform SaaS detection
        self._detect_saas(result)

        return result

    def _process_dns(self, dns_queries: list, result: AnalyzedDomain):
        """Extract and analyze DNS data"""
        for query in dns_queries:
            qname = query.get('query_name', '')
            qtype = query.get('query_type', '')
            answers = query.get('answer', [])

            # Skip failed queries
            if query.get('status') not in ['NOERROR', None]:
                continue

            # Extract by record type
            if qtype == 'A' and qname == result.domain:
                result.a_records = [a['data'] for a in answers if a.get('type') == 'A']
            elif qtype == 'AAAA' and qname == result.domain:
                result.aaaa_records = [a['data'] for a in answers if a.get('type') == 'AAAA']
            elif qtype == 'MX':
                for a in answers:
                    if a.get('type') == 'MX':
                        # Parse MX record: "10 mail.example.com."
                        parts = a['data'].split(None, 1)
                        if len(parts) == 2:
                            result.mx_records.append({
                                'priority': int(parts[0]),
                                'host': parts[1].rstrip('.')
                            })
            elif qtype == 'TXT':
                for a in answers:
                    if a.get('type') == 'TXT':
                        # Remove quotes from TXT record
                        txt = a['data'].strip('"')
                        if qname == result.domain:
                            result.txt_records.append(txt)
                            if txt.startswith('v=spf1'):
                                result.spf_record = txt
                        elif qname.startswith('_dmarc.'):
                            result.dmarc_record = txt
                            # Extract policy
                            match = re.search(r'p=(none|quarantine|reject)', txt)
                            if match:
                                result.dmarc_policy = match.group(1)
                        elif '_domainkey.' in qname:
                            # Validate DKIM record contains required fields
                            # Valid DKIM must have v=DKIM1 and p= (public key)
                            if 'v=DKIM1' in txt.upper() or 'p=' in txt:
                                selector = qname.split('._domainkey.')[0]
                                result.dkim_selectors_found.append(selector)
            elif qtype == 'NS':
                result.ns_records = [a['data'].rstrip('.') for a in answers if a.get('type') == 'NS']
            elif qtype == 'CAA':
                # Parse CAA records
                for a in answers:
                    if a.get('type') == 'CAA':
                        caa_data = a['data']
                        result.caa_records.append({'raw': caa_data})
                        # Parse CAA: "0 issue \"letsencrypt.org\""
                        match = re.search(r'issue[wild]*\s+"([^"]+)"', caa_data)
                        if match:
                            ca_domain = match.group(1).lower()
                            result.caa_authorized_cas.append(ca_domain)
                            # Classify CA
                            ca_info = self._classify_ca(ca_domain)
                            if ca_info:
                                if ca_info[2]:  # is_eu
                                    result.caa_has_eu_ca = True
                                else:
                                    result.caa_has_non_eu_ca = True
            elif qtype == 'DNSKEY':
                if answers:
                    result.has_dnskey = True
                    result.dnssec_enabled = True
            elif qtype == 'DS':
                if answers:
                    result.has_ds = True
                    result.dnssec_enabled = True
            elif qtype == 'DNSSEC_CHECK':
                # Check AD flag from DNSSEC validation query
                flags = query.get('flags', {})
                if flags.get('ad'):
                    result.dnssec_validated = True
                    result.dnssec_enabled = True

        # IP to ASN mapping — collect ALL provider matches, then classify
        cdn_matches = []      # (provider, hq, is_eu, ip, asn)
        non_cdn_matches = []  # (provider, hq, is_eu, ip, asn)

        for ip in result.a_records[:5]:  # Limit to first 5 IPs
            try:
                ip_info = self.ip_mapper.lookup_ip(ip)
                result.hosting_ips.append({
                    'ip': ip_info.ip,
                    'asn': ip_info.asn,
                    'asn_name': ip_info.asn_name,
                    'provider': ip_info.provider,
                    'provider_hq': ip_info.provider_hq,
                    'is_eu': ip_info.is_eu_provider
                })

                if ip_info.provider:
                    entry = (ip_info.provider, ip_info.provider_hq,
                             ip_info.is_eu_provider, ip, ip_info.asn)
                    if ip_info.is_cdn or ip_info.provider in CDN_PROVIDERS:
                        cdn_matches.append(entry)
                    else:
                        non_cdn_matches.append(entry)
            except Exception as e:
                result.analysis_errors.append(f"IP lookup error ({ip}): {str(e)}")

        # If CDN detected, record CDN info separately
        if cdn_matches:
            cdn = cdn_matches[0]
            result.hosting_behind_cdn = True
            result.hosting_cdn_provider = cdn[0]
            result.hosting_cdn_provider_hq = cdn[1]
            result.hosting_cdn_is_eu = cdn[2]
            result.classification_log.append(
                f"cdn: {cdn[0]} (HQ={cdn[1]}) via IP {cdn[3]} -> ASN {cdn[4]}"
            )

        # Select primary hosting from non-CDN providers
        if non_cdn_matches:
            # Prefer EU provider if available
            eu_providers = [m for m in non_cdn_matches if m[2]]
            primary = eu_providers[0] if eu_providers else non_cdn_matches[0]
            result.hosting_provider = primary[0]
            result.hosting_provider_hq = primary[1]
            result.hosting_is_eu = primary[2]
            result.hosting_status = 'cdn_and_origin' if cdn_matches else 'direct'
            result.classification_log.append(
                f"hosting: {primary[0]} (HQ={primary[1]}) "
                f"via IP {primary[3]} -> ASN {primary[4]}"
            )
        elif cdn_matches:
            # Only CDN found — CDN terminates all traffic, so the CDN vendor
            # is the effective host. Classify by CDN's jurisdiction.
            result.hosting_provider = cdn_matches[0][0]
            result.hosting_provider_hq = cdn_matches[0][1]
            result.hosting_is_eu = cdn_matches[0][2]
            result.hosting_status = 'cdn_only'
            result.classification_log.append(
                f"hosting: behind CDN only, classified by CDN HQ "
                f"({cdn_matches[0][1]}, EU={cdn_matches[0][2]})"
            )

        # Fallback: if no known provider matched, use Cymru country code
        if result.hosting_is_eu is None and not cdn_matches and result.a_records:
            ip = result.a_records[0]
            try:
                cymru_info = self.ip_mapper._query_cymru(ip)
                if cymru_info and cymru_info.get('country'):
                    cc = cymru_info['country'].upper()
                    result.hosting_provider_hq = cc
                    result.hosting_is_eu = cc in EU_COUNTRIES or cc == 'EU'
                    result.hosting_status = 'direct'
                    result.classification_log.append(
                        f"hosting_fallback: {ip} -> ASN {cymru_info.get('asn')} "
                        f"(country={cc}, EU={result.hosting_is_eu})"
                    )
                else:
                    result.hosting_status = 'lookup_failed'
            except Exception as e:
                result.hosting_status = 'lookup_failed'
                result.analysis_errors.append(f"Hosting fallback error ({ip}): {str(e)}")

        # Set terminal status for domains with no A records
        if not result.a_records and result.hosting_status is None:
            result.hosting_status = 'no_dns'

        # --- NS provider resolution (same rigor as hosting) ---
        for ns_host in result.ns_records:
            try:
                answers = dns.resolver.resolve(ns_host, 'A', lifetime=5)
                ns_ip = str(answers[0])
                ip_info = self.ip_mapper.lookup_ip(ns_ip)
                hq = ip_info.provider_hq
                is_eu = ip_info.is_eu_provider
                # Fallback: if no provider matched, use Cymru country
                if hq is None:
                    try:
                        cymru = self.ip_mapper._query_cymru(ns_ip)
                        if cymru and cymru.get('country'):
                            hq = cymru['country'].upper()
                            is_eu = hq in EU_COUNTRIES or hq == 'EU'
                    except Exception:
                        pass
                result.ns_providers.append({
                    'ns': ns_host,
                    'ip': ns_ip,
                    'provider': ip_info.provider,
                    'hq': hq,
                    'is_eu': is_eu,
                })
            except Exception:
                result.ns_providers.append({
                    'ns': ns_host,
                    'ip': None,
                    'provider': None,
                    'hq': None,
                    'is_eu': None,
                })

    # Block detection patterns
    def _detect_saas(self, result: AnalyzedDomain):
        """Detect SaaS services from DNS data"""
        try:
            saas_result = self.saas_detector.analyze(
                domain=result.domain,
                txt_records=result.txt_records,
                mx_records=result.mx_records,
                spf_record=result.spf_record,
                dkim_found={s: True for s in result.dkim_selectors_found}
            )

            result.email_provider = saas_result.email_provider
            if saas_result.email_provider_details:
                result.email_provider_hq = saas_result.email_provider_details.get('hq')
                result.email_is_eu = result.email_provider_hq in EU_COUNTRIES
                result.classification_log.append(
                    f"email: {saas_result.email_provider} (HQ={result.email_provider_hq})"
                )
            elif result.mx_records:
                # No known provider detected — resolve MX hostname IPs
                # to determine email server location
                self._resolve_mx_location(result)

            result.office_suite = saas_result.office_suite
            if result.office_suite:
                # Both Microsoft 365 and Google Workspace are US-based
                result.office_suite_hq = 'US'
                result.classification_log.append(f"office: {result.office_suite}")

            for svc in saas_result.detected_services:
                result.detected_services.append({
                    'vendor': svc.vendor,
                    'category': svc.category,
                    'hq_country': svc.hq_country,
                    'is_eu': svc.is_eu,
                    'evidence': svc.evidence,
                    'detection_source': svc.detection_source,
                    'is_active_use': svc.is_active_use,
                })
                result.classification_log.append(
                    f"saas: {svc.vendor} ({svc.category}) via {svc.evidence[:60]}"
                )
        except Exception as e:
            result.analysis_errors.append(f"SaaS detection error: {str(e)}")

    def _resolve_mx_location(self, result: AnalyzedDomain):
        """Resolve MX hostnames to IPs and determine email server location."""
        import dns.resolver as dns_resolver

        # If cache is already populated (re-run), use it
        if result.mx_resolution_cache:
            for cached in result.mx_resolution_cache:
                if cached.get('provider'):
                    result.email_provider_hq = cached.get('provider_hq')
                    result.email_is_eu = cached.get('is_eu')
                    result.classification_log.append(
                        f"email_mx_resolve (cached): {cached.get('mx_host')} -> "
                        f"{cached.get('ip')} -> {cached.get('provider')}"
                    )
                    return
                elif cached.get('country'):
                    cc = cached['country']
                    result.email_provider_hq = cc
                    result.email_is_eu = cc in EU_COUNTRIES or cc == 'EU'
                    result.classification_log.append(
                        f"email_mx_resolve (cached): {cached.get('mx_host')} -> "
                        f"{cached.get('ip')} -> ASN {cached.get('asn')} (country={cc})"
                    )
                    return
            return

        # Use the highest-priority (lowest number) MX record
        sorted_mx = sorted(result.mx_records, key=lambda m: m.get('priority', 99))

        for mx in sorted_mx[:2]:  # Check top 2 MX hosts
            mx_host = mx.get('host', '')
            if not mx_host:
                continue

            try:
                resolver = dns_resolver.Resolver()
                resolver.timeout = 3
                resolver.lifetime = 5
                answers = resolver.resolve(mx_host, 'A')
                for rdata in answers:
                    ip = str(rdata)
                    ip_info = self.ip_mapper.lookup_ip(ip)

                    cache_entry = {
                        'mx_host': mx_host,
                        'ip': ip,
                        'asn': ip_info.asn,
                        'asn_name': ip_info.asn_name,
                        'provider': ip_info.provider,
                        'provider_hq': ip_info.provider_hq,
                        'is_eu': ip_info.is_eu_provider,
                    }

                    if ip_info.provider:
                        result.email_provider_hq = ip_info.provider_hq
                        result.email_is_eu = ip_info.is_eu_provider
                        result.classification_log.append(
                            f"email_mx_resolve: {mx_host} -> {ip} -> "
                            f"{ip_info.provider} (HQ={ip_info.provider_hq})"
                        )
                        result.mx_resolution_cache.append(cache_entry)
                        return
                    elif ip_info.asn:
                        cymru_info = self.ip_mapper._query_cymru(ip)
                        if cymru_info and cymru_info.get('country'):
                            cc = cymru_info['country'].upper()
                            cache_entry['country'] = cc
                            result.email_provider_hq = cc
                            result.email_is_eu = cc in EU_COUNTRIES or cc == 'EU'
                            result.classification_log.append(
                                f"email_mx_resolve: {mx_host} -> {ip} -> "
                                f"ASN {ip_info.asn} (country={cc})"
                            )
                            result.mx_resolution_cache.append(cache_entry)
                            return

                    result.mx_resolution_cache.append(cache_entry)
            except Exception as e:
                logger.debug(f"MX resolve failed for {mx_host}: {e}")
                continue


def load_raw_data(path: Path) -> list[dict]:
    """Load raw data from file or directory"""
    if path.is_file():
        if path.suffix == '.gz':
            with gzip.open(path, 'rt', encoding='utf-8') as f:
                return json.load(f)
        else:
            with open(path) as f:
                return json.load(f)
    elif path.is_dir():
        # Load from per-domain directories
        results = []
        for domain_dir in path.iterdir():
            if domain_dir.is_dir():
                raw_file = domain_dir / 'raw_data.json.gz'
                if not raw_file.exists():
                    raw_file = domain_dir / 'raw_data.json'
                if raw_file.exists():
                    if raw_file.suffix == '.gz':
                        with gzip.open(raw_file, 'rt', encoding='utf-8') as f:
                            results.append(json.load(f))
                    else:
                        with open(raw_file) as f:
                            results.append(json.load(f))
        return results
    else:
        raise ValueError(f"Path not found: {path}")


def save_results(results: list[AnalyzedDomain], output_dir: Path):
    """Save analyzed results"""
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')

    # Full JSON
    json_path = output_dir / f'analyzed_results_{timestamp}.json'
    with open(json_path, 'w') as f:
        json.dump([asdict(r) for r in results], f, indent=2, default=str)
    logger.info(f"Saved full results to {json_path}")

    # Summary CSV
    csv_path = output_dir / f'analyzed_summary_{timestamp}.csv'
    with open(csv_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'domain', 'country', 'country_code', 'institution_name', 'category',
            'hosting_provider', 'hosting_hq', 'hosting_eu',
            'email_provider', 'email_hq', 'email_eu',
            'office_suite', 'cdn', 'dmarc_policy',
            'has_https', 'has_hsts',
            'tracker_count', 'third_party_count',
            'http_status', 'error_count'
        ])

        for r in results:
            writer.writerow([
                r.domain, r.country, r.country_code, r.institution_name,
                r.institution_category,
                r.hosting_provider, r.hosting_provider_hq, r.hosting_is_eu,
                r.email_provider, r.email_provider_hq, r.email_is_eu,
                r.office_suite, r.cdn_detected, r.dmarc_policy,
                r.has_https, r.has_hsts,
                len(r.trackers), len(r.third_party_domains),
                r.http_status, len(r.collection_errors) + len(r.analysis_errors)
            ])
    logger.info(f"Saved summary to {csv_path}")

    # Print statistics
    print_statistics(results)


def print_statistics(results: list[AnalyzedDomain]):
    """Print analysis statistics"""
    total = len(results)
    if total == 0:
        return

    print("\n" + "=" * 70)
    print("ANALYSIS STATISTICS")
    print("=" * 70)
    print(f"Total domains analyzed: {total}")

    # Hosting
    eu_hosting = sum(1 for r in results if r.hosting_is_eu is True)
    non_eu_hosting = sum(1 for r in results if r.hosting_is_eu is False)
    unknown_hosting = total - eu_hosting - non_eu_hosting

    print(f"\nHosting Sovereignty:")
    print(f"  EU-based: {eu_hosting} ({eu_hosting/total*100:.1f}%)")
    print(f"  Non-EU: {non_eu_hosting} ({non_eu_hosting/total*100:.1f}%)")
    print(f"  Unknown: {unknown_hosting} ({unknown_hosting/total*100:.1f}%)")

    # Email
    email_providers = Counter(r.email_provider for r in results if r.email_provider)
    print(f"\nEmail Providers:")
    for provider, count in email_providers.most_common(5):
        print(f"  {provider}: {count} ({count/total*100:.1f}%)")

    # DMARC
    dmarc_policies = Counter(r.dmarc_policy or 'None' for r in results)
    print(f"\nDMARC Policies:")
    for policy, count in dmarc_policies.most_common():
        print(f"  {policy}: {count} ({count/total*100:.1f}%)")

    # CDN
    cdn_usage = Counter(r.cdn_detected for r in results if r.cdn_detected)
    print(f"\nCDN Usage:")
    for cdn, count in cdn_usage.most_common(5):
        print(f"  {cdn}: {count}")

    # HTTPS/HSTS
    has_https = sum(1 for r in results if r.has_https)
    has_hsts = sum(1 for r in results if r.has_hsts)
    print(f"\nSecurity:")
    print(f"  HTTPS: {has_https} ({has_https/total*100:.1f}%)")
    print(f"  HSTS: {has_hsts} ({has_hsts/total*100:.1f}%)")

    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description='Post-Processor - Analyzes raw collected data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This processor reads raw data and performs analysis:
- IP to ASN/Provider mapping
- SaaS service detection
- Email provider identification
- Tracker classification

Examples:
  # Process all raw data
  python post_processor.py raw_data/ -o results/

  # Process single combined file
  python post_processor.py raw_data/all_raw_data.json.gz -o results/
        """
    )
    parser.add_argument('input', help='Raw data directory or file')
    parser.add_argument('-o', '--output', default='results', help='Output directory')

    args = parser.parse_args()

    # Load raw data
    logger.info(f"Loading raw data from {args.input}")
    raw_data = load_raw_data(Path(args.input))
    logger.info(f"Loaded {len(raw_data)} domains")

    # Process
    processor = PostProcessor()
    results = []

    for i, raw in enumerate(raw_data):
        try:
            analyzed = processor.process_raw_data(raw)
            results.append(analyzed)
            if (i + 1) % 50 == 0:
                logger.info(f"Processed {i+1}/{len(raw_data)} domains")
        except Exception as e:
            logger.error(f"Failed to process {raw.get('domain', 'unknown')}: {e}")

    # Save results
    save_results(results, Path(args.output))

    # Write error log for failed Cymru lookups
    if processor.ip_mapper.failed_lookups:
        error_log = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'total_unique_ips_queried': len(processor.ip_mapper.cache),
            'failed_lookups': len(processor.ip_mapper.failed_lookups),
            'failures': processor.ip_mapper.failed_lookups,
        }
        err_path = Path(args.output) / f'cymru_errors_{datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")}.json'
        with open(err_path, 'w') as f:
            json.dump(error_log, f, indent=2)
        logger.warning(
            f"{len(processor.ip_mapper.failed_lookups)} Cymru lookup failures "
            f"logged to {err_path}"
        )
    else:
        logger.info("No Cymru lookup failures.")

    logger.info("Post-processing complete!")


if __name__ == '__main__':
    main()
