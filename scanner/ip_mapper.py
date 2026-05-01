#!/usr/bin/env python3
"""
IP to ASN/Provider Mapping Module
Maps IP addresses to ASN numbers and classifies cloud providers
"""

import csv
import socket
import ipaddress
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import logging
import dns.resolver
import dns.exception

from constants import EU_COUNTRIES

logger = logging.getLogger(__name__)

LOOKUP_DIR = Path(__file__).resolve().parent.parent / 'lookup_tables'


@dataclass
class IPInfo:
    ip: str
    asn: Optional[int] = None
    asn_name: Optional[str] = None
    provider: Optional[str] = None
    provider_hq: Optional[str] = None  # Country of HQ
    is_eu_provider: Optional[bool] = None
    is_eu_datacenter: Optional[bool] = None
    is_cdn: bool = False


def _load_cloud_providers_csv():
    """Load cloud providers from CSV lookup table."""
    providers = defaultdict(lambda: {'asns': [], 'hq': '', 'patterns': []})
    csv_path = LOOKUP_DIR / 'cloud_providers.csv'
    with open(csv_path, newline='') as f:
        for row in csv.DictReader(f):
            name = row['provider']
            providers[name]['asns'].append(int(row['asn']))
            providers[name]['hq'] = row['hq']
            if row['patterns']:
                providers[name]['patterns'] = row['patterns'].split(';')
    return dict(providers)


def _load_provider_overrides():
    """Load per-ASN canonical-name / CDN overrides."""
    overrides = {}
    csv_path = LOOKUP_DIR / 'provider_overrides.csv'
    if not csv_path.exists():
        return overrides
    with open(csv_path, newline='') as f:
        # Skip blank lines and comment lines (start with #)
        rows = (line for line in f if line.strip() and not line.lstrip().startswith('#'))
        for row in csv.DictReader(rows):
            overrides[int(row['asn'])] = {
                'name': row['canonical_name'],
                'hq': row['hq'],
                'is_eu': row['is_eu'].strip().lower() == 'true',
                'is_cdn': row['is_cdn'].strip().lower() == 'true',
                'category': row.get('category', '').strip(),
            }
    return overrides


# Known cloud provider ASN ranges and classifications
CLOUD_PROVIDERS = _load_cloud_providers_csv()
PROVIDER_OVERRIDES = _load_provider_overrides()


# Build ASN lookup table
ASN_TO_PROVIDER = {}
for provider, info in CLOUD_PROVIDERS.items():
    for asn in info['asns']:
        ASN_TO_PROVIDER[asn] = {
            'name': provider,
            'hq': info['hq'],
            'is_eu': info['hq'] in EU_COUNTRIES or info['hq'] == 'EU',
            'is_cdn': False,
        }

# Apply overrides — these win over the auto-built table
for asn, override in PROVIDER_OVERRIDES.items():
    ASN_TO_PROVIDER[asn] = override


class IPMapper:
    """Map IP addresses to ASN and provider information"""

    # Retry configuration
    MAX_RETRIES = 3
    INITIAL_BACKOFF = 0.5    # seconds
    BACKOFF_FACTOR = 2.0     # exponential multiplier
    REQUEST_INTERVAL = 0.05  # 50ms between Cymru queries to avoid rate-limiting

    def __init__(self):
        self.cache = {}
        self._last_query_time = 0.0
        self.failed_lookups = []  # tracks IPs that failed after all retries

    def _throttle(self):
        """Enforce minimum interval between Cymru DNS queries."""
        now = time.monotonic()
        elapsed = now - self._last_query_time
        if elapsed < self.REQUEST_INTERVAL:
            time.sleep(self.REQUEST_INTERVAL - elapsed)
        self._last_query_time = time.monotonic()

    def _dns_resolve_with_retry(self, query: str, rdtype: str = 'TXT') -> Optional[dns.resolver.Answer]:
        """Resolve a DNS query with exponential backoff retry."""
        last_err = None
        for attempt in range(self.MAX_RETRIES):
            self._throttle()
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 8
                return resolver.resolve(query, rdtype)
            except Exception as e:
                last_err = e
                if attempt < self.MAX_RETRIES - 1:
                    backoff = self.INITIAL_BACKOFF * (self.BACKOFF_FACTOR ** attempt)
                    logger.debug(
                        f"Cymru query '{query}' attempt {attempt+1} failed: {e}; "
                        f"retrying in {backoff:.1f}s"
                    )
                    time.sleep(backoff)
        logger.warning(f"Cymru query '{query}' failed after {self.MAX_RETRIES} attempts: {last_err}")
        return None

    def lookup_ip(self, ip: str) -> IPInfo:
        """Look up IP information including ASN and provider"""
        if ip in self.cache:
            return self.cache[ip]

        info = IPInfo(ip=ip)

        # Query Team Cymru via DNS for ASN info
        try:
            asn_info = self._query_cymru(ip)
            if asn_info:
                info.asn = asn_info.get('asn')
                info.asn_name = asn_info.get('name')

                # Check if known provider
                if info.asn in ASN_TO_PROVIDER:
                    provider_info = ASN_TO_PROVIDER[info.asn]
                    info.provider = provider_info['name']
                    info.provider_hq = provider_info['hq']
                    info.is_eu_provider = provider_info['is_eu']
                    info.is_cdn = provider_info.get('is_cdn', False)
            else:
                self.failed_lookups.append({
                    'ip': ip,
                    'error': 'cymru_origin_lookup_failed',
                    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
                })
        except Exception as e:
            logger.warning(f"Failed to lookup IP {ip}: {e}")
            self.failed_lookups.append({
                'ip': ip,
                'error': str(e),
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
            })

        self.cache[ip] = info
        return info

    def _query_cymru(self, ip: str) -> Optional[dict]:
        """Query Team Cymru DNS service for ASN info (with retry)."""
        # Determine if IPv4 or IPv6
        addr = ipaddress.ip_address(ip)

        if addr.version == 4:
            reversed_ip = '.'.join(reversed(ip.split('.')))
            query = f"{reversed_ip}.origin.asn.cymru.com"
        else:
            expanded = addr.exploded.replace(':', '')
            reversed_ip = '.'.join(reversed(expanded))
            query = f"{reversed_ip}.origin6.asn.cymru.com"

        answers = self._dns_resolve_with_retry(query)
        if not answers:
            return None

        for rdata in answers:
            txt = ''.join([s.decode('utf-8', errors='ignore') for s in rdata.strings])
            # Format: "ASN | IP Prefix | CC | Registry | Allocated"
            # Note: ASN field may contain multiple ASNs separated by spaces
            parts = [p.strip() for p in txt.split('|')]
            if len(parts) >= 3:
                asn_str = parts[0].split()[0]
                try:
                    asn = int(asn_str)
                except ValueError:
                    logger.debug(f"Invalid ASN value: {parts[0]}")
                    continue

                # Now get ASN name (also retried)
                name = self._get_asn_name(asn)

                return {
                    'asn': asn,
                    'prefix': parts[1] if len(parts) > 1 else None,
                    'country': parts[2] if len(parts) > 2 else None,
                    'name': name
                }

        return None

    def _get_asn_name(self, asn: int) -> Optional[str]:
        """Get ASN name from Team Cymru (with retry)."""
        query = f"AS{asn}.asn.cymru.com"
        answers = self._dns_resolve_with_retry(query)
        if not answers:
            return None

        for rdata in answers:
            txt = ''.join([s.decode('utf-8', errors='ignore') for s in rdata.strings])
            # Format: "ASN | CC | Registry | Allocated | Name"
            parts = [p.strip() for p in txt.split('|')]
            if len(parts) >= 5:
                return parts[4]

        return None

    def classify_provider(self, hostname: str) -> Optional[dict]:
        """Classify provider based on hostname patterns"""
        hostname_lower = hostname.lower()

        for provider, info in CLOUD_PROVIDERS.items():
            for pattern in info['patterns']:
                if pattern in hostname_lower:
                    return {
                        'name': provider,
                        'hq': info['hq'],
                        'is_eu': info['hq'] in EU_COUNTRIES or info['hq'] == 'EU'
                    }

        return None

    def lookup_bulk(self, ips: list[str]) -> list[IPInfo]:
        """Look up multiple IPs"""
        return [self.lookup_ip(ip) for ip in ips]


if __name__ == '__main__':
    mapper = IPMapper()

    test_ips = [
        '147.67.241.148',  # europa.eu
        '151.101.1.69',    # likely Fastly
        '104.18.32.7',     # likely Cloudflare
    ]

    for ip in test_ips:
        info = mapper.lookup_ip(ip)
        print(f"{ip}: ASN={info.asn} ({info.asn_name}) Provider={info.provider} EU={info.is_eu_provider}")
