#!/usr/bin/env python3
"""
SaaS/Vendor Detection Module
Detects cloud services from DNS TXT records, MX records, and DKIM selectors
"""

import csv
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import logging

from constants import EU_COUNTRIES, is_eu_hq

LOOKUP_DIR = Path(__file__).resolve().parent.parent / 'lookup_tables'

logger = logging.getLogger(__name__)


@dataclass
class VendorDetection:
    vendor: str
    category: str  # email, office, analytics, security, collaboration, etc.
    hq_country: str
    is_eu: bool
    evidence: str
    detection_source: str = "unknown"  # "mx", "txt", "spf", "dkim"
    is_active_use: bool = False  # True for MX/SPF/DKIM (active mail routing)


@dataclass
class SaaSDetectionResult:
    domain: str
    email_provider: Optional[str] = None
    email_provider_details: Optional[dict] = None
    office_suite: Optional[str] = None
    detected_services: list[VendorDetection] = field(default_factory=list)


def _load_txt_patterns():
    """Load TXT patterns from CSV lookup table."""
    patterns = {}
    csv_path = LOOKUP_DIR / 'txt_patterns.csv'
    with open(csv_path, newline='') as f:
        for row in csv.DictReader(f):
            patterns[row['regex']] = {'vendor': row['vendor'], 'category': row['category'], 'hq': row['hq']}
    return patterns


def _load_mx_patterns():
    """Load MX patterns from CSV lookup table."""
    patterns = {}
    csv_path = LOOKUP_DIR / 'mx_patterns.csv'
    with open(csv_path, newline='') as f:
        for row in csv.DictReader(f):
            patterns[row['regex']] = {'vendor': row['vendor'], 'category': row['category'], 'hq': row['hq']}
    return patterns


# TXT record verification patterns — loaded from lookup_tables/txt_patterns.csv
TXT_PATTERNS = _load_txt_patterns()

# MX record patterns — loaded from lookup_tables/mx_patterns.csv
MX_PATTERNS = _load_mx_patterns()




class SaaSDetector:
    """Detect SaaS vendors from DNS records"""

    def __init__(self):
        self.txt_patterns = {re.compile(k, re.IGNORECASE): v for k, v in TXT_PATTERNS.items()}
        self.mx_patterns = {re.compile(k, re.IGNORECASE): v for k, v in MX_PATTERNS.items()}

    def analyze(self, domain: str, txt_records: list[str], mx_records: list[dict],
                spf_record: Optional[str] = None, dkim_found: dict = None) -> SaaSDetectionResult:
        """Analyze DNS records to detect SaaS vendors"""
        result = SaaSDetectionResult(domain=domain)

        # Analyze TXT records
        for txt in txt_records:
            txt = txt.strip('"')
            is_spf = txt.startswith('v=spf1')
            for pattern, info in self.txt_patterns.items():
                if pattern.search(txt):
                    txt_display = txt[:100] + '...' if len(txt) > 100 else txt
                    # SPF records contain active mail routing directives
                    source = 'spf' if is_spf else 'txt'
                    active = is_spf
                    detection = VendorDetection(
                        vendor=info['vendor'],
                        category=info['category'],
                        hq_country=info['hq'],
                        is_eu=is_eu_hq(info['hq']),
                        evidence=f"{'SPF' if is_spf else 'TXT'}: {txt_display}",
                        detection_source=source,
                        is_active_use=active,
                    )
                    result.detected_services.append(detection)

        # Analyze SPF record separately (often contains multiple includes)
        if spf_record:
            for pattern, info in self.txt_patterns.items():
                if pattern.search(spf_record):
                    # Check if already added from TXT
                    if not any(d.vendor == info['vendor'] and d.category == info['category']
                              for d in result.detected_services):
                        spf_display = spf_record[:100] + '...' if len(spf_record) > 100 else spf_record
                        detection = VendorDetection(
                            vendor=info['vendor'],
                            category=info['category'],
                            hq_country=info['hq'],
                            is_eu=is_eu_hq(info['hq']),
                                evidence=f"SPF: {spf_display}",
                            detection_source='spf',
                            is_active_use=True,
                        )
                        result.detected_services.append(detection)

        # Analyze MX records — collect all matches
        mx_email = None       # primary mailbox provider (category=email)
        mx_security = None    # security gateway (category=email_security)
        for mx in mx_records:
            host = mx.get('host', '')
            for pattern, info in self.mx_patterns.items():
                if pattern.search(host):
                    detection = VendorDetection(
                        vendor=info['vendor'],
                        category=info['category'],
                        hq_country=info['hq'],
                        is_eu=is_eu_hq(info['hq']),
                        evidence=f"MX: {host}",
                        detection_source='mx',
                        is_active_use=True,
                    )
                    result.detected_services.append(detection)

                    if info['category'] == 'email' and mx_email is None:
                        mx_email = info
                    elif info['category'] == 'email_security' and mx_security is None:
                        mx_security = info

        # Primary email provider: prefer mailbox provider over security gateway
        if mx_email and result.email_provider is None:
            result.email_provider = mx_email['vendor']
            result.email_provider_details = mx_email
        elif mx_security and result.email_provider is None:
            result.email_provider = mx_security['vendor']
            result.email_provider_details = mx_security

        # Analyze DKIM selectors
        if dkim_found:
            if dkim_found.get('selector1') or dkim_found.get('selector2'):
                if result.email_provider is None:
                    result.email_provider = 'Microsoft 365'
                    result.email_provider_details = {'hq': 'US', 'category': 'email'}
                result.detected_services.append(VendorDetection(
                    vendor='Microsoft 365',
                    category='email',
                    hq_country='US',
                    is_eu=False,
                    evidence='DKIM: selector1/selector2._domainkey',
                    detection_source='dkim',
                    is_active_use=True,
                ))

            if dkim_found.get('google'):
                if result.email_provider is None:
                    result.email_provider = 'Google Workspace'
                    result.email_provider_details = {'hq': 'US', 'category': 'email'}
                result.detected_services.append(VendorDetection(
                    vendor='Google Workspace',
                    category='email',
                    hq_country='US',
                    is_eu=False,
                    evidence='DKIM: google._domainkey',
                    detection_source='dkim',
                    is_active_use=True,
                ))

            if dkim_found.get('proofpoint') or dkim_found.get('ppkey1') or dkim_found.get('ppkey2'):
                result.detected_services.append(VendorDetection(
                    vendor='Proofpoint',
                    category='email_security',
                    hq_country='US',
                    is_eu=False,
                    evidence='DKIM: proofpoint/ppkey._domainkey',
                    detection_source='dkim',
                    is_active_use=True,
                ))

            if dkim_found.get('mimecast'):
                result.detected_services.append(VendorDetection(
                    vendor='Mimecast',
                    category='email_security',
                    hq_country='GB',
                    is_eu=False,
                    evidence='DKIM: mimecast._domainkey',
                    detection_source='dkim',
                    is_active_use=True,
                ))

        # Infer office suite from email provider
        if result.email_provider == 'Microsoft 365':
            result.office_suite = 'Microsoft 365'
        elif result.email_provider == 'Google Workspace':
            result.office_suite = 'Google Workspace'

        # Deduplicate services
        seen = set()
        unique_services = []
        for svc in result.detected_services:
            key = (svc.vendor, svc.category)
            if key not in seen:
                seen.add(key)
                unique_services.append(svc)
        result.detected_services = unique_services

        return result


if __name__ == '__main__':
    detector = SaaSDetector()

    # Test with sample data
    txt_records = [
        'v=spf1 include:spf.protection.outlook.com -all',
        'MS=ms12345678',
        'google-site-verification=abcd1234',
    ]
    mx_records = [
        {'priority': 10, 'host': 'domain-com.mail.protection.outlook.com'}
    ]

    result = detector.analyze(
        domain='example.com',
        txt_records=txt_records,
        mx_records=mx_records,
        spf_record=txt_records[0]
    )

    print(f"Email Provider: {result.email_provider}")
    print(f"Office Suite: {result.office_suite}")
    print(f"Detected Services:")
    for svc in result.detected_services:
        print(f"  - {svc.vendor} ({svc.category}) - HQ: {svc.hq_country}, EU: {svc.is_eu}")
