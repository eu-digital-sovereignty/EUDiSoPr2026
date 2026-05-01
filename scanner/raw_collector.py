#!/usr/bin/env python3
"""
Raw Data Collector for EU Government Infrastructure Survey

Collects raw DNS and HTTP data with NO post-processing.
Outputs are in standard formats for reproducibility:
- DNS: Full response data in JSON (similar to dig +json output)
- HTTP: HAR (HTTP Archive) format

Usage:
    python raw_collector.py domains.txt -o raw_data/
    python raw_collector.py domains.json -o raw_data/ --limit 10

! WHILE THIS COMES WITH THE ABILITY TO COLLECT HTTP, WE ONLY USED THE DNS COLLECTION AND SPLIT UP THE SSL/WEB PART
"""

import json
import hashlib
import base64
import gzip
import socket
import ssl
import time
import logging
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse

from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import dns.rdatatype
import dns.query
import dns.message
import dns.name
import dns.exception
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# DNS Record types to query
DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA', 'DNSKEY', 'DS']
DKIM_SELECTORS = ['selector1', 'selector2', 'google', 'default', 'mail', 'k1', 's1', 's2',
                   'protonmail', 'protonmail2', 'protonmail3', 'mxvault', 'dkim', 'key1', 'key2',
                   'proofpoint', 'ppkey1', 'ppkey2', 'mimecast']


@dataclass
class RawDNSResponse:
    """Raw DNS query response"""
    query_name: str
    query_type: str
    query_time: str
    resolver: str
    status: str  # NOERROR, NXDOMAIN, SERVFAIL, etc.
    flags: dict
    question: list
    answer: list
    authority: list
    additional: list
    response_time_ms: float
    raw_wire: Optional[str] = None  # Base64 encoded wire format
    error: Optional[str] = None


@dataclass
class RawSSLCertificate:
    """Raw SSL/TLS certificate data"""
    subject: dict  # CN, O, OU, etc.
    issuer: dict   # CA information
    version: int
    serial_number: str
    not_before: str
    not_after: str
    subject_alt_names: list  # DNS names, IP addresses
    signature_algorithm: str
    public_key_algorithm: str
    public_key_bits: int
    fingerprint_sha256: str
    pem: str  # Full certificate in PEM format
    chain: list = field(default_factory=list)  # Certificate chain (issuer certs)


@dataclass
class RawHTTPTransaction:
    """Single HTTP request/response in HAR-like format"""
    started_datetime: str
    time_ms: float
    request: dict
    response: dict
    timings: dict
    server_ip: Optional[str] = None
    connection: Optional[str] = None
    ssl_certificate: Optional[dict] = None  # RawSSLCertificate as dict
    ssl_protocol: Optional[str] = None  # TLS version
    ssl_cipher: Optional[str] = None  # Cipher suite
    error: Optional[str] = None


@dataclass
class RawDomainData:
    """Complete raw data for a domain"""
    domain: str
    collection_timestamp: str
    collection_version: str = "1.0"

    # Metadata (from input, not processed)
    metadata: dict = field(default_factory=dict)

    # Raw DNS responses
    dns_queries: list = field(default_factory=list)

    # Raw HTTP transactions (HAR entries format)
    http_transactions: list = field(default_factory=list)

    # Collection errors
    errors: list = field(default_factory=list)


class RawDNSCollector:
    """Collects raw DNS responses without interpretation"""

    RETRY_TIMEOUTS = [5, 10, 15]  # escalating timeouts for retries

    def __init__(self, resolvers: list[str] = None, timeout: float = 5.0, retries: int = 3):
        self.resolvers = resolvers or ['1.1.1.1', '8.8.8.8']
        self.timeout = timeout
        self.retries = retries
        self._resolver_index = 0

    def _next_resolver(self) -> str:
        """Rotate through available resolvers"""
        resolver = self.resolvers[self._resolver_index]
        self._resolver_index = (self._resolver_index + 1) % len(self.resolvers)
        return resolver

    def _do_query(self, domain: str, rdtype: str, resolver_ip: str, timeout: float) -> RawDNSResponse:
        """Perform a single DNS query attempt and return raw response"""
        start_time = time.time()

        response = RawDNSResponse(
            query_name=domain,
            query_type=rdtype,
            query_time=datetime.now(timezone.utc).isoformat(),
            resolver=resolver_ip,
            status='',
            flags={},
            question=[],
            answer=[],
            authority=[],
            additional=[],
            response_time_ms=0
        )

        try:
            # Create resolver
            res = dns.resolver.Resolver()
            res.nameservers = [resolver_ip]
            res.timeout = timeout
            res.lifetime = timeout

            # Perform query
            try:
                answers = res.resolve(domain, rdtype)
                response.status = 'NOERROR'

                # Extract flags from response
                if hasattr(answers.response, 'flags'):
                    response.flags = {
                        'qr': bool(answers.response.flags & dns.flags.QR),
                        'aa': bool(answers.response.flags & dns.flags.AA),
                        'tc': bool(answers.response.flags & dns.flags.TC),
                        'rd': bool(answers.response.flags & dns.flags.RD),
                        'ra': bool(answers.response.flags & dns.flags.RA),
                        'ad': bool(answers.response.flags & dns.flags.AD),
                        'cd': bool(answers.response.flags & dns.flags.CD),
                    }

                # Extract question section
                for q in answers.response.question:
                    response.question.append({
                        'name': str(q.name),
                        'type': dns.rdatatype.to_text(q.rdtype),
                        'class': dns.rdataclass.to_text(q.rdclass)
                    })

                # Extract answer section
                for rrset in answers.response.answer:
                    for rdata in rrset:
                        response.answer.append({
                            'name': str(rrset.name),
                            'type': dns.rdatatype.to_text(rrset.rdtype),
                            'class': dns.rdataclass.to_text(rrset.rdclass),
                            'ttl': rrset.ttl,
                            'data': str(rdata)
                        })

                # Extract authority section
                for rrset in answers.response.authority:
                    for rdata in rrset:
                        response.authority.append({
                            'name': str(rrset.name),
                            'type': dns.rdatatype.to_text(rrset.rdtype),
                            'ttl': rrset.ttl,
                            'data': str(rdata)
                        })

                # Extract additional section
                for rrset in answers.response.additional:
                    for rdata in rrset:
                        response.additional.append({
                            'name': str(rrset.name),
                            'type': dns.rdatatype.to_text(rrset.rdtype),
                            'ttl': rrset.ttl,
                            'data': str(rdata)
                        })

                # Store raw wire format (base64 encoded)
                if hasattr(answers.response, 'to_wire'):
                    response.raw_wire = base64.b64encode(answers.response.to_wire()).decode('ascii')

            except dns.resolver.NXDOMAIN:
                response.status = 'NXDOMAIN'
            except dns.resolver.NoAnswer:
                response.status = 'NOERROR'  # Query succeeded but no records
            except dns.resolver.NoNameservers:
                response.status = 'SERVFAIL'
                response.error = 'No nameservers available'

        except dns.exception.Timeout:
            response.status = 'TIMEOUT'
            response.error = f'Query timed out after {timeout}s'
        except Exception as e:
            response.status = 'ERROR'
            response.error = str(e)

        response.response_time_ms = (time.time() - start_time) * 1000
        return response

    def query_record(self, domain: str, rdtype: str, resolver: str = None) -> RawDNSResponse:
        """Perform a DNS query with retries on transient failures"""
        resolver_ip = resolver or self._next_resolver()
        timeouts = self.RETRY_TIMEOUTS[:self.retries] if self.retries else [self.timeout]

        for attempt, timeout in enumerate(timeouts):
            response = self._do_query(domain, rdtype, resolver_ip, timeout)
            if response.status not in ('TIMEOUT', 'SERVFAIL', 'ERROR'):
                return response
            # Don't retry NXDOMAIN — that's definitive
            if attempt < len(timeouts) - 1:
                logger.debug(f"Retry {attempt+1} for {domain}/{rdtype} (was {response.status}, next timeout {timeouts[attempt+1]}s)")
        return response

    def collect_all(self, domain: str) -> list[RawDNSResponse]:
        """Collect all DNS record types for a domain"""
        self._resolver_index = 0  # Reset resolver rotation per domain
        responses = []

        # Standard record types
        for rdtype in DNS_RECORD_TYPES:
            resp = self.query_record(domain, rdtype)
            responses.append(resp)

        # DMARC record
        dmarc_resp = self.query_record(f'_dmarc.{domain}', 'TXT')
        dmarc_resp.query_name = f'_dmarc.{domain}'
        responses.append(dmarc_resp)

        # DKIM selectors
        for selector in DKIM_SELECTORS:
            dkim_domain = f'{selector}._domainkey.{domain}'
            dkim_resp = self.query_record(dkim_domain, 'TXT')
            dkim_resp.query_name = dkim_domain
            responses.append(dkim_resp)

        # BIMI record (Brand Indicators for Message Identification)
        bimi_resp = self.query_record(f'default._bimi.{domain}', 'TXT')
        bimi_resp.query_name = f'default._bimi.{domain}'
        responses.append(bimi_resp)

        # MTA-STS
        mta_sts_resp = self.query_record(f'_mta-sts.{domain}', 'TXT')
        mta_sts_resp.query_name = f'_mta-sts.{domain}'
        responses.append(mta_sts_resp)

        # TLSRPT (TLS Reporting)
        tlsrpt_resp = self.query_record(f'_smtp._tls.{domain}', 'TXT')
        tlsrpt_resp.query_name = f'_smtp._tls.{domain}'
        responses.append(tlsrpt_resp)

        # DNSSEC validation check - query A record with DNSSEC validation
        dnssec_resp = self._check_dnssec(domain)
        responses.append(dnssec_resp)

        return responses

    def _check_dnssec(self, domain: str) -> RawDNSResponse:
        """Check DNSSEC validation status for a domain"""
        start_time = time.time()
        resolver_ip = self._next_resolver()

        response = RawDNSResponse(
            query_name=domain,
            query_type='DNSSEC_CHECK',
            query_time=datetime.now(timezone.utc).isoformat(),
            resolver=resolver_ip,
            status='',
            flags={},
            question=[],
            answer=[],
            authority=[],
            additional=[],
            response_time_ms=0
        )

        try:
            # Create a resolver that requests DNSSEC validation
            res = dns.resolver.Resolver()
            res.nameservers = [resolver_ip]
            res.timeout = self.timeout
            res.lifetime = self.timeout
            res.use_edns(0, dns.flags.DO, 4096)  # Request DNSSEC records

            try:
                # Query A record with DNSSEC
                answers = res.resolve(domain, 'A')

                response.status = 'NOERROR'

                # Check AD (Authenticated Data) flag
                ad_flag = bool(answers.response.flags & dns.flags.AD)
                response.flags = {
                    'qr': bool(answers.response.flags & dns.flags.QR),
                    'aa': bool(answers.response.flags & dns.flags.AA),
                    'tc': bool(answers.response.flags & dns.flags.TC),
                    'rd': bool(answers.response.flags & dns.flags.RD),
                    'ra': bool(answers.response.flags & dns.flags.RA),
                    'ad': ad_flag,  # This indicates DNSSEC validation succeeded
                    'cd': bool(answers.response.flags & dns.flags.CD),
                }

                # Store DNSSEC validation status in answer section
                # Note: has_dnskey/has_ds are determined from separate DNSKEY/DS queries
                response.answer.append({
                    'name': domain,
                    'type': 'DNSSEC_STATUS',
                    'ttl': 0,
                    'data': json.dumps({
                        'validated': ad_flag,
                    })
                })

                # Check for RRSIG in answer (indicates signed zone)
                for rrset in answers.response.answer:
                    if rrset.rdtype == dns.rdatatype.RRSIG:
                        response.answer.append({
                            'name': str(rrset.name),
                            'type': 'RRSIG',
                            'ttl': rrset.ttl,
                            'data': str(list(rrset)[0]) if rrset else ''
                        })

            except dns.resolver.NXDOMAIN:
                response.status = 'NXDOMAIN'
            except dns.resolver.NoAnswer:
                response.status = 'NOERROR'
            except dns.resolver.NoNameservers:
                response.status = 'SERVFAIL'
                response.error = 'No nameservers available'

        except Exception as e:
            response.status = 'ERROR'
            response.error = str(e)

        response.response_time_ms = (time.time() - start_time) * 1000
        return response


class RawHTTPCollector:
    """Collects raw HTTP responses in HAR-like format"""

    def __init__(self, timeout: float = 30.0, max_body_size: int = 10 * 1024 * 1024):
        self.timeout = timeout
        self.max_body_size = max_body_size  # 10MB default
        self.user_agent = 'Mozilla/5.0 (compatible; EU Government Infrastructure Survey - Research)'

        # Session with retry capability
        self.session = requests.Session()
        retry_strategy = Retry(
            total=0,  # No automatic retries - we want raw responses
            backoff_factor=0
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    def _get_ssl_certificate(self, hostname: str, port: int = 443) -> Optional[dict]:
        """Fetch SSL certificate data for a host"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate in DER format
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()

                    # Get protocol and cipher
                    protocol = ssock.version()
                    cipher = ssock.cipher()

                    # Convert DER to PEM
                    import base64
                    cert_pem = (
                        "-----BEGIN CERTIFICATE-----\n" +
                        base64.encodebytes(cert_der).decode('ascii') +
                        "-----END CERTIFICATE-----"
                    )

                    # Calculate fingerprint
                    import hashlib
                    fingerprint = hashlib.sha256(cert_der).hexdigest()

                    # Parse subject and issuer
                    def parse_dn(dn_tuple):
                        result = {}
                        for rdn in dn_tuple:
                            for attr, value in rdn:
                                result[attr] = value
                        return result

                    # Extract SANs
                    sans = []
                    if 'subjectAltName' in cert_dict:
                        for san_type, san_value in cert_dict['subjectAltName']:
                            sans.append({'type': san_type, 'value': san_value})

                    # Get certificate chain if available
                    chain = []
                    try:
                        # Try to get full chain (Python 3.10+)
                        if hasattr(ssock, 'get_verified_chain'):
                            for cert in ssock.get_verified_chain()[1:]:  # Skip leaf cert
                                chain_der = cert.public_bytes(ssl._ssl.ENCODING_DER)
                                chain_pem = (
                                    "-----BEGIN CERTIFICATE-----\n" +
                                    base64.encodebytes(chain_der).decode('ascii') +
                                    "-----END CERTIFICATE-----"
                                )
                                chain.append(chain_pem)
                    except:
                        pass  # Chain not available

                    return {
                        'subject': parse_dn(cert_dict.get('subject', ())),
                        'issuer': parse_dn(cert_dict.get('issuer', ())),
                        'version': cert_dict.get('version', 0),
                        'serial_number': cert_dict.get('serialNumber', ''),
                        'not_before': cert_dict.get('notBefore', ''),
                        'not_after': cert_dict.get('notAfter', ''),
                        'subject_alt_names': sans,
                        'signature_algorithm': cert_dict.get('signatureAlgorithm', ''),
                        'public_key_algorithm': '',  # Not easily available from getpeercert
                        'public_key_bits': 0,
                        'fingerprint_sha256': fingerprint,
                        'pem': cert_pem,
                        'chain': chain,
                        'protocol': protocol,
                        'cipher': cipher[0] if cipher else None,
                        'cipher_bits': cipher[2] if cipher else None,
                    }

        except ssl.SSLError as e:
            return {'error': f'SSL Error: {str(e)}'}
        except socket.timeout:
            return {'error': 'Connection timeout'}
        except socket.gaierror as e:
            return {'error': f'DNS Error: {str(e)}'}
        except Exception as e:
            return {'error': f'Error: {str(e)}'}

    def collect(self, domain: str, urls: list[str] = None, max_redirects: int = 10) -> list[RawHTTPTransaction]:
        """Collect HTTP transactions for a domain, following redirects"""
        transactions = []

        # Default URLs to try
        if urls is None:
            urls = [
                f'https://{domain}/',
                f'https://www.{domain}/',
                f'http://{domain}/',
            ]

        for start_url in urls:
            # Follow redirect chain
            current_url = start_url
            redirect_count = 0

            while current_url and redirect_count < max_redirects:
                txn = self._fetch_url(current_url)
                transactions.append(txn)

                # Check for redirect
                status = txn.response.get('status', 0)
                redirect_url = txn.response.get('redirectURL', '')

                if status in (301, 302, 303, 307, 308) and redirect_url:
                    # Handle relative redirects
                    if redirect_url.startswith('/'):
                        from urllib.parse import urlparse
                        parsed = urlparse(current_url)
                        redirect_url = f'{parsed.scheme}://{parsed.netloc}{redirect_url}'
                    current_url = redirect_url
                    redirect_count += 1
                else:
                    break

            # If HTTPS succeeded with final response, don't try HTTP
            if start_url.startswith('https://') and transactions and transactions[-1].response.get('status', 0) >= 200:
                break

        return transactions

    def _fetch_url(self, url: str) -> RawHTTPTransaction:
        """Fetch a single URL and return HAR-formatted transaction"""
        start_time = datetime.now(timezone.utc)
        timings = {
            'blocked': -1,
            'dns': -1,
            'connect': -1,
            'ssl': -1,
            'send': -1,
            'wait': -1,
            'receive': -1
        }

        request_data = {
            'method': 'GET',
            'url': url,
            'httpVersion': 'HTTP/1.1',
            'headers': [
                {'name': 'User-Agent', 'value': self.user_agent},
                {'name': 'Accept', 'value': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'},
                {'name': 'Accept-Language', 'value': 'en-US,en;q=0.5'},
                {'name': 'Accept-Encoding', 'value': 'gzip, deflate'},
                {'name': 'Connection', 'value': 'keep-alive'},
            ],
            'queryString': [],
            'cookies': [],
            'headersSize': -1,
            'bodySize': 0
        }

        response_data = {
            'status': 0,
            'statusText': '',
            'httpVersion': '',
            'headers': [],
            'cookies': [],
            'content': {
                'size': 0,
                'mimeType': '',
                'text': '',
                'encoding': ''
            },
            'redirectURL': '',
            'headersSize': -1,
            'bodySize': 0
        }

        txn = RawHTTPTransaction(
            started_datetime=start_time.isoformat(),
            time_ms=0,
            request=request_data,
            response=response_data,
            timings=timings
        )

        try:
            # DNS timing
            dns_start = time.time()
            parsed = urlparse(url)
            try:
                server_ip = socket.gethostbyname(parsed.hostname)
                txn.server_ip = server_ip
            except socket.gaierror as e:
                txn.error = f'DNS resolution failed: {e}'
                return txn
            timings['dns'] = (time.time() - dns_start) * 1000

            # Get SSL certificate for HTTPS URLs
            if parsed.scheme == 'https':
                ssl_start = time.time()
                ssl_data = self._get_ssl_certificate(parsed.hostname, parsed.port or 443)
                timings['ssl'] = (time.time() - ssl_start) * 1000
                if ssl_data:
                    if 'error' not in ssl_data:
                        txn.ssl_certificate = ssl_data
                        txn.ssl_protocol = ssl_data.get('protocol')
                        txn.ssl_cipher = ssl_data.get('cipher')
                    else:
                        txn.error = ssl_data.get('error')

            # Make request
            connect_start = time.time()
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=False,  # Capture redirects as separate entries
                headers={
                    'User-Agent': self.user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                },
                stream=True  # Stream to handle large responses
            )

            timings['connect'] = (time.time() - connect_start) * 1000

            # Response status
            response_data['status'] = response.status_code
            response_data['statusText'] = response.reason or ''
            response_data['httpVersion'] = f'HTTP/{response.raw.version / 10:.1f}' if response.raw.version else 'HTTP/1.1'

            # Response headers
            for name, value in response.headers.items():
                response_data['headers'].append({'name': name, 'value': value})

            # Redirect URL
            if 'Location' in response.headers:
                response_data['redirectURL'] = response.headers['Location']

            # Response body
            receive_start = time.time()
            content_length = int(response.headers.get('Content-Length', 0))

            if content_length > self.max_body_size:
                # Too large - just note the size
                response_data['content']['size'] = content_length
                response_data['content']['mimeType'] = response.headers.get('Content-Type', '')
                response_data['content']['text'] = f'[Body too large: {content_length} bytes, max {self.max_body_size}]'
                response.close()
            else:
                # Read body
                body_bytes = response.content
                response_data['content']['size'] = len(body_bytes)
                response_data['content']['mimeType'] = response.headers.get('Content-Type', '')
                response_data['bodySize'] = len(body_bytes)

                # Try to decode as text
                try:
                    encoding = response.encoding or 'utf-8'
                    response_data['content']['text'] = body_bytes.decode(encoding, errors='replace')
                except:
                    # Store as base64 if not decodable
                    response_data['content']['text'] = base64.b64encode(body_bytes).decode('ascii')
                    response_data['content']['encoding'] = 'base64'

            timings['receive'] = (time.time() - receive_start) * 1000

            # Connection info
            if hasattr(response.raw, '_connection') and response.raw._connection:
                conn = response.raw._connection
                if hasattr(conn, 'sock') and conn.sock:
                    txn.connection = str(conn.sock.getpeername()) if hasattr(conn.sock, 'getpeername') else None

        except requests.exceptions.SSLError as e:
            txn.error = f'SSL Error: {str(e)}'
        except requests.exceptions.ConnectionError as e:
            txn.error = f'Connection Error: {str(e)}'
        except requests.exceptions.Timeout as e:
            txn.error = f'Timeout: {str(e)}'
        except requests.exceptions.RequestException as e:
            txn.error = f'Request Error: {str(e)}'
        except Exception as e:
            txn.error = f'Error: {str(e)}'

        txn.time_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
        return txn

    def close(self):
        self.session.close()


class RawDataCollector:
    """Main collector orchestrating DNS and HTTP collection"""

    def __init__(self,
                 dns_timeout: float = 5.0,
                 http_timeout: float = 30.0,
                 skip_http: bool = False,
                 rate_limit: float = 1.0,
                 tld_rate_limit: float = 0.5,
                 resolvers: list[str] = None,
                 workers: int = 1,
                 retries: int = 3):
        self.dns_collector = RawDNSCollector(resolvers=resolvers, timeout=dns_timeout, retries=retries)
        self.http_collector = RawHTTPCollector(timeout=http_timeout) if not skip_http else None
        self.skip_http = skip_http
        self.rate_limit = rate_limit
        self.tld_rate_limit = tld_rate_limit
        self.workers = workers
        self.last_tld_request = {}  # Track last request per TLD
        self._tld_lock = __import__('threading').Lock()

    # Known second-level TLDs (ccSLDs) used by governments
    KNOWN_SLDS = {
        # Format: (sld, cctld) pairs that should be treated as single TLD for rate limiting
        'gov.uk', 'gov.au', 'gov.br', 'gov.cn', 'gov.in', 'gov.za',
        'gv.at', 'gov.ie', 'gov.mt', 'gov.cy', 'gov.gr', 'gov.ro',
        'gov.bg', 'gov.pl', 'gov.lt', 'gov.lv', 'gov.ee', 'gov.si',
        'gov.sk', 'gov.cz', 'gov.hu', 'gov.hr', 'gov.pt', 'gov.it',
        'gouv.fr', 'gouv.be', 'government.nl', 'regeringen.se',
        'gob.es', 'bund.de', 'admin.ch',
        'europa.eu',  # EU institutions
        # Generic SLDs
        'co.uk', 'org.uk', 'ac.uk', 'com.au', 'org.au', 'edu.au',
    }

    def _get_tld(self, domain: str) -> str:
        """Extract effective TLD from domain for rate limiting purposes"""
        parts = domain.lower().rsplit('.', 3)
        if len(parts) >= 2:
            # Check for known second-level TLD
            potential_sld = '.'.join(parts[-2:])
            if potential_sld in self.KNOWN_SLDS:
                return potential_sld
            # Check for three-part TLD (e.g., gov.uk patterns)
            if len(parts) >= 3:
                potential_sld3 = '.'.join(parts[-3:])
                for known in self.KNOWN_SLDS:
                    if potential_sld3 == known or potential_sld3.endswith('.' + known):
                        return known
            # Default to ccTLD
            return parts[-1]
        return domain

    def _wait_for_tld(self, domain: str):
        """Rate limit per TLD (thread-safe)"""
        tld = self._get_tld(domain)
        with self._tld_lock:
            now = time.time()
            if tld in self.last_tld_request:
                elapsed = now - self.last_tld_request[tld]
                if elapsed < self.tld_rate_limit:
                    time.sleep(self.tld_rate_limit - elapsed)
            self.last_tld_request[tld] = time.time()

    def collect_domain(self, domain: str, metadata: dict = None) -> RawDomainData:
        """Collect all raw data for a single domain"""
        data = RawDomainData(
            domain=domain,
            collection_timestamp=datetime.now(timezone.utc).isoformat(),
            metadata=metadata or {}
        )

        logger.info(f"Collecting raw data for {domain}...")

        # TLD rate limiting
        self._wait_for_tld(domain)

        # Collect DNS
        try:
            dns_responses = self.dns_collector.collect_all(domain)
            data.dns_queries = [asdict(r) for r in dns_responses]
        except Exception as e:
            data.errors.append(f"DNS collection failed: {str(e)}")

        # Rate limit between DNS and HTTP
        time.sleep(self.rate_limit)

        # Collect HTTP
        if not self.skip_http and self.http_collector:
            try:
                http_txns = self.http_collector.collect(domain)
                data.http_transactions = [asdict(t) for t in http_txns]
            except Exception as e:
                data.errors.append(f"HTTP collection failed: {str(e)}")

        return data

    def collect_domains(self, domains: list[dict], output_dir: Path,
                        save_per_domain: bool = True) -> list[RawDomainData]:
        """Collect raw data for multiple domains"""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        results = [None] * len(domains)
        total = len(domains)
        start_time = time.time()
        completed = [0]  # mutable counter for threads
        counter_lock = __import__('threading').Lock()

        logger.info(f"Starting raw data collection for {total} domains ({self.workers} workers)")

        def _collect_one(idx, domain_info):
            domain = domain_info['domain']
            try:
                data = self.collect_domain(domain, domain_info)

                # Save individual domain data
                if save_per_domain:
                    domain_dir = output_dir / self._sanitize_filename(domain)
                    domain_dir.mkdir(parents=True, exist_ok=True)
                    with open(domain_dir / 'raw_data.json', 'w') as f:
                        json.dump(asdict(data), f, indent=2, default=str)
                    with gzip.open(domain_dir / 'raw_data.json.gz', 'wt', encoding='utf-8') as f:
                        json.dump(asdict(data), f, default=str)

                return idx, data

            except Exception as e:
                logger.error(f"Failed to collect {domain}: {e}")
                return idx, RawDomainData(
                    domain=domain,
                    collection_timestamp=datetime.now(timezone.utc).isoformat(),
                    metadata=domain_info,
                    errors=[f"Collection failed: {str(e)}"]
                )

        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {pool.submit(_collect_one, i, info): i for i, info in enumerate(domains)}
            for future in as_completed(futures):
                idx, data = future.result()
                results[idx] = data
                with counter_lock:
                    completed[0] += 1
                    n = completed[0]
                elapsed = time.time() - start_time
                rate = n / elapsed if elapsed > 0 else 0
                remaining = (total - n) / rate / 60 if rate > 0 else 0
                logger.info(f"[{n}/{total}] {data.domain} - {rate*60:.1f} domains/min, ~{remaining:.1f}min remaining")

        # Save combined results
        combined_path = output_dir / 'all_raw_data.json.gz'
        with gzip.open(combined_path, 'wt', encoding='utf-8') as f:
            json.dump([asdict(r) for r in results], f, default=str)
        logger.info(f"Saved combined raw data to {combined_path}")

        # Save manifest
        manifest = {
            'collection_timestamp': datetime.now(timezone.utc).isoformat(),
            'total_domains': total,
            'collection_version': '1.0',
            'collector': 'raw_collector.py',
            'dns_record_types': DNS_RECORD_TYPES,
            'dkim_selectors': DKIM_SELECTORS,
            'domains': [d['domain'] for d in domains]
        }
        with open(output_dir / 'manifest.json', 'w') as f:
            json.dump(manifest, f, indent=2)

        return results

    def _sanitize_filename(self, domain: str) -> str:
        """Convert domain to safe filename"""
        return domain.replace('/', '_').replace(':', '_')

    def close(self):
        if self.http_collector:
            self.http_collector.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def load_domains(path: str) -> list[dict]:
    """Load domains from JSON or text file"""
    path = Path(path)

    if path.suffix == '.json':
        with open(path) as f:
            data = json.load(f)
        return [
            {
                'domain': item['domain'],
                'name': item.get('name', ''),
                'country': item.get('country', ''),
                'country_code': item.get('country_code', ''),
                'category': item.get('category', '')
            }
            for item in data
        ]
    else:
        # Plain text - one domain per line
        with open(path) as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return [{'domain': d} for d in domains]


def main():
    parser = argparse.ArgumentParser(
        description='Raw Data Collector - Captures unprocessed DNS and HTTP data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This collector saves RAW data without interpretation:
- DNS: Full query responses including wire format
- HTTP: HAR-like format with full headers and body

Output structure:
  output_dir/
    manifest.json           # Collection metadata
    all_raw_data.json.gz    # Combined data (gzipped)
    domain.tld/
      raw_data.json         # Per-domain raw data
      raw_data.json.gz      # Gzipped version

Examples:
  # Collect DNS only
  python raw_collector.py domains.txt -o raw_data/ --skip-http

  # Full collection with rate limiting
  python raw_collector.py domains.json -o raw_data/ --rate-limit 2.0

  # Test with few domains
  python raw_collector.py domains.json -o raw_data/ --limit 5
        """
    )
    parser.add_argument('input', help='Input file (JSON or text with domains)')
    parser.add_argument('-o', '--output', default='raw_data', help='Output directory')
    parser.add_argument('--skip-http', action='store_true', help='Skip HTTP collection (DNS only)')
    parser.add_argument('--limit', type=int, help='Limit number of domains')
    parser.add_argument('--offset', type=int, default=0, help='Skip first N domains')
    parser.add_argument('--dns-timeout', type=float, default=5.0, help='DNS timeout in seconds')
    parser.add_argument('--http-timeout', type=float, default=30.0, help='HTTP timeout in seconds')
    parser.add_argument('--rate-limit', type=float, default=1.0, help='Seconds between requests')
    parser.add_argument('--no-per-domain', action='store_true', help='Skip saving per-domain files')
    parser.add_argument('--resolver', type=str, help='Use a single DNS resolver (e.g. 1.1.1.1)')
    parser.add_argument('--workers', type=int, default=1, help='Parallel domain workers (default: 1)')
    parser.add_argument('--retries', type=int, default=3, help='Retry attempts with escalating timeouts (default: 3)')

    args = parser.parse_args()

    # Load domains
    domains = load_domains(args.input)

    if args.offset:
        domains = domains[args.offset:]
    if args.limit:
        domains = domains[:args.limit]

    logger.info(f"Loaded {len(domains)} domains")

    # Collect
    resolvers = [args.resolver] if args.resolver else None
    with RawDataCollector(
        dns_timeout=args.dns_timeout,
        http_timeout=args.http_timeout,
        skip_http=args.skip_http,
        rate_limit=args.rate_limit,
        resolvers=resolvers,
        workers=args.workers,
        retries=args.retries,
    ) as collector:
        collector.collect_domains(
            domains,
            Path(args.output),
            save_per_domain=not args.no_per_domain
        )

    logger.info("Raw data collection complete!")


if __name__ == '__main__':
    main()
