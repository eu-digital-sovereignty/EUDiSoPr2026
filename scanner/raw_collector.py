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
import base64
import gzip
import time
import logging
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field, asdict

from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import dns.rcode
import dns.rdatatype
import dns.query
import dns.message
import dns.name
import dns.exception

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
    checking_disabled: bool = False


@dataclass
class RawDomainData:
    """Complete raw data for a domain"""
    domain: str
    collection_timestamp: str
    collection_version: str = "2.0"

    # Metadata (from input, not processed)
    metadata: dict = field(default_factory=dict)

    # Raw DNS responses
    dns_queries: list = field(default_factory=list)
    ns_authority: Optional[dict] = None

    # Collection errors
    errors: list = field(default_factory=list)


class RawDNSCollector:
    """Collects raw DNS responses without interpretation"""

    RETRY_TIMEOUTS = [5, 10, 15]  # escalating timeouts for retries
    MAX_NS_QUERIES = 128
    MAX_NS_ALIASES = 16

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

    def _do_query(self, domain: str, rdtype: str, resolver_ip: str, timeout: float,
                  checking_disabled: bool = False) -> RawDNSResponse:
        """Perform a single DNS query attempt and return raw response"""
        start_time = time.time()

        response = RawDNSResponse(
            query_name=domain,
            query_type=rdtype,
            checking_disabled=checking_disabled,
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
            if checking_disabled:
                res.set_flags(dns.flags.RD | dns.flags.CD)

            # Perform query
            try:
                try:
                    message = res.resolve(
                        domain, rdtype, raise_on_no_answer=False
                    ).response
                except dns.resolver.NXDOMAIN as e:
                    message = e.response(e.qnames()[0])
                except dns.resolver.NoNameservers as e:
                    messages = [error[4] for error in e.kwargs.get('errors', [])
                                if error[4] is not None]
                    if not messages:
                        raise
                    message = messages[-1]
                    response.error = 'No nameservers available'
                response.status = dns.rcode.to_text(message.rcode())

                # Extract flags from response
                if hasattr(message, 'flags'):
                    response.flags = {
                        'qr': bool(message.flags & dns.flags.QR),
                        'aa': bool(message.flags & dns.flags.AA),
                        'tc': bool(message.flags & dns.flags.TC),
                        'rd': bool(message.flags & dns.flags.RD),
                        'ra': bool(message.flags & dns.flags.RA),
                        'ad': bool(message.flags & dns.flags.AD),
                        'cd': bool(message.flags & dns.flags.CD),
                    }

                # Extract question section
                for q in message.question:
                    response.question.append({
                        'name': str(q.name),
                        'type': dns.rdatatype.to_text(q.rdtype),
                        'class': dns.rdataclass.to_text(q.rdclass)
                    })

                # Extract answer section
                for rrset in message.answer:
                    for rdata in rrset:
                        response.answer.append({
                            'name': str(rrset.name),
                            'type': dns.rdatatype.to_text(rrset.rdtype),
                            'class': dns.rdataclass.to_text(rrset.rdclass),
                            'ttl': rrset.ttl,
                            'data': str(rdata)
                        })

                # Extract authority section
                for rrset in message.authority:
                    for rdata in rrset:
                        response.authority.append({
                            'name': str(rrset.name),
                            'type': dns.rdatatype.to_text(rrset.rdtype),
                            'ttl': rrset.ttl,
                            'data': str(rdata)
                        })

                # Extract additional section
                for rrset in message.additional:
                    for rdata in rrset:
                        response.additional.append({
                            'name': str(rrset.name),
                            'type': dns.rdatatype.to_text(rrset.rdtype),
                            'ttl': rrset.ttl,
                            'data': str(rdata)
                        })

                # Store raw wire format (base64 encoded)
                if hasattr(message, 'to_wire'):
                    wire = getattr(message, 'wire', None) or message.to_wire()
                    response.raw_wire = base64.b64encode(wire).decode('ascii')
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

    def query_record(self, domain: str, rdtype: str, resolver: str = None,
                     log: list[RawDNSResponse] = None, query_limit: int = None) -> RawDNSResponse:
        """Perform a DNS query with retries on transient failures"""
        resolver_ip = resolver or self._next_resolver()
        timeouts = self.RETRY_TIMEOUTS[:self.retries] if self.retries else [self.timeout]

        for attempt, timeout in enumerate(timeouts):
            if log is not None and query_limit is not None and len(log) >= query_limit:
                raise ValueError('NS authority query limit exceeded')
            response = self._do_query(domain, rdtype, resolver_ip, timeout)
            if log is not None:
                log.append(response)
            if response.status not in ('TIMEOUT', 'SERVFAIL', 'ERROR'):
                return response
            # Don't retry NXDOMAIN — that's definitive
            if attempt < len(timeouts) - 1:
                logger.debug(f"Retry {attempt+1} for {domain}/{rdtype} (was {response.status}, next timeout {timeouts[attempt+1]}s)")
        return response

    def collect_ns_authority(self, domain: str) -> dict:
        """Collect SOA-proven zones and apex NS sets along the CNAME path."""
        result = {'method': 'recursive_soa_v1', 'resolver': self.resolvers[0],
                  'status': 'unknown', 'path': [], 'addresses': {},
                  'address_errors': {}, 'queries': [], 'error': None,
                  'address_status': 'not_attempted', 'unchecked_data_used': False,
                  'dnssec_warnings': []}
        log, cache = [], {}

        def ask(name, rdtype):
            key = (name, rdtype, False)
            if key not in cache:
                reply = self.query_record(name.to_text(omit_final_dot=True), rdtype,
                                          resolver=result['resolver'], log=log,
                                          query_limit=self.MAX_NS_QUERIES)
                cache[key] = reply, len(log) - 1
            reply, index = cache[key]
            if reply.status != 'SERVFAIL':
                return cache[key]
            cd_key = (name, rdtype, True)
            if cd_key not in cache:
                if len(log) >= self.MAX_NS_QUERIES:
                    raise ValueError('NS authority query limit exceeded')
                unchecked = self._do_query(name.to_text(omit_final_dot=True), rdtype,
                                           result['resolver'], self.timeout,
                                           checking_disabled=True)
                log.append(unchecked)
                cache[cd_key] = unchecked, len(log) - 1
                if unchecked.status == 'NOERROR':
                    result['unchecked_data_used'] = True
                    result['dnssec_warnings'].append({
                        'normal_query': index, 'cd_query': len(log) - 1,
                        'finding': 'validation_failure_suspected'})
            return cache[cd_key] if cache[cd_key][0].status == 'NOERROR' else cache[key]

        def records(reply, name, rdtype):
            return [r['data'] for r in reply.answer if r['type'] == rdtype
                    and dns.name.from_text(r['name']) == name]

        def zone_for(name):
            candidate = name
            while True:
                reply, index = ask(candidate, 'SOA')
                if reply.status not in ('NOERROR', 'NXDOMAIN'):
                    raise ValueError(f'SOA {candidate}: {reply.status}')
                aliases = records(reply, candidate, 'CNAME')
                if aliases:
                    if len(aliases) != 1 or records(reply, candidate, 'SOA'):
                        raise ValueError(f'Ambiguous SOA/CNAME for {candidate}')
                    # A CNAME owner cannot be a zone apex; its parent stays in its zone.
                    candidate = candidate.parent()
                    continue
                if reply.status != 'NOERROR':
                    raise ValueError(f'SOA {candidate}: {reply.status}')
                if any(r['type'] in ('CNAME', 'DNAME') for r in reply.answer):
                    raise ValueError(f'Unresolved SOA alias for {candidate}')
                if records(reply, candidate, 'SOA'):
                    return candidate, index
                zones = {dns.name.from_text(r['name']).canonicalize()
                         for r in reply.authority if r['type'] == 'SOA'
                         and candidate.is_subdomain(dns.name.from_text(r['name']))
                         and candidate != dns.name.from_text(r['name'])}
                if len(zones) == 1:
                    return zones.pop(), index
                raise ValueError(f'No unambiguous SOA evidence for {name}')

        try:
            name = dns.name.from_text(domain).canonicalize()
            seen = set()
            for _ in range(self.MAX_NS_ALIASES):
                if name in seen:
                    raise ValueError('CNAME cycle')
                seen.add(name)
                reply, _ = ask(name, 'NS')
                aliases = records(reply, name, 'CNAME')
                if reply.status not in ('NOERROR', 'NXDOMAIN') or (
                        reply.status == 'NXDOMAIN' and not aliases):
                    raise ValueError(f'NS {name}: {reply.status}')
                if len(aliases) > 1 or (aliases and records(reply, name, 'NS')):
                    raise ValueError(f'Ambiguous CNAME for {name}')
                if not aliases and any(r['type'] == 'DNAME' for r in reply.answer):
                    raise ValueError(f'DNAME without synthesized CNAME for {name}')
                zone, soa_index = zone_for(name)
                if aliases and zone == name:
                    raise ValueError(f'CNAME owner is also a zone apex: {name}')
                apex, ns_index = ask(zone, 'NS')
                ns = sorted({dns.name.from_text(host).canonicalize().to_text(omit_final_dot=True)
                             for host in records(apex, zone, 'NS')})
                if apex.status != 'NOERROR' or not ns:
                    raise ValueError(f'No apex NS answer for {zone}: {apex.status}')
                target = dns.name.from_text(aliases[0]).canonicalize() if aliases else None
                result['path'].append({
                    'name': name.to_text(omit_final_dot=True),
                    'zone': zone.to_text(omit_final_dot=True), 'ns': ns,
                    'cname': target.to_text(omit_final_dot=True) if target else None,
                    'soa_query': soa_index, 'ns_query': ns_index})
                if target is None:
                    break
                name = target
            else:
                raise ValueError('CNAME limit exceeded')
            result['status'] = 'complete'
        except (dns.exception.DNSException, ValueError) as e:
            result['status'] = 'partial' if result['path'] else 'unknown'
            result['error'] = f'{type(e).__name__}: {e}'

        if result['status'] == 'complete':
            for host in sorted({host for hop in result['path'] for host in hop['ns']}):
                addresses, errors = [], []
                for rdtype in ('A', 'AAAA'):
                    try:
                        reply, _ = ask(dns.name.from_text(host), rdtype)
                    except (dns.exception.DNSException, ValueError) as e:
                        errors.append(f'{rdtype}: {type(e).__name__}: {e}')
                        continue
                    if reply.status != 'NOERROR':
                        errors.append(f'{rdtype}: {reply.status}: {reply.error or ""}')
                        continue
                    try:
                        message = dns.message.from_wire(base64.b64decode(reply.raw_wire))
                        answer = message.resolve_chaining().answer
                        if answer is not None and answer.rdtype == dns.rdatatype.from_text(rdtype):
                            addresses.extend(str(r) for r in answer)
                    except (dns.exception.DNSException, ValueError, TypeError) as e:
                        errors.append(f'{rdtype}: {type(e).__name__}: {e}')
                result['addresses'][host] = list(dict.fromkeys(addresses))
                if not addresses and not errors:
                    errors.append('No A/AAAA addresses returned')
                if errors:
                    result['address_errors'][host] = errors
            result['address_status'] = 'partial' if result['address_errors'] else 'complete'
        result['queries'] = [asdict(reply) for reply in log]
        return result

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


class RawDataCollector:
    """Main collector orchestrating DNS and HTTP collection"""

    def __init__(self,
                 dns_timeout: float = 5.0,
                 rate_limit: float = 1.0,
                 tld_rate_limit: float = 0.5,
                 resolvers: list[str] = None,
                 workers: int = 1,
                 retries: int = 3):
        self.dns_collector = RawDNSCollector(resolvers=resolvers, timeout=dns_timeout, retries=retries)
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
            data.ns_authority = self.dns_collector.collect_ns_authority(domain)
        except Exception as e:
            data.errors.append(f"DNS collection failed: {str(e)}")
            data.ns_authority = {'status': 'unknown', 'path': [], 'error': str(e)}

        # Rate limit between DNS and HTTP
        time.sleep(self.rate_limit)

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
            'collection_version': '2.0',
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
  python raw_collector.py domains.txt -o raw_data/

  # Full collection with rate limiting
  python raw_collector.py domains.json -o raw_data/ --rate-limit 2.0

  # Test with few domains
  python raw_collector.py domains.json -o raw_data/ --limit 5
        """
    )
    parser.add_argument('input', help='Input file (JSON or text with domains)')
    parser.add_argument('-o', '--output', default='raw_data', help='Output directory')
    parser.add_argument('--limit', type=int, help='Limit number of domains')
    parser.add_argument('--offset', type=int, default=0, help='Skip first N domains')
    parser.add_argument('--dns-timeout', type=float, default=5.0, help='DNS timeout in seconds')
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
    collector = RawDataCollector(
        dns_timeout=args.dns_timeout,
        rate_limit=args.rate_limit,
        resolvers=resolvers,
        workers=args.workers,
        retries=args.retries,
    )
    collector.collect_domains(
        domains,
        Path(args.output),
        save_per_domain=not args.no_per_domain
    )

    logger.info("Raw data collection complete!")


if __name__ == '__main__':
    main()
