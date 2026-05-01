#!/usr/bin/env python3
"""
Lightweight SSL-only collector.
Connects to each domain on port 443, grabs the TLS certificate,
and writes results to a JSON file. No DNS re-collection needed.

Usage:
    python collect_ssl.py results/government/analyzed_results_*.json \
                          results/banks/analyzed_results_*.json ...
    python collect_ssl.py --all   # auto-find latest results per sector
"""

import argparse
import json
import glob
import random
import ssl
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import dns.resolver
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID, ExtensionOID

sys.stdout.reconfigure(line_buffering=True)

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
OUTPUT_FILE = RESULTS_DIR / "ssl_collection.json"
TIMEOUT = 8
WORKERS = 20
DNS_RESOLVER = "1.1.1.1"
RETRIES = 3
INITIAL_BACKOFF = 0.5
BACKOFF_FACTOR = 2.0


def _resolve(domain, resolver):
    """Resolve domain to first A/AAAA. Returns IP or None."""
    for rdtype in ("A", "AAAA"):
        try:
            answers = resolver.resolve(domain, rdtype)
            return str(answers[0])
        except Exception:
            continue
    return None


def _name_attr(cert_name, oid):
    try:
        return cert_name.get_attributes_for_oid(oid)[0].value
    except (IndexError, AttributeError):
        return None


def _parse_cert(der_bytes):
    cert = x509.load_der_x509_certificate(der_bytes)
    sans = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = [v.value for v in ext.value if hasattr(v, "value")]
    except x509.ExtensionNotFound:
        pass
    issuer_country = _name_attr(cert.issuer, NameOID.COUNTRY_NAME)
    return {
        "ssl_issuer_org":     _name_attr(cert.issuer,  NameOID.ORGANIZATION_NAME),
        "ssl_issuer_country": issuer_country.upper() if issuer_country else None,
        "ssl_issuer_cn":      _name_attr(cert.issuer,  NameOID.COMMON_NAME),
        "ssl_subject_cn":     _name_attr(cert.subject, NameOID.COMMON_NAME),
        "ssl_valid_from":     cert.not_valid_before_utc.strftime("%b %d %H:%M:%S %Y GMT"),
        "ssl_valid_to":       cert.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT"),
        "ssl_san":            sans,
    }


def _grab_once(host, ip, validate=True):
    """Single TLS handshake attempt. Returns (cert_dict, validation_error, protocol)."""
    if validate:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl._create_unverified_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
        s.settimeout(TIMEOUT)
        s.connect((ip, 443))
        der = s.getpeercert(binary_form=True)
        proto = s.version()
    return _parse_cert(der), proto


def _try_host(host, resolver):
    """Resolve+handshake one hostname. Returns (result_dict, fatal?). On fatal, dont try www."""
    ip = _resolve(host, resolver)
    if not ip:
        return {"error": f"DNS resolution failed ({DNS_RESOLVER})", "_fatal": False}, False

    last_err = None
    backoff = INITIAL_BACKOFF
    for attempt in range(RETRIES):
        try:
            cert, proto = _grab_once(host, ip, validate=False)
            cert["ssl_protocol"] = proto
            cert["error"] = None
            return cert, True
        except (socket.timeout, ConnectionResetError, ConnectionRefusedError, OSError) as e:
            last_err = str(e)
            if attempt < RETRIES - 1:
                time.sleep(backoff + random.uniform(0, 0.2))
                backoff *= BACKOFF_FACTOR
        except ssl.SSLError as e:
            last_err = str(e)
            break  # TLS-level errors don't recover via retry
        except Exception as e:
            last_err = str(e)
            break
    return {"error": last_err}, False


def grab_cert(domain, resolver):
    """Try domain, then www.domain on DNS failure."""
    res, success = _try_host(domain, resolver)
    if success:
        return {"domain": domain, "tried_www": False, **res}
    if "DNS resolution failed" in (res.get("error") or "") and not domain.startswith("www."):
        res2, success2 = _try_host(f"www.{domain}", resolver)
        if success2:
            return {"domain": domain, "tried_www": True, **res2}
    return {"domain": domain, "tried_www": False, **res}


def find_latest(sector):
    pattern = str(RESULTS_DIR / sector / "analyzed_results_*.json")
    files = sorted(glob.glob(pattern))
    return files[-1] if files else None


def load_domains(paths):
    """Load unique domains from analyzed result files."""
    domains = {}
    for path in paths:
        with open(path) as f:
            for r in json.load(f):
                d = r["domain"]
                if d not in domains:
                    domains[d] = r.get("country_code", "")
    return list(domains.keys())


def main():
    parser = argparse.ArgumentParser(description="Lightweight SSL certificate collector")
    parser.add_argument("files", nargs="*", help="Analyzed result JSON files")
    parser.add_argument("--all", action="store_true", help="Auto-find latest results")
    parser.add_argument("--workers", type=int, default=WORKERS)
    parser.add_argument("-o", "--output", default=str(OUTPUT_FILE))
    args = parser.parse_args()

    if args.all:
        paths = []
        for sector in ["government", "banks", "newspapers", "universities"]:
            p = find_latest(sector)
            if p:
                paths.append(p)
                print(f"  {sector}: {p}")
        if not paths:
            print("No result files found")
            return
    else:
        paths = args.files

    domains = load_domains(paths)
    print(f"Collecting SSL certificates for {len(domains)} domains ({args.workers} workers, resolver {DNS_RESOLVER}) ...")

    # Create a resolver per thread (dnspython resolvers aren't thread-safe)
    import threading
    _thread_local = threading.local()

    def get_resolver():
        if not hasattr(_thread_local, "resolver"):
            r = dns.resolver.Resolver()
            r.nameservers = [DNS_RESOLVER]
            r.lifetime = 5
            _thread_local.resolver = r
        return _thread_local.resolver

    def grab_cert_threaded(domain):
        return grab_cert(domain, get_resolver())

    results = []
    done = 0
    errors = 0
    t0 = time.time()

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(grab_cert_threaded, d): d for d in domains}
        for future in as_completed(futures):
            r = future.result()
            results.append(r)
            done += 1
            if r.get("error"):
                errors += 1
            if done % 50 == 0 or done == len(domains):
                elapsed = time.time() - t0
                rate = done / elapsed
                print(f"  {done}/{len(domains)} ({errors} errors) — {rate:.1f} domains/s")

    # Sort by domain for stable output
    results.sort(key=lambda r: r["domain"])

    elapsed = time.time() - t0
    success = sum(1 for r in results if not r.get("error"))
    print(f"\nDone in {elapsed:.0f}s: {success} certs collected, {errors} errors")

    # Write results
    output = {
        "collection_timestamp": datetime.now(timezone.utc).isoformat(),
        "total_domains": len(domains),
        "successful": success,
        "errors": errors,
        "results": results,
    }
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
