#!/usr/bin/env python3
"""2x3 grid summary for paper section 4 (Sovereignty Assessment).

Unified visual scheme: hatch encodes jurisdiction, color encodes vendor.
  ** star      -> EU
  // diagonal  -> Non-EU
  ++ plus      -> Relay (CDN / email security gateway)
  xx cross     -> Mixed (per-domain mixed exposure)
  .. dots      -> No data / Unknown

Within each band, named vendors get a fill color from VENDOR_COLORS;
unnamed remainder is white. One figure-level legend.

Panels:
  (0,0) Nameservers
  (0,1) Hosting
  (0,2) Email
  (1,0) TLS CA
  (1,1) SaaS
  (1,2) Web Requests
"""

import csv
import glob
import json
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from matplotlib.patches import Patch, Rectangle
from matplotlib.legend_handler import HandlerBase


class _LabelOnlyHandler(HandlerBase):
    """Render a legend entry as just its (bold) label — no swatch. The
    handle's bbox is collapsed to zero width so the row label sits flush
    against the first real swatch."""
    def legend_artist(self, legend, orig_handle, fontsize, handlebox):
        handlebox.set_width(0)
        return None

from chart_style import (
    SECTOR_ORDER,
    FONT_TITLE, FONT_SUBTITLE, FONT_LABEL, FONT_TICK, FONT_LEGEND,
    FONT_ANNOT, apply_style,
)

ROOT = Path(__file__).resolve().parent.parent
EU = set("AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE".split())


def load_data():
    out = {}
    for sector in SECTOR_ORDER:
        d = sector.lower()
        f = sorted(glob.glob(str(ROOT / "results" / d / "analyzed_results*.json")))
        f = [p for p in f if "BEFORE" not in p][-1]
        with open(f) as fp:
            out[sector] = json.load(fp)
    return out


def _canonical_ca(issuer_raw):
    """Map raw SSL issuer org to a short canonical name for grouping."""
    s = (issuer_raw or "").lower()
    for needle, canon in [
        ("let's encrypt", "Let's Encrypt"),
        ("digicert", "DigiCert"),
        ("sectigo", "Sectigo"),
        ("comodo", "Sectigo"),
        ("globalsign", "GlobalSign"),
        ("google trust services", "Google Trust Services"),
        ("amazon", "Amazon"),
        ("microsoft", "Microsoft"),
        ("cloudflare", "Cloudflare"),
        ("entrust", "Entrust"),
        ("godaddy", "GoDaddy"),
        ("hellenic academic", "HARICA"),
        ("harica", "HARICA"),
        ("fnmt", "FNMT-RCM"),
        ("actalis", "Actalis"),
        ("certigna", "Certigna"),
        ("t-systems", "T-Systems TeleSec"),
        ("telesec", "T-Systems TeleSec"),
        ("telekom security", "Telekom Security"),
        ("d-trust", "D-Trust"),
        ("buypass", "Buypass"),
        ("certum", "Certum"),
        ("staat der nederlanden", "Staat der Nederlanden"),
    ]:
        if needle in s:
            return canon
    return issuer_raw or None


def load_ssl_lookup():
    overrides = []
    with open(ROOT / "lookup_tables" / "ca_database.csv") as f:
        for row in csv.reader(f):
            if row and not row[0].startswith("#") and row[0] != "pattern":
                overrides.append((row[0].lower(), row[2]))
    with open(ROOT / "results" / "ssl_collection.json") as f:
        ssl = [r for r in json.load(f)["results"] if not r.get("error")]
    lookup = {}
    for r in ssl:
        issuer_raw = r.get("ssl_issuer_org")
        issuer_l = (issuer_raw or "").lower()
        country = r.get("ssl_issuer_country")
        for pattern, cc in overrides:
            if pattern in issuer_l:
                country = cc
                break
        lookup[r["domain"]] = {
            "is_eu":  (country or "").upper() in EU,
            "issuer": _canonical_ca(issuer_raw),
        }
    return lookup


# ─────────────────────────────────────────────────────────────
# Hatch convention: hatch encodes jurisdiction, color encodes vendor
# ─────────────────────────────────────────────────────────────
HATCH_EU      = "*"     # sparser than ** so labels stay readable
HATCH_NEU     = "//"
HATCH_RELAY   = "++"
HATCH_MIXED   = "xx"
HATCH_UNKNOWN = ".."

# Thin hatch lines (matplotlib default 1.0 is heavy at print resolution)
plt.rcParams["hatch.linewidth"] = 0.3

WHITE = "#FFFFFF"
UNKNOWN_GREY = "#95a5a6"

# EU flag colors for the unnamed-EU bar (blue background, yellow hatch).
EU_BLUE   = "#003399"
EU_YELLOW = "#FFCC00"

# White rectangle behind data labels so they stay legible over hatch
LABEL_BBOX = dict(facecolor="white", edgecolor="none", pad=1.0, alpha=0.85)

# ---- Vendor palette: brand-aligned where possible, spread across the
#      luminance range so colors stay distinct in B&W prints.
#      Approximate greyscale L (BT.601) shown next to each entry.
VENDOR_COLORS = {
    # Hyperscalers / CDN (non-EU)
    "Cloudflare":            "#F38020",  # brand orange   L=152
    "Amazon":                "#B71C1C",  # dark red       L=74
    "Microsoft":             "#0078D4",  # brand blue     L=94
    "Microsoft Azure":       "#0078D4",
    "Microsoft 365":         "#0078D4",
    "Akamai":                "#8B3DFF",  # purple         L=107
    "Google":                "#2CA02C",  # brand green    L=122
    "Google Cloud":          "#2CA02C",
    "Google Workspace":      "#2CA02C",
    "Google Trust Services": "#2CA02C",
    "Fastly":                "#FF6B00",  # deep orange    L=130 (Fastly brand)
    "Oracle Cloud":          "#7E0009",
    # CAs — spread across luminance bands, away from Microsoft/Google
    "Let's Encrypt":         "#73D2E2",  # light cyan     L=183 (was 123 — collided with Google)
    "DigiCert":              "#D4A017",  # darker gold    L=145 (was 177 — too close to LE 183)
    "Sectigo":               "#3E2723",  # near-black     L=47  (was 72  — collided with Amazon)
    "GoDaddy":               "#1BDBDB",
    "Entrust":               "#FFB000",
    # EU CAs
    "HARICA":                "#E91E63",  # bright magenta L=99  (was 82  — closer to Akamai/Google now)
    "GlobalSign":            "#76448A",
    "FNMT-RCM":              "#C0392B",
    "Actalis":               "#16A085",
    "T-Systems TeleSec":     "#7B241C",
    "Telekom Security":      "#7B241C",
    "D-Trust":               "#34495E",
    "Certigna":              "#A569BD",
    "Buypass":               "#0E6655",
    "Certum":                "#1ABC9C",
    "Staat der Nederlanden": "#FF8C42",
    # EU hosting providers
    "Hetzner":               "#D50000",
    "OVH":                   "#455A64",  # blue-grey (was navy — clashed with Microsoft)
    "IONOS":                 "#303F9F",  # indigo (was navy — clashed with Microsoft)
    "Aruba":                 "#FFC107",
    "Self-hosted":           "#5FA992",
    # Email security
    "Proofpoint":            "#FF6F00",
    "Mimecast":              "#5C2D91",
    "Email Security Appliance": "#bdc3c7",
}
OTHER_EU_COLOR = "#7FA897"
OTHER_NEU_COLOR = "#B07A7A"
THRESHOLD_PCT = 10.0  # vendors below this % in every sector roll up


_EMAIL_SECURITY_APPLIANCES = {
    "Cisco IronPort", "Cisco CES", "Forcepoint", "Trend Micro",
    "Symantec (Broadcom)", "Barracuda", "Mimecast", "Hornetsecurity",
    "Sophos", "Vade Secure", "Proofpoint",
}


def _fading_eu_bar(ax, y, left, width, fill_color, hatch_char,
                    height=0.6, max_alpha=0.40, n=24):
    """EU bar with a constant fill and a left-to-right fading hatch.
    The fill stays solid (vendor color or EU blue); only the yellow stars
    are alpha-faded across the width so they recede toward the right edge.
    """
    if width <= 0:
        return
    slice_w = width / n
    for k in range(n):
        a = max_alpha * (1.0 - k / max(1, n - 1))
        if a < 0.03:
            h = ""
            ec = "none"
        else:
            ec = (1.0, 0.8, 0.0, a)  # yellow @ alpha
            h = hatch_char
        # rasterized=True bakes the alpha hatch into raster pixels at savefig
        # time — Overleaf/pdfTeX renders alpha-on-hatch inconsistently when
        # left as vector, so we hand them an embedded PNG instead.
        bar = ax.barh(y, slice_w, left=left + k * slice_w, color=fill_color,
                      hatch=h, edgecolor=ec, linewidth=0, height=height)
        for patch in bar:
            patch.set_rasterized(True)
    # Single thin black border around the whole segment
    ax.add_patch(Rectangle((left, y - height / 2), width, height,
                            fill=False, edgecolor="black",
                            linewidth=0.5, zorder=10))


def _canonical_vendor(v):
    """Collapse vendor variants into legend palette entries (so Google Cloud /
    Google Workspace / Google Trust Services all appear as one 'Google')."""
    if not v:
        return None
    s = v.lower()
    if "microsoft" in s or "azure" in s:                 return "Microsoft"
    if "google" in s:                                    return "Google"
    if "amazon" in s or "aws" in s or "cloudfront" in s: return "Amazon"
    return v


def _categorical_split(ax, data, classify, bands, title,
                      threshold=THRESHOLD_PCT, xlabel="% of Domains"):
    """Per-sector stacked bar with each band sub-divided by vendor.

    Hatch encodes jurisdiction (passed in via bands), color encodes vendor.
    Inside each band, vendors that breach the threshold in any sector get
    a coloured stripe via VENDOR_COLORS; the unnamed remainder is white,
    so the hatch alone carries the jurisdiction signal.

    bands: list of (name, hatch) tuples.
    Returns (used_vendors, band_handles) for the figure-level legend.
    """
    band_names = [b[0] for b in bands]
    sector_totals = {s: len(data[s]) for s in SECTOR_ORDER}
    band_pct = {s: {b: 0 for b in band_names} for s in SECTOR_ORDER}
    vend_pct = {s: {b: {} for b in band_names} for s in SECTOR_ORDER}
    for sector in SECTOR_ORDER:
        for e in data[sector]:
            band, vendor = classify(e)
            if band is None:
                continue
            band_pct[sector][band] += 1
            vendor = _canonical_vendor(vendor)
            if vendor:
                vend_pct[sector][band][vendor] = (
                    vend_pct[sector][band].get(vendor, 0) + 1
                )
        n = sector_totals[sector]
        for b in band_names:
            band_pct[sector][b] = 100 * band_pct[sector][b] / n
            for v in vend_pct[sector][b]:
                vend_pct[sector][b][v] = 100 * vend_pct[sector][b][v] / n

    band_tops = {}
    for b in band_names:
        tops = sorted(
            {v for s in SECTOR_ORDER for v, p in vend_pct[s][b].items()
             if p >= threshold},
            key=lambda v: -sum(vend_pct[s][b].get(v, 0) for s in SECTOR_ORDER),
        )
        band_tops[b] = tops

    band_hatch = {name: hatch for name, hatch in bands}

    for i, sector in enumerate(SECTOR_ORDER):
        left = 0
        for b in band_names:
            hatch = band_hatch[b]
            # EU jurisdiction always renders stars in EU yellow,
            # whether the segment is a named vendor or unnamed remainder.
            edge_color = EU_YELLOW if hatch == HATCH_EU else "black"
            band_total = band_pct[sector][b]
            if band_total <= 0.05:
                continue
            consumed = 0
            for v in band_tops[b]:
                pct = vend_pct[sector][b].get(v, 0)
                if pct <= 0.05:
                    continue
                color = VENDOR_COLORS.get(v, WHITE)
                if hatch == HATCH_EU:
                    _fading_eu_bar(ax, i, left, pct, color, hatch)
                else:
                    ax.barh(i, pct, left=left, color=color, hatch=hatch,
                            edgecolor=edge_color, linewidth=0.5, height=0.6)
                if pct >= 6:
                    ax.text(left + pct / 2, i, f"{pct:.0f}",
                            ha="center", va="center",
                            fontsize=FONT_ANNOT, color="#222",
                            fontweight="bold", bbox=LABEL_BBOX)
                left += pct
                consumed += pct
            rest = band_total - consumed
            if rest > 0.05:
                if hatch == HATCH_EU:
                    _fading_eu_bar(ax, i, left, rest, EU_BLUE, hatch)
                else:
                    ax.barh(i, rest, left=left, color=WHITE, hatch=hatch,
                            edgecolor=edge_color, linewidth=0.5, height=0.6)
                if rest >= 6:
                    ax.text(left + rest / 2, i, f"{rest:.0f}",
                            ha="center", va="center",
                            fontsize=FONT_ANNOT, color="#222",
                            fontweight="bold", bbox=LABEL_BBOX)
                left += rest

    ax.set_yticks(range(len(SECTOR_ORDER)))
    ax.set_yticklabels(SECTOR_ORDER, fontsize=FONT_LABEL)
    ax.set_ylim(-0.5, len(SECTOR_ORDER) - 0.5)
    ax.invert_yaxis()  # SECTOR_ORDER[0] (Government) at top
    ax.set_xlim(0, 100)
    ax.set_xlabel(xlabel, fontsize=FONT_LABEL)
    ax.set_title(title, fontsize=FONT_SUBTITLE, fontweight="bold")

    used_vendors = []
    for b in band_names:
        for v in band_tops[b]:
            if v not in used_vendors:
                used_vendors.append(v)
    band_handles = [Patch(facecolor=WHITE, hatch=hatch, edgecolor="black",
                          linewidth=0.6, label=name)
                    for name, hatch in bands]
    return used_vendors, band_handles


def _stacked_barh(ax, sector_vals, categories, colors, hatches, title, xlabel="% of Domains"):
    for i, sector in enumerate(SECTOR_ORDER):
        vals = sector_vals[sector]
        left = 0
        for val, color, hatch in zip(vals, colors, hatches):
            ax.barh(i, val, left=left, color=color, hatch=hatch,
                    edgecolor="black", linewidth=0.5, height=0.6)
            if val > 6:
                ax.text(left + val / 2, i, f"{val:.0f}%",
                        ha="center", va="center",
                        fontsize=FONT_ANNOT, color="#222", fontweight="bold",
                        bbox=LABEL_BBOX)
            left += val
    ax.set_yticks(range(len(SECTOR_ORDER)))
    ax.set_yticklabels(SECTOR_ORDER, fontsize=FONT_LABEL)
    ax.set_ylim(-0.5, len(SECTOR_ORDER) - 0.5)
    ax.set_xlabel(xlabel, fontsize=FONT_LABEL)
    ax.set_xlim(0, 100)
    ax.set_title(title, fontsize=FONT_SUBTITLE, fontweight="bold")
    return [Patch(facecolor=c, hatch=h, edgecolor="black",
                  linewidth=0.75, label=cat)
            for cat, c, h in zip(categories, colors, hatches)]


def panel_ns(ax, data):
    """NS sovereignty per domain, with vendor stripes (Cloudflare etc.)."""
    bands = [
        ("EU NS",      HATCH_EU),
        ("Non-EU NS",  HATCH_NEU),
        ("No NS data", HATCH_UNKNOWN),
    ]

    def classify(e):
        provs = [p for p in (e.get("ns_providers") or [])
                 if p.get("is_eu") is not None]
        if not provs:
            return "No NS data", None
        eu_count = sum(1 for p in provs if p.get("is_eu"))
        names = [p.get("provider") for p in provs if p.get("provider")]
        dominant = Counter(names).most_common(1)[0][0] if names else None
        if eu_count > len(provs) / 2:
            return "EU NS", dominant
        return "Non-EU NS", dominant

    return _categorical_split(ax, data, classify, bands, "(a) Nameserver")


def panel_hosting(ax, data):
    bands = [
        ("EU Provider",     HATCH_EU),
        ("Non-EU Provider", HATCH_NEU),
        ("Relay (CDN)",     HATCH_RELAY),
        ("Unresolvable",    HATCH_UNKNOWN),
    ]

    def classify(e):
        if e.get("hosting_behind_cdn"):
            return "Relay (CDN)", e.get("hosting_cdn_provider")
        if e.get("hosting_is_eu") is True:
            return "EU Provider", e.get("hosting_provider")
        if e.get("hosting_is_eu") is False:
            return "Non-EU Provider", e.get("hosting_provider")
        return "Unresolvable", None

    return _categorical_split(ax, data, classify, bands, "(b) Service Hosting")


def panel_email(ax, data):
    bands = [
        ("EU email",                 HATCH_EU),
        ("Non-EU email",             HATCH_NEU),
        ("Email Security Appliance", HATCH_RELAY),
        ("No MX Record",             HATCH_UNKNOWN),
    ]

    def classify(e):
        ep = e.get("email_provider")
        if ep in _EMAIL_SECURITY_APPLIANCES:
            return "Email Security Appliance", ep
        if ep == "Microsoft 365":
            return "Non-EU email", "Microsoft"
        if ep == "Google Workspace":
            return "Non-EU email", "Google"
        if ep or e.get("mx_records"):
            # Self-hosted or other named provider — split by email_is_eu
            if e.get("email_is_eu") is True:
                return "EU email", ep
            if e.get("email_is_eu") is False:
                return "Non-EU email", ep
            # Unknown jurisdiction — falls into "No MX Record" hatch (no data)
            return "No MX Record", None
        return "No MX Record", None

    return _categorical_split(ax, data, classify, bands, "(e) EMail")


def panel_tls_ca(ax, data, ssl_lookup):
    bands = [
        ("EU CA",          HATCH_EU),
        ("Non-EU CA",      HATCH_NEU),
        ("No certificate", HATCH_UNKNOWN),
    ]

    def classify(e):
        r = ssl_lookup.get(e["domain"])
        if not r:
            return "No certificate", None
        return ("EU CA" if r.get("is_eu") else "Non-EU CA"), r.get("issuer")

    return _categorical_split(ax, data, classify, bands, "(d) TLS Certificates")


def panel_saas(ax, data):
    """Per-sector SaaS posture with vendor stripes (Microsoft, Google, etc.)."""
    bands = [
        ("EU SaaS only",        HATCH_EU),
        ("Mixed (EU + non-EU)", HATCH_MIXED),
        ("Non-EU SaaS only",    HATCH_NEU),
        ("No SaaS detected",    HATCH_UNKNOWN),
    ]

    def classify(e):
        svcs = e.get("detected_services", [])
        if not svcs:
            return "No SaaS detected", None
        # Pick the most-prominent vendor for the stripe — prefer non-EU
        # active-use services (those represent the actual sovereignty leak).
        active = [s for s in svcs if s.get("is_active_use")]
        candidates = active if active else svcs
        neu = [s for s in candidates if s.get("is_eu") is False]
        eu_svcs = [s for s in candidates if s.get("is_eu") is True]
        pick = (neu or eu_svcs)[0] if (neu or eu_svcs) else None
        vendor = pick.get("vendor") if pick else None
        has_eu = any(s.get("is_eu") is True for s in svcs)
        has_neu = any(s.get("is_eu") is False for s in svcs)
        if has_eu and has_neu:
            return "Mixed (EU + non-EU)", vendor
        if has_neu:
            return "Non-EU SaaS only", vendor
        if has_eu:
            return "EU SaaS only", vendor
        return "No SaaS detected", None

    return _categorical_split(ax, data, classify, bands, "(f) Software-as-a-Service")


def load_web_metrics():
    """Per-sector strict (% domains 100% EU) and mean (% requests EU)."""
    with open(ROOT / "results" / "domain_scope_class_summary_with_failed_compact.json") as f:
        cls_data = json.load(f)
    with open(ROOT / "results" / "in_eu_request_summary.json") as f:
        mean_data = json.load(f)
    sector_map = {"government": "Government", "newspaper": "Newspapers",
                  "bank": "Banks", "university": "Universities"}
    classes, mean = {}, {}
    for cat, r in cls_data["by_sector"].items():
        sn = sector_map.get(cat)
        if sn:
            classes[sn] = {
                "only_eu":  r["only_in_eu_share_pct"],
                "mixed":    r["mixed_in_eu_and_outside_eu_share_pct"],
                "only_neu": r["only_outside_eu_share_pct"],
                "failed":   r["crawl_failed_or_excluded_share_pct"],
            }
    for r in mean_data["by_sector"]:
        sn = sector_map.get(r["category"])
        if sn:
            mean[sn] = r["mean_domain_in_eu_request_share_pct"]
    return classes, mean


def panel_web_requests(ax, _data):
    """Twin-bar per sector:
       top sub-bar = 4-bucket per-domain classification (only-EU / mixed / only-outside-EU / failed),
       bottom sub-bar = mean per-domain in-EU request share (split EU vs non-EU).
       Note the two sub-bars use different denominators: top is full input set,
       bottom is the retained-crawl subset.
    """
    classes, mean = load_web_metrics()
    bar_h = 0.32
    offset = 0.20

    def _label(x, y, val, t=5):
        if val >= t:
            ax.text(x, y, f"{val:.0f}", ha="center", va="center",
                    fontsize=FONT_ANNOT, color="#222", fontweight="bold", bbox=LABEL_BBOX)

    for i, sector in enumerate(SECTOR_ORDER):
        # ---- top sub-bar: 4-bucket classification ----
        c = classes.get(sector, {})
        y_top = i - offset
        left = 0
        eu = c.get("only_eu", 0)
        if eu > 0:
            _fading_eu_bar(ax, y_top, left, eu, EU_BLUE, HATCH_EU, height=bar_h)
            _label(left + eu / 2, y_top, eu)
            left += eu
        mx = c.get("mixed", 0)
        if mx > 0:
            ax.barh(y_top, mx, left=left, height=bar_h, color=WHITE, hatch=HATCH_MIXED,
                    edgecolor="black", linewidth=0.4)
            _label(left + mx / 2, y_top, mx)
            left += mx
        ne = c.get("only_neu", 0)
        if ne > 0:
            ax.barh(y_top, ne, left=left, height=bar_h, color=WHITE, hatch=HATCH_NEU,
                    edgecolor="black", linewidth=0.4)
            _label(left + ne / 2, y_top, ne)
            left += ne
        fl = c.get("failed", 0)
        if fl > 0:
            ax.barh(y_top, fl, left=left, height=bar_h, color=WHITE, hatch=HATCH_UNKNOWN,
                    edgecolor="black", linewidth=0.4)
            _label(left + fl / 2, y_top, fl)

        # ---- bottom sub-bar: mean per-domain in-EU request share ----
        y_bot = i + offset
        eu_mean = mean.get(sector, 0)
        ne_mean = 100 - eu_mean
        if eu_mean > 0:
            _fading_eu_bar(ax, y_bot, 0, eu_mean, EU_BLUE, HATCH_EU, height=bar_h)
            _label(eu_mean / 2, y_bot, eu_mean)
        if ne_mean > 0:
            ax.barh(y_bot, ne_mean, left=eu_mean, height=bar_h, color=WHITE, hatch=HATCH_NEU,
                    edgecolor="black", linewidth=0.4)
            _label(eu_mean + ne_mean / 2, y_bot, ne_mean)

        ax.text(101, y_top, "(1)", ha="left", va="center",
                fontsize=FONT_TICK, color="#444")
        ax.text(101, y_bot, "(2)", ha="left", va="center",
                fontsize=FONT_TICK, color="#444")

    ax.set_yticks(range(len(SECTOR_ORDER)))
    ax.set_yticklabels(SECTOR_ORDER, fontsize=FONT_LABEL)
    ax.set_ylim(-0.5, len(SECTOR_ORDER) - 0.5)
    ax.invert_yaxis()  # SECTOR_ORDER[0] (Government) at top
    ax.set_xlim(0, 115)
    ax.set_xlabel("(1) % of Domains  /  (2) mean % of Requests", fontsize=FONT_LABEL)
    ax.set_title("(c) Web Content", fontsize=FONT_SUBTITLE, fontweight="bold")
    return [], []


def main():
    apply_style()
    data = load_data()
    ssl_lookup = load_ssl_lookup()

    fig = plt.figure(figsize=(22, 9.5))
    gs = gridspec.GridSpec(2, 3, figure=fig, hspace=0.33, wspace=0.30)

    # Order matches section 4 (Sovereignty Assessment) subsections:
    # Nameserver, Service Hosting, Web Content, TLS Certificates, Email, SaaS.
    panels = [
        (gs[0, 0], panel_ns,           (data,)),
        (gs[0, 1], panel_hosting,      (data,)),
        (gs[0, 2], panel_web_requests, (data,)),
        (gs[1, 0], panel_tls_ca,       (data, ssl_lookup)),
        (gs[1, 1], panel_email,        (data,)),
        (gs[1, 2], panel_saas,         (data,)),
    ]
    used_vendors = []
    for spec, fn, args in panels:
        ax = fig.add_subplot(spec)
        used, _handles = fn(ax, *args)
        for v in used:
            if v not in used_vendors:
                used_vendors.append(v)

    # Single universal jurisdiction legend — hatch carries the meaning.
    # The legend swatch is small, so we use a denser hatch (** vs *) and
    # a slightly thicker stroke so the star pattern actually renders.
    jurisdiction_handles = [
        Patch(facecolor=EU_BLUE, hatch="***", edgecolor=EU_YELLOW,
              linewidth=1.0, label="EU"),
        Patch(facecolor=WHITE, hatch=HATCH_NEU,     edgecolor="black",
              linewidth=0.6, label="Non-EU"),
        Patch(facecolor=WHITE, hatch=HATCH_RELAY,   edgecolor="black",
              linewidth=0.6, label="Relay (CDN/gateway)"),
        Patch(facecolor=WHITE, hatch=HATCH_MIXED,   edgecolor="black",
              linewidth=0.6, label="Mixed"),
        Patch(facecolor=WHITE, hatch=HATCH_UNKNOWN, edgecolor="black",
              linewidth=0.6, label="No data"),
    ]
    vendor_handles = [Patch(facecolor=VENDOR_COLORS.get(v, UNKNOWN_GREY),
                            edgecolor="black", linewidth=0.6, label=v)
                      for v in used_vendors]

    # Two-row layout: bold row labels integrated as the first "handle" of
    # each legend so they sit inside the same framed box and don't push
    # the figure bbox outward.
    label_juris = Patch(facecolor="none", edgecolor="none",
                         label=r"$\bf{Jurisdiction}$")
    label_vendor = Patch(facecolor="none", edgecolor="none",
                          label=r"$\bf{Vendor}$")

    leg1 = fig.legend(handles=[label_juris] + jurisdiction_handles,
                      loc="lower center", bbox_to_anchor=(0.5, -0.025),
                      ncol=len(jurisdiction_handles) + 1,
                      fontsize=FONT_LEGEND, framealpha=0.95,
                      handler_map={label_juris: _LabelOnlyHandler(),
                                   label_vendor: _LabelOnlyHandler()})
    fig.add_artist(leg1)

    leg2 = fig.legend(handles=[label_vendor] + vendor_handles,
                      loc="lower center", bbox_to_anchor=(0.5, -0.060),
                      ncol=len(vendor_handles) + 1,
                      fontsize=FONT_LEGEND, framealpha=0.95,
                      handler_map={label_juris: _LabelOnlyHandler(),
                                   label_vendor: _LabelOnlyHandler()})
    # NOTE: do NOT rasterize legend handles — the legend swatches use
    # full-opacity colors, so the alpha-on-hatch PDF bug that affects the
    # bars doesn't apply here. Rasterizing them at swatch size breaks the
    # hatch rendering and the frame/swatch alignment in some PDF viewers.

    out = ROOT / "visualization" / "figures"
    fig.savefig(out / "sovereignty_section4_grid.png", dpi=180, bbox_inches="tight")
    fig.savefig(out / "sovereignty_section4_grid.pdf", bbox_inches="tight")
    print(f"Wrote {out / 'sovereignty_section4_grid.png'}")
    print(f"Wrote {out / 'sovereignty_section4_grid.pdf'}")


if __name__ == "__main__":
    main()
