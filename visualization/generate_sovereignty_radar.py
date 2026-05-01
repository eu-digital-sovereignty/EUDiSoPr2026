#!/usr/bin/env python3
"""
Generate a per-sector radar chart for the EU Digital Sovereignty Index.

Produces: sovereignty_radar.png / .pdf
"""

import json
import os
from pathlib import Path

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scanner"))
from constants import EU_COUNTRIES

from chart_style import (
    SECTOR_COLORS, SECTOR_FILL, FONT_TITLE, FONT_SUBTITLE, FONT_LABEL,
    FONT_TICK, FONT_LEGEND, FONT_ANNOT_LG, apply_style,
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
def _find_latest(sector):
    d = Path(__file__).resolve().parent.parent / "results" / sector
    files = sorted(f for f in d.iterdir()
                   if f.name.startswith("analyzed_results") and f.suffix == ".json")
    return str(files[-1]) if files else None


DATA_FILES = {
    "Government": _find_latest("government"),
    "Banks": _find_latest("banks"),
    "Newspapers": _find_latest("newspapers"),
    "Universities": _find_latest("universities"),
}

# SSL collection (lightweight cert-only pass)
SSL_COLLECTION = str(Path(__file__).resolve().parent.parent / "results" / "ssl_collection.json")
FIGURES_DIR = str(Path(__file__).resolve().parent / "figures")
os.makedirs(FIGURES_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Compute index components from raw data
# ---------------------------------------------------------------------------

def _ns_majority_eu(e):
    """True if a strict majority of classified NS providers are EU-hosted."""
    provs = [p for p in (e.get("ns_providers") or []) if p.get("is_eu") is not None]
    if not provs:
        return False
    return sum(1 for p in provs if p.get("is_eu")) > len(provs) / 2


def compute_scores(records, ssl_lookup=None, web_eu_pct=None):
    """Return dict with the sovereignty index components (0-100).

    web_eu_pct: optional mean per-domain in-EU request share (from page-load data).
    """
    n = len(records)

    # 1. Hosting sovereignty — heatmap definition: post-processed hosting_is_eu flag.
    eu_hosted = sum(1 for r in records if r.get("hosting_is_eu") is True)
    hosting = 100 * eu_hosted / max(n, 1)

    # 2. Email sovereignty — strict, to match the "EU email" band in fig.~2:
    # only domains whose email is positively classified as EU-hosted.
    eu_email = sum(1 for r in records if r.get("email_is_eu") is True)
    email = 100 * eu_email / max(n, 1)

    # 4. Nameserver sovereignty — heatmap definition: strict per-domain
    # majority of classified ns_providers (post-processed via ip_mapper.py).
    ns_eu_domains = sum(1 for r in records if _ns_majority_eu(r))
    ns_sov = 100 * ns_eu_domains / max(n, 1)

    # 5. SaaS sovereignty — heatmap definition: per-domain "no non-EU detected".
    eu_saas = sum(1 for r in records
                  if not any(s.get("is_eu") is False
                             for s in r.get("detected_services", [])))
    saas = 100 * eu_saas / max(n, 1)

    # 6. TLS/CA sovereignty — from ssl_collection.json
    has_ca, eu_ca = 0, 0
    if ssl_lookup:
        for r in records:
            sr = ssl_lookup.get(r["domain"])
            if sr and sr.get("ssl_issuer_country"):
                has_ca += 1
                if sr["ssl_issuer_country"] in EU_COUNTRIES:
                    eu_ca += 1
    ca_sov = 100 * eu_ca / max(n, 1)

    scores = {
        "Web\nHosting": round(hosting, 1),
        "Email": round(email, 1),
        "Name-\nservers": round(ns_sov, 1),
        "TLS CA": round(ca_sov, 1),
        "SaaS": round(saas, 1),
    }
    if web_eu_pct is not None:
        scores["Web\nRequests"] = round(web_eu_pct, 1)
    return scores


# ---------------------------------------------------------------------------
# Load data & compute
# ---------------------------------------------------------------------------
print("Loading data ...")

# Load SSL collection once, with CA parent-company overrides
ssl_lookup = {}
if os.path.exists(SSL_COLLECTION):
    import csv as _csv
    _ca_overrides = []
    _ca_path = Path(__file__).resolve().parent.parent / "lookup_tables" / "ca_database.csv"
    if _ca_path.exists():
        with open(_ca_path) as _f:
            for row in _csv.reader(_f):
                if len(row) >= 3 and not row[0].startswith("#"):
                    _ca_overrides.append((row[0].lower(), row[2]))
    with open(SSL_COLLECTION) as f:
        for r in json.load(f)["results"]:
            if not r.get("error"):
                issuer = (r.get("ssl_issuer_org") or "").lower()
                for pattern, country in _ca_overrides:
                    if pattern in issuer:
                        r["ssl_issuer_country"] = country
                        break
                ssl_lookup[r["domain"]] = r
    print(f"  SSL collection: {len(ssl_lookup)} certs loaded")

# Load page-load web measurement (mean per-domain in-EU request share)
WEB_EU_FILE = Path(__file__).resolve().parent.parent / "results" / "in_eu_request_summary.json"
web_eu_by_sector = {}
if WEB_EU_FILE.exists():
    with open(WEB_EU_FILE) as f:
        _web = json.load(f)
    _sector_map = {"government": "Government", "newspaper": "Newspapers",
                   "bank": "Banks", "university": "Universities"}
    for r in _web["by_sector"]:
        if r["category"] in _sector_map:
            web_eu_by_sector[_sector_map[r["category"]]] = r["mean_domain_in_eu_request_share_pct"]
    print(f"  Web layer: {web_eu_by_sector}")

sector_scores = {}
for sector, path in DATA_FILES.items():
    with open(path) as f:
        records = json.load(f)
    sector_scores[sector] = compute_scores(records, ssl_lookup,
                                           web_eu_pct=web_eu_by_sector.get(sector))
    print(f"  {sector}: {sector_scores[sector]}")

# ---------------------------------------------------------------------------
# Radar chart
# ---------------------------------------------------------------------------
def make_radar(sector_scores):
    categories = list(next(iter(sector_scores.values())).keys())
    N = len(categories)
    angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
    angles += angles[:1]  # close the polygon

    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))

    # Style the grid
    ax.set_theta_offset(np.pi / 2)
    ax.set_theta_direction(-1)
    ax.set_rlabel_position(30)

    # Draw gridlines at 20, 40, 60, 80, 100
    grid_levels = [20, 40, 60, 80, 100]
    ax.set_yticks(grid_levels)
    ax.set_yticklabels([f"{g}%" for g in grid_levels], fontsize=FONT_TICK, color="#666666")
    ax.set_ylim(0, 100)

    # Category labels
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories, fontsize=FONT_LABEL, fontweight="bold")

    # Grid styling
    ax.yaxis.grid(True, color="#dddddd", linewidth=0.8)
    ax.xaxis.grid(True, color="#cccccc", linewidth=0.8)
    ax.spines["polar"].set_visible(False)

    # Plot each sector
    for sector, scores in sector_scores.items():
        values = [scores[c] for c in categories]
        values += values[:1]
        color = SECTOR_COLORS[sector]
        fill = SECTOR_FILL[sector]

        ax.plot(angles, values, 'o-', linewidth=2.2, markersize=6,
                label=sector, color=color)
        ax.fill(angles, values, alpha=0.08, color=color)

    # Add value labels — offset radially outward from each spoke, with extra
    # stacking when sector values converge on the same axis.
    sector_list = list(sector_scores.keys())
    for axis_i in range(N):
        angle = angles[axis_i]
        # Display-space outward direction for this spoke. Polar axis uses
        # theta_offset=π/2, theta_direction=-1, so display_theta = π/2 - angle.
        disp_theta = np.pi / 2 - angle
        ux, uy = np.cos(disp_theta), np.sin(disp_theta)

        pts = sorted(
            [(sector_scores[s][categories[axis_i]], si)
             for si, s in enumerate(sector_list)],
            key=lambda x: x[0],
        )
        offsets_r = []
        for j, (val, si) in enumerate(pts):
            base = 8  # base radial offset in display points
            if j > 0 and abs(val - pts[j - 1][0]) < 6:
                base = offsets_r[j - 1] + 11
            offsets_r.append(base)
        for (val, si), off in zip(pts, offsets_r):
            color = SECTOR_COLORS[sector_list[si]]
            ax.annotate(f"{val:.0f}", xy=(angle, val),
                        xytext=(ux * off, uy * off), textcoords="offset points",
                        ha="center", va="center", fontsize=FONT_ANNOT_LG - 3,
                        color=color, fontweight="bold")

    ax.legend(loc="upper right", bbox_to_anchor=(1.28, 1.08),
              fontsize=FONT_LEGEND, frameon=True, fancybox=True,
              edgecolor="#cccccc")

    return fig


fig = make_radar(sector_scores)

# Save
for ext in ("png", "pdf"):
    path = os.path.join(FIGURES_DIR, f"sovereignty_radar.{ext}")
    fig.savefig(path, dpi=200, bbox_inches="tight", facecolor="white")
    print(f"Saved {path}")
plt.close(fig)
