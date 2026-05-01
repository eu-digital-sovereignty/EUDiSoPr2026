#!/usr/bin/env python3
"""Generate sovereignty heatmap: countries × sovereignty dimensions.

Rows = countries sorted by avg sovereignty score (descending).
EU-27 average row inserted at its natural position with margins.
Combined view: Avg column + one heatmap per sector (order from SECTORS).

Usage:
    uv run python3 visualization/generate_sovereignty_heatmap.py
"""

import glob
import json
from collections import defaultdict
from pathlib import Path

import plotly.graph_objects as go
from plotly.subplots import make_subplots

from chart_style import COLORSCALE_PLOTLY

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE = Path(__file__).parent.parent
RESULTS_DIR = BASE / "results"
OUT_DIR = Path(__file__).parent / "figures"
SSL_COLLECTION = RESULTS_DIR / "ssl_collection.json"

EU_COUNTRIES = frozenset({
    'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR',
    'DE', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL',
    'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE'
})

SECTORS = [
    ("Government",   "government"),
    ("Universities", "universities"),
    ("Banks",        "banks"),
    ("Newspapers",   "newspapers"),
]

CC_LABELS = {"EU": "EU Inst.", "EU27": "⌀ EU-27"}
CC_FLAGS = {
    "AT": "🇦🇹", "BE": "🇧🇪", "BG": "🇧🇬", "HR": "🇭🇷", "CY": "🇨🇾",
    "CZ": "🇨🇿", "DK": "🇩🇰", "EE": "🇪🇪", "FI": "🇫🇮", "FR": "🇫🇷",
    "DE": "🇩🇪", "GR": "🇬🇷", "HU": "🇭🇺", "IE": "🇮🇪", "IT": "🇮🇹",
    "LV": "🇱🇻", "LT": "🇱🇹", "LU": "🇱🇺", "MT": "🇲🇹", "NL": "🇳🇱",
    "PL": "🇵🇱", "PT": "🇵🇹", "RO": "🇷🇴", "SK": "🇸🇰", "SI": "🇸🇮",
    "ES": "🇪🇸", "SE": "🇸🇪", "EU": "🇪🇺", "EU27": "🇪🇺",
}

# ---------------------------------------------------------------------------
# Sovereignty dimensions
# ---------------------------------------------------------------------------
def _ns_majority_eu(e):
    """True if a strict majority of classified NS providers are EU-hosted."""
    provs = [p for p in (e.get("ns_providers") or []) if p.get("is_eu") is not None]
    if not provs:
        return False
    return sum(1 for p in provs if p.get("is_eu")) > len(provs) / 2


# Order matches section-4 grid layout (NS, Hosting, Email, TLS CA, SaaS, Web).
DIMENSIONS = [
    ("Nameservers\n(EU majority)", _ns_majority_eu),
    # Hosting: must be provably EU (None = non-participation at infrastructure
    # layer should not count as sovereign).
    ("Hosting\n(EU-hosted)", lambda e: e.get("hosting_is_eu") is True),
    # Email: EU-routed OR no email infrastructure (no MX records).
    # A domain with no MX has no email leak risk — vacuously sovereign.
    ("Email\n(EU-routed)",   lambda e: (
        e.get("email_is_eu") is True or not e.get("mx_records")
    )),
    ("TLS Certificate\n(EU CA)", lambda e: e.get("ssl_issuer_is_eu") is True),
    # SaaS: no detected non-EU service. No detected services is also
    # vacuously sovereign.
    ("SaaS\n(no non-EU)",    lambda e: not any(
        svc.get("is_eu") is False for svc in e.get("detected_services", [])
    )),
]

# Web Layer is sourced from page-load measurement (mean per-domain in-EU
# request share), not per-domain — appended as a precomputed continuous value.
WEB_DIM_NAME = "Web Layer\n(EU req)"
DIM_NAMES = [d[0] for d in DIMENSIONS] + [WEB_DIM_NAME]
DIM_FUNCS = [d[1] for d in DIMENSIONS]

COLORSCALE = COLORSCALE_PLOTLY


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def load_sector(sector_dir):
    pattern = str(RESULTS_DIR / sector_dir / "analyzed_results*.json")
    files = sorted(glob.glob(pattern))
    if not files:
        return None
    with open(files[-1]) as f:
        return json.load(f)


def y_label(cc):
    flag = CC_FLAGS.get(cc, '')
    label = CC_LABELS.get(cc, cc)
    return f"{flag} {label}"


def compute_row(entries, cc, web_pct=None):
    """Compute one row: [dim1%, ..., dimN%, web%, avg%] for a country."""
    n = len(entries)
    row = []
    for dim_func in DIM_FUNCS:
        if n == 0:
            row.append(None)
        else:
            row.append(round(sum(1 for e in entries if dim_func(e)) / n * 100, 1))
    row.append(round(web_pct, 1) if web_pct is not None else None)
    valid = [v for v in row if v is not None]
    avg = round(sum(valid) / len(valid), 1) if valid else None
    row.append(avg)
    return row


def compute_sector(data, country_order, sector_name, web_lookup):
    """Compute matrix for one sector: rows=countries, cols=dims+web+avg."""
    by_cc = defaultdict(list)
    for e in data:
        by_cc[e["country_code"]].append(e)

    rows = {}
    for cc in country_order:
        rows[cc] = compute_row(by_cc.get(cc, []), cc,
                               web_lookup.get((cc, sector_name)))

    # EU-27 aggregate (all entries except EU institutions)
    eu27_entries = [e for e in data if e["country_code"] != "EU"]
    rows["EU27"] = compute_row(eu27_entries, "EU27",
                               web_lookup.get(("EU27", sector_name)))

    return rows, {cc: len(by_cc.get(cc, [])) for cc in country_order}, len(eu27_entries)


def load_web_lookup():
    """{(cc, sector_display_name): mean_eu_pct} from in_eu_request_summary.json.

    Also populates ('EU27', sector) as a domain-count-weighted mean across EU members.
    """
    path = BASE / "results" / "in_eu_request_summary.json"
    if not path.exists():
        return {}
    with open(path) as f:
        data = json.load(f)
    sector_map = {"government": "Government", "newspaper": "Newspapers",
                  "bank": "Banks", "university": "Universities"}
    lookup = {}
    eu_acc = defaultdict(lambda: [0.0, 0])  # sector -> [weighted_sum, total_n]
    for r in data["by_country_sector"]:
        sn = sector_map.get(r["category"])
        if not sn:
            continue
        cc = r["country_code"]
        pct = r["mean_domain_in_eu_request_share_pct"]
        n = r["domain_request_share_n"]
        lookup[(cc, sn)] = pct
        if cc in EU_COUNTRIES:
            eu_acc[sn][0] += pct * n
            eu_acc[sn][1] += n
    for sn, (wsum, tot) in eu_acc.items():
        if tot > 0:
            lookup[("EU27", sn)] = wsum / tot
    return lookup


# ---------------------------------------------------------------------------
# Build ordered row list with EU-27 at natural position
# ---------------------------------------------------------------------------
def build_display_order(country_order, cross_sector_avg, eu27_avg):
    """Return list of (cc, is_separator) tuples with EU-27 at its natural avg position."""
    # EU institutions first
    result = [("EU", False)]

    # Countries sorted by score (already in country_order minus EU)
    countries = [cc for cc in country_order if cc != "EU"]

    # Find where EU-27 avg fits naturally
    eu27_inserted = False
    for cc in countries:
        cc_avg = cross_sector_avg.get(cc, 0)
        if not eu27_inserted and eu27_avg is not None and cc_avg <= eu27_avg:
            result.append(("_SEP", True))
            result.append(("EU27", False))
            result.append(("_SEP", True))
            eu27_inserted = True
        result.append((cc, False))

    if not eu27_inserted:
        result.append(("_SEP", True))
        result.append(("EU27", False))

    return result


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------
def write_csv(sector_data, country_order, cross_avg, eu27_avg):
    """Long-form CSV: one row per (country, sector). Cross-sector averages
    are not stored — they are the unweighted mean of the per-sector `avg` column.
    """
    import csv as _csv
    out_path = OUT_DIR / "sovereignty_heatmap.csv"
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    sector_names = [s[0] for s in SECTORS]
    headers = ["country_code"] + DIM_NAMES + ["avg", "sector", "n"]
    headers = [h.replace("\n", " ") for h in headers]

    with open(out_path, "w", newline="") as f:
        w = _csv.writer(f)
        w.writerow(headers)
        for cc in country_order + ["EU27"]:
            for sector in sector_names:
                row_data = sector_data.get(sector, {}).get(cc)
                if row_data is None:
                    continue
                n = sector_data.get(f"{sector}_n", {}).get(cc, 0)
                if n == 0:
                    continue
                cells = [cc] + [
                    "" if v is None else f"{v:.1f}" for v in row_data
                ] + [sector, n]
                w.writerow(cells)

    print(f"Wrote {out_path.name} ({sum(1 for _ in open(out_path)) - 1} rows)")


# ---------------------------------------------------------------------------
# Combined figure
# ---------------------------------------------------------------------------
def render_combined(sector_data, display_order):
    """Avg column + 4 sector heatmaps, 3 vertical sections split by EU-27."""
    # Split display_order into: above, eu27, below
    above, eu27, below = [], [], []
    current = above
    for cc, is_sep in display_order:
        if is_sep:
            continue
        if cc == "EU27":
            eu27.append(cc)
            current = below
        else:
            current.append(cc)

    sections = [above, eu27, below]
    section_heights = [len(above), 1, len(below)]
    total_rows = sum(section_heights)

    # 3 rows × 7 cols: [Avg, spacer, Gov, spacer, News, Banks, Uni]
    n_sectors = len(SECTORS)
    n_dims = len(DIM_NAMES)
    fig = make_subplots(
        rows=3, cols=n_sectors + 3,
        column_widths=[1.2, 0.3, n_dims, 0.3, n_dims, n_dims, n_dims],
        row_heights=section_heights,
        horizontal_spacing=0.005,
        vertical_spacing=0.008,
    )

    avg_col = 1
    sector_cols = [3, 5, 6, 7]

    for sec_idx, sec_ccs in enumerate(sections):
        row_num = sec_idx + 1

        # Y labels for this section
        y_labels = [y_label(cc) for cc in sec_ccs]

        # Cross-sector avg column
        avg_z = []
        for cc in sec_ccs:
            vals = [sector_data[sn][cc][-1] for sn in [s[0] for s in SECTORS]
                    if cc in sector_data[sn] and sector_data[sn][cc][-1] is not None]
            avg_z.append([round(sum(vals) / len(vals), 1) if vals else None])

        fig.add_trace(go.Heatmap(
            z=avg_z, x=["⌀"], y=y_labels,
            colorscale=COLORSCALE, zmin=0, zmax=100,
            showscale=False,
            texttemplate="%{z:.0f}",
            textfont=dict(size=28, color="black"),
            xgap=1, ygap=1, hoverinfo="skip",
        ), row=row_num, col=avg_col)

        # Per-sector columns
        for i, (sector_name, _) in enumerate(SECTORS):
            col = sector_cols[i]
            z = []
            sec_y_labels = []
            for cc in sec_ccs:
                row_data = sector_data[sector_name].get(cc)
                if row_data:
                    z.append(row_data[:-1])  # strip avg
                else:
                    z.append([None] * len(DIM_NAMES))
                cnt = sector_data.get(f"{sector_name}_n", {}).get(cc, 0)
                sec_y_labels.append(y_label(cc))

            x_labels = [d.replace("\n", "<br>") for d in DIM_NAMES]

            fig.add_trace(go.Heatmap(
                z=z, x=x_labels, y=sec_y_labels,
                colorscale=COLORSCALE, zmin=0, zmax=100,
                showscale=False,
                texttemplate="%{z:.0f}",
                textfont=dict(size=28, color="black"),
                xgap=1, ygap=1, hoverinfo="skip",
            ), row=row_num, col=col)

    # Layout
    fig.update_layout(
        font=dict(size=36, family="Arial, sans-serif"),
        width=4800, height=2800,
        margin=dict(l=5, r=5, t=260, b=5),
        paper_bgcolor="white",
    )

    # Configure axes
    for row in range(1, 4):
        for spacer_col in [2, 4]:
            fig.update_xaxes(visible=False, row=row, col=spacer_col)
            fig.update_yaxes(visible=False, row=row, col=spacer_col)
        for col in [avg_col] + sector_cols:
            # X-axis: show tick labels on top row only, on top side
            fig.update_xaxes(
                side="top", tickangle=-30, tickfont=dict(size=24),
                showticklabels=(row == 1),
                row=row, col=col,
            )
            # Y-axis: show labels only on Avg column
            fig.update_yaxes(
                autorange="reversed", tickfont=dict(size=32),
                showticklabels=(col == avg_col),
                row=row, col=col,
            )

    # Remove any auto-generated subplot titles
    fig.layout.annotations = []

    # Add column titles centered above each column's data range — derived
    # from SECTORS so order edits there can't desync labels from data.
    col_titles = {avg_col: ("⌀", 1)}
    for col, (sector_name, _) in zip(sector_cols, SECTORS):
        col_titles[col] = (sector_name, n_dims)
    for col_num, (title, n_cells) in col_titles.items():
        xaxis_name = "x" if col_num == 1 else f"x{col_num}"
        fig.add_annotation(
            text=title,
            xref=xaxis_name, yref="paper",
            x=(n_cells - 1) / 2,  # center of data range (0-indexed)
            y=1.10, showarrow=False,
            font=dict(size=42, family="Arial, sans-serif"),
        )

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for ext in ("png", "pdf"):
        path = OUT_DIR / f"sovereignty_heatmap_combined.{ext}"
        try:
            fig.write_image(str(path), scale=2 if ext == "png" else 1)
            print(f"Wrote {path.name}")
        except Exception as e:
            print(f"Failed {path.name}: {e}")


# ---------------------------------------------------------------------------
# Per-sector static exports
# ---------------------------------------------------------------------------
def render_per_sector(sector_data, display_order):
    for sector_name, _ in SECTORS:
        # Build matrix in display order (skip separators)
        y_labels, z, hover = [], [], []
        for cc, is_sep in display_order:
            if is_sep:
                y_labels.append("")
                z.append([None] * (len(DIM_NAMES) + 1))
                hover.append([""] * (len(DIM_NAMES) + 1))
                continue
            row_data = sector_data[sector_name].get(cc, [None] * (len(DIM_NAMES) + 1))
            n = sector_data[sector_name].get(cc, {})
            # Get count
            cnt = sector_data[f"{sector_name}_n"].get(cc, 0)
            y_labels.append(y_label(cc))
            z.append(row_data)
            h = [f"{cc}: {v:.0f}%" if v is not None else "" for v in row_data]
            hover.append(h)

        x_labels = [d.replace("\n", "<br>") for d in DIM_NAMES] + ["Avg"]

        fig = go.Figure(data=[go.Heatmap(
            z=z, x=x_labels, y=y_labels,
            colorscale=COLORSCALE, zmin=0, zmax=100,
            showscale=False,
            texttemplate="%{z:.0f}",
            textfont=dict(size=18, color="white"),
            xgap=1, ygap=1,
        )])
        fig.update_layout(
            title=dict(text=f"{sector_name}: Sovereignty by Country",
                       font=dict(size=30, family="Arial, sans-serif"), x=0.01),
            font=dict(size=22, family="Arial, sans-serif"),
            width=1300, height=1400,
            margin=dict(l=5, r=5, t=160, b=5),
            paper_bgcolor="white",
            xaxis=dict(side="top", tickangle=-30, tickfont=dict(size=18)),
            yaxis=dict(autorange="reversed"),
        )
        slug = sector_name.lower()
        try:
            fig.write_image(str(OUT_DIR / f"sovereignty_heatmap_{slug}.png"), scale=2)
            fig.write_image(str(OUT_DIR / f"sovereignty_heatmap_{slug}.pdf"))
            print(f"Wrote sovereignty_heatmap_{slug}.png/pdf")
        except Exception as e:
            print(f"Export failed for {sector_name}: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    # Load SSL collection with CA parent-company overrides
    import csv as _csv
    _ca_overrides = []
    _ca_path = Path(__file__).resolve().parent.parent / "lookup_tables" / "ca_database.csv"
    if _ca_path.exists():
        with open(_ca_path) as _f:
            for row in _csv.reader(_f):
                if len(row) >= 3 and not row[0].startswith("#"):
                    _ca_overrides.append((row[0].lower(), row[2]))
    ssl_lookup = {}
    if SSL_COLLECTION.exists():
        with open(SSL_COLLECTION) as f:
            for r in json.load(f)["results"]:
                if not r.get("error") and r.get("ssl_issuer_country"):
                    country = r["ssl_issuer_country"]
                    issuer = (r.get("ssl_issuer_org") or "").lower()
                    for pattern, override_cc in _ca_overrides:
                        if pattern in issuer:
                            country = override_cc
                            break
                    ssl_lookup[r["domain"]] = country in EU_COUNTRIES
        print(f"SSL collection: {len(ssl_lookup)} certs loaded")

    # Load and enrich sector data
    raw_data = {}
    all_countries = set()
    for sector_name, sector_dir in SECTORS:
        data = load_sector(sector_dir)
        if data is None:
            continue
        for entry in data:
            if entry.get("ssl_issuer_is_eu") is None:
                ssl_eu = ssl_lookup.get(entry["domain"])
                if ssl_eu is not None:
                    entry["ssl_issuer_is_eu"] = ssl_eu
        raw_data[sector_name] = data
        all_countries.update(e["country_code"] for e in data)

    web_lookup = load_web_lookup()
    if web_lookup:
        print(f"Web layer: {len(web_lookup)} (country, sector) entries")

    # Compute per-sector scores
    sector_data = {}
    for sector_name, _ in SECTORS:
        if sector_name not in raw_data:
            continue
        rows, counts, n27 = compute_sector(raw_data[sector_name],
                                            sorted(all_countries),
                                            sector_name, web_lookup)
        sector_data[sector_name] = rows
        sector_data[f"{sector_name}_n"] = counts
        sector_data[f"{sector_name}_n"]["EU27"] = n27
        print(f"Processed {sector_name}: {sum(1 for v in counts.values() if v > 0)} countries")

    # Compute cross-sector avg per country for sorting
    cross_avg = {}
    for cc in all_countries:
        vals = [sector_data[s[0]][cc][-1] for s in SECTORS
                if s[0] in sector_data and cc in sector_data[s[0]]
                and sector_data[s[0]][cc][-1] is not None]
        cross_avg[cc] = sum(vals) / len(vals) if vals else 0

    # EU-27 cross-sector avg
    eu27_vals = [sector_data[s[0]]["EU27"][-1] for s in SECTORS
                 if s[0] in sector_data and sector_data[s[0]]["EU27"][-1] is not None]
    eu27_avg = sum(eu27_vals) / len(eu27_vals) if eu27_vals else 0

    # Sort countries by cross-sector avg (descending), EU first
    country_order = ["EU"] + sorted(
        all_countries - {"EU"},
        key=lambda cc: cross_avg.get(cc, 0),
        reverse=True,
    )

    display_order = build_display_order(country_order, cross_avg, eu27_avg)

    write_csv(sector_data, country_order, cross_avg, eu27_avg)
    render_combined(sector_data, display_order)
    render_per_sector(sector_data, display_order)


if __name__ == "__main__":
    main()
