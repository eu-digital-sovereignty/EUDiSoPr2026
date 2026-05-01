#!/usr/bin/env python3
"""Generate choropleth maps of EU digital sovereignty scores.

Produces:
  1. sovereignty_map_overall.png/pdf     -- single map, cross-sector average
  2. sovereignty_map_sectors.png/pdf     -- 2×2 grid, one per sector
  3. sovereignty_map_grid.png/pdf        -- 4×4 grid, sector × dimension
  4. sovereignty_map_interactive.html    -- dropdown selector for sector/dimension

Usage:
    uv run python3 visualization/generate_sovereignty_map.py
"""

import csv
import glob
import json
from collections import defaultdict
from pathlib import Path

import plotly.graph_objects as go
from plotly.subplots import make_subplots

from chart_style import COLORSCALE_PLOTLY

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------
BASE = Path(__file__).parent.parent
RESULTS_DIR = BASE / "results"
OUT_DIR = Path(__file__).parent / "figures"
SSL_COLLECTION = RESULTS_DIR / "ssl_collection.json"
CA_DB = BASE / "lookup_tables" / "ca_database.csv"

EU_COUNTRIES = frozenset(
    "AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE".split()
)

# ISO 3166-1 alpha-2 → alpha-3 for plotly choropleth
CC2_TO_CC3 = {
    "AT": "AUT", "BE": "BEL", "BG": "BGR", "HR": "HRV", "CY": "CYP",
    "CZ": "CZE", "DK": "DNK", "EE": "EST", "FI": "FIN", "FR": "FRA",
    "DE": "DEU", "GR": "GRC", "HU": "HUN", "IE": "IRL", "IT": "ITA",
    "LV": "LVA", "LT": "LTU", "LU": "LUX", "MT": "MLT", "NL": "NLD",
    "PL": "POL", "PT": "PRT", "RO": "ROU", "SK": "SVK", "SI": "SVN",
    "ES": "ESP", "SE": "SWE",
}

SECTORS = [
    ("Government", "government"),
    ("Universities", "universities"),
    ("Banks", "banks"),
    ("Newspapers", "newspapers"),
]

def _ns_majority_eu(e):
    """Strict majority of classified NS providers are EU-hosted."""
    provs = [p for p in (e.get("ns_providers") or []) if p.get("is_eu") is not None]
    if not provs:
        return False
    return sum(1 for p in provs if p.get("is_eu")) > len(provs) / 2


# Dimensions match heatmap canonical definitions and ordering.
DIMENSIONS = [
    ("Nameservers\n(EU majority)", _ns_majority_eu),
    ("Hosting\n(EU-hosted)", lambda e: e.get("hosting_is_eu") is True),
    ("Email\n(EU-routed)", lambda e:
        e.get("email_is_eu") is True or not e.get("mx_records")),
    ("TLS Certificate\n(EU CA)", lambda e: e.get("ssl_issuer_is_eu") is True),
    ("SaaS\n(no non-EU)", lambda e: not any(
        svc.get("is_eu") is False for svc in e.get("detected_services", [])
    )),
]
WEB_DIM_NAME = "Web Layer\n(EU req)"

COLORSCALE = COLORSCALE_PLOTLY

GEO_LAYOUT = dict(
    scope="europe",
    projection_type="natural earth",
    showlakes=False,
    showframe=False,
    bgcolor="white",
    lonaxis=dict(range=[-12, 35]),
    lataxis=dict(range=[34, 72]),
    showcoastlines=True,
    coastlinecolor="#cccccc",
    showland=True,
    landcolor="#f0f0f0",
    countrycolor="#cccccc",
    showocean=True,
    oceancolor="white",
)


# ---------------------------------------------------------------------------
# Data loading (shared with heatmap)
# ---------------------------------------------------------------------------
def load_ssl_lookup():
    """Load SSL collection with CA parent-company overrides."""
    ca_overrides = []
    if CA_DB.exists():
        with open(CA_DB) as f:
            for row in csv.reader(f):
                if len(row) >= 3 and not row[0].startswith("#") and row[0] != "pattern":
                    ca_overrides.append((row[0].lower(), row[2]))

    ssl_lookup = {}
    if SSL_COLLECTION.exists():
        with open(SSL_COLLECTION) as f:
            for r in json.load(f)["results"]:
                if not r.get("error") and r.get("ssl_issuer_country"):
                    country = r["ssl_issuer_country"]
                    issuer = (r.get("ssl_issuer_org") or "").lower()
                    for pattern, override_cc in ca_overrides:
                        if pattern in issuer:
                            country = override_cc
                            break
                    ssl_lookup[r["domain"]] = country in EU_COUNTRIES
    return ssl_lookup


def load_all_sectors(ssl_lookup):
    """Load and enrich all sector data. Returns {sector_name: [entries]}."""
    data = {}
    for sector_name, sector_dir in SECTORS:
        pattern = str(RESULTS_DIR / sector_dir / "analyzed_results*.json")
        files = sorted(glob.glob(pattern))
        if not files:
            continue
        with open(files[-1]) as f:
            entries = json.load(f)
        for entry in entries:
            if entry.get("ssl_issuer_is_eu") is None:
                ssl_eu = ssl_lookup.get(entry["domain"])
                if ssl_eu is not None:
                    entry["ssl_issuer_is_eu"] = ssl_eu
        data[sector_name] = entries
    return data


def load_web_lookup():
    """{(cc, sector_display_name|'All Sectors'): mean_eu_pct} from page-load data."""
    path = RESULTS_DIR / "in_eu_request_summary.json"
    if not path.exists():
        return {}
    with open(path) as f:
        data = json.load(f)
    sector_map = {"government": "Government", "newspaper": "Newspapers",
                  "bank": "Banks", "university": "Universities"}
    lookup = {}
    for r in data.get("by_country_sector", []):
        sn = sector_map.get(r["category"])
        if sn:
            lookup[(r["country_code"], sn)] = r["mean_domain_in_eu_request_share_pct"]
    for r in data.get("by_country", []):
        lookup[(r["country_code"], "All Sectors")] = r["mean_domain_in_eu_request_share_pct"]
    return lookup


def compute_country_scores(entries, web_lookup=None, sector_label="All Sectors"):
    """Per-country scores for all dimensions + Web Layer (continuous) + average.
    Returns {cc: {dim_name: score, ..., "Average": score, "n": count}}.
    """
    by_cc = defaultdict(list)
    for e in entries:
        cc = e.get("country_code")
        if cc and cc in EU_COUNTRIES:
            by_cc[cc].append(e)

    scores = {}
    for cc, ents in by_cc.items():
        n = len(ents)
        row = {"n": n}
        dim_vals = []
        for dim_name, dim_func in DIMENSIONS:
            val = round(sum(1 for e in ents if dim_func(e)) / n * 100, 1)
            row[dim_name] = val
            dim_vals.append(val)
        web_val = (web_lookup or {}).get((cc, sector_label))
        if web_val is not None:
            web_val = round(web_val, 1)
            row[WEB_DIM_NAME] = web_val
            dim_vals.append(web_val)
        else:
            row[WEB_DIM_NAME] = None
        row["Average"] = round(sum(dim_vals) / len(dim_vals), 1)
        scores[cc] = row
    return scores


# ---------------------------------------------------------------------------
# Core choropleth builder
# ---------------------------------------------------------------------------
def make_choropleth(scores, value_key, title=None, geo_name="geo"):
    """Build a single Choropleth trace from {cc: {value_key: score}}."""
    locs, vals, texts = [], [], []
    for cc in sorted(EU_COUNTRIES):
        if cc not in scores:
            continue
        cc3 = CC2_TO_CC3.get(cc)
        if not cc3:
            continue
        score = scores[cc].get(value_key)
        if score is None:
            continue
        n = scores[cc].get("n", 0)
        locs.append(cc3)
        vals.append(score)
        texts.append(f"{cc}: {score:.0f}% (n={n})")

    return go.Choropleth(
        locations=locs,
        z=vals,
        locationmode="ISO-3",
        colorscale=COLORSCALE,
        zmin=0, zmax=100,
        text=texts,
        hoverinfo="text",
        marker_line_color="#666666",
        marker_line_width=0.5,
        colorbar=dict(title="%", len=0.6) if geo_name == "geo" else None,
        showscale=(geo_name == "geo"),
        geo=geo_name,
    )


def save_fig(fig, name):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for ext in ("png", "pdf"):
        path = OUT_DIR / f"{name}.{ext}"
        try:
            fig.write_image(str(path), scale=2 if ext == "png" else 1)
            print(f"  Saved {path.name}")
        except Exception as e:
            print(f"  Failed {path.name}: {e}")


# ---------------------------------------------------------------------------
# Option 1: Single map -- cross-sector average
# ---------------------------------------------------------------------------
def map_overall(all_data, web_lookup):
    print("Map 1: Overall sovereignty")
    all_entries = [e for entries in all_data.values() for e in entries]
    scores = compute_country_scores(all_entries, web_lookup, "All Sectors")

    fig = go.Figure(make_choropleth(scores, "Average"))
    fig.update_geos(**GEO_LAYOUT)
    fig.update_layout(
        title=dict(text="EU Digital Sovereignty: Cross-Sector Average",
                   font=dict(size=28), x=0.5),
        font=dict(size=18),
        width=1100, height=850,
        margin=dict(l=0, r=0, t=70, b=0),
    )
    save_fig(fig, "sovereignty_map_overall")


# ---------------------------------------------------------------------------
# Option 2: 2×2 grid -- one per sector (average score)
# ---------------------------------------------------------------------------
def map_sectors(all_data, web_lookup):
    print("Map 2: Per-sector sovereignty")

    fig = make_subplots(
        rows=2, cols=2,
        specs=[[{"type": "choropleth"}, {"type": "choropleth"}],
               [{"type": "choropleth"}, {"type": "choropleth"}]],
        subplot_titles=[s[0] for s in SECTORS],
        horizontal_spacing=0.02,
        vertical_spacing=0.05,
    )

    geo_names = ["geo", "geo2", "geo3", "geo4"]
    positions = [(1, 1), (1, 2), (2, 1), (2, 2)]

    for i, (sector_name, _) in enumerate(SECTORS):
        entries = all_data.get(sector_name, [])
        scores = compute_country_scores(entries, web_lookup, sector_name)
        trace = make_choropleth(scores, "Average", geo_name=geo_names[i])
        fig.add_trace(trace, row=positions[i][0], col=positions[i][1])

    for geo_name in geo_names:
        fig.update_geos(**GEO_LAYOUT, selector=dict(geo=geo_name) if geo_name != "geo" else None)
        fig.update_layout(**{geo_name: GEO_LAYOUT})

    # Single shared colorbar
    fig.data[0].showscale = True
    fig.data[0].colorbar = dict(
        title=dict(text="%", font=dict(size=20)),
        len=0.4, y=0.5, tickfont=dict(size=18))

    fig.update_layout(
        title=dict(text="EU Digital Sovereignty by Sector",
                   font=dict(size=28), x=0.5),
        font=dict(size=18),
        width=1700, height=1300,
        margin=dict(l=0, r=0, t=110, b=0),
    )
    for ann in fig.layout.annotations:
        ann.font.size = 24
    save_fig(fig, "sovereignty_map_sectors")


# ---------------------------------------------------------------------------
# Option 3: 4×4 grid -- sector × dimension
# ---------------------------------------------------------------------------
def map_grid(all_data, web_lookup):
    print("Map 3: Sector × dimension grid")

    dim_names = [d[0] for d in DIMENSIONS] + [WEB_DIM_NAME]
    n_sectors = len(SECTORS)
    n_dims = len(dim_names)

    specs = [[{"type": "choropleth"} for _ in range(n_dims)] for _ in range(n_sectors)]
    titles = [f"{s[0]}: {d.split(chr(10))[0]}" for s in SECTORS for d in dim_names]

    fig = make_subplots(
        rows=n_sectors, cols=n_dims,
        specs=specs,
        subplot_titles=titles,
        horizontal_spacing=0.01,
        vertical_spacing=0.05,
    )

    geo_idx = 0
    for row_i, (sector_name, _) in enumerate(SECTORS):
        entries = all_data.get(sector_name, [])
        scores = compute_country_scores(entries, web_lookup, sector_name)
        for col_i, dim_name in enumerate(dim_names):
            geo_idx += 1
            geo_name = "geo" if geo_idx == 1 else f"geo{geo_idx}"
            trace = make_choropleth(scores, dim_name, geo_name=geo_name)
            fig.add_trace(trace, row=row_i + 1, col=col_i + 1)
            fig.update_layout(**{geo_name: GEO_LAYOUT})

    # Single shared colorbar on first trace
    fig.data[0].showscale = True
    fig.data[0].colorbar = dict(
        title=dict(text="%", font=dict(size=22)),
        len=0.3, y=0.5, tickfont=dict(size=20))

    fig.update_layout(
        font=dict(size=20),
        width=3000, height=2700,
        margin=dict(l=0, r=0, t=40, b=0),
    )
    for ann in fig.layout.annotations:
        ann.font.size = 22

    save_fig(fig, "sovereignty_map_grid")


# ---------------------------------------------------------------------------
# Option 4: Interactive map with dropdown
# ---------------------------------------------------------------------------
def map_interactive(all_data, web_lookup):
    print("Map 4: Interactive map with dropdown")

    # Pre-compute all scores
    all_scores = {}
    for sector_name, _ in SECTORS:
        all_scores[sector_name] = compute_country_scores(
            all_data.get(sector_name, []), web_lookup, sector_name)
    all_entries = [e for entries in all_data.values() for e in entries]
    all_scores["All Sectors"] = compute_country_scores(
        all_entries, web_lookup, "All Sectors")

    dim_names = [d[0] for d in DIMENSIONS] + [WEB_DIM_NAME, "Average"]
    sector_names = ["All Sectors"] + [s[0] for s in SECTORS]

    # Build all traces (hidden by default)
    fig = go.Figure()
    trace_map = {}  # (sector, dim) -> trace index

    for sector in sector_names:
        scores = all_scores[sector]
        for dim in dim_names:
            idx = len(fig.data)
            trace_map[(sector, dim)] = idx

            locs, vals, texts = [], [], []
            for cc in sorted(EU_COUNTRIES):
                if cc not in scores:
                    continue
                cc3 = CC2_TO_CC3.get(cc)
                if not cc3:
                    continue
                val = scores[cc].get(dim)
                if val is None:
                    continue
                n = scores[cc].get("n", 0)
                locs.append(cc3)
                vals.append(val)
                texts.append(f"{cc}: {val:.0f}% (n={n})")

            fig.add_trace(go.Choropleth(
                locations=locs, z=vals,
                locationmode="ISO-3",
                colorscale=COLORSCALE, zmin=0, zmax=100,
                text=texts, hoverinfo="text",
                marker_line_color="#666666", marker_line_width=0.5,
                colorbar=dict(title="%", len=0.6),
                visible=False,
            ))

    # Default view: All Sectors, Average
    default_idx = trace_map[("All Sectors", "Average")]
    fig.data[default_idx].visible = True

    # Build dropdown menus
    sector_buttons = []
    for sector in sector_names:
        visible = [False] * len(fig.data)
        # Show the "Average" dimension for this sector by default
        visible[trace_map[(sector, "Average")]] = True
        sector_buttons.append(dict(
            label=sector,
            method="update",
            args=[{"visible": visible},
                  {"title.text": f"EU Digital Sovereignty: {sector}"}],
        ))

    dim_buttons = []
    for dim in dim_names:
        dim_label = dim.split("\n")[0] if "\n" in dim else dim
        visible = [False] * len(fig.data)
        # Show current sector? Default to All Sectors
        visible[trace_map[("All Sectors", dim)]] = True
        dim_buttons.append(dict(
            label=dim_label,
            method="update",
            args=[{"visible": visible},
                  {"title.text": f"EU Digital Sovereignty: {dim_label}"}],
        ))

    fig.update_layout(
        updatemenus=[
            dict(buttons=sector_buttons, direction="down",
                 x=0.01, xanchor="left", y=1.12, yanchor="top",
                 showactive=True, active=0,
                 font=dict(size=13)),
            dict(buttons=dim_buttons, direction="down",
                 x=0.30, xanchor="left", y=1.12, yanchor="top",
                 showactive=True, active=len(dim_names) - 1,  # "Average"
                 font=dict(size=13)),
        ],
        geo=GEO_LAYOUT,
        title=dict(text="EU Digital Sovereignty: All Sectors",
                   font=dict(size=20), x=0.5),
        width=900, height=700,
        margin=dict(l=0, r=0, t=100, b=0),
    )

    path = OUT_DIR / "sovereignty_map_interactive.html"
    fig.write_html(str(path), include_plotlyjs="cdn")
    print(f"  Saved {path.name}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("Loading data...")
    ssl_lookup = load_ssl_lookup()
    print(f"  SSL lookup: {len(ssl_lookup)} certs")
    all_data = load_all_sectors(ssl_lookup)
    for name, entries in all_data.items():
        print(f"  {name}: {len(entries)} domains")

    web_lookup = load_web_lookup()
    print(f"  Web layer: {len(web_lookup)} (country, sector) entries")

    map_overall(all_data, web_lookup)
    map_sectors(all_data, web_lookup)
    map_grid(all_data, web_lookup)
    map_interactive(all_data, web_lookup)
    print("\nDone!")


if __name__ == "__main__":
    main()
