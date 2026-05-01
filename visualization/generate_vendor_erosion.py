#!/usr/bin/env python3
"""
Layer-by-layer erosion chart: as major US vendors fall one by one, each
dependency layer (Nameservers, Hosting, Email, TLS CA, SaaS) shrinks.

Per-layer baselines: each line starts at the count of domains that
actually use that layer (e.g., TLS CA starts at # of domains with a
collected cert, not the total dataset).

Vendor order is chosen greedily worst-first: at each step we pick the
remaining candidate whose removal causes the largest aggregate drop
across all layers, given what has already fallen.
"""

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

from chart_style import (
    FONT_TITLE, FONT_LABEL, FONT_TICK, FONT_ANNOT_LG, apply_style,
)

ROOT = Path(__file__).resolve().parent.parent
FIGURES_DIR = Path(__file__).resolve().parent / "figures"
FIGURES_DIR.mkdir(exist_ok=True)


def _latest(sector):
    d = ROOT / "results" / sector
    files = sorted(
        f for f in d.iterdir()
        if f.name.startswith("analyzed_results") and f.suffix == ".json"
    )
    return files[-1]


def _norm(p):
    if not p or not isinstance(p, str):
        return None
    p = p.lower()
    if "microsoft" in p or "azure" in p:
        return "Microsoft"
    if "amazon" in p or "aws" in p:
        return "Amazon"
    if "google" in p:
        return "Google"
    if "cloudflare" in p:
        return "Cloudflare"
    if "akamai" in p:
        return "Akamai"
    if "cisco" in p or "webex" in p or "meraki" in p or "duo security" in p:
        return "Cisco"
    if "let's encrypt" in p or "lets encrypt" in p or "letsencrypt" in p:
        return "Let's Encrypt"
    if "digicert" in p:
        return "DigiCert"
    if "sectigo" in p or "comodo" in p:
        return "Sectigo"
    if "proofpoint" in p or "pphosted" in p:
        return "Proofpoint"
    if "fastly" in p:
        return "Fastly"
    if "atlassian" in p or "trello" in p:
        return "Atlassian"
    return None


def load_domain_vendor_map():
    all_entries = []
    for sector in ["government", "banks", "newspapers", "universities"]:
        with open(_latest(sector)) as f:
            all_entries.extend(json.load(f))
    with open(ROOT / "results" / "ssl_collection.json") as f:
        ssl_lookup = {
            r["domain"]: r for r in json.load(f)["results"] if not r.get("error")
        }

    dlv_map = {}
    for e in all_entries:
        d = e["domain"]
        # Hosting: vendor (one of CA_VENDORS) or None; uses-flag covers any host
        host_v = _norm(e.get("hosting_provider")) or _norm(
            e.get("hosting_cdn_provider")
        )
        host_uses = bool(e.get("hosting_provider")
                         or e.get("hosting_cdn_provider"))

        email_v = _norm(e.get("email_provider"))
        email_uses = bool(e.get("email_provider") or e.get("mx_records"))

        saas_set = set()
        for s in e.get("detected_services", []):
            v = _norm(s.get("vendor"))
            if v:
                saas_set.add(v)
        saas_uses = bool(e.get("detected_services"))

        ns_normed = [_norm(p.get("provider"))
                     for p in (e.get("ns_providers") or [])]
        ns_uses = len(ns_normed) > 0

        ca_v = None
        ca_uses = False
        sr = ssl_lookup.get(d)
        if sr:
            ca_uses = True
            ca_v = _norm(sr.get("ssl_issuer_org"))

        dlv_map[d] = {
            "hosting": {"uses": host_uses, "vendor": host_v},
            "email":   {"uses": email_uses, "vendor": email_v},
            "ns":      {"uses": ns_uses, "list": ns_normed},
            "ca":      {"uses": ca_uses, "vendor": ca_v},
            "saas":    {"uses": saas_uses, "set": saas_set},
        }
    return dlv_map, len(all_entries)


def _layer_affected(L, layer, fallen):
    """True if this domain is broken at `layer` given fallen vendors."""
    if not L["uses"]:
        return False  # vacuously fine: no dependency on this layer
    if layer == "saas":
        return bool(L["set"] & fallen)
    if layer == "ns":
        # Resilient: broken only if every classified NS vendor is fallen
        # AND no unclassified NS exists.
        return all(n is not None and n in fallen for n in L["list"])
    v = L["vendor"]
    return v is not None and v in fallen


def count_served(dlv_map, fallen, layer):
    """Domains still served at `layer`. All domains start counted; only those
    actively broken on this layer are subtracted (so domains without that
    layer remain at the top)."""
    return sum(1 for d in dlv_map.values()
               if not _layer_affected(d[layer], layer, fallen))


def count_combined(dlv_map, fallen, layers):
    """Domains unaffected on every layer (zero failures across the stack)."""
    return sum(1 for d in dlv_map.values()
               if not any(_layer_affected(d[l], l, fallen) for l in layers))


def count_all(dlv_map, fallen, layers):
    out = {l: count_served(dlv_map, fallen, l) for l in layers}
    out["combined"] = count_combined(dlv_map, fallen, layers)
    return out


def greedy_worst_first(dlv_map, candidates, layers):
    """Order vendors so each pick maximizes the additional aggregate drop."""
    fallen = set()
    remaining = set(candidates)
    order = []
    while remaining:
        before = sum(count_served(dlv_map, fallen, l) for l in layers)
        def drop(v):
            after = sum(count_served(dlv_map, fallen | {v}, l) for l in layers)
            return before - after
        nxt = max(remaining, key=drop)
        order.append(nxt)
        fallen.add(nxt)
        remaining.remove(nxt)
    return order


def main():
    apply_style()
    dlv_map, total = load_domain_vendor_map()
    layers = ["ns", "hosting", "email", "ca", "saas"]
    layer_labels = {
        "ns":      "Nameservers",
        "hosting": "Hosting",
        "email":   "Email",
        "ca":      "TLS CA",
        "saas":    "SaaS",
    }

    candidates = ["Microsoft", "Google", "Amazon", "Cloudflare", "Akamai",
                  "Cisco", "Let's Encrypt", "DigiCert", "Sectigo",
                  "Proofpoint", "Fastly", "Atlassian"]
    vendor_order = greedy_worst_first(dlv_map, candidates, layers)
    print(f"Greedy worst-first order: {vendor_order}")

    # Timeline
    counts_series = [count_all(dlv_map, set(), layers)]
    fallen = set()
    for v in vendor_order:
        fallen.add(v)
        counts_series.append(count_all(dlv_map, fallen, layers))

    steps = ["initial"] + [f"−{v}" for v in vendor_order]
    for step, c in zip(steps, counts_series):
        print(f"{step:20s} {c}  sum={sum(c.values())}")

    x = np.arange(len(steps))
    data = np.array([[c[layer] for c in counts_series] for layer in layers])

    # Friendly palette, hatches for greyscale print readability.
    colors = {
        "ns":      "#D4A24C",  # warm amber
        "hosting": "#5FA992",  # soft moss green
        "email":   "#E8956C",  # warm apricot
        "ca":      "#5B9BD5",  # friendly sky blue
        "saas":    "#B088B8",  # soft lavender
    }
    hatches = {
        "ns":      "\\\\\\",
        "hosting": "...",
        "email":   "///",
        "ca":      "",
        "saas":    "xxx",
    }

    fig, ax = plt.subplots(figsize=(22, 7.2))
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")


    # Draw layers: least-eroded first (TLS CA on back), most-eroded on top
    layer_order = sorted(layers, key=lambda l: -data[layers.index(l)][-1])
    for layer in layer_order:
        row = data[layers.index(layer)]
        # Main filled area with subtle hatch for printability
        ax.fill_between(
            x, 0, row,
            facecolor=colors[layer], alpha=0.22,
            hatch=hatches[layer], edgecolor=colors[layer],
            linewidth=0.0, zorder=2,
        )
        # Top boundary line
        ax.plot(
            x, row,
            color=colors[layer], linewidth=2.6, zorder=4,
            marker="o", markersize=7, markerfacecolor="white",
            markeredgewidth=2, markeredgecolor=colors[layer],
            label=layer_labels[layer],
        )
        # End label to the right of the last marker
        ax.text(
            x[-1] + 0.22, row[-1],
            f"{int(row[-1]):,}  {layer_labels[layer]}",
            ha="left", va="center",
            fontsize=FONT_LABEL + 1, fontweight="bold", color=colors[layer],
        )

    # Combined line: domains unaffected on every layer (cumulative impact).
    combined_row = np.array([c["combined"] for c in counts_series])
    ax.plot(
        x, combined_row,
        color="#1B1B1B", linewidth=3.4, zorder=6, linestyle="--",
        marker="D", markersize=8, markerfacecolor="white",
        markeredgewidth=2, markeredgecolor="#1B1B1B",
        label="Unaffected on all layers (combined)",
    )
    ax.text(
        x[-1] + 0.22, combined_row[-1],
        f"{int(combined_row[-1]):,}  Combined",
        ha="left", va="center",
        fontsize=FONT_LABEL + 1, fontweight="bold", color="#1B1B1B",
    )

    # Vendor name "headers" at top of each removal column
    for i, v in enumerate(vendor_order, start=1):
        ax.text(
            i, total * 1.07, v,
            ha="center", va="center",
            fontsize=FONT_LABEL - 2, fontweight="bold",
            color="white",
            bbox=dict(boxstyle="round,pad=0.25",
                      facecolor="#2C3E50", edgecolor="none"),
        )

    ax.set_xticks(x)
    step_display = [""] + [f"after\n−{v}" for v in vendor_order]
    ax.set_xticklabels(step_display, fontsize=FONT_LABEL)
    ax.set_ylabel(
        f"Domains still served at this layer", fontsize=FONT_LABEL + 1,
    )
    ax.set_xlim(-0.05, len(steps) - 1 + 1.6)
    ax.set_ylim(0, total * 1.15)
    ax.legend(
        loc="lower left", fontsize=FONT_TICK,
        frameon=True, edgecolor="#CCCCCC", ncol=3,
    )
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(True, axis="y", linestyle=":", alpha=0.3)
    ax.set_axisbelow(True)
    ax.tick_params(labelsize=FONT_TICK)

    fig.tight_layout()
    out_png = FIGURES_DIR / "vendor_erosion.png"
    out_pdf = FIGURES_DIR / "vendor_erosion.pdf"
    fig.savefig(out_png, dpi=200, bbox_inches="tight")
    fig.savefig(out_pdf, bbox_inches="tight")
    print(f"\nSaved {out_png}")
    print(f"Saved {out_pdf}")


if __name__ == "__main__":
    main()
