"""Shared chart style for EU Digital Sovereignty paper.

Usage:
    from chart_style import *
    apply_style()  # call once before plotting

All figures use the same sector palette, sovereignty palette,
font sizes, and hatching conventions for print + accessibility.
"""

import matplotlib.pyplot as plt
from matplotlib.patches import Patch

# ─────────────────────────────────────────────────────────────
# Sector palette (colorblind-distinguishable, with hatches)
# ─────────────────────────────────────────────────────────────
SECTOR_ORDER = ["Government", "Universities", "Banks", "Newspapers"]

SECTOR_COLORS = {
    "Government":   "#4C78A8",  # steel blue
    "Newspapers":   "#E45756",  # salmon red
    "Banks":        "#F58518",  # orange
    "Universities": "#72B7B2",  # teal
}

SECTOR_HATCHES = {
    "Government":   "",       # solid fill — darkest in greyscale
    "Newspapers":   "///",    # diagonal lines — medium density
    "Banks":        "xxx",    # dense crosshatch — reads dark but textured
    "Universities": "...",    # dots — lightest, clearly distinct
}

SECTOR_LABELS_SHORT = {
    "Government":   "Gov",
    "Newspapers":   "News",
    "Banks":        "Banks",
    "Universities": "Uni",
}

SECTOR_FILL = {s: c + "22" for s, c in SECTOR_COLORS.items()}  # 13% alpha hex


def sector_style(sector):
    """Return dict with facecolor, hatch, edgecolor for a sector."""
    return {
        "facecolor": SECTOR_COLORS[sector],
        "hatch": SECTOR_HATCHES[sector],
        "edgecolor": "black",
        "linewidth": 0.75,
        "alpha": 0.88,
    }

# ─────────────────────────────────────────────────────────────
# Sovereignty palette (EU vs Non-EU vs neutral)
# ─────────────────────────────────────────────────────────────
EU_BLUE       = "#003399"   # official EU flag blue
NON_EU_RED    = "#CC0000"
CDN_ORANGE    = "#e67e22"
UNKNOWN_GREY  = "#95a5a6"
SELF_HOSTED   = "#5dade2"   # neutral teal (not green = not implying EU)

EU_HATCH      = ""          # solid — reads dark in greyscale
NON_EU_HATCH  = "///"       # diagonal lines — clearly different from solid

SOVEREIGNTY_COLORS = {
    "EU Provider":     EU_BLUE,
    "Non-EU Provider": NON_EU_RED,
    "Non-EU CDN":      CDN_ORANGE,
    "EU CDN":          "#2980b9",   # lighter blue
    "Unresolvable":    UNKNOWN_GREY,
}

SOVEREIGNTY_HATCHES = {
    "EU Provider":     "",         # solid
    "Non-EU Provider": "///",      # diagonal
    "Non-EU CDN":      "xxx",      # crosshatch
    "EU CDN":          "",         # solid (same family as EU Provider)
    "Unresolvable":    "...",      # dots
}

# Email provider colors
EMAIL_COLORS = {
    "Microsoft 365":            "#0078d4",
    "Google Workspace":         "#ea4335",
    "Self-hosted":              SELF_HOSTED,
    "Email Security Appliance": "#bdc3c7",
    "No MX Record":             UNKNOWN_GREY,
}

EMAIL_HATCHES = {
    "Microsoft 365":            "",        # solid
    "Google Workspace":         "///",     # diagonal
    "Self-hosted":              "...",     # dots
    "Email Security Appliance": "xxx",     # crosshatch
    "No MX Record":             "\\\\\\",  # back-diagonal
}

# ─────────────────────────────────────────────────────────────
# Colorscale for heatmaps / choropleths
# Monotonic luminance: 38% → 65% → 82% grey for B&W print
# ─────────────────────────────────────────────────────────────
COLORSCALE_PLOTLY = [[0.0, "#c0392b"], [0.5, "#f39c12"], [1.0, "#c4e67e"]]

# ─────────────────────────────────────────────────────────────
# Typography
# ─────────────────────────────────────────────────────────────
FONT_TITLE    = 20
FONT_SUBTITLE = 17
FONT_LABEL    = 15
FONT_TICK     = 14
FONT_LEGEND   = 14
FONT_ANNOT    = 12     # value labels on bars
FONT_ANNOT_LG = 15     # value labels when more space

DPI = 150

# ─────────────────────────────────────────────────────────────
# Apply global matplotlib style
# ─────────────────────────────────────────────────────────────
def apply_style():
    """Set global rcParams. Call once at the top of each script."""
    plt.rcParams.update({
        "font.family":        "sans-serif",
        "font.size":          FONT_TICK,
        "figure.facecolor":   "white",
        "figure.dpi":         DPI,
        "savefig.dpi":        DPI,
        "savefig.bbox":       "tight",
        "savefig.facecolor":  "white",
        "axes.facecolor":     "white",
        "axes.edgecolor":     "#333333",
        "axes.labelsize":     FONT_LABEL,
        "axes.titlesize":     FONT_SUBTITLE,
        "axes.grid":          False,
        "axes.spines.top":    False,
        "axes.spines.right":  False,
        "xtick.labelsize":    FONT_TICK,
        "ytick.labelsize":    FONT_TICK,
        "legend.fontsize":    FONT_LEGEND,
        "legend.frameon":     True,
        "legend.edgecolor":   "#cccccc",
    })


# ─────────────────────────────────────────────────────────────
# Helper: sector legend with hatches
# ─────────────────────────────────────────────────────────────
def sector_legend(ax, loc="upper right", **kwargs):
    """Add a legend with sector colors + hatches."""
    handles = [
        Patch(facecolor=SECTOR_COLORS[s], hatch=SECTOR_HATCHES[s],
              edgecolor="black", linewidth=0.75, label=s)
        for s in SECTOR_ORDER
    ]
    return ax.legend(handles=handles, loc=loc, fontsize=FONT_LEGEND, **kwargs)


def eu_legend(ax, loc="lower right", **kwargs):
    """Add EU vs Non-EU legend."""
    handles = [
        Patch(facecolor=EU_BLUE, hatch=EU_HATCH,
              edgecolor="black", linewidth=0.75, label="EU"),
        Patch(facecolor=NON_EU_RED, hatch=NON_EU_HATCH,
              edgecolor="black", linewidth=0.75, label="Non-EU"),
    ]
    return ax.legend(handles=handles, loc=loc, fontsize=FONT_LEGEND, **kwargs)
