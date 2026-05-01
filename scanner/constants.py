"""Shared constants for EU digital sovereignty scanner."""

EU_COUNTRIES = frozenset({
    'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR',
    'DE', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL',
    'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE'
})

EEA_COUNTRIES = EU_COUNTRIES | frozenset({'NO', 'IS', 'LI'})

CDN_PROVIDERS = frozenset({
    'Cloudflare', 'Akamai', 'Fastly', 'Amazon CloudFront',
    'Imperva/Incapsula', 'F5 Networks',
})


def is_eu_hq(cc):
    """Check if a country code represents an EU-headquartered entity."""
    return cc in EU_COUNTRIES or cc == 'EU'
