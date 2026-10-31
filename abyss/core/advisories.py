"""
advisories.py - Turns a detected service banner into search links on
authoritative vulnerability databases.

This deliberately does NOT ship a local "version X.Y is vulnerable"
lookup table. A hand-maintained CVE mapping goes stale immediately and
risks giving false confidence either way (missing new CVEs, or
flagging patched versions as vulnerable). Instead, this generates the
same searches a careful analyst would run by hand - the "manually
search version numbers on Exploit-DB or CVE Details" step - just
pre-filled from what Abyss already detected, so you don't have to
retype it.
"""

import re
from urllib.parse import quote

# Very loose heuristics to pull a product name + version out of a banner
# string. Banners are inconsistent across services, so this aims for
# "good enough to build a useful search query", not perfect parsing.
_VERSION_PATTERNS = [
    r"([A-Za-z][A-Za-z0-9]*)[_/](\d+\.\d+(?:\.\d+)?)",  # e.g. "OpenSSH_8.9p1", "Apache/2.4.41"
    r"([A-Za-z][A-Za-z0-9_\-]*)[/ ]v?(\d+\.\d+(?:\.\d+)?)",
]


def extract_product_version(banner):
    if not banner:
        return None
    for pattern in _VERSION_PATTERNS:
        match = re.search(pattern, banner)
        if match:
            return match.group(1), match.group(2)
    return None


def get_advisory_links(service, banner):
    """
    Returns a dict of labeled search URLs for a detected service/banner.
    Always returns something usable even if version parsing fails -
    falls back to searching by service name alone.
    """
    parsed = extract_product_version(banner)
    if parsed:
        product, version = parsed
        query = f"{product} {version}"
    else:
        query = service or "unknown service"

    q = quote(query)
    return {
        "query_used": query,
        "nvd": f"https://nvd.nist.gov/vuln/search/results?query={q}",
        "cve_details": f"https://www.cvedetails.com/google-search-results.php?q={q}",
        "exploit_db": f"https://www.exploit-db.com/search?q={q}",
    }
