"""
Public Suffix List / Registered Domain Extraction
Supports two-level and multi-level ccTLDs (e.g. .co.uk, .edu.in, .com.au, .gov.in, etc.)
Deterministic, no external network dependencies.
"""

from urllib.parse import urlparse
import re

# Comprehensive list of two-level and multi-level public suffixes
TWO_LEVEL_TLDS = {
    # UK
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "ac.uk", "gov.uk", "nhs.uk", "police.uk",
    # India
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "nic.in", "ac.in", "edu.in", "res.in", "gov.in", "mil.in",
    # Australia
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    # Canada
    "gc.ca", "ab.ca", "bc.ca", "mb.ca", "nb.ca", "nl.ca", "ns.ca", "nt.ca", "nu.ca", "on.ca", "pe.ca", "qc.ca", "sk.ca", "yk.ca",
    # Japan
    "co.jp", "ne.jp", "or.jp", "ac.jp", "ad.jp", "ed.jp", "go.jp", "gr.jp", "lg.jp",
    # Brazil
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "mil.br", "art.br", "dev.br",
    # New Zealand
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz", "geek.nz",
    # South Africa
    "co.za", "net.za", "org.za", "ac.za", "gov.za", "law.za",
    # Singapore
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg", "per.sg",
    # Hong Kong
    "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk", "idv.hk",
    # Mexico
    "com.mx", "net.mx", "org.mx", "gob.mx", "edu.mx",
    # Germany / EU special subdomains / others
    "asso.fr", "presse.fr", "gouv.fr",
    "co.il", "org.il", "net.il", "ac.il", "gov.il", "muni.il",
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr",
    "co.kr", "ne.kr", "or.kr", "re.kr", "pe.kr", "go.kr", "ac.kr",
    "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "com.pk", "net.pk", "org.pk", "gov.pk", "edu.pk",
    "com.ng", "org.ng", "gov.ng", "edu.ng", "net.ng",
    "com.ar", "net.ar", "org.ar", "gob.ar", "edu.ar",
    "com.co", "net.co", "org.co", "gov.co", "edu.co",
    "co.id", "net.id", "org.id", "go.id", "ac.id", "web.id", "my.id"
}

IP_REGEX = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")


def extract_registered_domain(hostname_or_url: str) -> str:
    """
    Extracts the registrable root domain (eTLD+1) considering multi-part ccTLDs.
    Examples:
      'www.apnacollege.in' -> 'apnacollege.in'
      'sub.example.co.uk'  -> 'example.co.uk'
      'login.service.com'   -> 'service.com'
      '192.168.1.1'        -> '192.168.1.1'
      'localhost'          -> 'localhost'
    """
    if not hostname_or_url:
        return ""

    raw = hostname_or_url.strip().lower()
    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.hostname or ""
    else:
        # Might contain path
        host = raw.split("/")[0].split(":")[0]

    host = host.strip(".")
    if not host:
        return ""

    if IP_REGEX.match(host):
        return host

    parts = host.split(".")
    if len(parts) <= 1:
        return host

    # Check for two-level suffix (e.g. parts[-2] + '.' + parts[-1])
    if len(parts) >= 3:
        two_level_candidate = f"{parts[-2]}.{parts[-1]}"
        if two_level_candidate in TWO_LEVEL_TLDS:
            return f"{parts[-3]}.{two_level_candidate}"

    # Default to single level TLD: parts[-2] + '.' + parts[-1]
    return f"{parts[-2]}.{parts[-1]}"


def extract_public_suffix(hostname_or_url: str) -> str:
    """Returns the public suffix part (e.g. 'co.uk', 'in', 'com')."""
    reg_dom = extract_registered_domain(hostname_or_url)
    if not reg_dom or IP_REGEX.match(reg_dom):
        return ""
    parts = reg_dom.split(".")
    if len(parts) >= 2:
        return ".".join(parts[1:])
    return parts[-1]
