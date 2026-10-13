"""Domain helpers: registered-domain extraction, lookalike and homoglyph detection."""

from __future__ import annotations

import ipaddress
import re

# Common multi-label public suffixes. Not the full Public Suffix List, but enough for
# the domains phishing mail usually uses, and it keeps the tool dependency-free.
_MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp",
    "com.br", "com.cn", "com.mx", "co.in", "co.za", "com.tr", "com.sg", "com.hk",
}

# Brands most often impersonated in phishing, mapped to their legitimate domains.
BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "office.com", "live.com", "outlook.com", "microsoftonline.com"},
    "office365": {"office.com", "microsoft.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazonaws.com"},
    "google": {"google.com", "gmail.com", "googlemail.com", "googleusercontent.com", "gstatic.com"},
    "netflix": {"netflix.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "linkedin": {"linkedin.com"},
    "facebook": {"facebook.com", "facebookmail.com"},
    "instagram": {"instagram.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "dropbox": {"dropbox.com"},
    "adobe": {"adobe.com"},
    "coinbase": {"coinbase.com"},
}
LEGIT_DOMAINS = {d for domains in BRANDS.values() for d in domains}

_BRAND_DISPLAY = {
    "paypal": "PayPal", "docusign": "DocuSign", "linkedin": "LinkedIn", "dhl": "DHL", "fedex": "FedEx",
    "wellsfargo": "Wells Fargo", "bankofamerica": "Bank of America", "office365": "Office 365",
}

FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "aol.com",
    "icloud.com", "protonmail.com", "proton.me", "gmx.com", "mail.com", "yandex.com", "zoho.com",
}


def brand_name(brand: str) -> str:
    return _BRAND_DISPLAY.get(brand, brand.title())

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "ga", "work",
    "support", "rest", "cam", "icu", "monster", "buzz", "live", "sbs", "cfd",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc",
}

_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def registered_domain(host: str) -> str:
    """Return the registrable domain, e.g. ``login.paypal.co.uk`` -> ``paypal.co.uk``."""
    host = host.lower().strip(".").split(":")[0]
    if is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def tld(host: str) -> str:
    return host.lower().rsplit(".", 1)[-1]


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def normalize_homoglyphs(label: str) -> str:
    return label.translate(_HOMOGLYPHS).replace("rn", "m").replace("vv", "w")


def lookalike_brand(domain: str) -> str | None:
    """Return the brand a domain imitates, or None if it looks legitimate or unrelated.

    Catches typosquats (``paypai.com``), homoglyphs (``paypa1.com``, ``rnicrosoft.com``),
    brand-plus-keyword domains (``paypal-secure-login.com``) and punycode (``xn--...``).
    """
    domain = registered_domain(domain)
    if domain in LEGIT_DOMAINS or is_ip(domain):
        return None
    name = domain.split(".")[0]
    normalized = normalize_homoglyphs(name)
    tokens = re.split(r"[-_.]", normalized)
    for brand in BRANDS:
        if brand in tokens or normalized == brand:
            return brand
        # Short brands (apple, chase, dhl) collide with real words, so only long
        # brands get substring and edit-distance matching.
        if len(brand) < 6:
            continue
        max_distance = 1 if len(brand) < 9 else 2
        if brand in normalized or any(levenshtein(t, brand) <= max_distance for t in tokens):
            return brand
    return None


def is_punycode(host: str) -> bool:
    return any(label.startswith("xn--") for label in host.lower().split("."))


def defang(value: str) -> str:
    """Make an IOC safe to paste into tickets and chat: hxxps://evil[.]com."""
    value = re.sub(r"^http", "hxxp", value, flags=re.IGNORECASE)
    return value.replace(".", "[.]").replace("@", "[@]")


_URL_IN_TEXT = re.compile(r"https?://\S+", re.IGNORECASE)


def defang_text(text: str) -> str:
    """Defang every URL inside free text, such as a finding message."""
    return _URL_IN_TEXT.sub(lambda m: defang(m.group(0)), text)
