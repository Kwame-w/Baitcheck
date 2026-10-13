"""Parse an .eml file and run phishing checks on it.

The analyzer never opens links or executes attachments. It only reads headers,
bodies and attachment bytes (to hash them), so it is safe to run on live samples.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import asdict, dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

from .domains import (
    BRANDS,
    FREEMAIL_DOMAINS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
    brand_name,
    is_ip,
    is_punycode,
    lookalike_brand,
    registered_domain,
    tld,
)

# --- data model ---------------------------------------------------------------


@dataclass
class Finding:
    check: str
    severity: str  # info, low, medium, high
    score: int
    message: str


@dataclass
class Link:
    url: str
    host: str
    domain: str
    text: str = ""  # anchor text when the link came from HTML


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    md5: str


@dataclass
class Report:
    file: str
    subject: str
    from_header: str
    from_domain: str
    reply_to: str
    return_path: str
    date: str
    auth: dict[str, str]
    received_hops: int
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    received_raw: str = field(default="", repr=False)

    @property
    def score(self) -> int:
        return min(100, sum(f.score for f in self.findings))

    @property
    def verdict(self) -> str:
        if self.score >= 60:
            return "likely phishing"
        if self.score >= 30:
            return "suspicious"
        return "no strong indicators"

    def iocs(self) -> dict[str, list[str]]:
        sender_ips = sorted({ip for ip in _RECEIVED_IP.findall(self.received_raw) if not _is_internal(ip)})
        return {
            "urls": sorted({link.url for link in self.links}),
            "domains": sorted({link.domain for link in self.links} | ({self.from_domain} - {""})),
            "sender_ips": sender_ips,
            "attachment_sha256": sorted({a.sha256 for a in self.attachments}),
        }

    def to_dict(self) -> dict:
        data = asdict(self)
        data.pop("received_raw", None)
        data["score"] = self.score
        data["verdict"] = self.verdict
        data["iocs"] = self.iocs()
        return data


# --- parsing helpers ----------------------------------------------------------

_INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")]


def _is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # not a real address, so not a useful IOC
    return any(addr in net for net in _INTERNAL_NETS)


_URL = re.compile(r"""https?://[^\s<>"'()\[\]]+""", re.IGNORECASE)
_RECEIVED_IP = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
_AUTH_RESULT = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*(\w+)", re.IGNORECASE)

RISKY_EXTENSIONS = {
    "exe", "scr", "com", "bat", "cmd", "pif", "js", "jse", "vbs", "vbe", "wsf", "hta", "ps1",
    "jar", "lnk", "iso", "img", "vhd", "msi", "dll", "cpl", "html", "htm", "svg", "one",
}
MACRO_EXTENSIONS = {"docm", "xlsm", "pptm", "dotm", "xlam", "xlsb"}
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "gz", "tar", "ace", "cab"}

URGENCY_PHRASES = (
    "verify your account", "account will be suspended", "account has been suspended", "unusual activity",
    "unusual sign-in", "confirm your identity", "update your payment", "immediately", "within 24 hours",
    "urgent", "action required", "final notice", "password expires", "you have won", "wire transfer",
    "gift card", "invoice attached", "click here", "limited time", "security alert",
)


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def _strip_html(html: str) -> str:
    return re.sub(r"<[^>]+>", " ", html)


def _make_link(url: str, text: str = "") -> Link | None:
    url = url.strip().rstrip(".,;")
    parts = urlsplit(url)
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return None
    return Link(url=url, host=parts.hostname.lower(), domain=registered_domain(parts.hostname), text=text)


def _addr_domain(header_value: str) -> str:
    _, addr = parseaddr(header_value or "")
    return registered_domain(addr.rsplit("@", 1)[1]) if "@" in addr else ""


def load(path: Path) -> EmailMessage:
    with path.open("rb") as handle:
        return BytesParser(policy=policy.default).parse(handle)


# --- analysis -----------------------------------------------------------------


def analyze(msg: EmailMessage, source: str = "<message>") -> Report:
    from_header = str(msg.get("From", ""))
    received = msg.get_all("Received", []) or []
    auth_headers = " ".join(str(h) for h in (msg.get_all("Authentication-Results", []) or []))
    auth = {k.lower(): v.lower() for k, v in _AUTH_RESULT.findall(auth_headers)}
    received_spf = str(msg.get("Received-SPF", ""))
    if "spf" not in auth and received_spf:
        auth["spf"] = received_spf.split()[0].lower()

    report = Report(
        file=source,
        subject=str(msg.get("Subject", "")),
        from_header=from_header,
        from_domain=_addr_domain(from_header),
        reply_to=str(msg.get("Reply-To", "")),
        return_path=str(msg.get("Return-Path", "")),
        date=str(msg.get("Date", "")),
        auth=auth,
        received_hops=len(received),
    )
    report.received_raw = " ".join(str(r) for r in received)

    text_parts, html_parts = [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if filename or disposition == "attachment":
            payload = part.get_payload(decode=True) or b""
            report.attachments.append(Attachment(
                filename=filename or "(unnamed)",
                content_type=part.get_content_type(),
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
                md5=hashlib.md5(payload, usedforsecurity=False).hexdigest(),
            ))
            continue
        if part.get_content_type() == "text/plain":
            text_parts.append(part.get_content())
        elif part.get_content_type() == "text/html":
            html_parts.append(part.get_content())

    seen: set[str] = set()
    anchor_texts: set[str] = set()
    for html in html_parts:
        extractor = _LinkExtractor()
        extractor.feed(html)
        for href, text in extractor.links:
            anchor_texts.add(text)
            link = _make_link(href, text)
            if link and link.url not in seen:
                seen.add(link.url)
                report.links.append(link)
    body_text = "\n".join(text_parts + [_strip_html(h) for h in html_parts])
    for url in _URL.findall(body_text):
        if url in anchor_texts:
            continue  # the visible text of a link, not a destination (checked in check_links)
        link = _make_link(url)
        if link and link.url not in seen:
            seen.add(link.url)
            report.links.append(link)

    for check in CHECKS:
        report.findings.extend(check(report, msg, body_text))
    report.findings.sort(key=lambda f: -f.score)
    return report


def analyze_file(path: Path) -> Report:
    return analyze(load(path), source=str(path))


# --- checks -------------------------------------------------------------------
# Each check returns zero or more Findings. Scores are additive and capped at 100.


def check_authentication(report: Report, msg: EmailMessage, body: str) -> list[Finding]:
    findings = []
    weights = {"spf": 15, "dkim": 15, "dmarc": 25}
    for mech, weight in weights.items():
        result = report.auth.get(mech)
        if result in ("fail", "softfail", "permerror"):
            findings.append(Finding("auth", "high" if mech == "dmarc" else "medium", weight,
                                    f"{mech.upper()} {result}: the sender is not authorized to send for this domain."))
        elif result in (None, "none", "neutral", "temperror"):
            findings.append(Finding("auth", "low", weight // 3,
                                    f"{mech.upper()} {'missing' if result is None else result}: sender could not be verified."))
    return findings


def check_sender_alignment(report: Report, msg: EmailMessage, body: str) -> list[Finding]:
    findings = []
    reply_domain = _addr_domain(report.reply_to)
    if reply_domain and report.from_domain and reply_domain != report.from_domain:
        findings.append(Finding("sender", "high", 20,
                                f"Reply-To goes to {reply_domain}, but the message claims to be from {report.from_domain}. "
                                "Replies would reach a different party (common in business email compromise)."))
        if reply_domain in FREEMAIL_DOMAINS and report.from_domain not in FREEMAIL_DOMAINS:
            findings.append(Finding("sender", "medium", 15,
                                    f"A corporate sender asks for replies to a free webmail account ({reply_domain})."))
    return_domain = _addr_domain(report.return_path)
    if return_domain and report.from_domain and return_domain != report.from_domain:
        findings.append(Finding("sender", "low", 5,
                                f"Return-Path domain {return_domain} differs from From domain {report.from_domain}. "
                                "Normal for mailing services, suspicious otherwise."))
    return findings


def check_display_name(report: Report, msg: EmailMessage, body: str) -> list[Finding]:
    findings = []
    display, addr = parseaddr(report.from_header)
    display_l = display.lower()
    embedded = re.search(r"[\w.+-]+@([\w-]+\.[\w.-]+)", display)
    if embedded and registered_domain(embedded.group(1)) != report.from_domain:
        findings.append(Finding("spoofing", "high", 25,
                                f"Display name shows the address {embedded.group(0)} but the real sender is {addr}."))
    for brand, legit in BRANDS.items():
        if brand in display_l.replace(" ", "") and report.from_domain not in legit:
            findings.append(Finding("spoofing", "high", 25,
                                    f"Display name claims to be {brand_name(brand)} but the sending domain is {report.from_domain or 'unknown'}."))
            break
    return findings


def check_lookalike_domains(report: Report, msg: EmailMessage, body: str) -> list[Finding]:
    findings = []
    domains = {report.from_domain} | {link.domain for link in report.links}
    for domain in sorted(d for d in domains if d):
        brand = lookalike_brand(domain)
        if brand:
            where = "sender" if domain == report.from_domain else "link"
            findings.append(Finding("lookalike", "high", 30,
                                    f"{where.title()} domain {domain} imitates {brand_name(brand)} "
                                    f"(real: {', '.join(sorted(BRANDS[brand]))})."))
        if is_punycode(domain):
            findings.append(Finding("lookalike", "high", 20,
                                    f"{domain} is a punycode (internationalized) domain, often used for homograph attacks."))
    return findings


def check_links(report: Report, msg: EmailMessage, body: str) -> list[Finding]:
    findings = []
    for link in report.links:
        shown = _URL.search(link.text or "")
        if shown:
            shown_link = _make_link(shown.group(0))
            if shown_link and shown_link.domain != link.domain:
                findings.append(Finding("links", "high", 25,
                                        f"Link text shows {shown_link.domain} but actually goes to {link.domain}."))
        if is_ip(link.host):
            findings.append(Finding("links", "high", 20, f"Link points to a raw IP address: {link.url}"))
        if link.domain in URL_SHORTENERS:
            findings.append(Finding("links", "medium", 10, f"Link uses a URL shortener that hides its destination: {link.url}"))
        if tld(link.host) in SUSPICIOUS_TLDS:
            findings.append(Finding("links", "medium", 10, f"Link uses a TLD frequently abused for phishing (.{tld(link.host)}): {link.host}"))
        if "@" in urlsplit(link.url).netloc:
            findings.append(Finding("links", "high", 20, f"Link hides its real host behind an @ sign: {link.url}"))
        if link.url.lower().startswith("http://") and re.search(r"login|signin|verify|account|password", link.url, re.I):
            findings.append(Finding("links", "medium", 10, f"Credential-related page served over plain HTTP: {link.url}"))
    return findings


def check_attachments(report: Report, msg: EmailMessage, body: str) -> list[Finding]:
    findings = []
    for att in report.attachments:
        name = att.filename.lower()
        parts = name.split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        if len(parts) > 2 and ext in RISKY_EXTENSIONS | MACRO_EXTENSIONS:
            findings.append(Finding("attachments", "high", 35,
                                    f"{att.filename} uses a double extension to disguise a .{ext} file."))
        elif ext in RISKY_EXTENSIONS:
            findings.append(Finding("attachments", "high", 30, f"{att.filename} is an executable or script-capable file type (.{ext})."))
        elif ext in MACRO_EXTENSIONS:
            findings.append(Finding("attachments", "high", 25, f"{att.filename} is a macro-enabled Office document."))
        elif ext in ARCHIVE_EXTENSIONS:
            findings.append(Finding("attachments", "medium", 10, f"{att.filename} is an archive, which can hide malware from scanners."))
    return findings


def check_urgency(report: Report, msg: EmailMessage, body: str) -> list[Finding]:
    text = f"{report.subject}\n{body}".lower()
    hits = sorted({p for p in URGENCY_PHRASES if p in text})
    if not hits:
        return []
    score = min(15, 5 * len(hits))
    return [Finding("language", "medium" if score >= 10 else "low", score,
                    f"Pressure or urgency language: {', '.join(repr(h) for h in hits[:6])}.")]


_PAYMENT = re.compile(r"wire transfer|bank (details|account)|payment|invoice|gift cards?|routing number|iban", re.I)
_PRESSURE = re.compile(r"urgent|asap|today|before \d|end of (the )?day|confidential|keep this (between us|quiet)|"
                       r"in (a )?meetings?|can't talk|are you available", re.I)


def check_bec(report: Report, msg: EmailMessage, body: str) -> list[Finding]:
    """Business email compromise: a payment request plus urgency or secrecy, usually with no links at all."""
    text = f"{report.subject}\n{body}"
    payment, pressure = _PAYMENT.search(text), _PRESSURE.search(text)
    if not (payment and pressure):
        return []
    return [Finding("bec", "high", 20,
                    f"Business email compromise pattern: a payment request ({payment.group(0)!r}) "
                    f"combined with pressure or secrecy ({pressure.group(0)!r}). Verify by phone before paying.")]


CHECKS = (
    check_authentication,
    check_sender_alignment,
    check_display_name,
    check_lookalike_domains,
    check_links,
    check_attachments,
    check_urgency,
    check_bec,
)
