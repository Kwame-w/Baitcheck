"""Render a Report as console text, JSON or a Markdown triage note."""

from __future__ import annotations

import json

from .analyzer import Report
from .domains import defang, defang_text
from .virustotal import VTResult

_SEV_ICON = {"high": "[!]", "medium": "[~]", "low": "[-]", "info": "[i]"}
_VERDICT_COLOR = {"likely phishing": "\033[1;31m", "suspicious": "\033[33m", "no strong indicators": "\033[32m"}


def _bar(score: int, width: int = 20) -> str:
    filled = round(score / 100 * width)
    return "#" * filled + "." * (width - filled)


def to_console(report: Report, vt: list[VTResult] | None = None, color: bool = True) -> str:
    verdict = report.verdict.upper()
    if color:
        verdict = f"{_VERDICT_COLOR[report.verdict]}{verdict}\033[0m"
    auth = ", ".join(f"{k.upper()}={v}" for k, v in sorted(report.auth.items())) or "no results"
    lines = [
        f"File:     {report.file}",
        f"Subject:  {report.subject}",
        f"From:     {report.from_header}",
        f"Reply-To: {report.reply_to or '-'}",
        f"Auth:     {auth}",
        "",
        f"Risk score: {report.score}/100 [{_bar(report.score)}]  {verdict}",
        "",
        "Findings:",
    ]
    lines += [f"  {_SEV_ICON[f.severity]} (+{f.score:>2}) {defang_text(f.message)}" for f in report.findings] or ["  none"]

    iocs = report.iocs()
    lines += ["", "IOCs (defanged):"]
    for kind, values in iocs.items():
        if values:
            shown = values if kind == "attachment_sha256" else [defang(v) for v in values]
            lines.append(f"  {kind}:")
            lines += [f"    {v}" for v in shown]
    if report.attachments:
        lines += ["", "Attachments:"]
        lines += [f"  {a.filename} ({a.content_type}, {a.size} bytes) sha256={a.sha256}" for a in report.attachments]
    if vt:
        lines += ["", "VirusTotal:"]
        for r in vt:
            status = r.error or f"{r.malicious} malicious, {r.suspicious} suspicious"
            lines.append(f"  {r.kind:<6} {defang(r.ioc) if r.kind == 'domain' else r.ioc}: {status}")
    return "\n".join(lines)


def to_dict(report: Report, vt: list[VTResult] | None = None) -> dict:
    data = report.to_dict()
    if vt is not None:
        data["virustotal"] = [r.__dict__ for r in vt]
    return data


def to_json(reports: list[dict]) -> str:
    return json.dumps(reports[0] if len(reports) == 1 else reports, indent=2)


def to_markdown(report: Report, vt: list[VTResult] | None = None) -> str:
    """A triage note ready to paste into a ticket. IOCs are defanged."""
    md = [
        f"## Phishing triage: {report.subject or '(no subject)'}",
        "",
        f"**Verdict:** {report.verdict} (score {report.score}/100)",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| From | `{report.from_header}` |",
        f"| Reply-To | `{report.reply_to or '-'}` |",
        f"| Return-Path | `{report.return_path or '-'}` |",
        f"| Date | {report.date or '-'} |",
        f"| SPF / DKIM / DMARC | {report.auth.get('spf', '-')} / {report.auth.get('dkim', '-')} / {report.auth.get('dmarc', '-')} |",
        "",
        "### Findings",
        "",
    ]
    md += [f"- **{f.severity.upper()}** (+{f.score}) {defang_text(f.message)}" for f in report.findings] or ["- None"]
    md += ["", "### Indicators of compromise", ""]
    for kind, values in report.iocs().items():
        if values:
            md.append(f"**{kind}**")
            md += [f"- `{v if kind == 'attachment_sha256' else defang(v)}`" for v in values]
            md.append("")
    if vt:
        md += ["### VirusTotal", ""]
        md += [f"- `{r.ioc}`: {r.error or f'{r.malicious} malicious, {r.suspicious} suspicious'}" for r in vt]
        md.append("")
    md += [
        "### Recommended actions",
        "",
    ]
    if report.score >= 30:
        md += [
            "- Do not click links or open attachments; report the message to the security team.",
            "- Search the mail gateway for other recipients of this sender / subject and purge.",
            "- Block the listed domains and hashes on the proxy, EDR and mail gateway.",
            "- If anyone entered credentials, reset them and revoke active sessions.",
        ]
    else:
        md.append("- No strong indicators. Release if the user confirms they expected it.")
    return "\n".join(md) + "\n"
