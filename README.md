# Baitcheck

**A phishing email analyzer for SOC and incident response triage.** Point it at a suspicious `.eml` file and it checks email authentication, sender spoofing, lookalike domains, deceptive links, risky attachments and business email compromise patterns, then gives the message a risk score and extracts defanged indicators of compromise (IOCs) ready for a ticket.

It never opens links or runs attachments. It only reads headers, bodies and attachment bytes (to hash them), so it is safe to run on live samples. No runtime dependencies: pure Python 3.10+.

```
$ baitcheck samples/paypal_credential_phish.eml

Subject:  Action required: unusual sign-in activity on your account
From:     PayPal Security <service@paypa1-security.com>
Auth:     DKIM=none, DMARC=fail, SPF=softfail

Risk score: 100/100 [####################]  LIKELY PHISHING

Findings:
  [!] (+30) Sender domain paypa1-security.com imitates PayPal (real: paypal.com).
  [!] (+25) DMARC fail: the sender is not authorized to send for this domain.
  [!] (+25) Display name claims to be PayPal but the sending domain is paypa1-security.com.
  [!] (+25) Link text shows paypal.com but actually goes to paypa1-security.com.
  [!] (+20) Link points to a raw IP address: hxxp://198[.]51[.]100[.]14/assets/track[.]gif
  [~] (+15) SPF softfail: the sender is not authorized to send for this domain.
  [~] (+15) Pressure or urgency language: 'account will be suspended', 'action required', ...
  [~] (+10) Credential-related page served over plain HTTP: hxxp://paypa1-security[.]com/login/verify?session=8f2a

IOCs (defanged):
  urls:
    hxxp://paypa1-security[.]com/login/verify?session=8f2a
  domains:
    paypa1-security[.]com
  sender_ips:
    203[.]0[.]113[.]66
```

It can also write a [Markdown triage note](docs/example-triage-note.md) per email, with findings, IOCs and recommended response actions, ready to paste into a ticket.

## What it checks

| Area | Checks |
|---|---|
| **Authentication** | SPF, DKIM and DMARC results from `Authentication-Results` (falls back to `Received-SPF`). Fail and softfail score higher than missing results. |
| **Sender** | `Reply-To` pointing to a different domain, replies redirected to free webmail from a corporate sender, `Return-Path` mismatch. |
| **Display name spoofing** | Brand names in the display name sent from a non-brand domain, and display names that contain a different email address (`"support@paypal.com" <x@evil.example>`). |
| **Lookalike domains** | Typosquats (`paypai.com`), homoglyphs (`paypa1.com`, `rnicrosoft.com`), brand-plus-keyword domains (`paypal-secure-login.com`) and punycode (`xn--`) for ~20 commonly impersonated brands. Uses Levenshtein distance after homoglyph normalization, with guards so short brands don't match ordinary words. |
| **Links** | Anchor text that shows one domain but links to another, raw IP links, URL shorteners, abused TLDs (`.top`, `.xyz`, `.zip`, ...), `user@host` URL tricks, and login pages over plain HTTP. |
| **Attachments** | SHA-256 and MD5 hashes, double extensions (`label.pdf.js`), executable and script types, macro-enabled Office files, and archives. |
| **Language** | Urgency and pressure phrases common in phishing. |
| **BEC** | A payment request (wire transfer, gift cards, bank details) combined with urgency or secrecy, the pattern behind CEO fraud, which often has no links or attachments at all. |

Each finding adds to a score capped at 100: **0-29** no strong indicators, **30-59** suspicious, **60+** likely phishing.

### Optional VirusTotal enrichment

```bash
export VT_API_KEY=your-key
baitcheck suspicious.eml --vt
```

Looks up attachment hashes and link domains with the VirusTotal v3 API. Only hashes and domains are queried; nothing is uploaded. The free tier's rate limit is respected automatically.

## Quick start

```bash
git clone https://github.com/<your-username>/baitcheck.git
cd baitcheck
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

baitcheck samples/                                  # analyze every .eml in a folder
baitcheck samples/ --json out.json --markdown notes # also write JSON and triage notes
baitcheck suspicious.eml --fail-score 60            # exit code 2 if score >= 60 (automation)
```

To get an `.eml` from your own mailbox: in Gmail use **More > Download message**, in Outlook drag the message to a folder or use **File > Save As**.

## Sample emails

`samples/` contains four harmless emails built by `scripts/make_samples.py`:

| Sample | Scenario | Verdict |
|---|---|---|
| `legit_newsletter.eml` | Order summary from a retailer, fully authenticated | no strong indicators (0) |
| `paypal_credential_phish.eml` | Credential phishing with a homoglyph domain and a deceptive link | likely phishing (100) |
| `malware_delivery.eml` | Fake DHL notice with a `.pdf.js` attachment and a shortened link | likely phishing (100) |
| `bec_wire_transfer.eml` | "CEO" asks finance for an urgent, confidential wire, replies go to webmail | likely phishing (65) |

The BEC sample passes SPF, DKIM and DMARC, which is the point: authentication alone doesn't stop business email compromise.

## Project layout

```
baitcheck/
├── analyzer.py     # MIME parsing, link and attachment extraction, all checks, scoring
├── domains.py      # registered-domain logic, lookalike/homoglyph detection, defanging
├── virustotal.py   # optional VT v3 enrichment (injectable fetcher for testing)
├── output.py       # console, JSON and Markdown triage note
└── cli.py          # argparse entry point
tests/              # 40 pytest tests, including a mocked VirusTotal API
scripts/            # sample email builder
.github/workflows/  # CI: ruff, Bandit, pytest on Python 3.10-3.13
```

## Limitations and ideas

* Registered-domain extraction uses a short built-in suffix list rather than the full Public Suffix List.
* Header results are trusted as written by your mail server. Headers added before your gateway can be forged, so the tool reads the `Authentication-Results` your own server adds.
* Ideas: parse `.msg` files, follow redirect chains in a sandbox, QR-code phishing detection in images, and a YARA scan of attachments.

## Disclaimer

Baitcheck is a defensive, educational tool for analyzing emails you received or are authorized to investigate.

## License

MIT
