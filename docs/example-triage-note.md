## Phishing triage: Action required: unusual sign-in activity on your account

**Verdict:** likely phishing (score 100/100)

| Field | Value |
|---|---|
| From | `PayPal Security <service@paypa1-security.com>` |
| Reply-To | `-` |
| Return-Path | `<service@paypa1-security.com>` |
| Date | Mon, 12 Oct 2026 09:14:20 +0000 |
| SPF / DKIM / DMARC | softfail / none / fail |

### Findings

- **HIGH** (+30) Sender domain paypa1-security.com imitates PayPal (real: paypal.com).
- **HIGH** (+25) DMARC fail: the sender is not authorized to send for this domain.
- **HIGH** (+25) Display name claims to be PayPal but the sending domain is paypa1-security.com.
- **HIGH** (+25) Link text shows paypal.com but actually goes to paypa1-security.com.
- **HIGH** (+20) Link points to a raw IP address: hxxp://198[.]51[.]100[.]14/assets/track[.]gif
- **MEDIUM** (+15) SPF softfail: the sender is not authorized to send for this domain.
- **MEDIUM** (+15) Pressure or urgency language: 'account will be suspended', 'action required', 'immediately', 'unusual sign-in', 'verify your account', 'within 24 hours'.
- **MEDIUM** (+10) Credential-related page served over plain HTTP: hxxp://paypa1-security[.]com/login/verify?session=8f2a
- **LOW** (+5) DKIM none: sender could not be verified.

### Indicators of compromise

**urls**
- `hxxp://198[.]51[.]100[.]14/assets/track[.]gif`
- `hxxp://paypa1-security[.]com/login/verify?session=8f2a`

**domains**
- `198[.]51[.]100[.]14`
- `paypa1-security[.]com`

**sender_ips**
- `203[.]0[.]113[.]66`

### Recommended actions

- Do not click links or open attachments; report the message to the security team.
- Search the mail gateway for other recipients of this sender / subject and purge.
- Block the listed domains and hashes on the proxy, EDR and mail gateway.
- If anyone entered credentials, reset them and revoke active sessions.
