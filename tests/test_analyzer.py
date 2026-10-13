from email.message import EmailMessage
from pathlib import Path

from baitcheck.analyzer import analyze, analyze_file

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def make(from_="Alice <alice@corp.example>", subject="Hello", body="Hi there", html=None,
         auth="spf=pass; dkim=pass; dmarc=pass", **headers) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = from_
    msg["To"] = "bob@corp.example"
    msg["Subject"] = subject
    msg["Authentication-Results"] = f"mx.corp.example; {auth}"
    for name, value in headers.items():
        msg[name.replace("_", "-")] = value
    msg.set_content(body)
    if html:
        msg.add_alternative(html, subtype="html")
    return msg


def checks(report):
    return {f.check for f in report.findings}


def test_clean_message_scores_zero():
    report = analyze(make())
    assert report.score == 0
    assert report.verdict == "no strong indicators"


def test_auth_failures_are_scored():
    report = analyze(make(auth="spf=fail; dkim=fail; dmarc=fail"))
    assert report.auth == {"spf": "fail", "dkim": "fail", "dmarc": "fail"}
    assert report.score == 55


def test_missing_auth_is_low_risk():
    msg = make()
    del msg["Authentication-Results"]
    report = analyze(msg)
    assert 0 < report.score < 30


def test_received_spf_fallback():
    msg = make()
    del msg["Authentication-Results"]
    msg["Received-SPF"] = "softfail (domain does not designate 203.0.113.5 as permitted sender)"
    assert analyze(msg).auth["spf"] == "softfail"


def test_reply_to_mismatch_and_freemail():
    report = analyze(make(Reply_To="ceo@gmail.com"))
    messages = " ".join(f.message for f in report.findings)
    assert "Reply-To goes to gmail.com" in messages
    assert "free webmail" in messages


def test_display_name_brand_spoof():
    report = analyze(make(from_="Microsoft Account Team <alerts@account-notice.example>"))
    assert any("claims to be Microsoft" in f.message for f in report.findings)


def test_display_name_embedded_address():
    report = analyze(make(from_='"support@paypal.com" <x@evil.example>'))
    assert any("Display name shows the address" in f.message for f in report.findings)


def test_link_text_mismatch_and_ip_link():
    html = ('<a href="http://203.0.113.9/login">https://www.chase.com/login</a>'
            '<a href="https://bit.ly/abc">track</a>')
    report = analyze(make(html=html))
    messages = " ".join(f.message for f in report.findings)
    assert "Link text shows chase.com but actually goes to 203.0.113.9" in messages
    assert "raw IP address" in messages
    assert "URL shortener" in messages
    # the visible anchor text is not an IOC; the real destination is
    assert "https://www.chase.com/login" not in report.iocs()["urls"]
    assert "http://203.0.113.9/login" in report.iocs()["urls"]


def test_at_sign_url_trick():
    report = analyze(make(body="Go to https://www.paypal.com@evil.example/login now"))
    assert any("behind an @ sign" in f.message for f in report.findings)


def test_attachments_are_hashed_and_rated():
    msg = make()
    msg.add_attachment(b"MZ fake", maintype="application", subtype="octet-stream", filename="invoice.pdf.exe")
    msg.add_attachment(b"doc", maintype="application", subtype="octet-stream", filename="report.docm")
    report = analyze(msg)
    assert len(report.attachments) == 2
    assert all(len(a.sha256) == 64 for a in report.attachments)
    messages = " ".join(f.message for f in report.findings)
    assert "double extension" in messages
    assert "macro-enabled" in messages


def test_bec_pattern():
    report = analyze(make(subject="Quick favour", body="Are you available? I need a wire transfer done today. Keep this confidential."))
    assert "bec" in checks(report)


def test_score_capped_at_100():
    report = analyze_file(SAMPLES / "paypal_credential_phish.eml")
    assert report.score == 100


def test_sample_verdicts():
    verdicts = {p.name: analyze_file(p).verdict for p in SAMPLES.glob("*.eml")}
    assert verdicts == {
        "legit_newsletter.eml": "no strong indicators",
        "paypal_credential_phish.eml": "likely phishing",
        "malware_delivery.eml": "likely phishing",
        "bec_wire_transfer.eml": "likely phishing",
    }


def test_sender_ip_ioc_skips_internal_hops():
    report = analyze_file(SAMPLES / "paypal_credential_phish.eml")
    assert report.iocs()["sender_ips"] == ["203.0.113.66"]
