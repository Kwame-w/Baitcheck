"""Build the sample .eml files in samples/.

The phishing samples imitate real-world campaigns but are harmless: links point
nowhere real and the "malicious" attachments are plain text placeholders.

    python scripts/make_samples.py
"""

from __future__ import annotations

import hashlib
from email.message import EmailMessage
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples"


def base(subject, from_, to, auth, received_ip, reply_to=None, return_path=None) -> EmailMessage:
    msg = EmailMessage()
    msg["Return-Path"] = return_path or f"<{from_.split('<')[-1].rstrip('>')}>"
    msg["Received"] = f"from mx.sender.example (mx.sender.example [{received_ip}]) by mx.corp.example with ESMTPS; Mon, 12 Oct 2026 09:14:22 +0000"
    msg["Received"] = "from mx.corp.example ([10.0.0.25]) by mail.corp.example; Mon, 12 Oct 2026 09:14:23 +0000"
    msg["Authentication-Results"] = f"mx.corp.example; {auth}"
    msg["From"] = from_
    msg["To"] = to
    if reply_to:
        msg["Reply-To"] = reply_to
    msg["Subject"] = subject
    msg["Date"] = "Mon, 12 Oct 2026 09:14:20 +0000"
    msg["Message-ID"] = f"<{hashlib.sha256(subject.encode()).hexdigest()[:16]}@sender.example>"
    return msg


def legit_newsletter() -> EmailMessage:
    msg = base(
        "Your October order summary",
        "Acme Outfitters <orders@acme-outfitters.com>",
        "jordan@corp.example",
        "spf=pass smtp.mailfrom=acme-outfitters.com; dkim=pass header.d=acme-outfitters.com; dmarc=pass header.from=acme-outfitters.com",
        "192.0.2.25",
    )
    msg.set_content("Hi Jordan,\n\nThanks for shopping with us. View your order: https://www.acme-outfitters.com/orders/1042\n")
    msg.add_alternative(
        "<p>Hi Jordan,</p><p>Thanks for shopping with us.</p>"
        '<p><a href="https://www.acme-outfitters.com/orders/1042">View your order</a></p>',
        subtype="html",
    )
    return msg


def paypal_credential_phish() -> EmailMessage:
    msg = base(
        "Action required: unusual sign-in activity on your account",
        "PayPal Security <service@paypa1-security.com>",
        "jordan@corp.example",
        "spf=softfail smtp.mailfrom=paypa1-security.com; dkim=none; dmarc=fail header.from=paypa1-security.com",
        "203.0.113.66",
    )
    msg.set_content(
        "We detected unusual sign-in activity. Your account will be suspended within 24 hours "
        "unless you verify your account.\n"
    )
    msg.add_alternative(
        "<p>Dear Customer,</p><p>We detected <b>unusual sign-in</b> activity. Your account will be suspended "
        "within 24 hours unless you verify your account immediately.</p>"
        '<p><a href="http://paypa1-security.com/login/verify?session=8f2a">https://www.paypal.com/signin</a></p>'
        '<p><a href="http://198.51.100.14/assets/track.gif">Unsubscribe</a></p>',
        subtype="html",
    )
    return msg


def malware_delivery() -> EmailMessage:
    msg = base(
        "DHL: Delivery attempt failed - shipping label attached",
        "DHL Express <noreply@dhl-parcel-tracking.top>",
        "jordan@corp.example",
        "spf=fail smtp.mailfrom=dhl-parcel-tracking.top; dkim=fail; dmarc=fail header.from=dhl-parcel-tracking.top",
        "198.51.100.200",
    )
    msg.set_content(
        "We were unable to deliver your parcel. Print the attached shipping label or reschedule here: "
        "https://bit.ly/3xDhLre\n\nFinal notice: the parcel will be returned in 48 hours.\n"
    )
    msg.add_attachment(b"// harmless placeholder for a JavaScript dropper\n", maintype="application",
                       subtype="javascript", filename="DHL_Shipping_Label.pdf.js")
    msg.add_attachment(b"PK placeholder archive", maintype="application", subtype="zip", filename="label_docs.zip")
    return msg


def bec_wire_transfer() -> EmailMessage:
    msg = base(
        "Urgent wire transfer before end of day",
        "Dana Whitfield <dana.whitfield@corp-example.com>",
        "finance@corp.example",
        "spf=pass smtp.mailfrom=corp-example.com; dkim=pass header.d=corp-example.com; dmarc=pass header.from=corp-example.com",
        "192.0.2.77",
        reply_to="Dana Whitfield <dana.whitfield.ceo@protonmail.com>",
    )
    msg.set_content(
        "Hi,\n\nI'm in meetings all day. I need you to process an urgent wire transfer of $48,500 to a new "
        "vendor before 5pm. Keep this confidential for now; I'll explain later. Reply with confirmation "
        "once it's sent.\n\nDana\nSent from my iPhone\n"
    )
    return msg


SAMPLES = {
    "legit_newsletter.eml": legit_newsletter,
    "paypal_credential_phish.eml": paypal_credential_phish,
    "malware_delivery.eml": malware_delivery,
    "bec_wire_transfer.eml": bec_wire_transfer,
}


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for name, build in SAMPLES.items():
        (OUT / name).write_bytes(bytes(build()))
        print(f"wrote samples/{name}")


if __name__ == "__main__":
    main()
