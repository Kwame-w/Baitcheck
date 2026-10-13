import pytest

from baitcheck.domains import defang, is_ip, is_punycode, levenshtein, lookalike_brand, registered_domain


@pytest.mark.parametrize("host,expected", [
    ("login.paypal.com", "paypal.com"),
    ("a.b.example.co.uk", "example.co.uk"),
    ("PayPal.COM.", "paypal.com"),
    ("192.0.2.1", "192.0.2.1"),
])
def test_registered_domain(host, expected):
    assert registered_domain(host) == expected


@pytest.mark.parametrize("domain,brand", [
    ("paypa1.com", "paypal"),            # homoglyph 1 -> l
    ("paypai.com", "paypal"),            # typo
    ("rnicrosoft.com", "microsoft"),     # rn -> m
    ("micros0ft-support.net", "microsoft"),
    ("paypal-secure-login.com", "paypal"),
    ("apple-id-verify.top", "apple"),
    ("arnazon.com", "amazon"),
    ("secure.docusign-review.net", "docusign"),
])
def test_lookalikes_detected(domain, brand):
    assert lookalike_brand(domain) == brand


@pytest.mark.parametrize("domain", [
    "paypal.com", "login.microsoftonline.com", "example.com", "apply.com", "purchase.com",
    "pineapple.com", "googleusercontent.com", "github.com",
])
def test_legitimate_or_unrelated_domains_pass(domain):
    assert lookalike_brand(domain) is None


def test_helpers():
    assert levenshtein("paypal", "paypai") == 1
    assert levenshtein("", "abc") == 3
    assert is_ip("198.51.100.1") and is_ip("2001:db8::1") and not is_ip("example.com")
    assert is_punycode("xn--pypal-4ve.com")
    assert defang("https://evil.com/a") == "hxxps://evil[.]com/a"
