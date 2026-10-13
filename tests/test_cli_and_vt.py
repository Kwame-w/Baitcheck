import io
import json
import urllib.error
from pathlib import Path

import pytest

from baitcheck.cli import main
from baitcheck.virustotal import lookup

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def test_cli_directory_json_and_markdown(tmp_path, capsys):
    out_json, md_dir = tmp_path / "out.json", tmp_path / "notes"
    code = main([str(SAMPLES), "--json", str(out_json), "--markdown", str(md_dir), "--no-color"])
    assert code == 0
    data = json.loads(out_json.read_text())
    assert len(data) == 4
    assert {d["verdict"] for d in data} == {"likely phishing", "no strong indicators"}
    note = (md_dir / "paypal_credential_phish.md").read_text()
    assert "**Verdict:** likely phishing" in note
    assert "paypa1-security[.]com" in note  # IOCs are defanged in notes
    assert "http://paypa1" not in note


def test_cli_fail_score():
    assert main([str(SAMPLES / "legit_newsletter.eml"), "--fail-score", "60"]) == 0
    assert main([str(SAMPLES / "malware_delivery.eml"), "--fail-score", "60"]) == 2


def test_cli_missing_file():
    with pytest.raises(SystemExit):
        main(["does-not-exist.eml"])


def test_cli_vt_requires_key(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    with pytest.raises(SystemExit):
        main([str(SAMPLES / "legit_newsletter.eml"), "--vt"])


def test_vt_lookup_with_fake_api():
    calls = []

    def fake_fetch(url, key):
        calls.append(url)
        if url.endswith("/unknown.example"):
            raise urllib.error.HTTPError(url, 404, "not found", {}, io.BytesIO())
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 7, "suspicious": 1}}}}

    results = lookup({"attachment_sha256": ["ab" * 32], "domains": ["evil.example", "unknown.example"]},
                     "key", fetch=fake_fetch, delay=0)
    assert [r.kind for r in results] == ["file", "domain", "domain"]
    assert results[0].malicious == 7 and results[0].flagged
    assert results[2].error == "not found in VirusTotal"
    assert calls[0].endswith("/files/" + "ab" * 32)
