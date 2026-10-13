"""Command-line interface: ``baitcheck suspicious.eml``."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__, output
from .analyzer import analyze_file
from .virustotal import lookup


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="baitcheck",
        description="Analyze .eml files for phishing indicators and extract IOCs.",
    )
    p.add_argument("paths", nargs="+", type=Path, help=".eml files or directories containing them")
    p.add_argument("--json", type=Path, metavar="FILE", help="write the full analysis as JSON")
    p.add_argument("--markdown", type=Path, metavar="DIR", help="write one Markdown triage note per email into DIR")
    p.add_argument("--vt", action="store_true", help="enrich hashes and domains with VirusTotal (needs VT_API_KEY)")
    p.add_argument("--fail-score", type=int, metavar="N", help="exit with code 2 if any email scores N or higher")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _expand(paths: list[Path]) -> list[Path]:
    files = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(path.glob("*.eml")))
        elif path.is_file():
            files.append(path)
        else:
            raise FileNotFoundError(path)
    return files


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        files = _expand(args.paths)
    except FileNotFoundError as exc:
        parser.error(f"not found: {exc}")
    if not files:
        parser.error("no .eml files found")

    api_key = os.environ.get("VT_API_KEY")
    if args.vt and not api_key:
        parser.error("--vt needs the VT_API_KEY environment variable")

    color = not args.no_color and sys.stdout.isatty()
    results, worst = [], 0
    for i, path in enumerate(files):
        report = analyze_file(path)
        vt = lookup(report.iocs(), api_key) if args.vt else None
        worst = max(worst, report.score)
        if i:
            print("\n" + "=" * 72 + "\n")
        print(output.to_console(report, vt, color=color))
        results.append(output.to_dict(report, vt))
        if args.markdown:
            args.markdown.mkdir(parents=True, exist_ok=True)
            (args.markdown / f"{path.stem}.md").write_text(output.to_markdown(report, vt), encoding="utf-8")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(output.to_json(results), encoding="utf-8")
        print(f"\nJSON written to {args.json}")
    if args.markdown:
        print(f"Markdown triage notes written to {args.markdown}/")

    if args.fail_score is not None and worst >= args.fail_score:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
