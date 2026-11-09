"""Command line interface: apigee-bundle-lint BUNDLE."""

import argparse
import sys

from .checks import CHECK_NAMES, run_checks
from .loader import BundleError, load_bundle
from .report import to_json, to_markdown, to_text

FORMATS = ("text", "json", "markdown")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apigee-bundle-lint",
        description="Lint an Apigee API proxy bundle for common policy "
                    "mistakes.",
    )
    parser.add_argument(
        "bundle",
        metavar="BUNDLE",
        nargs="?",
        help="bundle directory (contains apiproxy/) or the apiproxy "
             "directory itself",
    )
    parser.add_argument(
        "--format",
        choices=FORMATS,
        default="text",
        help="output format: text, json, or markdown (default text)",
    )
    parser.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="CHECK",
        help="check name to skip (repeatable, or comma-separated); "
             f"known checks: {', '.join(CHECK_NAMES)}",
    )
    parser.add_argument(
        "--list-checks",
        action="store_true",
        help="print the check names and exit",
    )
    return parser


def _parse_ignores(raw: list[str]) -> tuple[str, ...]:
    ignored: list[str] = []
    for item in raw:
        ignored.extend(part.strip() for part in item.split(",") if part.strip())
    unknown = [name for name in ignored if name not in CHECK_NAMES]
    if unknown:
        raise ValueError(f"unknown check(s): {', '.join(unknown)}")
    return tuple(ignored)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_checks:
        for name in CHECK_NAMES:
            print(name)
        return 0
    if args.bundle is None:
        build_parser().error("the following arguments are required: BUNDLE")
    try:
        ignored = _parse_ignores(args.ignore)
    except ValueError as exc:
        print(f"apigee-bundle-lint: {exc}", file=sys.stderr)
        return 2
    try:
        bundle = load_bundle(args.bundle)
    except BundleError as exc:
        print(f"apigee-bundle-lint: {exc}", file=sys.stderr)
        return 2
    findings = run_checks(bundle, ignore=ignored)
    if args.format == "json":
        print(to_json(findings), end="")
    elif args.format == "markdown":
        print(to_markdown(findings), end="")
    else:
        print(to_text(findings), end="")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
