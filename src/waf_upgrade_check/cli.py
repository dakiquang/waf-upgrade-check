"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable
from typing import TextIO

from botocore.exceptions import BotoCoreError, ClientError

from . import __version__, aws
from .diff import VersionDiff, diff_versions

PROG = "waf-upgrade-check"


class UsageError(Exception):
    """A combination of options that argparse cannot reject on its own."""


def _common_options() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--scope",
        choices=["REGIONAL", "CLOUDFRONT"],
        default="REGIONAL",
        help="rule group scope (default: REGIONAL; CLOUDFRONT always uses us-east-1)",
    )
    common.add_argument("--region", default=None, help="AWS region for REGIONAL scope")
    common.add_argument("--profile", default=None, help="AWS named profile")
    common.add_argument(
        "--format", choices=["text", "json"], default="text", help="output format (default: text)"
    )
    return common


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Check what breaks before you upgrade an AWS WAF managed rule group version.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    common = _common_options()
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    versions = subparsers.add_parser(
        "versions",
        parents=[common],
        help="list available versions of a managed rule group",
        description="List available versions of an AWS managed rule group.",
    )
    versions.add_argument("rule_group", help="managed rule group name")
    versions.set_defaults(handler=_cmd_versions)

    diff = subparsers.add_parser(
        "diff",
        parents=[common],
        help="compare two versions of a managed rule group",
        description="Compare two versions of an AWS managed rule group.",
    )
    diff.add_argument("rule_group", help="managed rule group name")
    diff.add_argument("from_version", metavar="from", help="current version")
    diff.add_argument("to_version", metavar="to", help="target version")
    diff.set_defaults(handler=_cmd_diff)
    return parser


def _client(args: argparse.Namespace):
    if args.scope == "CLOUDFRONT" and args.region not in (None, aws.CLOUDFRONT_REGION):
        raise UsageError(
            f"--scope CLOUDFRONT requires region {aws.CLOUDFRONT_REGION}, got {args.region}"
        )
    return aws.make_client(args.scope, args.region, args.profile)


def _cmd_versions(args: argparse.Namespace, out: TextIO) -> None:
    client = _client(args)
    default, names = aws.list_versions(client, args.rule_group, args.scope)
    if args.format == "json":
        payload = {
            "rule_group": args.rule_group,
            "scope": args.scope,
            "default_version": default,
            "versions": names,
        }
        out.write(json.dumps(payload, indent=2) + "\n")
    else:
        out.write(_format_versions_text(default, names))


def _cmd_diff(args: argparse.Namespace, out: TextIO) -> None:
    client = _client(args)
    old = aws.describe(client, args.rule_group, args.scope, args.from_version)
    new = aws.describe(client, args.rule_group, args.scope, args.to_version)
    result = diff_versions(old, new)
    if args.format == "json":
        out.write(json.dumps(_diff_payload(args, result), indent=2) + "\n")
    else:
        out.write(_format_diff_text(args, result))


def _format_versions_text(default: str | None, names: list[str]) -> str:
    lines = [f"{name} (default)" if name == default else name for name in names]
    lines.append(f"Default version: {default or 'none'}")
    return "\n".join(lines) + "\n"


def _section(title: str, items: Iterable[str]) -> list[str]:
    entries = [f"  {item}" for item in items]
    return [f"{title} ({len(entries)}):", *(entries or ["  none"])]


def _format_diff_text(args: argparse.Namespace, result: VersionDiff) -> str:
    delta = result.capacity_new - result.capacity_old
    lines = [
        f"{args.rule_group} {args.from_version} -> {args.to_version} ({args.scope})",
        f"Capacity: {result.capacity_old} -> {result.capacity_new} ({delta:+d})",
    ]
    lines += _section("Rules added", result.rules_added)
    lines += _section("Rules removed", result.rules_removed)
    lines += _section(
        "Action changed",
        (
            f"{change.name}: {change.old or 'none'} -> {change.new or 'none'}"
            for change in result.actions_changed
        ),
    )
    lines += _section("Available labels added", result.available_labels_added)
    lines += _section("Available labels removed", result.available_labels_removed)
    lines += _section("Consumed labels added", result.consumed_labels_added)
    lines += _section("Consumed labels removed", result.consumed_labels_removed)
    return "\n".join(lines) + "\n"


def _diff_payload(args: argparse.Namespace, result: VersionDiff) -> dict:
    return {
        "rule_group": args.rule_group,
        "scope": args.scope,
        "from": args.from_version,
        "to": args.to_version,
        "capacity": {"old": result.capacity_old, "new": result.capacity_new},
        "rules": {
            "added": list(result.rules_added),
            "removed": list(result.rules_removed),
            "action_changed": [
                {"name": change.name, "old": change.old, "new": change.new}
                for change in result.actions_changed
            ],
        },
        "available_labels": {
            "added": list(result.available_labels_added),
            "removed": list(result.available_labels_removed),
        },
        "consumed_labels": {
            "added": list(result.consumed_labels_added),
            "removed": list(result.consumed_labels_removed),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    try:
        args.handler(args, sys.stdout)
    except (UsageError, BotoCoreError, ClientError) as exc:
        print(f"{PROG}: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
