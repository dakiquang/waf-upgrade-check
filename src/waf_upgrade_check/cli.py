"""Command-line entry point."""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from collections.abc import Iterable, Sequence
from typing import Any, TextIO

from botocore.exceptions import BotoCoreError, ClientError

from . import __version__, aws
from .bundle import BundleError, load_bundle
from .check import (
    LEVELS,
    Finding,
    ManagedRef,
    RuleGroupCatalog,
    TargetError,
    check_web_acl,
    managed_references,
    resolve_versions,
    rule_group_references,
)
from .collect import build_script
from .diff import VersionDiff, diff_versions
from .model import RuleGroupVersion

PROG = "waf-upgrade-check"


class UsageError(Exception):
    """A combination of options that argparse cannot reject on its own."""


def _scope_options() -> argparse.ArgumentParser:
    scope = argparse.ArgumentParser(add_help=False)
    scope.add_argument(
        "--scope",
        choices=["REGIONAL", "CLOUDFRONT"],
        default="REGIONAL",
        help="rule group scope (default: REGIONAL; CLOUDFRONT always uses us-east-1)",
    )
    scope.add_argument("--region", default=None, help="AWS region for REGIONAL scope")
    return scope


def _common_options(scope: argparse.ArgumentParser) -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False, parents=[scope])
    common.add_argument("--profile", default=None, help="AWS named profile")
    common.add_argument(
        "--format", choices=["text", "json"], default="text", help="output format (default: text)"
    )
    return common


def _web_acl_source(parser: argparse.ArgumentParser) -> argparse._MutuallyExclusiveGroup:
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--web-acl-file", metavar="PATH", help="web ACL JSON as returned by get-web-acl"
    )
    source.add_argument("--web-acl", metavar="NAME", help="name of the web ACL to fetch")
    parser.add_argument("--id", metavar="ID", help="web ACL ID (required with --web-acl)")
    return source


def _target_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--target",
        default="default",
        metavar="default|latest|VERSION",
        help=(
            "version to check against: the current default, the newest by "
            "LastUpdateTimestamp, or a version name (default: default)"
        ),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Check what breaks before you upgrade an AWS WAF managed rule group version.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    scope = _scope_options()
    common = _common_options(scope)
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

    check_cmd = subparsers.add_parser(
        "check",
        parents=[common],
        help="check a web ACL's AWS managed rule groups against a target version",
        description=(
            "Check every AWS managed rule group in a web ACL against a target version. "
            "Exit code 1 when at least one finding is an error."
        ),
    )
    source = _web_acl_source(check_cmd)
    source.add_argument(
        "--bundle",
        metavar="FILE",
        help="bundle JSON from collect-script; checks offline and ignores --scope, --region "
        "and --profile",
    )
    _target_option(check_cmd)
    check_cmd.set_defaults(handler=_cmd_check)

    collect = subparsers.add_parser(
        "collect-script",
        parents=[scope],
        help="print a read-only AWS MCP run_script snippet that collects a bundle for check",
        description=(
            "Print a read-only Python snippet for the AWS MCP Server run_script tool. It returns "
            "a bundle with the web ACL and the rule group versions that check --bundle needs "
            "for the same --target."
        ),
    )
    _web_acl_source(collect)
    _target_option(collect)
    collect.set_defaults(handler=_cmd_collect_script)
    return parser


def _region(args: argparse.Namespace) -> str | None:
    if args.scope != "CLOUDFRONT":
        return args.region
    if args.region not in (None, aws.CLOUDFRONT_REGION):
        raise UsageError(
            f"--scope CLOUDFRONT requires region {aws.CLOUDFRONT_REGION}, got {args.region}"
        )
    return aws.CLOUDFRONT_REGION


def _client(args: argparse.Namespace):
    return aws.make_client(args.scope, _region(args), args.profile)


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


def _read_web_acl(path: str) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        raise UsageError(f"cannot read web ACL file {path}: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("WebACL"), dict):
        raise UsageError(f"web ACL file {path} has no WebACL object")
    return data


def _check_id(args: argparse.Namespace) -> None:
    if args.web_acl is not None and args.id is None:
        raise UsageError("--web-acl requires --id")
    if args.web_acl_file is not None and args.id is not None:
        raise UsageError("--id cannot be used with --web-acl-file")


def _needed_versions(
    refs: list[ManagedRef],
    listed: dict[str, tuple[str | None, Sequence[tuple[str, Any]]]],
    target: str,
) -> dict[tuple[str, str], None]:
    """Return the ``(group, version)`` pairs to describe, in order: in use and target."""
    needed: dict[tuple[str, str], None] = {}
    for ref in refs:
        default, available = listed[ref.group]
        try:
            versions = resolve_versions(ref.group, ref.pinned, default, available, target)
        except TargetError as exc:
            raise UsageError(str(exc)) from exc
        for version in versions:
            if version is not None:
                needed[(ref.group, version)] = None
    return needed


def _api_inputs(
    args: argparse.Namespace,
) -> tuple[dict[str, Any], dict[str, RuleGroupCatalog], dict[str, dict[str, Any]]]:
    web_acl = _read_web_acl(args.web_acl_file) if args.web_acl_file is not None else None
    client = _client(args)
    if web_acl is None:
        web_acl = aws.get_web_acl(client, args.web_acl, args.id, args.scope)

    # A rule group that cannot be read is reported as not checked; it does not fail the run.
    referenced: dict[str, dict[str, Any]] = {}
    tried: set[str] = set()
    for reference in rule_group_references(web_acl):
        if reference.arn in tried:
            continue
        tried.add(reference.arn)
        try:
            referenced[reference.arn] = aws.get_rule_group(client, reference.arn)["RuleGroup"]
        except ClientError:
            continue

    refs = managed_references(web_acl)
    listed: dict[str, tuple[str | None, Sequence[tuple[str, Any]]]] = {}
    for ref in refs:
        if ref.group not in listed:
            listed[ref.group] = aws.list_version_timestamps(client, ref.group, args.scope)

    described: dict[str, dict[str, RuleGroupVersion]] = {group: {} for group in listed}
    for group, version in _needed_versions(refs, listed, args.target):
        default, available = listed[group]
        if version == default and all(name != default for name, _ in available):
            continue
        try:
            described[group][version] = aws.describe(client, group, args.scope, version)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if version != default or code != "WAFNonexistentItemException":
                raise

    catalogs = {
        group: RuleGroupCatalog(default, tuple(available), described[group])
        for group, (default, available) in listed.items()
    }
    return web_acl, catalogs, referenced


def _bundle_inputs(
    args: argparse.Namespace,
) -> tuple[dict[str, Any], dict[str, RuleGroupCatalog], dict[str, dict[str, Any]]]:
    try:
        bundle = load_bundle(args.bundle)
    except BundleError as exc:
        raise UsageError(str(exc)) from exc
    listed = {group: (c.default, c.available) for group, c in bundle.catalogs.items()}
    for group, version in _needed_versions(managed_references(bundle.web_acl), listed, args.target):
        catalog = bundle.catalogs[group]
        # A default absent from the bundle could not be described: check reports it.
        if version != catalog.default and version not in catalog.versions:
            raise UsageError(
                f"bundle file {args.bundle} has no description of {group} version {version}; "
                f"describe it or run collect-script again with --target {args.target}"
            )
    return bundle.web_acl, bundle.catalogs, bundle.referenced


def _cmd_check(args: argparse.Namespace, out: TextIO) -> int:
    if args.bundle is not None and args.id is not None:
        raise UsageError("--id cannot be used with --bundle")
    _check_id(args)
    if args.bundle is None:
        web_acl, catalogs, referenced = _api_inputs(args)
        findings = check_web_acl(web_acl, catalogs, args.target, referenced)
    else:
        # A bundle is outside data: a shape load_bundle missed must still exit 2, not crash.
        try:
            web_acl, catalogs, referenced = _bundle_inputs(args)
            findings = check_web_acl(web_acl, catalogs, args.target, referenced)
        except (TypeError, AttributeError, KeyError, ValueError) as exc:
            raise UsageError(
                f"bundle file {args.bundle} has data check cannot use: {exc!r}"
            ) from exc
    if args.format == "json":
        payload = [dataclasses.asdict(finding) for finding in findings]
        out.write(json.dumps(payload, indent=2) + "\n")
    else:
        out.write(_format_check_text(findings))
    return 1 if any(finding.level == "error" for finding in findings) else 0


def _cmd_collect_script(args: argparse.Namespace, out: TextIO) -> int:
    _check_id(args)
    region = _region(args)
    if region is None:
        raise UsageError("collect-script --scope REGIONAL requires --region")
    if args.web_acl_file is not None:
        web_acl = _read_web_acl(args.web_acl_file)
        out.write(build_script(args.scope, region, args.target, web_acl=web_acl))
    else:
        out.write(
            build_script(
                args.scope, region, args.target, web_acl_name=args.web_acl, web_acl_id=args.id
            )
        )
    return 0


def _format_versions_text(default: str | None, names: list[str]) -> str:
    lines = [f"{name} (default)" if name == default else name for name in names]
    lines.append(f"Default version: {default or 'none'}")
    return "\n".join(lines) + "\n"


def _format_check_text(findings: list[Finding]) -> str:
    lines = [
        f"{finding.level.upper()}  {finding.rule_group}  {finding.code}  {finding.message}"
        for finding in findings
    ]
    counts = {level: sum(finding.level == level for finding in findings) for level in LEVELS}
    lines.append(
        f"Summary: {counts['error']} error(s), {counts['warning']} warning(s), "
        f"{counts['info']} info"
    )
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
        status = args.handler(args, sys.stdout)
    except (UsageError, BotoCoreError, ClientError) as exc:
        print(f"{PROG}: error: {exc}", file=sys.stderr)
        return 2
    return status or 0


if __name__ == "__main__":
    sys.exit(main())
