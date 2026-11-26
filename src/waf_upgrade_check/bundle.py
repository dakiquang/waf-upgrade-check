"""Load a bundle: a web ACL and its rule group data collected through AWS MCP ``run_script``."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .check import RuleGroupCatalog, managed_references
from .model import RuleGroupVersion

FORMAT = "waf-upgrade-check/bundle/v1"
SCOPES = ("REGIONAL", "CLOUDFRONT")


class BundleError(ValueError):
    """A bundle file cannot be read or does not match the bundle format."""


@dataclass(frozen=True)
class Bundle:
    web_acl: dict[str, Any]
    catalogs: dict[str, RuleGroupCatalog]
    referenced: dict[str, dict[str, Any]]


def _object(path: str, parent: Mapping[str, Any], key: str, dotted: str) -> dict[str, Any]:
    if key not in parent:
        raise BundleError(f"bundle file {path} is missing {dotted}")
    value = parent[key]
    if not isinstance(value, dict):
        raise BundleError(f"bundle file {path} has {dotted} that is not an object")
    return value


def _check_statement(path: str, statement: Mapping[str, Any], dotted: str) -> None:
    """Check the nested statement shapes that label matching in ``check`` traverses."""
    if "LabelMatchStatement" in statement:
        label = statement["LabelMatchStatement"]
        if not isinstance(label, dict):
            raise BundleError(
                f"bundle file {path} has {dotted}.LabelMatchStatement that is not an object"
            )
        for key in ("Scope", "Key"):
            if not isinstance(label.get(key), str):
                raise BundleError(
                    f"bundle file {path} has {dotted}.LabelMatchStatement.{key} "
                    "that is not a string"
                )
    children = []
    for name in ("AndStatement", "OrStatement"):
        if name not in statement:
            continue
        group = statement[name]
        if not isinstance(group, dict):
            raise BundleError(f"bundle file {path} has {dotted}.{name} that is not an object")
        nested = group.get("Statements", [])
        if not isinstance(nested, list):
            raise BundleError(
                f"bundle file {path} has {dotted}.{name}.Statements that is not a list"
            )
        children += [(child, f"{dotted}.{name}.Statements[{i}]") for i, child in enumerate(nested)]
    for name, key in (
        ("NotStatement", "Statement"),
        ("RateBasedStatement", "ScopeDownStatement"),
        ("ManagedRuleGroupStatement", "ScopeDownStatement"),
    ):
        if name not in statement:
            continue
        parent = statement[name]
        if not isinstance(parent, dict):
            raise BundleError(f"bundle file {path} has {dotted}.{name} that is not an object")
        if parent.get(key):
            children.append((parent[key], f"{dotted}.{name}.{key}"))
    for child, where in children:
        if not isinstance(child, dict):
            raise BundleError(f"bundle file {path} has {where} that is not an object")
        _check_statement(path, child, where)


def _check_rule(path: str, rule: Any, dotted: str) -> dict[str, Any]:
    """Check the shape of one rule that ``check`` traverses; return its statement."""
    if not isinstance(rule, dict):
        raise BundleError(f"bundle file {path} has {dotted} that is not an object")
    if "Name" not in rule:
        raise BundleError(f"bundle file {path} is missing {dotted}.Name")
    priority = rule.get("Priority")
    if priority is not None and (not isinstance(priority, int) or isinstance(priority, bool)):
        raise BundleError(f"bundle file {path} has {dotted}.Priority that is not an integer")
    statement = rule.get("Statement", {})
    if not isinstance(statement, dict):
        raise BundleError(f"bundle file {path} has {dotted}.Statement that is not an object")
    _check_statement(path, statement, f"{dotted}.Statement")
    return statement


def _check_rules(path: str, acl: Mapping[str, Any]) -> None:
    """Check the rule structure that ``managed_references`` and ``check`` traverse."""
    rules = acl.get("Rules", [])
    if not isinstance(rules, list):
        raise BundleError(f"bundle file {path} has web_acl.WebACL.Rules that is not a list")
    for index, rule in enumerate(rules):
        dotted = f"web_acl.WebACL.Rules[{index}]"
        statement = _check_rule(path, rule, dotted)
        if "RuleGroupReferenceStatement" in statement:
            reference = statement["RuleGroupReferenceStatement"]
            if not isinstance(reference, dict) or not isinstance(reference.get("ARN"), str):
                raise BundleError(
                    f"bundle file {path} has {dotted}.Statement.RuleGroupReferenceStatement "
                    "without an ARN string"
                )
        managed = statement.get("ManagedRuleGroupStatement")
        dotted += ".Statement.ManagedRuleGroupStatement"
        if managed is None:
            continue
        if not isinstance(managed, dict):
            raise BundleError(f"bundle file {path} has {dotted} that is not an object")
        if managed.get("VendorName") != "AWS":
            continue
        if not isinstance(managed.get("Name"), str):
            raise BundleError(f"bundle file {path} has {dotted}.Name that is not a string")
        for key in ("RuleActionOverrides", "ExcludedRules"):
            entries = managed.get(key, [])
            if not isinstance(entries, list):
                raise BundleError(f"bundle file {path} has {dotted}.{key} that is not a list")
            for position, entry in enumerate(entries):
                if not isinstance(entry, dict) or "Name" not in entry:
                    raise BundleError(
                        f"bundle file {path} has {dotted}.{key}[{position}] without Name"
                    )


def _referenced(path: str, data: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Return ARN -> ``RuleGroup`` from the optional ``referenced_rule_groups`` key."""
    if "referenced_rule_groups" not in data:
        return {}
    entries = data["referenced_rule_groups"]
    if not isinstance(entries, dict):
        raise BundleError(f"bundle file {path} has referenced_rule_groups that is not an object")
    referenced = {}
    for arn, entry in entries.items():
        prefix = f"referenced_rule_groups.{arn}"
        if not isinstance(entry, dict):
            raise BundleError(f"bundle file {path} has {prefix} that is not an object")
        group = _object(path, entry, "RuleGroup", f"{prefix}.RuleGroup")
        if not isinstance(group.get("Name"), str):
            raise BundleError(
                f"bundle file {path} has {prefix}.RuleGroup.Name that is not a string"
            )
        if "ARN" in group and group["ARN"] != arn:
            raise BundleError(f"bundle file {path} has {prefix} with RuleGroup.ARN {group['ARN']}")
        rules = group.get("Rules", [])
        if not isinstance(rules, list):
            raise BundleError(f"bundle file {path} has {prefix}.RuleGroup.Rules that is not a list")
        for index, rule in enumerate(rules):
            _check_rule(path, rule, f"{prefix}.RuleGroup.Rules[{index}]")
        referenced[arn] = group
    return referenced


def _catalog(path: str, group: str, entry: Any) -> RuleGroupCatalog:
    prefix = f"rule_groups.{group}"
    if not isinstance(entry, dict):
        raise BundleError(f"bundle file {path} has {prefix} that is not an object")
    listing = _object(path, entry, "list_versions", f"{prefix}.list_versions")
    if "Versions" not in listing:
        raise BundleError(f"bundle file {path} is missing {prefix}.list_versions.Versions")
    listed = listing["Versions"]
    if not isinstance(listed, list):
        raise BundleError(
            f"bundle file {path} has {prefix}.list_versions.Versions that is not a list"
        )
    default = listing.get("CurrentDefaultVersion")
    if default is not None and not isinstance(default, str):
        raise BundleError(
            f"bundle file {path} has {prefix}.list_versions.CurrentDefaultVersion "
            "that is not a string"
        )
    available = []
    for index, version in enumerate(listed):
        dotted = f"{prefix}.list_versions.Versions[{index}]"
        if not isinstance(version, dict):
            raise BundleError(f"bundle file {path} has {dotted} that is not an object")
        if "Name" not in version:
            raise BundleError(f"bundle file {path} is missing {dotted}.Name")
        if not isinstance(version["Name"], str):
            raise BundleError(f"bundle file {path} has {dotted}.Name that is not a string")
        available.append((version["Name"], version.get("LastUpdateTimestamp")))

    described = {}
    for name, response in _object(path, entry, "versions", f"{prefix}.versions").items():
        dotted = f"{prefix}.versions.{name}"
        try:
            version = RuleGroupVersion.from_response(response)
        except KeyError as exc:
            raise BundleError(f"bundle file {path} has {dotted} without {exc}") from exc
        except (TypeError, ValueError, AttributeError) as exc:
            raise BundleError(f"bundle file {path} has an invalid {dotted}: {exc}") from exc
        if not isinstance(version.capacity, int) or isinstance(version.capacity, bool):
            raise BundleError(f"bundle file {path} has {dotted}.Capacity that is not an integer")
        for field, names in (
            ("Rules", version.rules),
            ("AvailableLabels", version.available_labels),
            ("ConsumedLabels", version.consumed_labels),
        ):
            if not all(isinstance(item, str) for item in names):
                raise BundleError(
                    f"bundle file {path} has {dotted}.{field} with a Name that is not a string"
                )
        if version.name != name:
            raise BundleError(f"bundle file {path} has {dotted} with VersionName {version.name}")
        described[name] = version
    return RuleGroupCatalog(default, tuple(available), described)


def load_bundle(path: str) -> Bundle:
    """Read and validate a bundle file; raise ``BundleError`` naming the first problem."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        raise BundleError(f"cannot read bundle file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise BundleError(f"bundle file {path} is not a JSON object")
    if "format" not in data:
        raise BundleError(f"bundle file {path} is missing format")
    if data["format"] != FORMAT:
        raise BundleError(f"bundle file {path} has format {data['format']}; expected {FORMAT}")
    if "scope" not in data:
        raise BundleError(f"bundle file {path} is missing scope")
    if data["scope"] not in SCOPES:
        raise BundleError(
            f"bundle file {path} has scope {data['scope']}; expected {' or '.join(SCOPES)}"
        )
    web_acl = _object(path, data, "web_acl", "web_acl")
    _check_rules(path, _object(path, web_acl, "WebACL", "web_acl.WebACL"))
    rule_groups = _object(path, data, "rule_groups", "rule_groups")
    catalogs = {group: _catalog(path, group, entry) for group, entry in rule_groups.items()}
    if "caller" in data and not isinstance(data["caller"], dict):
        raise BundleError(f"bundle file {path} has caller that is not an object")
    for ref in managed_references(web_acl):
        if ref.group not in catalogs:
            raise BundleError(
                f"bundle file {path} has no rule_groups entry for {ref.group}; "
                "run collect-script again"
            )
    return Bundle(web_acl, catalogs, _referenced(path, data))
