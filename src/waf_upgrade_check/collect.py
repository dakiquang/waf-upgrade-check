"""Generate a read-only AWS MCP ``run_script`` snippet that returns a bundle for ``check``."""

from __future__ import annotations

import pprint
from collections.abc import Mapping
from typing import Any

from .bundle import FORMAT

# The AWS MCP run_script validator rejects dunders, comprehensions and function definitions;
# the body keeps to plain loops and calls. It reads the in-use version of every AWS managed
# rule group in ``web_acl`` and the version that ``check --target TARGET`` resolves.
_BODY = """\
identity = await call_boto3(service_name="sts", operation_name="GetCallerIdentity",
                            region_name=REGION, params={})
uses = {}
for rule in web_acl["WebACL"].get("Rules", []):
    statement = rule.get("Statement", {}).get("ManagedRuleGroupStatement")
    if not statement or statement.get("VendorName") != "AWS":
        continue
    group = statement.get("Name")
    if group not in uses:
        uses[group] = []
    uses[group].append(statement.get("Version"))
rule_groups = {}
for group in uses:
    params = {"VendorName": "AWS", "Name": group, "Scope": SCOPE}
    default = None
    entries = []
    markers = []
    while True:
        page = await call_boto3(service_name="wafv2",
                                operation_name="ListAvailableManagedRuleGroupVersions",
                                region_name=REGION, params=params)
        if page.get("CurrentDefaultVersion"):
            default = page.get("CurrentDefaultVersion")
        for entry in page.get("Versions", []):
            entries.append(entry)
        marker = page.get("NextMarker")
        if not marker or marker in markers:
            break
        markers.append(marker)
        params = {"VendorName": "AWS", "Name": group, "Scope": SCOPE, "NextMarker": marker}
    names = []
    latest = None
    latest_stamp = None
    for entry in entries:
        names.append(entry.get("Name"))
        stamp = entry.get("LastUpdateTimestamp")
        if isinstance(stamp, str):
            try:
                stamp = datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
            except ValueError:
                stamp = None
        elif not isinstance(stamp, (int, float)):
            stamp = None
        if stamp is not None and (latest_stamp is None or stamp > latest_stamp):
            latest = entry.get("Name")
            latest_stamp = stamp
    if TARGET == "default":
        target_name = default
    elif TARGET == "latest":
        target_name = latest
    elif TARGET in names:
        target_name = TARGET
    else:
        target_name = None
    wanted = []
    for pinned in uses[group]:
        if pinned is None:
            in_use = default
        elif pinned in names:
            in_use = pinned
        else:
            in_use = None
        if in_use is not None and in_use not in wanted:
            wanted.append(in_use)
        if target_name is not None and target_name not in wanted:
            wanted.append(target_name)
    described = {}
    for version_name in wanted:
        if version_name == default and default not in names:
            continue
        try:
            described[version_name] = await call_boto3(service_name="wafv2",
                operation_name="DescribeManagedRuleGroup", region_name=REGION,
                params={"VendorName": "AWS", "Name": group, "Scope": SCOPE,
                        "VersionName": version_name})
        except Exception as error:
            if version_name != default or "WAFNonexistentItemException" not in str(error):
                raise
    rule_groups[group] = {"list_versions": {"CurrentDefaultVersion": default,
                                            "Versions": entries},
                          "versions": described}
result = {"format": FORMAT, "scope": SCOPE, "web_acl": web_acl,
          "rule_groups": rule_groups, "caller": {"account": identity.get("Account")}}
result
"""


def build_script(
    scope: str,
    region: str,
    target: str,
    *,
    web_acl: Mapping[str, Any] | None = None,
    web_acl_name: str | None = None,
    web_acl_id: str | None = None,
) -> str:
    """Return the snippet; pass either ``web_acl`` or both ``web_acl_name`` and ``web_acl_id``."""
    if (web_acl is None) == (web_acl_name is None or web_acl_id is None):
        raise ValueError("pass either web_acl or both web_acl_name and web_acl_id")
    lines = [
        "# waf-upgrade-check collect-script: read-only (Get, List and Describe calls only).",
        "# Paste it unchanged into the AWS MCP Server run_script tool and save return_value",
        "# as JSON for: waf-upgrade-check check --bundle FILE",
        "import datetime",
        f"FORMAT = {FORMAT!r}",
        f"SCOPE = {scope!r}",
        f"REGION = {region!r}",
        f"TARGET = {target!r}",
    ]
    if web_acl is not None:
        lines.append(f"web_acl = {pprint.pformat(web_acl, sort_dicts=False)}")
    else:
        lines += [
            'web_acl = await call_boto3(service_name="wafv2", operation_name="GetWebACL",',
            "                           region_name=REGION,",
            f'                           params={{"Name": {web_acl_name!r}, "Scope": SCOPE,',
            f'                                   "Id": {web_acl_id!r}}})',
        ]
    return "\n".join(lines) + "\n" + _BODY
