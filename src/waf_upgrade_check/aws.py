"""Thin wrapper over the read-only WAFV2 managed rule group APIs."""

from __future__ import annotations

from typing import Any

import boto3

from .model import RuleGroupVersion

CLOUDFRONT_REGION = "us-east-1"


def make_client(scope: str, region: str | None, profile: str | None) -> Any:
    """Create a wafv2 client; CLOUDFRONT scope always uses us-east-1."""
    session = boto3.session.Session(profile_name=profile)
    return session.client(
        "wafv2", region_name=CLOUDFRONT_REGION if scope == "CLOUDFRONT" else region
    )


def list_versions(
    client: Any, name: str, scope: str, vendor: str = "AWS"
) -> tuple[str | None, list[str]]:
    """Return ``(current default version, version names in API order)`` across all pages."""
    params: dict[str, Any] = {"VendorName": vendor, "Name": name, "Scope": scope}
    default: str | None = None
    names: list[str] = []
    while True:
        resp = client.list_available_managed_rule_group_versions(**params)
        default = resp.get("CurrentDefaultVersion") or default
        names.extend(version["Name"] for version in resp.get("Versions", []))
        marker = resp.get("NextMarker")
        if not marker:
            return default, names
        params["NextMarker"] = marker


def describe(
    client: Any, name: str, scope: str, version: str, vendor: str = "AWS"
) -> RuleGroupVersion:
    resp = client.describe_managed_rule_group(
        VendorName=vendor, Name=name, Scope=scope, VersionName=version
    )
    return RuleGroupVersion.from_response(resp)
