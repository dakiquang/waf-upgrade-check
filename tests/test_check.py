import pytest

from waf_upgrade_check.check import (
    RuleGroupCatalog,
    TargetError,
    check_web_acl,
    resolve_versions,
)
from waf_upgrade_check.model import RuleGroupVersion

GROUP = "AWSManagedRulesCommonRuleSet"
NS = "awswaf:managed:aws:core-rule-set:"
AVAILABLE = (
    ("Version_1.10", 1767225600),
    ("Version_1.1", 1759276800),
    ("Version_1.0", 1751328000),
)


@pytest.fixture
def v1_0(load_fixture):
    return RuleGroupVersion.from_response(load_fixture("describe_v1_0.json"))


@pytest.fixture
def v1_1(load_fixture):
    return RuleGroupVersion.from_response(load_fixture("describe_v1_1.json"))


def catalogs(*versions, default="Version_1.1", available=AVAILABLE):
    return {GROUP: RuleGroupCatalog(default, available, {v.name: v for v in versions})}


def managed_rule(version=None, overrides=(), excluded=(), vendor="AWS"):
    statement = {"VendorName": vendor, "Name": GROUP}
    if version is not None:
        statement["Version"] = version
    if overrides:
        statement["RuleActionOverrides"] = [
            {"Name": name, "ActionToUse": {"Count": {}}} for name in overrides
        ]
    if excluded:
        statement["ExcludedRules"] = [{"Name": name} for name in excluded]
    return {"Name": "AWS-CRS", "Statement": {"ManagedRuleGroupStatement": statement}}


def label(key, scope="LABEL"):
    return {"LabelMatchStatement": {"Scope": scope, "Key": key}}


def web_acl(*rules, capacity=None):
    acl = {"Rules": list(rules)}
    if capacity is not None:
        acl["Capacity"] = capacity
    return {"WebACL": acl}


def by_code(findings, code):
    return [finding for finding in findings if finding.code == code]


def version(name, capacity=700, rules=None, labels=()):
    return RuleGroupVersion(
        name=name,
        capacity=capacity,
        rules=rules if rules is not None else {"A": "Block"},
        available_labels=frozenset(labels),
        consumed_labels=frozenset(),
        label_namespace=NS,
    )


# override-missing-rule


@pytest.mark.parametrize(
    ("source", "kwargs"),
    [
        ("RuleActionOverrides", {"overrides": ["LegacyRule_QUERYARGUMENTS"]}),
        ("ExcludedRules", {"excluded": ["LegacyRule_QUERYARGUMENTS"]}),
    ],
)
def test_override_missing_rule_reported_per_source(v1_0, v1_1, source, kwargs):
    acl = web_acl(managed_rule("Version_1.0", **kwargs))

    [finding] = by_code(
        check_web_acl(acl, catalogs(v1_0, v1_1), "default"), "override-missing-rule"
    )

    assert finding.level == "error"
    assert finding.rule_group == GROUP
    assert finding.message == (
        f"{source} entry LegacyRule_QUERYARGUMENTS in rule AWS-CRS is not a rule in Version_1.1"
    )
    assert finding.details == {
        "rule": "AWS-CRS",
        "source": source,
        "override": "LegacyRule_QUERYARGUMENTS",
        "target_version": "Version_1.1",
    }


def test_override_present_in_target_not_reported(v1_0, v1_1):
    acl = web_acl(
        managed_rule(
            "Version_1.0", overrides=["SizeRestrictions_BODY"], excluded=["NoUserAgent_HEADER"]
        )
    )

    assert (
        by_code(check_web_acl(acl, catalogs(v1_0, v1_1), "default"), "override-missing-rule") == []
    )


# label-no-longer-emitted


@pytest.mark.parametrize(
    "statement",
    [
        {
            "AndStatement": {
                "Statements": [
                    {"NotStatement": {"Statement": label(NS + "LegacyRule_QueryArguments")}},
                    {"GeoMatchStatement": {"CountryCodes": ["US"]}},
                ]
            }
        },
        {
            "RateBasedStatement": {
                "Limit": 100,
                "AggregateKeyType": "IP",
                "ScopeDownStatement": label(NS + "LegacyRule_QueryArguments"),
            }
        },
    ],
    ids=["and-not", "rate-based-scope-down"],
)
def test_label_no_longer_emitted_found_in_nested_statements(v1_0, v1_1, statement):
    acl = web_acl(managed_rule("Version_1.0"), {"Name": "UsesLabel", "Statement": statement})

    [finding] = by_code(
        check_web_acl(acl, catalogs(v1_0, v1_1), "default"), "label-no-longer-emitted"
    )

    assert finding.level == "error"
    assert finding.message == (
        f"rule UsesLabel matches LABEL {NS}LegacyRule_QueryArguments, not emitted by Version_1.1"
    )
    assert finding.details == {
        "rule": "UsesLabel",
        "managed_rule": "AWS-CRS",
        "scope": "LABEL",
        "key": NS + "LegacyRule_QueryArguments",
        "in_use_version": "Version_1.0",
        "target_version": "Version_1.1",
    }


def test_label_namespace_no_longer_emitted():
    old = version("Version_1.0", labels=[NS + "legacy:A", NS + "Other"])
    new = version("Version_1.1", labels=[NS + "Other"])
    acl = web_acl(
        managed_rule("Version_1.0"),
        {"Name": "UsesNamespace", "Statement": label(NS + "legacy:", scope="NAMESPACE")},
    )

    [finding] = by_code(
        check_web_acl(acl, catalogs(old, new), "default"), "label-no-longer-emitted"
    )

    assert finding.details["scope"] == "NAMESPACE"
    assert finding.details["key"] == NS + "legacy:"


@pytest.mark.parametrize(
    "statement",
    [label(NS + "NoUserAgent_Header"), label(NS, scope="NAMESPACE")],
    ids=["label-still-emitted", "namespace-still-covered"],
)
def test_label_still_emitted_not_reported(v1_0, v1_1, statement):
    acl = web_acl(managed_rule("Version_1.0"), {"Name": "UsesLabel", "Statement": statement})

    assert (
        by_code(check_web_acl(acl, catalogs(v1_0, v1_1), "default"), "label-no-longer-emitted")
        == []
    )


# version-unavailable


def test_pinned_version_unavailable_skips_in_use_checks(v1_1):
    acl = web_acl(
        managed_rule("Version_0.9", overrides=["LegacyRule_QUERYARGUMENTS"]),
        {"Name": "UsesLabel", "Statement": label(NS + "LegacyRule_QueryArguments")},
        capacity=900,
    )

    findings = check_web_acl(acl, catalogs(v1_1), "default")

    assert [(f.code, f.details) for f in by_code(findings, "version-unavailable")] == [
        (
            "version-unavailable",
            {"rule": "AWS-CRS", "version": "Version_0.9", "default_version": "Version_1.1"},
        )
    ]
    assert by_code(findings, "version-unavailable")[0].message == (
        "pinned version Version_0.9 is not available; default is Version_1.1"
    )
    assert {f.code for f in findings} == {
        "version-unavailable",
        "override-missing-rule",
        "behind-default",
    }


def test_listed_pinned_version_not_unavailable(v1_0, v1_1):
    acl = web_acl(managed_rule("Version_1.0"))

    assert by_code(check_web_acl(acl, catalogs(v1_0, v1_1), "default"), "version-unavailable") == []


# capacity-increase


def test_capacity_increase_includes_web_acl_capacity(v1_0, v1_1):
    acl = web_acl(managed_rule("Version_1.0"), capacity=900)

    [finding] = by_code(check_web_acl(acl, catalogs(v1_0, v1_1), "default"), "capacity-increase")

    assert finding.level == "warning"
    assert finding.message == "capacity 700 -> 750 WCU (+50); web ACL capacity 900"
    assert finding.details == {
        "rule": "AWS-CRS",
        "in_use_version": "Version_1.0",
        "target_version": "Version_1.1",
        "in_use_capacity": 700,
        "target_capacity": 750,
        "web_acl_capacity": 900,
    }


@pytest.mark.parametrize("target_capacity", [700, 650])
def test_capacity_not_increased_not_reported(target_capacity):
    old = version("Version_1.0", capacity=700)
    new = version("Version_1.1", capacity=target_capacity)
    acl = web_acl(managed_rule("Version_1.0"))

    assert by_code(check_web_acl(acl, catalogs(old, new), "default"), "capacity-increase") == []


# behind-default


def test_behind_default_when_pinned_differs(v1_0, v1_1):
    acl = web_acl(managed_rule("Version_1.0"))

    [finding] = by_code(check_web_acl(acl, catalogs(v1_0, v1_1), "default"), "behind-default")

    assert finding.level == "info"
    assert finding.message == "pinned version Version_1.0 differs from default Version_1.1"
    assert finding.details == {
        "rule": "AWS-CRS",
        "version": "Version_1.0",
        "default_version": "Version_1.1",
    }


@pytest.mark.parametrize("pinned", [None, "Version_1.1"])
def test_behind_default_not_reported_when_unpinned_or_on_default(v1_1, pinned):
    acl = web_acl(managed_rule(pinned))

    assert by_code(check_web_acl(acl, catalogs(v1_1), "default"), "behind-default") == []


# rules-changed


def test_rules_changed_counts(v1_0, v1_1):
    acl = web_acl(managed_rule("Version_1.0"))

    [finding] = by_code(check_web_acl(acl, catalogs(v1_0, v1_1), "default"), "rules-changed")

    assert finding.level == "info"
    assert finding.message == ("Version_1.0 -> Version_1.1: 1 added, 1 removed, 1 action changed")
    assert finding.details == {
        "rule": "AWS-CRS",
        "in_use_version": "Version_1.0",
        "target_version": "Version_1.1",
        "added": 1,
        "removed": 1,
        "action_changed": 1,
    }


def test_rules_changed_not_reported_for_same_version(v1_1):
    acl = web_acl(managed_rule("Version_1.1"))

    assert check_web_acl(acl, catalogs(v1_1), "default") == []


# selection and ordering


def test_marketplace_rule_group_ignored():
    acl = web_acl(managed_rule("Version_1.0", overrides=["Missing"], vendor="ExampleVendor"))

    assert check_web_acl(acl, {}, "default") == []


def test_upgrade_fixture_findings_sorted_by_level_group_code(load_fixture, v1_0, v1_1):
    findings = check_web_acl(load_fixture("web_acl_upgrade.json"), catalogs(v1_0, v1_1), "default")

    assert [(f.level, f.code, f.details["rule"]) for f in findings] == [
        ("error", "label-no-longer-emitted", "BlockLegacyLabel"),
        ("error", "override-missing-rule", "AWS-CRS"),
        ("warning", "capacity-increase", "AWS-CRS"),
        ("info", "behind-default", "AWS-CRS"),
        ("info", "rules-changed", "AWS-CRS"),
    ]


# unversioned groups


def test_unversioned_group_needs_no_versions():
    unversioned = {GROUP: RuleGroupCatalog(None, (), {})}

    assert check_web_acl(web_acl(managed_rule()), unversioned, "latest") == []
    findings = check_web_acl(web_acl(managed_rule("Version_1.0")), unversioned, "default")
    assert [(f.code, f.message) for f in findings] == [
        ("version-unavailable", "pinned version Version_1.0 is not available; default is none")
    ]


# resolve_versions


@pytest.mark.parametrize(
    ("pinned", "target", "available", "expected"),
    [
        (None, "default", AVAILABLE, ("Version_1.1", "Version_1.1")),
        ("Version_1.0", "default", AVAILABLE, ("Version_1.0", "Version_1.1")),
        ("Version_1.0", "latest", AVAILABLE, ("Version_1.0", "Version_1.10")),
        (
            "Version_1.0",
            "latest",
            (("Version_1.0", 1751328000), ("Version_1.1", 1759276800), ("Version_2.0", 1800000000)),
            ("Version_1.0", "Version_2.0"),
        ),
        (
            None,
            "latest",
            (("Version_1.0", 1751328000), ("Version_2.0", None), ("Version_1.1", 1759276800)),
            ("Version_1.1", "Version_1.1"),
        ),
        (
            None,
            "latest",
            (("Version_1.0", 1759276800), ("Version_1.1", 1759276800)),
            ("Version_1.1", "Version_1.0"),
        ),
        ("Version_0.9", "Version_1.0", AVAILABLE, (None, "Version_1.0")),
    ],
    ids=[
        "default-unpinned",
        "default-pinned",
        "latest-newest-first",
        "latest-newest-last",
        "latest-skips-missing-timestamp",
        "latest-tie-first-wins",
        "explicit",
    ],
)
def test_resolve_versions(pinned, target, available, expected):
    assert resolve_versions(GROUP, pinned, "Version_1.1", available, target) == expected


def test_resolve_latest_without_any_timestamp_raises():
    with pytest.raises(TargetError, match=GROUP):
        resolve_versions(GROUP, None, "Version_1.1", (("Version_1.1", None),), "latest")


def test_resolve_explicit_missing_target_names_group_and_versions():
    with pytest.raises(TargetError) as error:
        resolve_versions(GROUP, None, "Version_1.1", AVAILABLE, "Version_9.9")

    assert str(error.value) == (
        f"target version Version_9.9 is not available for {GROUP}; "
        "available: Version_1.10, Version_1.1, Version_1.0"
    )


def test_resolve_unversioned_group_has_no_target():
    assert resolve_versions(GROUP, None, None, (), "default") == (None, None)
    assert resolve_versions(GROUP, None, None, (), "latest") == (None, None)
