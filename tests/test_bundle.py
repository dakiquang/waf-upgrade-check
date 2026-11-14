import copy
import datetime
import json

import pytest

from waf_upgrade_check.bundle import FORMAT, BundleError, load_bundle
from waf_upgrade_check.check import RuleGroupCatalog
from waf_upgrade_check.cli import main
from waf_upgrade_check.model import RuleGroupVersion

GROUP = "AWSManagedRulesCommonRuleSet"


def _iso(stamp):
    return datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).isoformat()


@pytest.fixture
def bundle(load_fixture):
    """A bundle as collect-script returns it: AWS MCP gives timestamps as ISO strings."""
    versions = [
        {"Name": entry["Name"], "LastUpdateTimestamp": _iso(entry["LastUpdateTimestamp"])}
        for page in ("list_versions_page1.json", "list_versions_page2.json")
        for entry in load_fixture(page)["Versions"]
    ]
    return {
        "format": FORMAT,
        "scope": "REGIONAL",
        "web_acl": load_fixture("web_acl_upgrade.json"),
        "rule_groups": {
            GROUP: {
                "list_versions": {"CurrentDefaultVersion": "Version_1.1", "Versions": versions},
                "versions": {
                    "Version_1.0": load_fixture("describe_v1_0.json"),
                    "Version_1.1": load_fixture("describe_v1_1.json"),
                },
            }
        },
        "caller": {"account": "123456789012"},
    }


def _write(tmp_path, data):
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(data))
    return str(path)


def test_load_bundle_builds_catalogs(bundle, load_fixture, tmp_path):
    expected = RuleGroupCatalog(
        "Version_1.1",
        (
            ("Version_1.10", "2026-01-01T00:00:00+00:00"),
            ("Version_1.1", "2025-10-01T00:00:00+00:00"),
            ("Version_1.0", "2025-07-01T00:00:00+00:00"),
        ),
        {
            "Version_1.0": RuleGroupVersion.from_response(load_fixture("describe_v1_0.json")),
            "Version_1.1": RuleGroupVersion.from_response(load_fixture("describe_v1_1.json")),
        },
    )

    loaded = load_bundle(_write(tmp_path, bundle))

    assert loaded.web_acl == load_fixture("web_acl_upgrade.json")
    assert loaded.catalogs == {GROUP: expected}


def _versions(data):
    return data["rule_groups"][GROUP]["versions"]


def _managed(data):
    return data["web_acl"]["WebACL"]["Rules"][0]["Statement"]["ManagedRuleGroupStatement"]


MUTATIONS = [
    ("wrong format", lambda d: d.update(format="other/v9"), "has format other/v9; expected"),
    ("format missing", lambda d: d.pop("format"), "is missing format"),
    ("bad scope", lambda d: d.update(scope="GLOBAL"), "has scope GLOBAL; expected"),
    ("no WebACL", lambda d: d["web_acl"].pop("WebACL"), "is missing web_acl.WebACL"),
    (
        "Rules null",
        lambda d: d["web_acl"]["WebACL"].update(Rules=None),
        "has web_acl.WebACL.Rules that is not a list",
    ),
    (
        "rule not an object",
        lambda d: d["web_acl"]["WebACL"]["Rules"].insert(0, "AWS-CRS"),
        "has web_acl.WebACL.Rules[0] that is not an object",
    ),
    (
        "override without Name",
        lambda d: _managed(d)["RuleActionOverrides"][0].pop("Name"),
        "has web_acl.WebACL.Rules[0].Statement.ManagedRuleGroupStatement.RuleActionOverrides[0]"
        " without Name",
    ),
    ("no rule_groups", lambda d: d.pop("rule_groups"), "is missing rule_groups"),
    (
        "no Versions",
        lambda d: d["rule_groups"][GROUP]["list_versions"].pop("Versions"),
        f"is missing rule_groups.{GROUP}.list_versions.Versions",
    ),
    (
        "no versions",
        lambda d: d["rule_groups"][GROUP].pop("versions"),
        f"is missing rule_groups.{GROUP}.versions",
    ),
    (
        "describe without Capacity",
        lambda d: _versions(d)["Version_1.1"].pop("Capacity"),
        f"has rule_groups.{GROUP}.versions.Version_1.1 without 'Capacity'",
    ),
    (
        "VersionName mismatch",
        lambda d: _versions(d)["Version_1.1"].update(VersionName="Version_1.10"),
        f"has rule_groups.{GROUP}.versions.Version_1.1 with VersionName Version_1.10",
    ),
    (
        "referenced group missing",
        lambda d: d.update(rule_groups={}),
        f"has no rule_groups entry for {GROUP}; run collect-script again",
    ),
    ("caller not an object", lambda d: d.update(caller="123"), "has caller that is not an object"),
]


@pytest.mark.parametrize(
    ("mutate", "fragment"), [m[1:] for m in MUTATIONS], ids=[m[0] for m in MUTATIONS]
)
def test_load_bundle_rejects_invalid_bundles(bundle, tmp_path, mutate, fragment):
    data = copy.deepcopy(bundle)
    mutate(data)
    path = _write(tmp_path, data)

    with pytest.raises(BundleError) as error:
        load_bundle(path)

    assert str(error.value).startswith(f"bundle file {path} ")
    assert fragment in str(error.value)


def test_load_bundle_unreadable_file(tmp_path):
    path = tmp_path / "bundle.json"
    path.write_text("not json")

    with pytest.raises(BundleError, match=f"^cannot read bundle file {path}: "):
        load_bundle(str(path))


def test_check_bundle_missing_in_use_version_exits_2(no_client, bundle, tmp_path, capsys):
    del _versions(bundle)["Version_1.0"]
    path = _write(tmp_path, bundle)

    assert main(["check", "--bundle", path]) == 2

    assert capsys.readouterr().err == (
        f"waf-upgrade-check: error: bundle file {path} has no description of {GROUP} version "
        "Version_1.0; describe it or run collect-script again with --target default\n"
    )


def test_check_bundle_invalid_exits_2(no_client, bundle, tmp_path, capsys):
    bundle["format"] = "other/v9"
    path = _write(tmp_path, bundle)

    assert main(["check", "--bundle", path]) == 2

    assert capsys.readouterr().err == (
        f"waf-upgrade-check: error: bundle file {path} has format other/v9; expected {FORMAT}\n"
    )


def test_check_bundle_malformed_rules_exits_2(no_client, bundle, tmp_path, capsys):
    bundle["web_acl"]["WebACL"]["Rules"] = None
    path = _write(tmp_path, bundle)

    assert main(["check", "--bundle", path]) == 2

    assert capsys.readouterr().err == (
        f"waf-upgrade-check: error: bundle file {path} has web_acl.WebACL.Rules "
        "that is not a list\n"
    )


def test_check_bundle_string_capacity_exits_2(no_client, bundle, tmp_path, capsys):
    bundle["rule_groups"][GROUP]["versions"]["Version_1.1"]["Capacity"] = "700"
    path = _write(tmp_path, bundle)

    assert main(["check", "--bundle", path]) == 2

    assert capsys.readouterr().err == (
        f"waf-upgrade-check: error: bundle file {path} has "
        f"rule_groups.{GROUP}.versions.Version_1.1.Capacity that is not an integer\n"
    )


def test_check_bundle_null_nested_statement_exits_2(no_client, bundle, tmp_path, capsys):
    rule = bundle["web_acl"]["WebACL"]["Rules"][-1]
    rule["Statement"] = {"AndStatement": {"Statements": [rule["Statement"], None]}}
    index = len(bundle["web_acl"]["WebACL"]["Rules"]) - 1
    path = _write(tmp_path, bundle)

    assert main(["check", "--bundle", path]) == 2

    assert capsys.readouterr().err == (
        f"waf-upgrade-check: error: bundle file {path} has web_acl.WebACL.Rules[{index}]"
        ".Statement.AndStatement.Statements[1] that is not an object\n"
    )


def test_check_bundle_numeric_label_name_exits_2(no_client, bundle, tmp_path, capsys):
    bundle["rule_groups"][GROUP]["versions"]["Version_1.1"]["AvailableLabels"].append({"Name": 7})
    path = _write(tmp_path, bundle)

    assert main(["check", "--bundle", path]) == 2

    assert capsys.readouterr().err == (
        f"waf-upgrade-check: error: bundle file {path} has "
        f"rule_groups.{GROUP}.versions.Version_1.1.AvailableLabels "
        "with a Name that is not a string\n"
    )


def test_check_bundle_empty_label_match_exits_2(no_client, bundle, tmp_path, capsys):
    bundle["web_acl"]["WebACL"]["Rules"][0]["Statement"] = {"LabelMatchStatement": {}}
    path = _write(tmp_path, bundle)

    assert main(["check", "--bundle", path]) == 2

    assert capsys.readouterr().err == (
        f"waf-upgrade-check: error: bundle file {path} has web_acl.WebACL.Rules[0]"
        ".Statement.LabelMatchStatement.Scope that is not a string\n"
    )


def test_check_bundle_null_listed_name_exits_2(no_client, bundle, tmp_path, capsys):
    bundle["rule_groups"][GROUP]["list_versions"]["Versions"][0]["Name"] = None
    path = _write(tmp_path, bundle)

    assert main(["check", "--bundle", path, "--target", "Version_9.9"]) == 2

    assert capsys.readouterr().err == (
        f"waf-upgrade-check: error: bundle file {path} has "
        f"rule_groups.{GROUP}.list_versions.Versions[0].Name that is not a string\n"
    )


def test_check_bundle_unexpected_shape_exits_2(no_client, bundle, tmp_path, capsys, monkeypatch):
    def broken(*args):
        raise TypeError("unexpected value")

    monkeypatch.setattr("waf_upgrade_check.cli.check_web_acl", broken)
    path = _write(tmp_path, bundle)

    assert main(["check", "--bundle", path]) == 2

    assert capsys.readouterr().err == (
        f"waf-upgrade-check: error: bundle file {path} has data check cannot use: "
        "TypeError('unexpected value')\n"
    )


def test_check_bundle_string_priority_exits_2(no_client, bundle, tmp_path, capsys):
    bundle["web_acl"]["WebACL"]["Rules"][0]["Priority"] = "1"
    path = _write(tmp_path, bundle)

    assert main(["check", "--bundle", path]) == 2

    assert capsys.readouterr().err == (
        f"waf-upgrade-check: error: bundle file {path} has web_acl.WebACL.Rules[0]"
        ".Priority that is not an integer\n"
    )


def test_check_bundle_missing_listed_default_warns(
    no_client, bundle, load_fixture, tmp_path, capsys
):
    bundle["web_acl"] = load_fixture("web_acl_clean.json")
    del _versions(bundle)["Version_1.1"]
    # --bundle ignores --scope, --region and --profile, even a combination API mode rejects.
    options = ["--scope", "CLOUDFRONT", "--region", "eu-west-1", "--profile", "unused"]

    assert main(["check", "--bundle", _write(tmp_path, bundle), *options]) == 0

    assert capsys.readouterr().out.splitlines() == [
        f"WARNING  {GROUP}  default-not-describable  default version Version_1.1 "
        "cannot be described; comparisons that need it are skipped",
        "Summary: 0 error(s), 1 warning(s), 0 info",
    ]
