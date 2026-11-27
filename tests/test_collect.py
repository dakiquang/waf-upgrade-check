import ast
import json
import re
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

from waf_upgrade_check.bundle import load_bundle
from waf_upgrade_check.cli import main

FIXTURES = Path(__file__).parent / "fixtures"
CRS = "AWSManagedRulesCommonRuleSet"
KBI = "AWSManagedRulesKnownBadInputsRuleSet"
WINDOWS = "AWSManagedRulesWindowsRuleSet"
WEB_ACL_ID = "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111"
UPGRADE = str(FIXTURES / "web_acl_upgrade.json")
CLEAN = str(FIXTURES / "web_acl_clean.json")
READ_OPERATIONS = {
    "GetCallerIdentity",
    "ListAvailableManagedRuleGroupVersions",
    "DescribeManagedRuleGroup",
    "GetRuleGroup",
}
ARN = (
    "arn:aws:wafv2:us-east-1:123456789012:regional/rulegroup/example-label-rules/"
    "b2c3d4e5-6789-0abc-def1-EXAMPLE33333"
)


def _snippet(capsys, *argv):
    assert main(["collect-script", *argv]) == 0
    return capsys.readouterr().out


def _described(fake_aws, group):
    return {
        params["VersionName"]
        for _, operation, _, params in fake_aws.calls
        if operation == "DescribeManagedRuleGroup" and params["Name"] == group
    }


@pytest.mark.parametrize(
    ("argv", "operations"),
    [
        (
            ["--web-acl", "example-web-acl", "--id", WEB_ACL_ID],
            READ_OPERATIONS | {"GetWebACL"},
        ),
        (["--web-acl-file", UPGRADE], READ_OPERATIONS),
    ],
)
def test_snippet_only_reads(no_client, capsys, argv, operations):
    snippet = _snippet(capsys, *argv, "--region", "us-east-1")
    tree = compile(
        snippet, "<collect-script>", "exec", ast.PyCF_ONLY_AST | ast.PyCF_ALLOW_TOP_LEVEL_AWAIT
    )

    names = [node.id for node in ast.walk(tree) if isinstance(node, ast.Name)]
    names += [node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)]
    assert not [name for name in names if "__" in name]
    calls = [
        {keyword.arg: keyword.value for keyword in node.keywords}
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "call_boto3"
    ]
    for call in calls:
        assert call["service_name"].value in {"wafv2", "sts"}
        assert re.fullmatch(r"(Get|List|Describe)[A-Za-z]+", call["operation_name"].value)
    assert {call["operation_name"].value for call in calls} == operations


def test_file_mode_bundle(no_client, windows_kbi_web_acl, fake_aws, run_snippet, tmp_path, capsys):
    windows_kbi_web_acl["WebACL"]["Description"] = 'it\'s a "quoted"\nweb ACL'
    path = tmp_path / "web-acl.json"
    path.write_text(json.dumps(windows_kbi_web_acl))

    bundle = run_snippet(
        _snippet(capsys, "--web-acl-file", str(path), "--region", "us-east-1"),
        fake_aws.call_boto3,
    )

    assert bundle["web_acl"] == windows_kbi_web_acl
    operations = [operation for _, operation, _, _ in fake_aws.calls]
    assert "GetWebACL" not in operations
    assert _described(fake_aws, WINDOWS) == set()
    windows_lists = [
        params.get("NextMarker")
        for _, operation, _, params in fake_aws.calls
        if operation == "ListAvailableManagedRuleGroupVersions" and params["Name"] == WINDOWS
    ]
    assert windows_lists == [None, "Version_1.0"]
    assert len(bundle["rule_groups"][KBI]["list_versions"]["Versions"]) == 7
    assert bundle["caller"] == {"account": "123456789012"}
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(bundle))
    assert set(load_bundle(str(bundle_path)).catalogs) == {WINDOWS, KBI}


def test_listing_follows_marker_past_empty_page(
    no_client, fake_aws, run_snippet, load_fixture, capsys
):
    fake_aws.lists[(CRS, None)]["NextMarker"] = "empty-page-marker"
    fake_aws.lists[(CRS, "empty-page-marker")] = {"Versions": [], "NextMarker": "page-2-marker"}
    snippet = _snippet(capsys, "--web-acl-file", UPGRADE, "--region", "us-east-1")

    bundle = run_snippet(snippet, fake_aws.call_boto3)

    expected = [
        entry
        for page in ("list_versions_page1.json", "list_versions_page2.json")
        for entry in load_fixture(page)["Versions"]
    ]
    assert bundle["rule_groups"][CRS]["list_versions"]["Versions"] == expected


@pytest.mark.parametrize(
    ("target", "described"),
    [
        ("default", {"Version_1.0", "Version_1.1"}),
        ("latest", {"Version_1.0", "Version_1.10"}),
        ("Version_1.1", {"Version_1.0", "Version_1.1"}),
        ("Version_9.9", {"Version_1.0"}),
    ],
)
def test_snippet_describes_in_use_and_target(
    no_client, fake_aws, run_snippet, load_fixture, capsys, target, described
):
    newest = load_fixture("describe_v1_1.json")
    newest["VersionName"] = "Version_1.10"
    fake_aws.describes[(CRS, "Version_1.10")] = newest
    argv = ["--web-acl-file", UPGRADE, "--region", "us-east-1", "--target", target]

    run_snippet(_snippet(capsys, *argv), fake_aws.call_boto3)

    assert _described(fake_aws, CRS) == described


def test_nonexistent_default_left_out_and_reported(
    no_client, fake_aws, run_snippet, tmp_path, capsys
):
    fake_aws.errors[(CRS, "Version_1.1")] = fake_aws.client_error("WAFNonexistentItemException")
    snippet = _snippet(capsys, "--web-acl-file", CLEAN, "--region", "us-east-1")

    bundle = run_snippet(snippet, fake_aws.call_boto3)

    assert bundle["rule_groups"][CRS]["versions"] == {}
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle))
    assert main(["check", "--bundle", str(path)]) == 0
    assert capsys.readouterr().out.splitlines() == [
        f"WARNING  {CRS}  default-not-describable  default version Version_1.1 "
        "cannot be described; comparisons that need it are skipped",
        "Summary: 0 error(s), 1 warning(s), 0 info",
    ]


def test_other_describe_error_fails_the_snippet(no_client, fake_aws, run_snippet, capsys):
    fake_aws.errors[(CRS, "Version_1.0")] = fake_aws.client_error("WAFAccessDeniedException")
    snippet = _snippet(capsys, "--web-acl-file", UPGRADE, "--region", "us-east-1")

    with pytest.raises(ClientError, match="WAFAccessDeniedException"):
        run_snippet(snippet, fake_aws.call_boto3)


def _web_acl_with_references(tmp_path, load_fixture, *names):
    """Write the upgrade web ACL plus one rule per name that references the example rule group."""
    web_acl = load_fixture("web_acl_upgrade.json")
    for priority, name in enumerate(names, start=4):
        statement = {"RuleGroupReferenceStatement": {"ARN": ARN}}
        web_acl["WebACL"]["Rules"].append(
            {"Name": name, "Priority": priority, "Statement": statement}
        )
    path = tmp_path / "web-acl.json"
    path.write_text(json.dumps(web_acl))
    return str(path)


def test_snippet_fetches_each_referenced_rule_group_once(
    no_client, fake_aws, run_snippet, load_fixture, tmp_path, capsys
):
    path = _web_acl_with_references(tmp_path, load_fixture, "Own-Rules", "Own-Rules-Again")

    bundle = run_snippet(
        _snippet(capsys, "--web-acl-file", path, "--region", "us-east-1"), fake_aws.call_boto3
    )

    fetched = [params for _, operation, _, params in fake_aws.calls if operation == "GetRuleGroup"]
    assert fetched == [{"ARN": ARN}]
    assert bundle["referenced_rule_groups"] == {ARN: load_fixture("rule_group_labels.json")}


def test_snippet_rule_group_error_left_out(
    no_client, fake_aws, run_snippet, load_fixture, tmp_path, capsys
):
    fake_aws.errors[ARN] = fake_aws.client_error("AccessDeniedException", "GetRuleGroup")
    path = _web_acl_with_references(tmp_path, load_fixture, "Own-Rules")

    bundle = run_snippet(
        _snippet(capsys, "--web-acl-file", path, "--region", "us-east-1"), fake_aws.call_boto3
    )

    assert bundle["referenced_rule_groups"] == {}
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(bundle))
    assert main(["check", "--bundle", str(bundle_path)]) == 1
    assert (
        f"WARNING  {ARN}  rule-group-not-checked  rule Own-Rules references rule group {ARN}, "
        "which was not fetched; its rules were not checked"
    ) in capsys.readouterr().out.splitlines()


def test_cloudfront_reads_us_east_1(no_client, fake_aws, run_snippet, capsys):
    snippet = _snippet(capsys, "--web-acl-file", UPGRADE, "--scope", "CLOUDFRONT")

    run_snippet(snippet, fake_aws.call_boto3)

    assert {region for _, _, region, _ in fake_aws.calls} == {"us-east-1"}
    assert {params["Scope"] for service, _, _, params in fake_aws.calls if service == "wafv2"} == {
        "CLOUDFRONT"
    }


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["--web-acl-file", UPGRADE], "collect-script --scope REGIONAL requires --region"),
        (
            ["--web-acl-file", UPGRADE, "--scope", "CLOUDFRONT", "--region", "eu-west-1"],
            "--scope CLOUDFRONT requires region us-east-1, got eu-west-1",
        ),
        (["--web-acl", "example-web-acl", "--region", "us-east-1"], "--web-acl requires --id"),
        (
            ["--web-acl-file", UPGRADE, "--id", WEB_ACL_ID, "--region", "us-east-1"],
            "--id cannot be used with --web-acl-file",
        ),
    ],
)
def test_collect_script_option_errors_exit_2(no_client, capsys, argv, message):
    assert main(["collect-script", *argv]) == 2

    assert capsys.readouterr().err == f"waf-upgrade-check: error: {message}\n"


def test_collect_script_unreadable_file_exits_2(no_client, tmp_path, capsys):
    path = tmp_path / "missing.json"

    assert main(["collect-script", "--web-acl-file", str(path), "--region", "us-east-1"]) == 2

    assert capsys.readouterr().err == (
        f"waf-upgrade-check: error: cannot read web ACL file {path}: "
        f"[Errno 2] No such file or directory: '{path}'\n"
    )
