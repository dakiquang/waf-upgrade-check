import json

import pytest
from botocore.exceptions import NoCredentialsError
from botocore.stub import Stubber

from waf_upgrade_check import __version__, aws
from waf_upgrade_check.cli import main

GROUP = "AWSManagedRulesCommonRuleSet"


def test_version_flag_prints_version(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert __version__ in capsys.readouterr().out


@pytest.fixture
def stub(wafv2_client, monkeypatch):
    monkeypatch.setattr(aws, "make_client", lambda scope, region, profile: wafv2_client)
    with Stubber(wafv2_client) as stubber:
        yield stubber
        stubber.assert_no_pending_responses()


@pytest.fixture
def versions_stub(stub, load_fixture):
    stub.add_response(
        "list_available_managed_rule_group_versions", load_fixture("list_versions_page1.json")
    )
    stub.add_response(
        "list_available_managed_rule_group_versions", load_fixture("list_versions_page2.json")
    )
    return stub


@pytest.fixture
def diff_stub(stub, load_fixture):
    stub.add_response("describe_managed_rule_group", load_fixture("describe_v1_0.json"))
    stub.add_response("describe_managed_rule_group", load_fixture("describe_v1_1.json"))
    return stub


def test_versions_text_marks_default(versions_stub, capsys):
    assert main(["versions", GROUP]) == 0

    assert capsys.readouterr().out.splitlines() == [
        "Version_1.10",
        "Version_1.1 (default)",
        "Version_1.0",
        "Default version: Version_1.1",
    ]


def test_versions_json(versions_stub, capsys):
    assert main(["versions", GROUP, "--format", "json"]) == 0

    assert json.loads(capsys.readouterr().out) == {
        "rule_group": GROUP,
        "scope": "REGIONAL",
        "default_version": "Version_1.1",
        "versions": ["Version_1.10", "Version_1.1", "Version_1.0"],
    }


def test_diff_text(diff_stub, capsys):
    assert main(["diff", GROUP, "Version_1.0", "Version_1.1"]) == 0

    out = capsys.readouterr().out
    assert out.startswith(f"{GROUP} Version_1.0 -> Version_1.1 (REGIONAL)\n")
    assert "Capacity: 700 -> 750 (+50)\n" in out
    assert "Rules added (1):\n  CrossSiteScripting_COOKIE\n" in out
    assert "Rules removed (1):\n  LegacyRule_QUERYARGUMENTS\n" in out
    assert "Action changed (1):\n  SizeRestrictions_BODY: Count -> Block\n" in out
    assert (
        "Available labels added (1):\n"
        "  awswaf:managed:aws:core-rule-set:CrossSiteScripting_Cookie\n" in out
    )
    assert (
        "Available labels removed (1):\n"
        "  awswaf:managed:aws:core-rule-set:LegacyRule_QueryArguments\n" in out
    )
    assert (
        "Consumed labels added (1):\n  awswaf:managed:aws:bot-control:signal:automated_browser\n"
        in out
    )
    assert out.endswith("Consumed labels removed (0):\n  none\n")


def test_diff_json(diff_stub, capsys):
    assert main(["diff", GROUP, "Version_1.0", "Version_1.1", "--format", "json"]) == 0

    assert json.loads(capsys.readouterr().out) == {
        "rule_group": GROUP,
        "scope": "REGIONAL",
        "from": "Version_1.0",
        "to": "Version_1.1",
        "capacity": {"old": 700, "new": 750},
        "rules": {
            "added": ["CrossSiteScripting_COOKIE"],
            "removed": ["LegacyRule_QUERYARGUMENTS"],
            "action_changed": [{"name": "SizeRestrictions_BODY", "old": "Count", "new": "Block"}],
        },
        "available_labels": {
            "added": ["awswaf:managed:aws:core-rule-set:CrossSiteScripting_Cookie"],
            "removed": ["awswaf:managed:aws:core-rule-set:LegacyRule_QueryArguments"],
        },
        "consumed_labels": {
            "added": ["awswaf:managed:aws:bot-control:signal:automated_browser"],
            "removed": [],
        },
    }


def test_api_error_exits_2_without_traceback(stub, capsys):
    stub.add_client_error("describe_managed_rule_group", "WAFNonexistentItemException")

    assert main(["diff", GROUP, "Version_9.9", "Version_1.1"]) == 2

    err = capsys.readouterr().err
    assert err.startswith("waf-upgrade-check: error: ")
    assert "WAFNonexistentItemException" in err
    assert "Traceback" not in err


def test_missing_credentials_exits_2(monkeypatch, capsys):
    def no_credentials(scope, region, profile):
        raise NoCredentialsError()

    monkeypatch.setattr(aws, "make_client", no_credentials)

    assert main(["versions", GROUP]) == 2

    assert "waf-upgrade-check: error: Unable to locate credentials" in capsys.readouterr().err


def test_cloudfront_with_other_region_exits_2(monkeypatch, capsys):
    def unexpected(scope, region, profile):
        raise AssertionError("client must not be created")

    monkeypatch.setattr(aws, "make_client", unexpected)

    assert main(["versions", GROUP, "--scope", "CLOUDFRONT", "--region", "eu-west-1"]) == 2

    assert "--scope CLOUDFRONT requires region us-east-1" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [["diff", GROUP, "Version_1.0"], ["versions", GROUP, "--scope", "GLOBAL"]],
)
def test_usage_errors_exit_2(argv):
    with pytest.raises(SystemExit) as exit_info:
        main(argv)
    assert exit_info.value.code == 2
