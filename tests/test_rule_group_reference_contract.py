import json

import pytest

from waf_upgrade_check import aws
from waf_upgrade_check.cli import main


@pytest.fixture(params=["file", "fetched"])
def check_acl(request, monkeypatch, tmp_path):
    # Stub above the SDK response validation so malformed fetched data reaches the CLI.
    monkeypatch.setattr(aws, "make_client", lambda *args: object())
    monkeypatch.setattr(aws, "get_rule_group", lambda *args: {"RuleGroup": {"Rules": []}})

    def run(statement):
        web_acl = {
            "WebACL": {"Rules": [{"Name": "Example", "Priority": 0, "Statement": statement}]}
        }
        if request.param == "file":
            path = tmp_path / "web-acl.json"
            path.write_text(json.dumps(web_acl))
            return main(["check", "--web-acl-file", str(path)])
        monkeypatch.setattr(aws, "get_web_acl", lambda *args: web_acl)
        return main(["check", "--web-acl", "example", "--id", "example-id"])

    return run


@pytest.mark.parametrize(
    "reference",
    [{}, {"Other": "value"}, "not-an-object", {"ARN": 123}],
    ids=["empty", "missing-arn", "non-object", "non-string-arn"],
)
def test_malformed_reference_is_controlled_input_error(check_acl, capsys, reference):
    assert check_acl({"RuleGroupReferenceStatement": reference}) == 2

    captured = capsys.readouterr()
    assert captured.err.startswith("waf-upgrade-check: error: ")
    assert "reference" in captured.err.lower() or "arn" in captured.err.lower()
    assert "Traceback" not in captured.out + captured.err


def test_rule_without_reference_is_valid(check_acl, capsys):
    statement = {"LabelMatchStatement": {"Scope": "LABEL", "Key": "example:label"}}
    assert check_acl(statement) == 0
    assert "Traceback" not in capsys.readouterr().err
