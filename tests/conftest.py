import ast
import asyncio
import copy
import json
from pathlib import Path

import boto3
import pytest
from botocore.exceptions import ClientError

from waf_upgrade_check import aws

FIXTURES = Path(__file__).parent / "fixtures"
CRS = "AWSManagedRulesCommonRuleSet"
KBI = "AWSManagedRulesKnownBadInputsRuleSet"
WINDOWS = "AWSManagedRulesWindowsRuleSet"
ACCOUNT = "123456789012"
RULE_GROUP_ARN = (
    "arn:aws:wafv2:us-east-1:123456789012:regional/rulegroup/example-label-rules/"
    "b2c3d4e5-6789-0abc-def1-EXAMPLE33333"
)


@pytest.fixture(autouse=True)
def isolated_aws_env(monkeypatch, tmp_path):
    """Keep tests away from real AWS config, credentials and region settings."""
    missing = tmp_path / "does-not-exist"
    monkeypatch.setenv("AWS_CONFIG_FILE", str(missing))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(missing))
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    for name in (
        "AWS_SESSION_TOKEN",
        "AWS_SECURITY_TOKEN",
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_DEFAULT_REGION",
        "AWS_REGION",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def load_fixture():
    def load(name):
        return json.loads((FIXTURES / name).read_text())

    return load


@pytest.fixture
def wafv2_client():
    return boto3.session.Session().client(
        "wafv2",
        region_name="us-east-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )


@pytest.fixture
def no_client(monkeypatch):
    def unexpected(scope, region, profile):
        raise AssertionError("client must not be created")

    monkeypatch.setattr(aws, "make_client", unexpected)


def _managed_rule(name, priority, group, version=None, overrides=()):
    statement = {"VendorName": "AWS", "Name": group}
    if version is not None:
        statement["Version"] = version
    if overrides:
        statement["RuleActionOverrides"] = [
            {"Name": override, "ActionToUse": {"Count": {}}} for override in overrides
        ]
    return {
        "Name": name,
        "Priority": priority,
        "Statement": {"ManagedRuleGroupStatement": statement},
    }


@pytest.fixture
def windows_kbi_web_acl():
    """Windows (unpinned, default not describable) and KBI pinned at Version_1.0."""
    return {
        "WebACL": {
            "Rules": [
                _managed_rule("AWS-Windows", 0, WINDOWS),
                _managed_rule(
                    "AWS-KBI",
                    1,
                    KBI,
                    version="Version_1.0",
                    overrides=["BadAuthToken_COOKIE_AUTHORIZATION"],
                ),
            ]
        }
    }


class FakeAws:
    """Stand-in for the AWS MCP run_script ``call_boto3``, served from the fixtures."""

    max_calls = 50

    def __init__(self, load_fixture):
        self.calls = []
        self.errors = {}
        self.web_acl = load_fixture("web_acl_upgrade.json")
        self.lists = {
            (CRS, None): load_fixture("list_versions_page1.json"),
            (CRS, "page-2-marker"): load_fixture("list_versions_page2.json"),
            (KBI, None): load_fixture("aws/known_bad_inputs_list.json"),
            (KBI, "Version_1.0"): {"Versions": []},
            (WINDOWS, None): load_fixture("aws/windows_list_rc_default.json"),
            (WINDOWS, "Version_1.0"): {"Versions": [], "NextMarker": "Version_1.0"},
        }
        self.describes = {
            (CRS, "Version_1.0"): load_fixture("describe_v1_0.json"),
            (CRS, "Version_1.1"): load_fixture("describe_v1_1.json"),
            (KBI, "Version_1.0"): load_fixture("aws/known_bad_inputs_v1_0.json"),
            (KBI, "Version_1.26"): load_fixture("aws/known_bad_inputs_v1_26.json"),
        }
        self.rule_groups = {RULE_GROUP_ARN: load_fixture("rule_group_labels.json")}

    async def call_boto3(self, *, service_name, operation_name, region_name=None, params=None):
        params = params or {}
        self.calls.append((service_name, operation_name, region_name, copy.deepcopy(params)))
        if len(self.calls) > self.max_calls:
            raise AssertionError(f"more than {self.max_calls} calls")
        response = None
        if (service_name, operation_name) == ("sts", "GetCallerIdentity"):
            response = {
                "Account": ACCOUNT,
                "Arn": f"arn:aws:iam::{ACCOUNT}:user/example",
                "UserId": "AIDAEXAMPLE",
            }
        elif (service_name, operation_name) == ("wafv2", "GetWebACL"):
            response = self.web_acl
        elif (service_name, operation_name) == ("wafv2", "ListAvailableManagedRuleGroupVersions"):
            response = self.lists.get((params.get("Name"), params.get("NextMarker")))
        elif (service_name, operation_name) == ("wafv2", "DescribeManagedRuleGroup"):
            key = (params.get("Name"), params.get("VersionName"))
            if key in self.errors:
                raise self.errors[key]
            response = self.describes.get(key)
        elif (service_name, operation_name) == ("wafv2", "GetRuleGroup"):
            if params.get("ARN") in self.errors:
                raise self.errors[params["ARN"]]
            response = self.rule_groups.get(params.get("ARN"))
        if response is None:
            raise AssertionError(f"unexpected call {service_name} {operation_name} {params}")
        return copy.deepcopy(response)

    @staticmethod
    def client_error(code, operation="DescribeManagedRuleGroup"):
        """The exception run_script raises for a failed AWS call."""
        return ClientError({"Error": {"Code": code, "Message": "synthetic"}}, operation)


@pytest.fixture
def fake_aws(load_fixture):
    return FakeAws(load_fixture)


@pytest.fixture
def run_snippet():
    """Run a collect-script snippet the way run_script does: top-level await, ``result``."""

    def run(snippet, call_boto3):
        code = compile(snippet, "<collect-script>", "exec", flags=ast.PyCF_ALLOW_TOP_LEVEL_AWAIT)
        namespace = {"call_boto3": call_boto3}
        asyncio.run(eval(code, namespace))
        return namespace["result"]

    return run
