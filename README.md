# waf-upgrade-check

Find what breaks before you upgrade an AWS WAF managed rule group version — an extension for agents on the AWS MCP Server, and a CLI.

> **Work in progress.** Nothing is released yet. Personal project, not affiliated with any company, no support commitment.

When you move a web ACL to a newer static version of an AWS Managed Rules rule group, some breakage is silent:

- **Overrides by rule name stop working.** AWS WAF silently ignores a rule action override whose rule name does not exist in the managed rule group ([`ManagedRuleGroupStatement`](https://docs.aws.amazon.com/waf/latest/APIReference/API_ManagedRuleGroupStatement.html)).
- **Your own rules may match labels the new version no longer adds** ([labels](https://docs.aws.amazon.com/waf/latest/developerguide/waf-labels.html)).
- **Capacity (WCU) can grow.**
- **A pinned version can be scheduled to expire**, after which AWS WAF uses the default version and blocks web ACL updates until you change it ([version life cycle](https://docs.aws.amazon.com/waf/latest/developerguide/waf-managed-rule-groups-versioning-lifecycle.html)).

`waf-upgrade-check` reads the rule group versions and your web ACL, and reports these before you upgrade. It only calls read APIs.

### ☕ Found it useful? Buy me a coffee

If this project saves you time, a coffee keeps it maintained. Any amount helps. More
options on the [donate page](https://dakiquang.github.io/donate/).

| MoMo · VietQR | PayPal |
|:---:|:---:|
| <img src="https://dakiquang.github.io/donate/images/qr-momo.png" width="180" alt="MoMo and VietQR code"> | <img src="https://dakiquang.github.io/donate/images/qr-paypal.png" width="180" alt="PayPal QR code"> |
| [![Open MoMo](https://img.shields.io/badge/Open%20MoMo-%E2%86%92-A50064?style=for-the-badge)](https://me.momo.vn/dakiquang) | [![Open PayPal](https://img.shields.io/badge/Open%20PayPal-%E2%86%92-0070BA?style=for-the-badge&logo=paypal&logoColor=white)](https://paypal.me/dakiquang) |

## Use with AWS MCP

Add the agent skill to your coding agent with the [skills CLI](https://github.com/vercel-labs/skills):

```console
npx skills add dakiquang/waf-upgrade-check
```

The agent needs the [AWS MCP Server](https://docs.aws.amazon.com/agent-toolkit/latest/userguide/understanding-mcp-server-tools.html) (its `run_script` tool) and the CLI below. When you ask whether an upgrade is safe, the agent:

1. Calls `GetCallerIdentity` through `run_script` and asks you to confirm the account and the web ACL (name, ID, scope, region) and the target.
2. Prints a read-only snippet with `waf-upgrade-check collect-script`.
3. Runs the snippet unchanged with `run_script` and checks that only Get, List and Describe calls ran.
4. Saves the returned bundle as JSON outside the repository; it contains your web ACL configuration.
5. Runs `waf-upgrade-check check --bundle FILE` offline.
6. Reports error findings first, as decisions for you, then warnings and info. It never changes the web ACL.

Example session (illustrative):

```text
You:   Is it safe to move example-web-acl to the default CommonRuleSet version?
Agent: AWS account 123456789012 (arn:aws:iam::123456789012:user/example). Check web ACL
       example-web-acl, ID a1b2c3d4-..., REGIONAL in eu-west-1, target default?
You:   Yes.
Agent: Read-only calls: GetCallerIdentity, GetWebACL, ListAvailableManagedRuleGroupVersions,
       DescribeManagedRuleGroup.
Agent: 2 errors. AWS-CRS overrides LegacyRule_QUERYARGUMENTS, which Version_1.1 removes; rule
       BlockLegacyLabel matches a label Version_1.1 no longer adds. Options: drop the override,
       update BlockLegacyLabel, or stay pinned on Version_1.0. Also: +50 WCU (700 -> 750).
```

## Install the CLI

```console
pipx install waf-upgrade-check  # not published yet
```

From source:

```console
uv tool install git+https://github.com/dakiquang/waf-upgrade-check
```

Or clone the repository and run `uv run waf-upgrade-check`.

## Commands

### versions

List the available versions of a managed rule group; the current default is marked:

```console
$ waf-upgrade-check versions AWSManagedRulesCommonRuleSet --region eu-west-1
Version_1.10
Version_1.1 (default)
Version_1.0
Default version: Version_1.1
```

### diff

Compare two versions: rules added and removed, rule action changes, capacity (WCU), and available and consumed labels:

```console
$ waf-upgrade-check diff AWSManagedRulesCommonRuleSet Version_1.0 Version_1.1 --region eu-west-1
```

### check

Check every AWS managed rule group in a web ACL against a target version. Choose one source:

- `--bundle FILE`: a bundle returned by the `collect-script` snippet. Checks offline; no AWS credentials needed. `--scope`, `--region` and `--profile` are ignored.
- `--web-acl-file PATH`: the output of `aws wafv2 get-web-acl` ([`GetWebACL`](https://docs.aws.amazon.com/waf/latest/APIReference/API_GetWebACL.html)); rule group versions are read from the API.
- `--web-acl NAME --id ID`: fetch the web ACL and the rule group versions from the API.

```console
$ waf-upgrade-check check --web-acl-file web-acl.json --region eu-west-1
ERROR  AWSManagedRulesCommonRuleSet  label-no-longer-emitted  rule BlockLegacyLabel matches LABEL awswaf:managed:aws:core-rule-set:LegacyRule_QueryArguments, not emitted by Version_1.1
ERROR  AWSManagedRulesCommonRuleSet  override-missing-rule  RuleActionOverrides entry LegacyRule_QUERYARGUMENTS in rule AWS-CRS is not a rule in Version_1.1
WARNING  AWSManagedRulesCommonRuleSet  capacity-increase  capacity 700 -> 750 WCU (+50); web ACL capacity 900
INFO  AWSManagedRulesCommonRuleSet  behind-default  pinned version Version_1.0 differs from default Version_1.1
INFO  AWSManagedRulesCommonRuleSet  rules-changed  Version_1.0 -> Version_1.1: 1 added, 1 removed, 1 action changed
Summary: 2 error(s), 1 warning(s), 2 info
```

`--target` selects the version to check against: `default` (the current default version, the default), `latest` (the version with the newest `LastUpdateTimestamp` from [`ListAvailableManagedRuleGroupVersions`](https://docs.aws.amazon.com/waf/latest/APIReference/API_ListAvailableManagedRuleGroupVersions.html)), or a version name. A version name that a rule group in the web ACL does not have is a usage error. Only top-level rule groups from vendor `AWS` are checked; Marketplace rule groups are ignored.

Findings:

- `override-missing-rule` (error): a `RuleActionOverrides` or `ExcludedRules` entry names a rule that the target version does not have.
- `label-no-longer-emitted` (error): another rule matches a label or label namespace that the version in use adds and the target version does not.
- `labels-not-listed` (warning): the version in use lists no labels and a later rule matches a label, so `label-no-longer-emitted` could not compare labels. Reported once per managed rule group reference, and not when the target is the version in use.
- `version-unavailable` (error): the pinned version is no longer listed as available.
- `capacity-increase` (warning): the target version needs more WCU than the version in use.
- `default-not-describable` (warning): the default version is not listed or cannot be described ([`DescribeManagedRuleGroup`](https://docs.aws.amazon.com/waf/latest/APIReference/API_DescribeManagedRuleGroup.html)), so comparisons that need it are skipped.
- `behind-default` (info): the pinned version is not the current default.
- `rules-changed` (info): rules added, removed, or with a changed action between the version in use and the target.

### collect-script

Print a read-only Python snippet for the AWS MCP Server `run_script` tool. Run it unchanged; its `return_value` is a bundle (format `waf-upgrade-check/bundle/v1`) with the web ACL, the version list of each AWS managed rule group in it, and the descriptions of the versions in use and of the target. Save it as JSON outside your repository and pass it to `check --bundle`.

```console
$ waf-upgrade-check collect-script --web-acl example-web-acl --id ID --region eu-west-1 --target default
$ waf-upgrade-check collect-script --web-acl-file web-acl.json --region eu-west-1
```

- `--web-acl NAME --id ID` or `--web-acl-file PATH` (required): with a file the web ACL is embedded in the snippet and not read from AWS.
- `--target`: as for `check`. Use the same target for `check --bundle`; the snippet describes only the versions that target needs.
- `--scope` and `--region`: `--region` is required for `REGIONAL`; `CLOUDFRONT` always uses `us-east-1`.

The snippet calls only [`GetCallerIdentity`](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html), `GetWebACL` (with `--web-acl`), `ListAvailableManagedRuleGroupVersions` and `DescribeManagedRuleGroup`.

## Options

For `versions`, `diff` and `check`:

- `--scope {REGIONAL,CLOUDFRONT}`: rule group scope, default `REGIONAL`. `CLOUDFRONT` always uses `us-east-1`; any other `--region` with it is an error.
- `--region REGION`: AWS region for `REGIONAL` scope. Defaults to your AWS configuration.
- `--profile PROFILE`: AWS named profile. Defaults to the standard AWS credential chain.
- `--format {text,json}`: output format, default `text`.

`collect-script` takes `--scope` and `--region` only.

## Exit codes

- `0`: success, and `check` found no error finding.
- `1`: `check` reported at least one error finding.
- `2`: a usage error, a credential or configuration error, an AWS API error, an invalid bundle file, or a bundle that lacks a version the target needs.

Errors are printed to stderr as `waf-upgrade-check: error: <message>`.

## GitHub Actions

Check a web ACL export kept in your repository on every pull request, with OIDC credentials ([configure-aws-credentials](https://github.com/aws-actions/configure-aws-credentials), [IAM OIDC identity providers](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html)):

```yaml
name: waf-upgrade-check
on: pull_request
permissions:
  contents: read
  id-token: write
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: aws-actions/configure-aws-credentials@v6
        with:
          role-to-assume: arn:aws:iam::123456789012:role/waf-upgrade-check
          aws-region: eu-west-1
      - uses: astral-sh/setup-uv@v10.3.3
      - run: uvx --from git+https://github.com/dakiquang/waf-upgrade-check waf-upgrade-check check --web-acl-file waf/web-acl.json --region eu-west-1
```

## Read-only IAM policy

The CLI and the snippet need only these actions ([AWS WAF V2 actions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_wafv2.html)). `GetCallerIdentity` needs no permission; it is listed for clarity.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "wafv2:GetWebACL",
        "wafv2:ListAvailableManagedRuleGroupVersions",
        "wafv2:DescribeManagedRuleGroup",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

The AWS MCP Server may need permissions of its own to sign you in and to run calls; see [identity-based policy examples for AWS MCP Server](https://docs.aws.amazon.com/agent-toolkit/latest/userguide/security_iam_id-based-policy-examples.html).

## Known limits

- **Rule actions are the only rule detail compared.** `DescribeManagedRuleGroup` returns rule summaries with a name and an action only ([`RuleSummary`](https://docs.aws.amazon.com/waf/latest/APIReference/API_RuleSummary.html)). A version that changes what a rule detects without renaming it shows no finding. Read the [AWS Managed Rules changelog](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-changelog.html) for those changes; for the core rule set and other [baseline rule groups](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html) many entries read "Improved detection signatures".
- **Label rules inside your own rule groups are not checked.** Rules in a rule group referenced with [`RuleGroupReferenceStatement`](https://docs.aws.amazon.com/waf/latest/APIReference/API_RuleGroupReferenceStatement.html) can match labels too; only rules in the web ACL itself are checked.
- **Firewall Manager rule groups are not checked.** Rule groups that a [Firewall Manager AWS WAF policy](https://docs.aws.amazon.com/waf/latest/developerguide/waf-policies.html) adds to a web ACL (`PreProcessFirewallManagerRuleGroups` and `PostProcessFirewallManagerRuleGroups` in [`WebACL`](https://docs.aws.amazon.com/waf/latest/APIReference/API_WebACL.html)) are not part of this check, and their rules are not checked as label consumers.
- **Some old versions list no labels.** `DescribeManagedRuleGroup` returned no `AvailableLabels` for `AWSManagedRulesCommonRuleSet` `Version_1.0` (checked 2026-11-14). When the pinned version lists no labels, `label-no-longer-emitted` cannot tell which labels the target version stopped emitting; `check` reports `labels-not-listed` (warning) instead when a later rule matches a label.

## License

[MIT](LICENSE).
