# waf-upgrade-check

Check what breaks before you upgrade an AWS WAF managed rule group version.

> **Work in progress.** Nothing is released yet. Personal project, not affiliated with any company, no support commitment.

When you move a web ACL to a newer static version of an AWS Managed Rules rule group, some breakage is silent:

- **Overrides by rule name stop working.** AWS WAF silently ignores a rule action override whose rule name does not exist in the managed rule group ([`ManagedRuleGroupStatement`](https://docs.aws.amazon.com/waf/latest/APIReference/API_ManagedRuleGroupStatement.html)).
- **Your own rules may match labels the new version no longer adds.**
- **Capacity (WCU) can grow.**
- **A pinned version can be scheduled to expire**, after which AWS WAF uses the default version and blocks web ACL updates until you change it ([version life cycle](https://docs.aws.amazon.com/waf/latest/developerguide/waf-managed-rule-groups-versioning-lifecycle.html)).

`waf-upgrade-check` reads the rule group versions and your web ACL, and reports these before you upgrade. It only calls read APIs.

## Usage

List the available versions of a managed rule group; the current default is marked:

```console
$ waf-upgrade-check versions AWSManagedRulesCommonRuleSet --region eu-west-1
Version_1.10
Version_1.1 (default)
Version_1.0
Default version: Version_1.1
```

Compare two versions: rules added and removed, rule action changes, capacity (WCU), and available and consumed labels:

```console
$ waf-upgrade-check diff AWSManagedRulesCommonRuleSet Version_1.0 Version_1.1 --region eu-west-1
```

Options for both commands:

- `--scope {REGIONAL,CLOUDFRONT}`: rule group scope, default `REGIONAL`. `CLOUDFRONT` always uses `us-east-1`; any other `--region` with it is an error.
- `--region REGION`: AWS region for `REGIONAL` scope. Defaults to your AWS configuration.
- `--profile PROFILE`: AWS named profile. Defaults to the standard AWS credential chain.
- `--format {text,json}`: output format, default `text`.

Exit codes: `0` on success; `2` on a usage error, a credential or configuration error, or an AWS API error. Errors are printed to stderr as `waf-upgrade-check: error: <message>`.

## License

[MIT](LICENSE).
