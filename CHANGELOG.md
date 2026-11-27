# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `check` reports `labels-not-listed` (warning) when the version in use lists no `AvailableLabels` and a later rule in the web ACL matches a label, so label changes could not be checked.
- `check` checks the label rules in your own rule groups that the web ACL references with `RuleGroupReferenceStatement`: they count as label consumers at the priority of the referencing rule and are named `<rule group name>/<rule name>` in findings. API mode reads each rule group once with `GetRuleGroup` by ARN; bundles carry them in the optional key `referenced_rule_groups` (ARN to `GetRuleGroup` response), which `collect-script` collects. The bundle format stays `waf-upgrade-check/bundle/v1`.
- `check` reports `rule-group-not-checked` (warning) for a rule that references a rule group that could not be read or is missing from the bundle.

### Changed

- The read-only IAM policy needs `wafv2:GetRuleGroup`. Without it, `check` and the snippet still run and report `rule-group-not-checked`.

## [0.1.0] - 2026-11-14

### Added

- `versions <rule-group>` command: lists the available versions of an AWS managed rule group and marks the current default.
- `diff <rule-group> <from> <to>` command: compares two versions (rules added and removed, rule action changes, capacity, available and consumed labels).
- `check` command: checks every AWS managed rule group in a web ACL (from a file or from the API) against a target version (`default`, `latest` by `LastUpdateTimestamp`, or a version name) and reports overrides of missing rules, labels no longer emitted, unavailable pinned versions, capacity increases, pinned versions that differ from the default, a default version that is not listed or cannot be described when a comparison needs it (`default-not-describable`, warning) and rule changes. Exits with `1` when a finding is an error.
- `--scope`, `--region`, `--profile` and `--format` options for `versions`, `diff` and `check`; `collect-script` takes `--scope` and `--region`.
- Bundle format `waf-upgrade-check/bundle/v1`: a web ACL with the version list and the needed version descriptions of each AWS managed rule group in it, collected through the AWS MCP Server `run_script` tool.
- `check --bundle FILE`: checks a bundle offline, without AWS credentials. Exits with `2` when the bundle is invalid, has no entry for a rule group in the web ACL, or lacks a version the target needs.
- `collect-script` command: prints a read-only `run_script` snippet (Get, List and Describe calls only) that returns a bundle for a web ACL given by `--web-acl NAME --id ID` or `--web-acl-file PATH`.
- Agent skill `skills/waf-upgrade-check`: guides an agent on the AWS MCP Server through confirming the account, collecting a bundle, checking it and reporting findings, without changing AWS.

### Changed

- The README is organized around use with the AWS MCP Server, and adds a GitHub Actions example, a read-only IAM policy and the known limits.
- Known limits in the README include versions such as `AWSManagedRulesCommonRuleSet` `Version_1.0` that return no `AvailableLabels`.

[Unreleased]: https://github.com/dakiquang/waf-upgrade-check/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/dakiquang/waf-upgrade-check/releases/tag/v0.1.0
