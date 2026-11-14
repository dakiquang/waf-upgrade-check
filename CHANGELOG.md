# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
