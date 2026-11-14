# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `versions <rule-group>` command: lists the available versions of an AWS managed rule group and marks the current default.
- `diff <rule-group> <from> <to>` command: compares two versions (rules added and removed, rule action changes, capacity, available and consumed labels).
- `--scope`, `--region`, `--profile` and `--format` options for both commands.
