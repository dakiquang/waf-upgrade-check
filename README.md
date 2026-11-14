# waf-upgrade-check

Check what breaks before you upgrade an AWS WAF managed rule group version.

> **Work in progress.** Nothing is released yet. Personal project, not affiliated with any company, no support commitment.

When you move a web ACL to a newer static version of an AWS Managed Rules rule group, some breakage is silent:

- **Overrides by rule name stop working.** AWS WAF silently ignores a rule action override whose rule name does not exist in the managed rule group ([`ManagedRuleGroupStatement`](https://docs.aws.amazon.com/waf/latest/APIReference/API_ManagedRuleGroupStatement.html)).
- **Your own rules may match labels the new version no longer adds.**
- **Capacity (WCU) can grow.**
- **A pinned version can be scheduled to expire**, after which AWS WAF uses the default version and blocks web ACL updates until you change it ([version life cycle](https://docs.aws.amazon.com/waf/latest/developerguide/waf-managed-rule-groups-versioning-lifecycle.html)).

`waf-upgrade-check` reads the rule group versions and your web ACL, and reports these before you upgrade. It only calls read APIs.

## License

[MIT](LICENSE).
