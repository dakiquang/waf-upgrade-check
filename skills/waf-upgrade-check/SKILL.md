---
name: waf-upgrade-check
description: >-
  Find what breaks before moving an AWS WAF web ACL to a newer version of an AWS managed rule
  group, using the AWS MCP Server (run_script) and the waf-upgrade-check CLI. Use when the user
  asks whether it is safe to upgrade a managed rule group (for example
  AWSManagedRulesCommonRuleSet), what breaks if a web ACL moves to the default or latest version,
  or whether rule overrides and label rules still work after an upgrade.
---

# waf-upgrade-check with the AWS MCP Server

Read-only. You collect data through AWS MCP `run_script` with a snippet that the CLI prints, then
the CLI checks it offline. You report findings and suggest changes; you never change AWS.

## Prerequisites

- The AWS MCP Server is connected and its `run_script` tool is available.
- `waf-upgrade-check --version` works. If not, install it as described in the README:
  https://github.com/dakiquang/waf-upgrade-check#install-the-cli

## Steps

1. **Confirm the account and the web ACL.** Run this with `run_script`:

   ```python
   identity = await call_boto3(service_name="sts", operation_name="GetCallerIdentity", params={})
   result = {"account": identity.get("Account"), "arn": identity.get("Arn")}
   result
   ```

   Show the account and ARN. Ask the user to confirm the account and which web ACL to check:
   name, ID, scope (`REGIONAL` or `CLOUDFRONT`) and region, and the target (`default`, `latest`
   or a version name; `default` if they do not say). Read nothing else before they confirm. If
   the user has an export of the web ACL (`aws wafv2 get-web-acl` output), prefer it.

2. **Print the snippet.**

   ```console
   waf-upgrade-check collect-script --web-acl NAME --id ID --scope SCOPE --region REGION --target TARGET
   waf-upgrade-check collect-script --web-acl-file PATH --scope SCOPE --region REGION --target TARGET
   ```

   `--region` is required for `REGIONAL`. `CLOUDFRONT` always uses `us-east-1`.

3. **Run the snippet unchanged** with `run_script`. Then check `api_calls`: it must contain only
   `GetCallerIdentity`, `GetWebACL`, `ListAvailableManagedRuleGroupVersions` and
   `DescribeManagedRuleGroup`. A warning that pagination returned only the first page is
   expected; the snippet follows `NextMarker` itself. If the validator rejects the snippet or an
   API call fails, stop and report the error to the user. Do not rewrite the snippet. Compare
   `return_value.caller.account` with the account the user confirmed in step 1; if they differ,
   the credentials changed between the two calls: stop, do not save or check the bundle, and
   tell the user.

4. **Save `return_value`** as JSON to a file outside the repository, for example:

   ```console
   dir=$(mktemp -d) && echo "$dir/bundle.json"
   ```

   The bundle contains the web ACL configuration. Do not commit it.

5. **Check the bundle offline.**

   ```console
   waf-upgrade-check check --bundle BUNDLE_FILE --target TARGET --format json
   ```

   Use the same `--target` as in step 2. Exit codes: `0` no error findings, `1` at least one
   error finding, `2` a usage or bundle problem. If the message says the bundle has no
   description of a version, run `collect-script` again with the same `--target` and repeat
   steps 3 to 5.

6. **Report.** Error findings first, each as a decision for the user: the rule group, what
   breaks, and the options (drop or rename the override, update the rule that matches the label,
   or stay pinned on the current version). Then warnings (capacity increase, default version that
   cannot be described), then info (behind default, rules changed).

## Rules

- Never call write APIs: no `Create*`, `Update*`, `Delete*`, `Put*`, `Associate*`,
  `Disassociate*`, `Tag*` or `Untag*`.
- Never change the web ACL or apply an upgrade. Only suggest changes; the user applies them.
- Label rules inside `RuleGroupReferenceStatement` rule groups and Firewall Manager policies are
  not checked. Say so if the web ACL uses them.
