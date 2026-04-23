Managed bypass override rule seed files may be placed here before DB import.

- runtime authority: DB `override_rules`
- compatibility reference from bypass rules: `extra_rule`
- startup/db-import imports `*.conf` files only when the DB domain is empty
- DB-backed runtime does not materialize these files back to disk
