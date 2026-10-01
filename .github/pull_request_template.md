## What and why

<!-- One paragraph. Link the issue if there is one. -->

## Checklist

- [ ] Tests added or updated; `pytest` and `tirag eval` pass locally
- [ ] No secrets, tokens or real indicators in code, fixtures, logs or docs
- [ ] Security impact considered (auth, TLP filtering, prompt-injection surface, new egress)
- [ ] Docs updated (`docs/`, `README.md`) if behaviour or operations changed
- [ ] Infrastructure changes: reviewed the Terraform plan in the PR checks
- [ ] Rollback is possible (previous image tag still works; schema changes are additive)
