# Security policy

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private vulnerability reporting
("Security" tab → "Report a vulnerability") on this repository. Include the affected version or
commit, reproduction steps, and the impact you observed. You will receive an acknowledgement within
3 working days.

## Scope

In scope: authentication/authorisation (API keys, OIDC, TLP clearance), prompt-injection and data
exfiltration paths through the RAG pipeline, ingestion/poisoning controls, infrastructure code, and the
CI/CD pipeline. Out of scope: findings that need a compromised AWS account or an already-leaked API key,
and volumetric denial of service.

## Supported versions

Only the latest commit on `main` is supported; fixes are released by merging to `main` (which deploys
through the staged pipeline).

See `docs/security.md` and `security/threat-model.md` for the design and the known limitations.
