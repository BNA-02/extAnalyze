# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately by email to
[ahmedbn.pro@outlook.com](mailto:ahmedbn.pro@outlook.com).
Do not open a public issue for security problems.

Include the affected version or commit, a description of the impact, and steps
or a sample input to reproduce. This is a spare-time project: expect an
acknowledgement within about 7 days and a fix or mitigation plan within about
90 days, depending on severity.

## Scope

extanalyze downloads and unpacks **untrusted** browser extensions, so the
following are in scope:

- Archive handling: path traversal, zip bombs, resource exhaustion
- Unbounded or unsafe network responses (store APIs, threat-intel datasets)
- Injection in generated reports (HTML, CSV, text)
- Unsafe handling of temp files or cached data
- Dependency vulnerabilities that affect the tool

Out of scope: findings that require the user to run a malicious extension
(extanalyze performs static analysis only and never executes extension code),
and inaccuracies in risk scores or threat-intel data (open a normal issue).

## Built-in protections

- Downloads capped at 50 MB; metadata and dataset responses are size-capped
- Extraction limits: entry count, per-member and total uncompressed size,
  compression ratio, with path-containment checks (zip-slip)
- Downloaded packages and extraction directories are deleted after each scan
- HTML report output is escaped

## Recommendations when scanning hostile extensions

Run extanalyze in a disposable VM or container with limited disk and no
sensitive credentials, and treat generated HTML reports as untrusted until
reviewed.

## Supported versions

Only the latest release on `main` receives security fixes.
