# Security reporting

## Reporting a vulnerability

Do not post credentials, private documents, personal data or a working exploit in a public issue. If GitHub displays **Report a vulnerability** in this repository's Security tab, use that private reporting channel. Otherwise, open an issue requesting a private reporting channel without disclosing exploit details; wait for a maintainer to establish the channel before sending sensitive material.

Once a private channel is available, include the affected commit, configuration, reproduction steps, impact and a suggested mitigation when known. Use synthetic data. Acknowledge any dependency on local access, provider credentials or deployment configuration.

## Support boundary

No security response time or supported-release window is promised. Treat the documented application limits as part of the deployment contract. Keep credentials outside version control and rotate exposed credentials; removing them from the current file does not remove them from Git history.

A report should distinguish a demonstrated vulnerability from a configuration concern or a missing production feature. Keep public follow-up reports sanitized until coordinated disclosure is complete.
