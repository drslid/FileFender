# Security Policy

## Project status

FileFender is young software. It has not received an independent security audit. Evaluate it with your own files before you rely on it, and keep other defenses around uploaded files.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Use GitHub's private vulnerability reporting (Security tab, "Report a vulnerability"). Include:

- the affected version or image digest;
- the affected component: API, dashboard, installer, update timer or image;
- prerequisites and impact;
- reproducible steps or a minimal proof of concept;
- relevant logs with keys, domains, IP addresses and tokens removed.

Allow time to reproduce and assess the report before publishing details. There is no paid bug bounty.

Detection gaps (a malicious file reported as `clean`) are not vulnerabilities of FileFender: report them to [ClamAV](https://www.clamav.net/reports/malware) or to the author of the YARA rule concerned.

## Sensitive data

Never include these values in an issue, discussion, screenshot or diagnostic archive:

- `.env` contents;
- API keys (`ff_...`) or `keys.json`;
- `accounts.json`, passwords, two-factor setup keys, QR codes or recovery codes;
- `settings.json`: it holds the abuse.ch Auth-Key, the webhook addresses, which often embed a secret, and the webhook signing secrets;
- DuckDNS token or abuse.ch Auth-Key;
- the `acme` directory of the data volume (it holds the certificate private key);
- `audit.log` and `hashlists.json` when they reveal your users or incidents;
- files that users uploaded to your instance.

## Deployment baseline

- Use a dedicated, patched Ubuntu or Debian server.
- Create the administrator account as soon as the installation ends: until then, the first visitor can create it.
- Give each person their own account with the lowest role that fits (viewer, operator, administrator), and delete the accounts of people who leave.
- Turn on two-factor authentication and keep the recovery codes offline.
- Expose only ports `80` and `443`, or only `127.0.0.1:8080` behind a reverse proxy.
- Limit the dashboard to your networks (**Settings → Dashboard access**). If you lock yourself out, run `docker exec filefender filefender admin unlock-dashboard` on the server.
- Give each application its own API key, restricted to its server addresses, with a request limit and an expiry date when possible. Revoke keys you no longer use.
- Add a webhook for security events, so that sign-ins, new keys and setting changes reach you, and read **Activity** from time to time. On a generic webhook, check the `X-FileFender-Signature` header.
- Keep the update timer enabled so signatures, rules and the image stay current.
- Treat any answer other than `200` as "not scanned", and reject `suspicious` files unless you review them.
