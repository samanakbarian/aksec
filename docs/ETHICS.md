# Authorisation and responsible use

aksec is built for **defensive** work: understanding and reducing the attack
surface of assets you own or are explicitly authorised to assess.

## Load only data you are allowed to hold

Only ingest observations for networks and hosts where you have ownership or
written authorisation (your own infrastructure, a documented penetration-test
scope, assets your organisation operates). Scanning or probing systems you do
not control may be unlawful in many jurisdictions regardless of intent.

## Collection is a separate, accountable step

This repository does not scan. If you connect a collector that actively
probes hosts, that collector — not aksec — is where authorisation, rate
limiting and opt-out must be enforced. The `targets.py` module carries the
building blocks a responsible collector should respect:

- **Reserved/special-purpose ranges** (RFC 1918, loopback, link-local,
  multicast, documentation ranges, …) are excluded by default.
- **A blocklist** (`config/blocklist.txt`) lets network operators opt out;
  honour opt-out requests promptly.
- Identify yourself: `config.py` builds a `User-Agent` with a contact URL so
  operators can find out who is probing and ask to be excluded.

## Handle findings responsibly

Exposure findings are advisory heuristics, not proof of vulnerability. Review
them in context before acting, and follow coordinated disclosure if your work
ever surfaces an issue on a system operated by someone else.
