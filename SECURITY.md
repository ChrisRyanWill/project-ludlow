# Security policy

Project Ludlow protects people who may be at risk for organizing. A vulnerability here can hurt real workers, so we take reports seriously and ask you to report them privately.

> **Status:** an early, unaudited prototype. Please do not use it for real organizing yet.

## How to report

**Use GitHub's private vulnerability reporting:** on the repository, go to **Security → Report a vulnerability**. Please do not open a public issue or discussion for a vulnerability, and do not post exploit details publicly until it is fixed.

Helpful reports include what you found, the impact (what an attacker learns or can do), and steps to reproduce. A failing test is ideal.

We will try to acknowledge a report within a week, keep you updated, and credit you (if you want) when it is fixed. We ask for up to **90 days** to fix a vulnerability before public disclosure, less if it is trivial and more only by agreement.

## What is in scope

- `shared/crypto.js` and the protocols in `docs/PROTOCOL.md` (key handling, sealing, Shamir sharing, key files, signatures).
- The server API: authentication, the permission matrix, the release lock, vote and ballot handling, the ledger.
- The web app: XSS, CSP bypasses, secrets leaking to logs, URLs, storage or third parties.
- The build: anything that could make the served code differ from the source.

## Known limits (please read before reporting)

Some weaknesses are known and documented in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), for example: the release lock is enforced by the server rather than by cryptography, a campaign's founder can open early cards alone until the committee is complete, and the code is delivered by the server. A report that only restates a documented limit is welcome as a discussion, but it is not a vulnerability.

## Safe harbor

If you make a good-faith effort to follow this policy, we will not pursue or support legal action against you for your research. Please only test against your own local copy (`npm start`), never against other people's deployments or real data, and do not attempt denial of service.

## Supported versions

Only the `main` branch. There are no releases yet.
