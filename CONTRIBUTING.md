# Contributing to Project Ludlow

Thank you for being here. This project exists to put real power in workers' hands, so **care matters more than speed**: a privacy bug or a wrong legal statement can hurt people who take a risk to organize. This page explains how to help well.

> **Status:** an early prototype. It has not been independently security-reviewed or legally reviewed. Please don't use it for real organizing yet. Helping it get there is the point of this page.

## Ways to help

| You are... | Good places to start |
|---|---|
| **A developer** | Issues labelled [`good first issue`](../../labels/good%20first%20issue) and [`help wanted`](../../labels/help%20wanted). Tests are always welcome. |
| **A security reviewer or cryptographer** | `shared/crypto.js`, `docs/PROTOCOL.md`, `docs/THREAT_MODEL.md`. See [SECURITY.md](SECURITY.md) for private reporting. |
| **A labor attorney, paralegal or experienced organizer** | Everything in `content/legal/` is a **draft** waiting for you. Every `TODO(lawyer)` is a real open question. |
| **A translator** | Add a language: it is one file (see below). Native, legally aware review of the Spanish text is especially useful. |
| **A designer or accessibility tester** | Screen reader passes, contrast, low-end phones, right-to-left languages. |
| **An organizer or worker** | Tell us what would break in real life. Use [Discussions](../../discussions). Never share real names or workplaces. |

## Run it locally

```bash
git clone https://github.com/ChrisRyanWill/project-ludlow.git
cd project-ludlow
npm install
npm start                # builds the web app, serves http://localhost:8787 (Node 20+)
npm run test:unit        # fast: crypto, deadlines, permissions
npm run test:api         # the API, in-process, against a temp database
npm run test:e2e         # a real Chromium drives the whole product (needs Chromium; see below)
npm test                 # everything
```

The browser tests look for Chromium under `~/.cache/ms-playwright`. Install it with `npx playwright-core install chromium`, or point `CHROME_PATH` at any Chromium/Chrome.

## The rules that don't bend

These protect the people using the tool. A change that breaks one will not be merged, however useful it is otherwise. The full text is in [CLAUDE.md](CLAUDE.md).

1. **No plaintext personal data is stored by the campaign system.** Never log request bodies, query strings, headers, tokens or IP addresses.
2. **Secrets live in URL fragments** (`#...`), never in paths or query strings. The server stores only hashes.
3. **Only libsodium and Shamir sharing, only in `shared/crypto.js`.** No home-made cryptography. Every crypto function gets tests, including failure cases.
4. **No third-party requests, no `innerHTML`, `eval` or inline scripts.** Tests enforce this, including a browser test that watches every network request.
5. **Legal text is a draft.** Cite sources, mark uncertainty with `TODO(lawyer)`, never invent a legal requirement, and never let a document claim a majority the numbers don't show.
6. **The release lock is enforced by the server.** `export-bundle` is the only route allowed to return card ciphertext, and it must check the release number first.
7. **Every permission is data** in `shared/permissions.js`, and every workspace route goes through `W()`. The permission-matrix test walks the route table.
8. **Representation is never gated by dues or membership.**

## Making a change

1. For anything bigger than a small fix, open an issue or a discussion first so we can agree on the approach.
2. Branch, make the change, and **add tests** that fail without it.
3. Run `npm test`. UI changes: run the browser tests and include screenshots (light and dark) in the pull request.
4. Open a pull request using the template. Keep it focused; small PRs get reviewed faster.

## Add a language

Keys are the English sentences themselves, so a missing translation falls back to English instead of breaking.

1. Copy `web/src/es.js` to `web/src/<code>.js` and translate the values.
2. Register it in `web/src/i18n.js` (`DICTS`, `LANGS`, and `DIR` if it is right-to-left).
3. Translate the card: add `content/legal/<pack>/card-v1.<code>.md` (keep the `<!-- CARD -->` marker) and list it under `cards` in that pack in `web/src/packs.js`. **A bilingual, legally aware reader should check the card text**, because it is what a signer agrees to.

## Add a country (jurisdiction pack)

Everything that depends on the law where you work is data, not code.

1. Create `content/legal/<id>/` with `card-v1.md`, `next-steps.md`, `rights.md` and a recognition-request letter. Every file starts with the `DRAFT — REQUIRES REVIEW BY A LICENSED LABOR ATTORNEY BEFORE REAL-WORLD USE` header.
2. Add the pack to `web/src/packs.js`: name, currency, and the **thresholds that appear on the progress bar**.
3. In the pull request, **link a source for every threshold, deadline and legal claim.** Pull requests that change legal content are labelled `needs-legal-review` and stay open until someone qualified has looked.

## AI-assisted contributions

Much of this codebase was written with AI assistance (Claude Code), and you may use AI tools too. You are responsible for what you submit: understand it, test it, and say so in the pull request if a large part is AI-generated. Cryptography, authentication and the release lock need a human who can explain every line.

## Licensing of contributions

By submitting a contribution you agree that it is licensed under the project's license (see [LICENSE](LICENSE)). You keep your copyright.

## Conduct

Please read the [Code of Conduct](CODE_OF_CONDUCT.md). In this project it includes one extra rule: **never post real member data, real workplaces or real people's details**, even to illustrate a bug.
