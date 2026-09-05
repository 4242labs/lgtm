# lgtm

A config-driven audit harness that runs current best-practice **security, accessibility, privacy
and quality** checks against any website — locally, before launch, and re-pointable at a live URL.
One config per site, one command, one scored HTML and JSON report with a CI-gating exit code. It
does not reinvent scanners; it orchestrates best-of-breed OSS tools behind a single local-first
workflow and a unified report.

**The rule the whole tool is built around:** a scan that examined nothing is not a clean scan.
Every runner reports what it actually looked at — lockfiles walked, commits read, URLs spidered,
pages rendered — and a verdict of "clean" is *derived* from that evidence, never asserted. A runner
that cannot run does not quietly drop out: the domain it covers went unaudited and the run fails,
unless the site config waives it explicitly. Any change that lets a runner disappear silently
breaks the product.

**This is also the fleet's CI gate.** Other 42labs repositories call
`.github/workflows/gate.yml` here by ref, so a change to that file changes what every consuming
project is held to. Treat it as a published interface, not as local code.

**Open source, dual-licensed** — AGPL-3.0, commercial on request (`LICENSING.md`) — and passively
maintained. The public `README.md` is the user documentation.

## How work flows

Branch, work from a worktree, open a PR against `main`. `main` **is** branch-protected here, with
`typecheck + test` required — the only repository in this group that is. The gate, typecheck, unit
and integration suites all run on a PR. The `.claude/` CLU guards enforce worktree-only writes and
refuse a self-merge, but only while a CLU run is active.

## Crew

The roles this project is worked by, and what each one needs. **No personas live here** — an agent
arrives already knowing who it is, and reads this project to learn the project.

| Role | What this project needs from it |
|------|---------------------------------|
| Engineering | Runners, the report, the site-config schema |
| Security review | Every runner encodes a published standard — OWASP Top 10 and ASVS, WCAG 2.2 AA, Mozilla TLS, RFC 6797. Changing one changes what the fleet is measured against |
| Code review | Any change to `gate.yml`, because other repositories consume it by ref |
| Sysadmin | Branch protection here, and the required-check wiring in consuming repos |

No architect, content or data role is in use.

**After any context loss, re-read your anchor under `~/.agent-anchors/lgtm/`** (canon §17).

## Key files

- `README.md` — user documentation: the runners, the standards, the config format
- `.github/workflows/gate.yml` — the reusable workflow the rest of the fleet calls. A shared interface
- `src/` — the harness and the runners
- `sites/` — one config per audited site
- `test/`, `test-fixtures/` — the suites; `vitest.config.ts` and `vitest.integration.config.ts` split them
- `reports/` — generated output, gitignored, not source
