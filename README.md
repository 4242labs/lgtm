# lgtm

[![Project Status: Active](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)
[![Maintenance](https://img.shields.io/badge/maintenance-passively--maintained-yellowgreen.svg)](CONTRIBUTING.md)

> _"looks good to me"_ — except this one actually checks.

A config-driven audit harness that runs current best-practice **security,
accessibility, privacy, and quality** checks against **any** website — **locally,
before you launch**, and re-pointable at a live URL. One config per site, one
command, one scored HTML + JSON report with a CI-gating exit code.

lgtm doesn't reinvent scanners — it **orchestrates** best-of-breed OSS tools
behind a single authenticated, local-first workflow and a unified report.

## What it checks

| Runner | Domain | Standard | Mode | Tool |
|---|---|---|---|---|
| `headers` | security | OWASP Secure Headers, CSP L3, RFC 6797 | black-box | native |
| `tls` | transport | Mozilla intermediate TLS | black-box | testssl.sh (docker) |
| `cookies` | privacy | OWASP ASVS 3.4 / 4.2 (CSRF) | black-box | native |
| `a11y` | accessibility | **WCAG 2.2 AA incl. color contrast** | black-box (authed) | axe-core + Playwright |
| `authz` | access control | OWASP Top 10 A01, ASVS 8.3 | black-box (authed) | Playwright |
| `lighthouse` | perf/SEO | Core Web Vitals | black-box (authed) | Lighthouse |
| `deps` | supply chain | OSV / GHSA | white-box | osv-scanner (docker) |
| `secrets` | secrets | OWASP ASVS 2.10 | white-box | gitleaks (docker) |
| `sast` | static analysis | OWASP Top 10, CWE | white-box | Semgrep (docker) |
| `zap` | DAST | OWASP ZAP | black-box | ZAP (docker) |

**Black-box** runners need only a reachable URL. **White-box** runners need the
repo checkout (`repoPath` in the site config). Docker-hosted scanners need
Docker running.

A runner that cannot run does **not** quietly drop out: the domain it covers
went unaudited, and the run fails. If that is intentional — you genuinely do not
want ZAP against this site — waive it explicitly with `skip:` in the site
config. The waiver is reported; the run can still pass.

That is the rule the whole tool is built around:

> **A scan that examined nothing is not a clean scan.** Every runner reports
> what it actually looked at — lockfiles walked, commits read, URLs spidered,
> pages rendered — and a verdict of "clean" is *derived* from that evidence,
> never asserted by the scanner itself. No evidence, no pass.

So `lgtm` goes red on things a scanner usually goes green on: a secret scan
pointed at a directory that isn't a git repo, a dependency scan whose only
lockfile is gitignored, a Semgrep run over a language its rulesets don't parse,
a ZAP baseline whose spider never got past the front door, an axe audit of a
page that rendered an empty body. Each of those exits 0 and reports nothing. None
of them looked at anything. Every report states its own coverage, so you can
check the claim rather than take it.

## Setup

```bash
cd lgtm
npm install          # also installs the Chromium Playwright needs
# Docker Desktop running unlocks tls / deps / secrets / sast / zap
```

## Configure a site

Copy the template and edit it — real site configs are git-ignored, so yours stay
local:

```bash
cp sites/example.yaml sites/mysite.yaml
$EDITOR sites/mysite.yaml
```

`baseUrl` is required; `repoPath` unlocks the white-box scanners;
`auth.type: storageState` unlocks authenticated coverage.

## Run

```bash
# 1. Start your dev server (e.g. on :3000), then:
npm run audit -- run mysite

# Re-point at any URL (prod sweep, staging, preview):
npm run audit -- run mysite --url https://example.com

# Subset of checks:
npm run audit -- run mysite --only headers,a11y,cookies

# Everything except a subset — NOT combinable with --only (--only wins outright,
# --skip is silently ignored if both are passed in the same run):
npm run audit -- run mysite --skip zap,lighthouse

# Override the site's failOn threshold for this run (critical|high|medium|low —
# the CLI rejects anything else, so a typo can't silently disable the gate):
npm run audit -- run mysite --fail-on critical

# Active/attacking DAST — localhost ONLY, opt-in:
npm run audit -- run mysite --allow-active

npm run audit -- list      # runners + configured sites
```

The report lands in `reports/<site>/<site>-<stamp>.html` (+ `.json` for CI). Exit
code is `0` on pass, `1` when any finding meets the site's `failOn` threshold —
wire it into CI as a gate.

## Authenticated surfaces

Most apps live behind login. Capture a session once — the harness reuses it for
`a11y`, `authz`, and `lighthouse` so they see the real, logged-in app:

```bash
npm run audit -- auth mysite     # opens a browser; log in; press Enter
```

The session is written to `.auth/<site>.json` (git-ignored, never committed). The
`authz` runner then verifies protected routes actually enforce auth (anonymous
access → high finding), authed responses aren't cacheable, and cookies are sound.

## Security scanning — two tiers

Both `secrets` and `sast` are split so the blocking gate stays fast and only ever
fails a PR on what the PR introduces, while the whole repo is still covered:

- **Per-PR gate (`gate.yml`, blocking)** is **diff-scoped**: `secrets` scans only
  the PR's commits (`base..head`); `sast` runs semgrep diff-aware
  (`--baseline-commit <base>`) so only findings **new since the PR base** count.
  A pre-existing finding in an untouched file never fails a PR. The gate sets the
  scope automatically via `LGTM_SECRETS_LOG_OPTS` / `LGTM_SAST_BASELINE_REF`. A PR
  whose diff is entirely binary assets and/or deletions (regenerated screenshots,
  a removed doc) skips `sast` — not fails it — since diff-aware semgrep opens
  nothing in that case and there is no source to have an opinion on. `sast` still
  hard-fails on a **full-tree** 0-file scan (unset baseline, i.e. the sweep below):
  that is the real, permanent gap this guard exists to catch — a repo whose
  language nothing in the rulesets understands.
- **Scheduled sweep (`sweep.yml`, non-blocking)** runs both full-scope on a cron:
  `secrets` walks the **full history** (catches a secret committed-then-deleted in
  old history), `sast` scans the **whole tree** (the pre-existing backlog). Wire
  it per repo (see `sweep.yml` header); a finding reds the scheduled run, never a
  PR.

Binary blobs are covered too. gitleaks only ever sees diff text, so a PR that
adds a PDF, an image, a font or a keystore hands it nothing to read. Rather than
refuse on that silence — which blocked every such PR and still never looked
inside the file — `secrets` reads each undiffable blob back out of the commit
that introduced it, reduces it to its printable runs (the `strings(1)` view,
behind an ASCII header so gitleaks does not sniff the format and skip it), and
scans that. The byte count of that pass is the evidence the gate certifies on.
Compressed content inside a blob has no readable run, so a clean result there
means *no secret in the readable bytes* — the coverage trail says so rather than
implying more.

A found secret is remediated by **rotating the credential and purging it from
history** (git filter-repo / BFG) — not by narrowing the scan. A pre-existing
sast finding is fixed at source (or documented inline with `# nosemgrep`).

### Tuning

Scanners **fail closed** (a killed scan is "unknown", never "clean"), so a
too-short budget is a visible failure, not a silent pass. A wall-clock timeout is
**not** retried (a too-big scan is deterministic; retrying just burns another full
budget), so it fails fast and clear.

| Env var | Where | Default | Use |
|---|---|---|---|
| `LGTM_SECRETS_LOG_OPTS` | `secrets` | unset = full history | commit range to scan (the gate sets `base..head`) |
| `LGTM_SECRETS_TIMEOUT_MS` | `secrets` | `900000` (15 min) | raise for a slow full-history sweep |
| `LGTM_SAST_BASELINE_REF` | `sast` | unset = full tree | baseline commit for diff-aware semgrep (the gate sets the PR base SHA) |

`sast` (semgrep) is separately bounded for memory/parallelism on large repos (see
`src/runners/sast.ts`).

## Safety

- Active/mutating scans (`zap-full-scan`) run **only** against localhost and
  **only** with `--allow-active`. Against any remote target the harness refuses,
  and ZAP falls back to a passive baseline.
- Captured sessions, reports, and your real site configs are all git-ignored.

## Contributors

<!-- contributors:start -->
<a href="https://github.com/42piratas" title="42piratas"><img src="https://avatars.githubusercontent.com/u/18232600?v=4&s=64" width="64" height="64" alt="42piratas" /></a>
<!-- contributors:end -->

## License

Open source — [AGPL-3.0](LICENSE). Commercial — contact ahoy@42labs.io.

---
If it earned its keep, [coffee is appreciated](https://buymeacoffee.com/42piratas). ☕
