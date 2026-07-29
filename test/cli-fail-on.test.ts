import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

// A live bug caught reviewing PR #31 (README docs for --skip/--fail-on): the
// CLI accepted ANY string for --fail-on and assigned it straight onto
// cfg.failOn with no validation. SEVERITY_ORDER.indexOf() on a typo returns
// -1, so atLeastAsSevere() reads every REAL severity as "less severe than
// the (bogus) threshold" and computePass() returns true — a typo silently
// disables the gate instead of erroring. `run` exits before ever touching
// Docker/network (the check happens right after loadSite()), so this is
// exercised as a real subprocess, not mocked.
//
// The suite is otherwise hermetic (test/setup/no-network.ts patches
// fetch/dns/net.Socket — see its header comment, citing 42L-973, for why
// that matters), but that guard only covers the parent vitest process, not
// a spawned child. The rejection cases below never reach that risk (they
// exit before `only`/runAudit exist at all). The acceptance case DOES run
// to completion, so it targets `--only deps` — white-box, and `example`'s
// committed site config sets no repoPath, so the orchestrator's own gate()
// skips it before any Docker or network I/O, deterministically, same as a
// missing capability always does.

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function runCli(args: string[]): { status: number; stderr: string } {
  try {
    execFileSync("npx", ["tsx", "src/cli.ts", ...args], {
      cwd: ROOT,
      timeout: 20_000,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { status: 0, stderr: "" };
  } catch (err) {
    const e = err as { status: number | null; stderr: Buffer };
    return { status: e.status ?? -1, stderr: e.stderr.toString() };
  }
}

describe("cli.ts — run --fail-on validation", () => {
  it("rejects a typo'd severity instead of silently disabling the gate", () => {
    const r = runCli(["run", "example", "--fail-on", "critcal"]);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/--fail-on must be one of/i);
    expect(r.stderr).toMatch(/critcal/);
  });

  it("rejects 'info' — a real Severity, but never a settable threshold", () => {
    const r = runCli(["run", "example", "--fail-on", "info"]);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/--fail-on must be one of/i);
  });

  it("rejects an empty value rather than silently falling back to the site's configured failOn", () => {
    const r = runCli(["run", "example", "--fail-on", ""]);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/--fail-on must be one of/i);
  });

  it("accepts every real, CLI-facing severity — --only deps so example's repoPath-less config skips before any Docker/network I/O", () => {
    for (const sev of ["critical", "high", "medium", "low"]) {
      const r = runCli(["run", "example", "--fail-on", sev, "--only", "deps"]);
      expect(r.stderr, `--fail-on ${sev} should not be rejected`).not.toMatch(
        /--fail-on must be one of/i,
      );
      // exit 2 is this validation's own refusal code — anything else means
      // the value was accepted and the CLI moved on to a real run outcome.
      // It's exit 1 here (deps has no repoPath in this site config, an
      // unwaived coverage hole per orchestrator.ts's gate()) — that failure
      // is expected and has nothing to do with --fail-on, which is the only
      // thing this test is about.
      expect(r.status, `--fail-on ${sev} should not be refused by validation`).not.toBe(2);
    }
  });
}, 30_000);
