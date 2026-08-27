import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

// `--skip` was bolted on beside `--only` without the care `--only` got, and
// drifted from it in two ways that both surface as a stack trace:
//
//   1. It never got the `.trim()`. `--skip "zap, lighthouse"` — the spacing
//      the README's own prose invites — carried the space into the id and
//      died on " lighthouse". `--only "headers, cookies"` has always worked.
//   2. cli.ts merges --skip into cfg.skip before the orchestrator sees it, so
//      the guard there could only report a bad id as coming from "the site
//      config's `skip:`". An operator who typo'd it on the command line was
//      sent to search a YAML file for a value that was never in it.
//
// Both are now caught at the CLI boundary, where the flag the operator typed
// is still known — the same shape as the --fail-on validation beside it
// (clean message, exit 2, no trace). The orchestrator's assertKnownRunners is
// deliberately left alone: it is the real backstop against a typo widening
// into a waiver, it still covers callers reaching runAudit() directly, and
// its "site config" wording is now only ever shown when that is true.
//
// Run as real subprocesses for the same reason cli-fail-on.test.ts is: this
// is argument handling in `run`, and mocking it would test the mock. The
// rejection cases exit before `only`/runAudit exist at all, so they cannot
// reach the network. The acceptance case runs to completion but targets
// `--only deps`, which is white-box: `example`'s committed config sets no
// repoPath, so the orchestrator's gate() skips it with no Docker or I/O.

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

describe("cli.ts — run --skip/--only runner ids", () => {
  it("accepts the spacing --only has always accepted: --skip 'zap, lighthouse'", () => {
    const r = runCli(["run", "example", "--only", "deps", "--skip", "zap, lighthouse"]);
    // The bug: " lighthouse" was rejected as an unknown id and the process
    // died on an unhandled throw. Exit 2 is the id refusal specifically —
    // this run still exits non-zero for its own reason (deps has no repoPath
    // to scan), which is the orchestrator working, not the flag failing.
    expect(r.status).not.toBe(2);
    expect(r.stderr).not.toMatch(/unknown runner id/i);
  });

  it("names --skip, not the site config, when the bad id came from --skip", () => {
    const r = runCli(["run", "example", "--skip", "zapp"]);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/unknown runner id in --skip/i);
    expect(r.stderr).toMatch(/zapp/);
    // The misdirection this replaces: the operator was told to go and look in
    // a config file that never mentioned `zapp`.
    expect(r.stderr).not.toMatch(/site config/i);
    // A typo is an operator mistake, not a crash — it reads like the
    // --fail-on refusal beside it.
    expect(r.stderr).not.toMatch(/\bat .*\.ts:\d+/);
  });

  it("still names --only for a bad id there, and refuses it the same way", () => {
    const r = runCli(["run", "example", "--only", "headerz"]);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/unknown runner id in --only/i);
    expect(r.stderr).toMatch(/headerz/);
    expect(r.stderr).not.toMatch(/\bat .*\.ts:\d+/);
  });
  // Same suite budget as cli-fail-on.test.ts: each case is a real `npx tsx`
  // subprocess, which comfortably outruns the global 5s testTimeout on a CI
  // runner even though it does not locally.
}, 30_000);
