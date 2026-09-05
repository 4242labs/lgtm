import { describe, it, expect, afterEach } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, resolve, join } from "node:path";

// `run`'s four operator-error paths — bad slug, unparseable YAML, a config
// that fails validation, and a bad runner id in the config's `skip:` — all
// exited through an unhandled throw: a stack trace, and exit 1.
//
// The exit code is what actually mattered. README documents `1` as "a finding
// met the site's failOn threshold" and tells you to gate CI on it, so a run
// that never audited anything was reporting itself to a workflow step as an
// audit that ran and failed. `2` was already this CLI's code for operator
// error (--fail-on typo, --allow-active refusal, the auth type mismatch);
// these four just never joined it. Each assertion below therefore pins BOTH
// halves: exit 2, and no trace in what the operator reads.
//
// The classification is deliberately narrow — SiteNotFoundError,
// YAMLParseError, ZodError, UnknownRunnerError, and nothing else. A genuine
// crash keeps its trace, which is the case the last test here guards: it is
// the half of this change that is easy to regress by widening a catch, and
// impossible to notice until the day you need the trace.
//
// Real subprocesses, for the same reason cli-fail-on.test.ts uses them: this
// is `run`'s own argument and startup handling, and mocking it would test the
// mock. Every case exits before any runner executes — the first three before
// runAudit() is even called, the `skip:` one inside assertKnownRunners, which
// is the first thing runAudit does and runs ahead of any Docker, browser or
// network work. So none of them can reach the network the hermetic suite's
// setup (test/setup/no-network.ts) cannot police inside a spawned child.

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

let dir: string;
afterEach(() => {
  if (dir) rmSync(dir, { recursive: true, force: true });
});

/** Write a config to a temp dir and return its absolute path. `run` accepts a
 *  path ending in .yaml directly, which keeps these fixtures out of sites/. */
function writeConfig(yaml: string): string {
  dir = mkdtempSync(join(tmpdir(), "lgtm-operator-error-"));
  const path = join(dir, "site.yaml");
  writeFileSync(path, yaml);
  return path;
}

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

/** A stack frame — `at …/cli.ts:30:11`. What none of these should print. */
const TRACE = /^\s+at .+:\d+:\d+/m;

describe("cli.ts — run operator errors exit 2, not the gate-failure code", () => {
  it("refuses an unknown site slug without burying its own helpful message in a trace", () => {
    const r = runCli(["run", "nosuchsite"]);
    expect(r.status).toBe(2);
    // sitePath's message was always good — it names the slug AND where it
    // looked. It was just printed as the header of a stack trace.
    expect(r.stderr).toMatch(/site config not found: nosuchsite/);
    expect(r.stderr).toMatch(/looked in/);
    expect(r.stderr).not.toMatch(TRACE);
  });

  it("refuses a config that isn't valid YAML", () => {
    const path = writeConfig('name: t\nbaseUrl: "https://example.com"\n  oops: [\n');
    const r = runCli(["run", path]);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/could not parse site config/i);
    // Names the file that failed, not the argument that was typed — for a
    // slug (`run example`) those are not the same thing, and only one of them
    // tells the operator which file to open.
    expect(r.stderr).toContain(path);
    // yaml's own message carries the line/column; that part is worth keeping.
    expect(r.stderr).toMatch(/line \d+/);
    expect(r.stderr).not.toMatch(TRACE);
  });

  it("names the offending field when the config parses but fails validation", () => {
    const path = writeConfig("name: t\nbaseUrl: not-a-url\n");
    const r = runCli(["run", path]);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/invalid site config/i);
    expect(r.stderr).toContain(path);
    expect(r.stderr).toMatch(/baseUrl/);
    // The point of formatting zod's issues by hand: a bare ZodError prints as
    // a JSON dump, which buries the one line naming the wrong key.
    expect(r.stderr).not.toMatch(/"code":/);
    expect(r.stderr).not.toMatch(TRACE);
  });

  it("lists every invalid field, not just the first", () => {
    const path = writeConfig('name: t\nbaseUrl: not-a-url\nroutes: "/a"\n');
    const r = runCli(["run", path]);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/baseUrl/);
    expect(r.stderr).toMatch(/routes/);
  });

  it("refuses a bad runner id in the site config's `skip:` — the path loadSite never sees", () => {
    const path = writeConfig("name: t\nbaseUrl: https://example.com\nskip: [zapp]\n");
    const r = runCli(["run", path]);
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/unknown runner id in the site config's `skip:`/i);
    expect(r.stderr).toMatch(/zapp/);
    // This one comes from assertKnownRunners inside runAudit, so it is caught
    // around that call rather than around loadSite — and the orchestrator's
    // guard itself is untouched, still throwing for callers that use it
    // directly (see orchestrator.test.ts).
    expect(r.stderr).not.toMatch(TRACE);
  });

  it("still crashes with a trace on a failure it does not recognise", () => {
    // A directory where a config should be: readFileSync raises EISDIR, which
    // is not one of the four classified paths. This is the boundary the whole
    // change turns on — catching it too would make a real bug in lgtm harder
    // to debug than the noisy typo this fixes, which is the worse trade.
    dir = mkdtempSync(join(tmpdir(), "lgtm-operator-error-"));
    const path = join(dir, "notafile.yaml");
    mkdirSync(path);
    const r = runCli(["run", path]);
    expect(r.status).not.toBe(2);
    expect(r.stderr).toMatch(TRACE);
  });
  // Same suite budget as the other two CLI tests: each case is a real
  // `npx tsx` subprocess, which outruns the global 5s testTimeout on CI.
}, 40_000);
