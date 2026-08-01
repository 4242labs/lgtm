import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execSync } from "node:child_process";
import { derive } from "../../src/scoring.js";
import { numstatHasTextChanges } from "../../src/runners/sast.js";
import type { RunnerContext, SiteConfig } from "../../src/types.js";

// PR #26 on ff3e (2026-07-29): a docs-only/binary-only diff (two regenerated
// PNG screenshots + one deleted markdown file, zero source touched) failed the
// LGTM gate with "insufficient evidence — semgrep scanned 0 files". semgrep
// --baseline-commit only opens files that differ from the baseline, so 0
// scanned is the CORRECT, EXPECTED result there — there was no source for a
// text-based scanner to ever have an opinion on. That is a different failure
// mode than the one sufficient() was built to catch (a repo whose language
// nothing here understands, at ALL, forever) and must not fail the gate the
// same way. See the sibling "coverage holes" describe block in
// docker-parse.test.ts for proof the original guard still holds for full-tree
// sweeps and for diffs that DO touch real source.

const dockerRunMock = vi.fn();
const hasDockerMock = vi.fn();

vi.mock("../../src/util/docker.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/util/docker.js")>();
  return {
    ...actual,
    hasDocker: () => hasDockerMock(),
    dockerRun: (opts: unknown) => dockerRunMock(opts),
  };
});

const { sastRunner } = await import("../../src/runners/sast.js");

function ok(stdout: string, code = 0, stderr = "") {
  return { code, stdout, stderr, timedOut: false };
}

function ctx(repoPath: string): RunnerContext {
  const baseUrl = "https://example.com";
  const site: SiteConfig = {
    name: "site",
    baseUrl,
    repoPath,
    routes: [],
    auth: { type: "none" },
    failOn: "high",
  };
  return {
    site,
    run: { baseUrl, isLocalhost: false, allowActive: false, outDir: "", stamp: "stamp" },
    urls: [baseUrl],
    caps: { docker: true, browser: true },
    log: () => {},
  };
}

// ── numstatHasTextChanges — pure parsing ────────────────────────────────────

describe("numstatHasTextChanges", () => {
  it("is false for a binary-only diff (git renders add/delete as literal '-')", () => {
    expect(numstatHasTextChanges("-\t-\tdocs/forecast.png\n-\t-\tweb/public/og.png\n")).toBe(false);
  });

  it("is false for an empty diff", () => {
    expect(numstatHasTextChanges("")).toBe(false);
  });

  it("is true when at least one line is a real content change", () => {
    expect(numstatHasTextChanges("-\t-\tdocs/forecast.png\n12\t3\tsrc/App.tsx\n")).toBe(true);
  });

  it("is true for a modification with 0 additions (a pure line deletion inside a surviving file)", () => {
    expect(numstatHasTextChanges("0\t68\tREADME.md\n")).toBe(true);
  });
});

// ── observe() — real git, mocked docker ─────────────────────────────────────
//
// Exercises the actual `git diff --numstat` shell-out against a real repo, so
// a regression in the flags (wrong --diff-filter, wrong ref order) shows up
// here rather than only in the parser above.

describe("sast.ts — diff-scoped gate on a binary/deletion-only PR", () => {
  let repo: string;
  let baseline: string;
  const prevEnv = process.env.LGTM_SAST_BASELINE_REF;

  function git(args: string, cwd = repo) {
    execSync(`git ${args}`, { cwd, stdio: "pipe" });
  }

  beforeEach(() => {
    dockerRunMock.mockReset();
    hasDockerMock.mockReset();
    hasDockerMock.mockResolvedValue(true);
    repo = mkdtempSync(join(tmpdir(), "lgtm-sast-diff-"));
    git("init -q -b main");
    git('config user.email "t@example.com"');
    git('config user.name "t"');
    writeFileSync(join(repo, "app.ts"), "export const x = 1;\n");
    writeFileSync(join(repo, "README.md"), "one\ntwo\nthree\n");
    git("add -A");
    git('commit -q -m base');
    baseline = execSync("git rev-parse HEAD", { cwd: repo }).toString().trim();
  });

  afterEach(() => {
    if (prevEnv === undefined) delete process.env.LGTM_SAST_BASELINE_REF;
    else process.env.LGTM_SAST_BASELINE_REF = prevEnv;
    rmSync(repo, { recursive: true, force: true });
  });

  it("skips semgrep entirely — notApplicable — when the diff is a deleted doc + a binary asset", async () => {
    rmSync(join(repo, "README.md"));
    // A real (tiny) PNG-shaped binary payload, not text — git must classify it binary.
    writeFileSync(join(repo, "logo.png"), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x01, 0x02, 0x03]));
    git("add -A");
    git('commit -q -m "drop readme, add binary asset"');
    process.env.LGTM_SAST_BASELINE_REF = baseline;

    const r = await derive(sastRunner, ctx(repo));

    expect(dockerRunMock).not.toHaveBeenCalled();
    expect(r.status).toBe("skipped");
    expect(r.waived).toBe(true); // notApplicable, not a coverage hole
    expect(r.note).toMatch(/no non-binary added\/modified file/i);
  });

  it("still runs semgrep when the diff touches real source, even alongside binary/deleted files", async () => {
    rmSync(join(repo, "README.md"));
    writeFileSync(join(repo, "logo.png"), Buffer.from([0x89, 0x50, 0x4e, 0x47]));
    writeFileSync(join(repo, "app.ts"), "export const x = 2;\n");
    git("add -A");
    git('commit -q -m "touch source too"');
    process.env.LGTM_SAST_BASELINE_REF = baseline;
    dockerRunMock.mockResolvedValue(
      ok(JSON.stringify({ results: [], errors: [], paths: { scanned: ["/src/app.ts"] } })),
    );

    const r = await derive(sastRunner, ctx(repo));

    expect(dockerRunMock).toHaveBeenCalledTimes(1);
    expect(r.status).toBe("ok");
  });

  it("still runs (and can still REFUSE) a full-tree sweep with no baseline ref set", async () => {
    delete process.env.LGTM_SAST_BASELINE_REF;
    dockerRunMock.mockResolvedValue(ok(JSON.stringify({ results: [], errors: [], paths: { scanned: [] } })));

    const r = await derive(sastRunner, ctx(repo));

    expect(dockerRunMock).toHaveBeenCalledTimes(1);
    expect(r.status).toBe("error");
    expect(r.note).toMatch(/scanned 0 files/i);
  });

  // jubs-app PR #39 (2026-08-01): a one-line change to `tests/test_web_session.py` and
  // nothing else. The diff has real text changes, so the pre-scan guard correctly let
  // semgrep run — and semgrep then opened ZERO files, because p/security-audit and friends
  // carry `paths: exclude` filters for test files. Reported as insufficient evidence, that
  // made the gate unpassable for ANY test-only pull request in every repo on the fleet
  // gate: no commit could produce a file the rulesets agree to read.
  it("is notApplicable — not a coverage hole — when every changed file is excluded by the rulesets", async () => {
    writeFileSync(join(repo, "app.ts"), "export const x = 3;\n");
    git("add -A");
    git('commit -q -m "change source the rulesets happen to exclude"');
    process.env.LGTM_SAST_BASELINE_REF = baseline;
    // semgrep ran, understood the language, and filtered every candidate out.
    dockerRunMock.mockResolvedValue(
      ok(JSON.stringify({ results: [], errors: [], paths: { scanned: [] } })),
    );

    const r = await derive(sastRunner, ctx(repo));

    expect(dockerRunMock).toHaveBeenCalledTimes(1); // the scan DID run
    expect(r.status).toBe("skipped");
    expect(r.waived).toBe(true); // notApplicable, not "could not conclude"
    expect(r.note).toMatch(/excluded by the rulesets/i);
  });

  it("falls through to the real scan (does not silently skip) when git itself fails to resolve the baseline", async () => {
    process.env.LGTM_SAST_BASELINE_REF = "0000000000000000000000000000000000dead";
    dockerRunMock.mockResolvedValue(
      ok(JSON.stringify({ results: [], errors: [], paths: { scanned: ["/src/app.ts"] } })),
    );

    const r = await derive(sastRunner, ctx(repo));

    expect(dockerRunMock).toHaveBeenCalledTimes(1);
    expect(r.status).toBe("ok");
  });
});
