import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import {
  secretsRunner,
  rangeAddsUnscannedContent,
} from "../../src/runners/secrets.js";
import type { Coverage } from "../../src/types.js";

const CTX = {} as never;
const cov = (data: Coverage["data"]): Coverage => ({
  trail: [],
  data,
  provenance: "gitleaks scan log (stderr)",
});

// The evidence contract must REFUSE a scan that examined nothing — but a
// diff-scoped PR gate whose range is empty (0 commits) or pure deletions (0
// added bytes) examined exactly what the PR introduced: nothing that could
// carry a secret. That is a clean pass — PROVIDED git corroborates the range
// added no content gitleaks needed to read. gitleaks reports "no content"
// identically whether the range added nothing or added a binary/undiffable
// file it could not scan, so `addedContent` (git numstat) disambiguates the
// two: false = deletions/rename/mode only (pass); true = an added file gitleaks
// could not scan (refuse); absent = uncorroborated (fail closed).
describe("secretsRunner.sufficient — scoped empty-evidence needs git corroboration", () => {
  it("PASSES a real scan that examined commits and bytes (scoped or not)", () => {
    expect(
      secretsRunner.sufficient(cov({ commits: 14, bytes: 554058, scoped: true }), CTX),
    ).toBeNull();
    expect(
      secretsRunner.sufficient(cov({ commits: 3, bytes: 900, scoped: false }), CTX),
    ).toBeNull();
  });

  // ── unscoped full-history sweep: empty evidence is always an anomaly ──
  it("REFUSES an unscoped scan that walked 0 commits (non-repo / no history)", () => {
    const reason = secretsRunner.sufficient(
      cov({ commits: 0, bytes: 0, scoped: false }),
      CTX,
    );
    expect(reason).not.toBeNull();
    expect(reason).toMatch(/0 commits/);
  });

  it("REFUSES an unscoped scan that walked commits but read 0 bytes", () => {
    const reason = secretsRunner.sufficient(
      cov({ commits: 5, bytes: 0, scoped: false }),
      CTX,
    );
    expect(reason).not.toBeNull();
    expect(reason).toMatch(/0 bytes/);
  });

  it("stays strict when the scoped flag is absent (defaults to refusal)", () => {
    expect(secretsRunner.sufficient(cov({ commits: 0, bytes: 0 }), CTX)).not.toBeNull();
  });

  // ── scoped PR gate: pass only when git says the range added nothing ──
  it("PASSES an empty diff-scoped range (0 commits) corroborated as adding nothing", () => {
    expect(
      secretsRunner.sufficient(
        cov({ commits: 0, bytes: 0, scoped: true, addedContent: false }),
        CTX,
      ),
    ).toBeNull();
  });

  it("PASSES a pure-deletion PR (walked commits, 0 bytes) corroborated as adding nothing", () => {
    expect(
      secretsRunner.sufficient(
        cov({ commits: 5, bytes: 0, scoped: true, addedContent: false }),
        CTX,
      ),
    ).toBeNull();
  });

  it("REFUSES a scoped 0-byte scan whose range added a file gitleaks could not scan (binary secret)", () => {
    const reason = secretsRunner.sufficient(
      cov({ commits: 5, bytes: 0, scoped: true, addedContent: true }),
      CTX,
    );
    expect(reason).not.toBeNull();
    expect(reason).toMatch(/binary/);
  });

  it("REFUSES a scoped 0-commit scan whose range added a binary file (the commits==0 bypass)", () => {
    // A commit that adds ONLY a binary file reports "0 commits scanned"; without
    // corroboration that slipped through the old commits==0 scoped pass.
    const reason = secretsRunner.sufficient(
      cov({ commits: 0, bytes: 0, scoped: true, addedContent: true }),
      CTX,
    );
    expect(reason).not.toBeNull();
    expect(reason).toMatch(/binary/);
  });

  it("FAILS CLOSED on a scoped empty-evidence scan that could not be corroborated (addedContent absent)", () => {
    const reason = secretsRunner.sufficient(
      cov({ commits: 5, bytes: 0, scoped: true }),
      CTX,
    );
    expect(reason).not.toBeNull();
    expect(reason).toMatch(/could not be corroborated/);
  });
});

// ── rangeAddsUnscannedContent — the git corroboration itself ────────────────
// The load-bearing helper: it walks the range like gitleaks does (per-commit
// `git log`, ACMRT + rename detection) and reports whether the PR ADDED any
// content gitleaks needed to read but could not — the signal that turns a
// scoped "0 bytes / 0 commits" from a clean pass into a refusal. Real temp git
// repos; hermetic (no Docker, no network).
describe("rangeAddsUnscannedContent — git corroboration of a scoped range", () => {
  let repo: string;
  const git = (...args: string[]) =>
    execFileSync("git", args, { cwd: repo, stdio: "pipe" });
  const sha = (rev = "HEAD") =>
    execFileSync("git", ["rev-parse", rev], { cwd: repo, encoding: "utf8" }).trim();
  const commit = (msg: string) => {
    git("add", "-A");
    git("commit", "-q", "-m", msg);
  };
  const bin = (name: string) =>
    writeFileSync(join(repo, name), Buffer.from([0x41, 0x4b, 0x49, 0x41, 0x00, 0xff, 0x00]));

  beforeEach(() => {
    repo = mkdtempSync(join(tmpdir(), "lgtm-secrets-"));
    git("init", "-q");
    git("config", "user.email", "t@t.co");
    git("config", "user.name", "t");
    writeFileSync(join(repo, "seed.txt"), "a\nb\nc\nd\n");
    commit("base");
  });
  afterEach(() => rmSync(repo, { recursive: true, force: true }));

  it("false — a pure-deletion range added nothing", async () => {
    const base = sha();
    writeFileSync(join(repo, "seed.txt"), "a\nc\n"); // only removes lines
    commit("delete lines");
    expect(await rangeAddsUnscannedContent(repo, `${base}..${sha()}`)).toBe(false);
  });

  it("false — a pure rename added nothing (rename detection on)", async () => {
    const base = sha();
    git("mv", "seed.txt", "renamed.txt");
    commit("rename");
    expect(await rangeAddsUnscannedContent(repo, `${base}..${sha()}`)).toBe(false);
  });

  it("true — an added binary file is content gitleaks could not scan", async () => {
    const base = sha();
    bin("keystore.bin");
    commit("add binary");
    expect(await rangeAddsUnscannedContent(repo, `${base}..${sha()}`)).toBe(true);
  });

  it("true — added text (the range added scannable content)", async () => {
    const base = sha();
    writeFileSync(join(repo, "new.txt"), "AKIA-lookalike\n");
    commit("add text");
    expect(await rangeAddsUnscannedContent(repo, `${base}..${sha()}`)).toBe(true);
  });

  it("true — a TYPE CHANGE from symlink to a binary file (the ACMR→ACMRT gap)", async () => {
    rmSync(join(repo, "seed.txt"));
    symlinkSync("/etc/hostname", join(repo, "node"));
    commit("seed a symlink");
    const base = sha();
    rmSync(join(repo, "node"));
    bin("node"); // symlink → regular binary file: status T
    commit("symlink becomes binary");
    expect(await rangeAddsUnscannedContent(repo, `${base}..${sha()}`)).toBe(true);
  });

  it("true — a binary added then deleted WITHIN the range (per-commit, not net)", async () => {
    const base = sha();
    bin("transient.bin");
    commit("add binary secret");
    rmSync(join(repo, "transient.bin"));
    commit("delete it again");
    // Net diff shows nothing; per-commit traversal still sees the add.
    expect(await rangeAddsUnscannedContent(repo, `${base}..${sha()}`)).toBe(true);
  });

  it("null — a non-range log-opts is not corroboratable (fail closed)", async () => {
    expect(await rangeAddsUnscannedContent(repo, "--all")).toBeNull();
    expect(await rangeAddsUnscannedContent(repo, sha())).toBeNull(); // single rev, no range
  });

  it("null — a leading-dash range is rejected before it reaches git (argv-injection guard)", async () => {
    expect(
      await rangeAddsUnscannedContent(repo, `--output=/tmp/pwn..${sha()}`),
    ).toBeNull();
  });
});
