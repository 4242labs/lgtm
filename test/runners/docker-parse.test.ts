import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { derive } from "../../src/scoring.js";
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { RunnerContext, SiteConfig } from "../../src/types.js";

// The Docker-hosted runners are NOT just "skip when Docker is down". Each one
// carries a real, pure parse→severity mapping over a scanner's output, and a
// bug in any of those tables ships a wrong severity into the CI gate:
//   tls.ts     SEVERITY_MAP  (testssl CRITICAL/HIGH/MEDIUM/LOW/WARN)
//   deps.ts    SEVERITY_MAP + cvssFrom  (CVSS score → severity bands)
//   sast.ts    SEVERITY_MAP  (semgrep ERROR/WARNING/INFO)
//   zap.ts     RISK_MAP      (ZAP riskcode 3/2/1/0)
//   secrets.ts leak parsing + de-dup (everything is critical)
//
// We mock only util/docker.js — hasDocker() true, dockerRun() returning
// crafted scanner output — and drive each runner's real run(). No file under
// src/runners/ is modified.

// Plain mock fns referenced through a stable wrapper: vitest's global
// `restoreMocks: true` wipes a vi.fn()'s implementation between tests, so the
// implementations are (re)installed in beforeEach rather than in the factory.
const dockerRunMock = vi.fn();
const hasDockerMock = vi.fn();

vi.mock("../../src/util/docker.js", async (importOriginal) => {
  // Partial mock: hasDocker/dockerRun are faked, but the retry PREDICATES are
  // the real ones — the runners pass them to dockerRun, and a test that stubbed
  // them out would happily pass while the real classification was broken.
  const actual = await importOriginal<typeof import("../../src/util/docker.js")>();
  return {
    ...actual,
    hasDocker: () => hasDockerMock(),
    dockerRun: (opts: unknown) => dockerRunMock(opts),
    containerReachableUrl: (u: string) => u,
  };
});

// tls.ts resolves the target's addresses so it can pin ONE deterministic
// endpoint (42L-973 #7 — testssl.sh otherwise loops every resolved IP and
// emits every finding twice). Left unmocked that is real DNS from the unit
// suite: slow, offline-hostile, and it makes assertions depend on how many
// A-records a third party happens to publish today. Default: a single address,
// i.e. the ordinary case. Tests that care about the multi-endpoint path set
// `resolvedIps` themselves.
let resolvedIps: string[] = ["93.184.216.34"];
vi.mock("node:dns", () => ({
  promises: {
    resolve4: async () => resolvedIps,
    resolve6: async () => [],
  },
}));

// zap.ts probes the target before spending a container run on it, to refuse
// auth-gated / non-2xx responses (42L-973 #1/#2). Unmocked, that is a REAL
// HTTP request from the unit suite — and it is precisely how this file went
// red on CI while passing locally:
//
//   the two active-scan tests use http://localhost:3000. On the author's
//   laptop an unrelated dev server happened to be listening there and returned
//   200, so the probe succeeded and zap proceeded. On a CI runner nothing
//   listens, the connection is refused, the probe burns its retry backoff
//   (500ms + 1000ms — the tell-tale ~1.5s runtime), zapRunner returns early
//   with status "error", dockerRun is never called, and the assertions blow up
//   on an undefined mock call.
//
// A unit test must never depend on what is or isn't listening on the machine
// running it. Probe result is injectable; default is the ordinary "target is
// reachable and is really the site" case.
let probeResult: { ok: boolean; note?: string } = { ok: true };
vi.mock("../../src/util/authgate.js", () => ({
  probeTarget: async () => probeResult,
}));

const { tlsRunner } = await import("../../src/runners/tls.js");
const { depsRunner } = await import("../../src/runners/deps.js");
const { secretsRunner } = await import("../../src/runners/secrets.js");
const { sastRunner } = await import("../../src/runners/sast.js");
const { zapRunner } = await import("../../src/runners/zap.js");
const { runAudit } = await import("../../src/orchestrator.js");

let workRoot: string;
let cwdSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  dockerRunMock.mockReset();
  hasDockerMock.mockReset();
  hasDockerMock.mockResolvedValue(true); // Docker is UP for every test here
  resolvedIps = ["93.184.216.34"]; // single-endpoint host unless a test says otherwise
  probeResult = { ok: true }; // target reachable and really the site, unless a test says otherwise
  // tls/zap write their scanner output into a dir under process.cwd(); point
  // cwd at a temp dir so nothing is written into the repo.
  workRoot = mkdtempSync(join(tmpdir(), "lgtm-docker-parse-"));
  cwdSpy = vi.spyOn(process, "cwd").mockReturnValue(workRoot);
});

afterEach(() => {
  cwdSpy.mockRestore();
  rmSync(workRoot, { recursive: true, force: true });
});

function ok(stdout: string, code = 0, stderr = "") {
  return { code, stdout, stderr, timedOut: false };
}

// The scan logs the real tools print, and which the runners now read their
// coverage out of. A fixture that omits them is not a "clean scan" fixture —
// it is a scan that never ran, and the runner is right to refuse it.
//
// Verified against the real images (osv-scanner 2.x, gitleaks v8.30,
// zaproxy:stable), not invented: `osv-scanner` announces each manifest it
// walked on stderr and lists ONLY vulnerable sources in its JSON; `gitleaks`
// announces its commit and byte counts on stderr and writes NOTHING at all to
// the report path when a repo is clean; `zap-baseline.py` prints its spidered
// URL count and its rule tally on stdout.
const OSV_WALKED = "Scanned /src/package-lock.json file and found 304 packages\n";
const GITLEAKS_SCANNED = "14 commits scanned.\nscanned ~554058 bytes (554.06 KB) in 338ms\n";
const ZAP_CRAWLED =
  "Total of 12 URLs\nFAIL-NEW: 0\tFAIL-INPROG: 0\tWARN-NEW: 2\tWARN-INPROG: 0\tINFO: 1\tIGNORE: 0\tPASS: 58\n";

function ctx(overrides: Partial<{ baseUrl: string; repoPath: string }> = {}): RunnerContext {
  const baseUrl = overrides.baseUrl ?? "https://example.com";
  const site: SiteConfig = {
    name: "site",
    baseUrl,
    repoPath: overrides.repoPath ?? "/repo",
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

// ── tls.ts ────────────────────────────────────────────────────────────────────

/** tls.ts reads /wrk/out.json from the host dir it bind-mounts read-write. */
function tlsWritesJson(items: unknown[]) {
  dockerRunMock.mockImplementation(async (opts: { mountsRW?: Record<string, string> }) => {
    const dir = opts.mountsRW?.["/wrk"]!;
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "out.json"), JSON.stringify(items));
    return ok("");
  });
}

describe("tls.ts — testssl severity mapping", () => {
  it("maps each testssl severity onto the declared lgtm severity", async () => {
    tlsWritesJson([
      { id: "heartbleed", severity: "CRITICAL", finding: "vulnerable" },
      { id: "RC4", severity: "HIGH", finding: "offered" },
      { id: "BREACH", severity: "MEDIUM", finding: "potentially vulnerable" },
      { id: "cert_expiry", severity: "LOW", finding: "30 days" },
      { id: "TLS1_1", severity: "WARN", finding: "deprecated" },
    ]);
    const r = await derive(tlsRunner, ctx());
    const sev = (id: string) => r.findings.find((f) => f.id === `tls-${id}`)?.severity;
    expect(sev("heartbleed")).toBe("critical");
    expect(sev("RC4")).toBe("high");
    expect(sev("BREACH")).toBe("medium");
    expect(sev("cert_expiry")).toBe("low");
    expect(sev("TLS1_1")).toBe("low"); // WARN → low
  });

  it("drops OK/INFO entries entirely rather than scoring them", async () => {
    tlsWritesJson([
      { id: "cipherlist", severity: "OK", finding: "all good" },
      { id: "protocols", severity: "INFO", finding: "TLS1.3 offered" },
    ]);
    const r = await derive(tlsRunner, ctx());
    expect(r.status).toBe("ok");
    expect(r.findings).toEqual([]);
    // The OK/INFO entries were still TESTS testssl performed — they are the
    // proof it reached the host, which is what makes "no issues" readable as
    // clean rather than as silence.
    expect(r.coverage?.data.testsPerformed).toBe(2);
  });

  it("reads the nested scanResult shape as well as a flat array", async () => {
    dockerRunMock.mockImplementation(async (opts: { mountsRW?: Record<string, string> }) => {
      const dir = opts.mountsRW?.["/wrk"]!;
      mkdirSync(dir, { recursive: true });
      writeFileSync(
        join(dir, "out.json"),
        JSON.stringify({ scanResult: [{ id: "RC4", severity: "HIGH", finding: "offered" }] }),
      );
      return ok("");
    });
    const r = await derive(tlsRunner, ctx());
    expect(r.findings.find((f) => f.id === "tls-RC4")?.severity).toBe("high");
  });

  it("errors (not silently passes) when testssl writes no JSON at all", async () => {
    dockerRunMock.mockResolvedValue(ok(""));
    const r = await derive(tlsRunner, ctx());
    expect(r.status).toBe("error");
    expect(r.note).toMatch(/no JSON/i);
    expect(r.findings).toEqual([]);
  });

  it("an http/localhost target is not applicable — excused, not a coverage hole", async () => {
    const r = await derive(tlsRunner, ctx({ baseUrl: "http://localhost:3000" }));
    expect(r.status).toBe("skipped");
    expect(dockerRunMock).not.toHaveBeenCalled();
    // The load-bearing assertion. `status` is "skipped" for BOTH kinds of "did
    // not run", so checking it alone (as this test used to) cannot tell "there
    // is no TLS here" from "we never checked the TLS". `waived` is the flag the
    // orchestrator reads to decide whether the run may still pass, and it was
    // false here while the runner returned `unavailable`.
    expect(r.waived).toBe(true);
  });

  it("a PUBLIC plaintext http target is NOT excused — the domain applies and is failing", async () => {
    const r = await derive(tlsRunner, ctx({ baseUrl: "http://example.com" }));
    expect(r.status).toBe("skipped");
    expect(dockerRunMock).not.toHaveBeenCalled();
    // The opposite verdict to localhost, from the same absence of a TLS
    // endpoint. Here the transport domain exists and the site is failing it
    // outright, so the absence stays an unwaived coverage hole.
    expect(r.waived).toBe(false);
    // …and it must not be described as the localhost case it is not.
    expect(r.note).toMatch(/plaintext http/i);
  });
});

// The misclassification this guards against is invisible from the runner
// alone: derive() maps BOTH notApplicable and unavailable to status "skipped",
// so nothing short of a whole run shows what it actually cost. Driven through
// the real orchestrator against the real tlsRunner, because the question is
// exactly whether this runner's outcome lets a run reach a verdict.
describe("tlsRunner — an http dev server does not hold the whole run hostage", () => {
  it("a localhost run stays complete and can pass with tls in play", async () => {
    const site: SiteConfig = {
      name: "mysite",
      baseUrl: "http://localhost:3000",
      routes: [],
      auth: { type: "none" },
      failOn: "high",
    };
    const report = await runAudit({
      site,
      baseUrl: site.baseUrl,
      outDir: "",
      stamp: "t",
      allowActive: false,
      only: ["tls"],
    });

    const tls = report.results.find((r) => r.runnerId === "tls")!;
    expect(tls.status).toBe("skipped");
    expect(tls.note).toMatch(/no TLS to inspect/i);
    expect(dockerRunMock).not.toHaveBeenCalled();

    // "tls did not run" is still stated on the record, exactly as before …
    const entry = report.notAudited.find((n) => n.runnerId === "tls")!;
    // … but as an EXCUSED absence rather than a coverage hole.
    expect(entry.waived).toBe(true);
    expect(report.notAudited.filter((n) => !n.waived)).toEqual([]);

    // The symptom that sent us here: both of these were false, so the config
    // sites/example.yaml ships — baseUrl http://localhost:3000 — exited 1
    // however clean the site was, until `tls` was waived by hand.
    expect(report.complete).toBe(true);
    expect(report.passed).toBe(true);
  });

  it("does NOT hand the same excuse to a public plaintext site", async () => {
    const site: SiteConfig = {
      name: "plaintext",
      baseUrl: "http://example.com",
      routes: [],
      auth: { type: "none" },
      failOn: "high",
    };
    const report = await runAudit({
      site,
      baseUrl: site.baseUrl,
      outDir: "",
      stamp: "t",
      allowActive: false,
      // `--only tls` is the case that makes this load-bearing: `headers` is
      // the runner that would otherwise raise `no-tls` as high, and here it
      // never runs at all. If tls excused itself, a public site served over
      // plaintext would audit clean with zero findings.
      only: ["tls"],
    });

    const entry = report.notAudited.find((n) => n.runnerId === "tls")!;
    expect(entry.waived).toBe(false);
    expect(report.complete).toBe(false);
    expect(report.passed).toBe(false);
  });
});

// ── deps.ts ───────────────────────────────────────────────────────────────────

function osvOutput(vulns: Array<{ id: string; score?: string; name?: string }>) {
  return JSON.stringify({
    results: [
      {
        source: { path: "/src/package-lock.json" },
        packages: vulns.map((v) => ({
          package: { name: v.name ?? "pkg", version: "1.0.0" },
          vulnerabilities: [
            {
              id: v.id,
              summary: "a vulnerability",
              ...(v.score ? { severity: [{ type: "CVSS_V3", score: v.score }] } : {}),
            },
          ],
        })),
      },
    ],
  });
}

describe("deps.ts — CVSS → severity bands", () => {
  it("maps CVSS scores onto the correct severity band at each boundary", async () => {
    // Bands: >=9 critical, >=7 high, >=4 medium, else low. The boundaries
    // themselves are what a `>` vs `>=` slip would break.
    dockerRunMock.mockResolvedValue(
      ok(
        osvOutput([
          { id: "GHSA-crit", score: "9.0", name: "crit-pkg" },
          { id: "GHSA-high", score: "7.0", name: "high-pkg" },
          { id: "GHSA-med", score: "4.0", name: "med-pkg" },
          { id: "GHSA-low", score: "3.9", name: "low-pkg" },
        ]),
        1, // osv-scanner exits 1 when vulns are found — must NOT be treated as an error
        OSV_WALKED,
      ),
    );
    const r = await derive(depsRunner, ctx());
    expect(r.status).toBe("ok");
    const sev = (id: string) => r.findings.find((f) => f.id === `dep-${id}`)?.severity;
    expect(sev("GHSA-crit")).toBe("critical");
    expect(sev("GHSA-high")).toBe("high");
    expect(sev("GHSA-med")).toBe("medium");
    expect(sev("GHSA-low")).toBe("low");
  });

  it("sits just below each boundary correctly (8.9 high, 6.9 medium, 3.9 low)", async () => {
    dockerRunMock.mockResolvedValue(
      ok(
        osvOutput([
          { id: "GHSA-a", score: "8.9", name: "a" },
          { id: "GHSA-b", score: "6.9", name: "b" },
          { id: "GHSA-c", score: "3.9", name: "c" },
        ]),
        1,
      ),
    );
    const r = await derive(depsRunner, ctx());
    const sev = (id: string) => r.findings.find((f) => f.id === `dep-${id}`)?.severity;
    expect(sev("GHSA-a")).toBe("high");
    expect(sev("GHSA-b")).toBe("medium");
    expect(sev("GHSA-c")).toBe("low");
  });

  it("defaults a vulnerability with no CVSS score to medium — never drops it", async () => {
    dockerRunMock.mockResolvedValue(ok(osvOutput([{ id: "GHSA-noscore", name: "x" }]), 1));
    const r = await derive(depsRunner, ctx());
    const f = r.findings.find((x) => x.id === "dep-GHSA-noscore")!;
    expect(f).toBeDefined();
    expect(f.severity).toBe("medium");
  });

  it("extracts the base score out of a full CVSS vector string", async () => {
    dockerRunMock.mockResolvedValue(
      ok(osvOutput([{ id: "GHSA-vec", score: "9.8", name: "v" }]), 1),
    );
    const r = await derive(depsRunner, ctx());
    expect(r.findings.find((f) => f.id === "dep-GHSA-vec")?.severity).toBe("critical");
  });

  it("reports a clean scan as clean — no findings, with the manifests it walked on record", async () => {
    dockerRunMock.mockResolvedValue(ok(JSON.stringify({ results: [] }), 0, OSV_WALKED));
    const r = await derive(depsRunner, ctx());
    expect(r.status).toBe("ok");
    expect(r.findings).toEqual([]);
    expect(r.coverage?.data.sources).toBe(1);
    expect(r.coverage?.data.packages).toBe(304);
  });

  it("REFUSES a scan that DECLARES dependencies but walked none — a missing lockfile silently removes a whole ecosystem, and the tool still exits reporting nothing", async () => {
    const repoPath = join(workRoot, "has-manifest");
    mkdirSync(repoPath, { recursive: true });
    writeFileSync(join(repoPath, "package.json"), '{"name":"x","dependencies":{"lodash":"^4"}}');
    dockerRunMock.mockResolvedValue(ok(JSON.stringify({ results: [] }), 0, "No package sources found\n"));
    const r = await derive(depsRunner, ctx({ repoPath }));
    expect(r.status).toBe("error");
    expect(r.note).toMatch(/manifests are present but none were walked/i);
  });

  it("PASSES a genuinely dependency-free repo — no manifest anywhere is nothing to audit, not a coverage hole (docs/static/meta repos)", async () => {
    const repoPath = join(workRoot, "dep-free");
    mkdirSync(join(repoPath, "docs"), { recursive: true });
    writeFileSync(join(repoPath, "README.md"), "# just docs\n");
    writeFileSync(join(repoPath, "docs", "guide.md"), "content\n");
    dockerRunMock.mockResolvedValue(ok(JSON.stringify({ results: [] }), 0, "No package sources found\n"));
    const r = await derive(depsRunner, ctx({ repoPath }));
    expect(r.status).toBe("ok");
    expect(r.findings).toEqual([]);
    expect(r.coverage?.data.manifestPresent).toBe(false);
  });

  it.each(["Cargo.toml", "go.mod", "requirements.txt", "conanfile.txt", "renv.lock", "Podfile"])(
    "detects a non-npm manifest (%s) so a repo with real deps that walked nothing is REFUSED, not passed",
    async (manifest) => {
      const repoPath = join(workRoot, `manifest-${manifest.replace(/\W/g, "")}`);
      mkdirSync(repoPath, { recursive: true });
      writeFileSync(join(repoPath, manifest), "dep\n");
      dockerRunMock.mockResolvedValue(ok(JSON.stringify({ results: [] }), 0, "No package sources found\n"));
      const r = await derive(depsRunner, ctx({ repoPath }));
      expect(r.status).toBe("error");
      expect(r.note).toMatch(/manifests are present but none were walked/i);
    },
  );

  it("does NOT count a vendored manifest as the repo's own — a node_modules/*/package.json leaves a dep-free repo dep-free", async () => {
    const repoPath = join(workRoot, "vendored-only");
    mkdirSync(join(repoPath, "node_modules", "left-pad"), { recursive: true });
    writeFileSync(join(repoPath, "node_modules", "left-pad", "package.json"), '{"name":"left-pad"}');
    writeFileSync(join(repoPath, "index.md"), "docs\n");
    dockerRunMock.mockResolvedValue(ok(JSON.stringify({ results: [] }), 0, "No package sources found\n"));
    const r = await derive(depsRunner, ctx({ repoPath }));
    expect(r.status).toBe("ok");
    expect(r.coverage?.data.manifestPresent).toBe(false);
  });

  it("errors on a real scanner failure (exit > 1, no JSON) instead of reporting clean", async () => {
    dockerRunMock.mockResolvedValue({
      code: 127,
      stdout: "",
      stderr: "image not found",
      timedOut: false,
    });
    const r = await derive(depsRunner, ctx());
    expect(r.status).toBe("error");
    expect(r.findings).toEqual([]);
  });
});

// ── sast.ts ───────────────────────────────────────────────────────────────────

describe("sast.ts — semgrep severity mapping", () => {
  it("maps ERROR/WARNING/INFO onto high/medium/low", async () => {
    dockerRunMock.mockResolvedValue(
      ok(
        JSON.stringify({
          results: [
            { check_id: "rule.err", path: "/src/a.ts", start: { line: 1 }, extra: { severity: "ERROR", message: "bad" } },
            { check_id: "rule.warn", path: "/src/b.ts", start: { line: 2 }, extra: { severity: "WARNING", message: "meh" } },
            { check_id: "rule.info", path: "/src/c.ts", start: { line: 3 }, extra: { severity: "INFO", message: "fyi" } },
          ],
        }),
      ),
    );
    const r = await derive(sastRunner, ctx());
    const sev = (id: string) => r.findings.find((f) => f.id === `sast-${id}`)?.severity;
    expect(sev("rule.err")).toBe("high");
    expect(sev("rule.warn")).toBe("medium");
    expect(sev("rule.info")).toBe("low");
  });

  it("falls back to low for an unrecognized semgrep severity", async () => {
    dockerRunMock.mockResolvedValue(
      ok(
        JSON.stringify({
          results: [
            { check_id: "rule.weird", path: "/src/a.ts", start: { line: 1 }, extra: { severity: "NONSENSE", message: "?" } },
          ],
        }),
      ),
    );
    const r = await derive(sastRunner, ctx());
    expect(r.findings.find((f) => f.id === "sast-rule.weird")?.severity).toBe("low");
  });

  it("de-dupes identical rule+file+line hits", async () => {
    const hit = { check_id: "rule.x", path: "/src/a.ts", start: { line: 1 }, extra: { severity: "ERROR", message: "bad" } };
    dockerRunMock.mockResolvedValue(ok(JSON.stringify({ results: [hit, hit] })));
    const r = await derive(sastRunner, ctx());
    expect(r.findings.filter((f) => f.id === "sast-rule.x")).toHaveLength(1);
  });

  it("strips the container's /src/ prefix from the reported location", async () => {
    dockerRunMock.mockResolvedValue(
      ok(
        JSON.stringify({
          results: [
            { check_id: "rule.x", path: "/src/deep/a.ts", start: { line: 7 }, extra: { severity: "ERROR", message: "bad" } },
          ],
        }),
      ),
    );
    const r = await derive(sastRunner, ctx());
    expect(r.findings.find((f) => f.id === "sast-rule.x")?.location).toBe("deep/a.ts:7");
  });

  it("errors when semgrep emits malformed JSON", async () => {
    dockerRunMock.mockResolvedValue({
      code: 2,
      stdout: '{"results": [ truncated',
      stderr: "died",
      timedOut: false,
    });
    const r = await derive(sastRunner, ctx());
    expect(r.status).toBe("error");
    expect(r.findings).toEqual([]);
  });

  // FOUND WHILE TESTING — a live bug, and the same class as the "429 reported
  // as no security headers" defect: when semgrep dies WITHOUT printing any
  // JSON at all (crash, OOM, bad ruleset → plain-text stderr, empty stdout),
  // sast.ts's `stdout.indexOf("{")` is -1, so nothing is parsed, nothing
  // throws, and the runner falls through to its "No Semgrep findings across
  // security rulesets" info note — a crashed scanner reports CLEAN and the CI
  // gate goes green on an unscanned repo.
  //
  // Fixing it is a src/runners/sast.ts behavior change, which the concurrent
  // runner-bugs branch owns. Written to the correct post-fix expectation and
  // left skipped rather than fixed here or faked green.
  // Was it.skip pending the runner-side fix — 42L-973 #8 shipped it: no `{` in
  // stdout at all (the shape a crashed/killed container leaves) is now an
  // error, not a silent "sast-ok". This is the test that would have caught a
  // gate going green on a repo that was never scanned.
  it("does not report a clean scan when semgrep crashed with no JSON output at all", async () => {
    dockerRunMock.mockResolvedValue({
      code: 2,
      stdout: "",
      stderr: "semgrep: fatal error",
      timedOut: false,
    });
    const r = await derive(sastRunner, ctx());
    expect(r.status).toBe("error");
    expect(r.findings.find((f) => f.id === "sast-ok")).toBeUndefined();
  });
});

// ── secrets.ts ────────────────────────────────────────────────────────────────


/**
 * secrets.ts reads gitleaks' report from a FILE in a bind-mounted work dir —
 * never from stdout. The real image accepts `--report-path /dev/stdout` and then
 * writes nothing to it, so a runner that read stdout reported zero secrets for
 * every repo it ever scanned, including one with two AWS keys committed in
 * plaintext. This fake writes where the real tool writes.
 *
 * `body` is the raw report content: a JSON array when there are leaks, and an
 * EMPTY FILE when the repo is clean — which is what gitleaks actually does.
 */
function gitleaksWritesReport(body: string, stderr: string = GITLEAKS_SCANNED) {
  dockerRunMock.mockImplementation(async (opts: { mountsRW?: Record<string, string> }) => {
    const dir = opts.mountsRW?.["/out"]!;
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "gitleaks.json"), body);
    return ok("", 0, stderr);
  });
}

describe("secrets.ts — gitleaks parsing", () => {
  it("never asks gitleaks for its report on /dev/stdout — the image accepts that and writes nothing", async () => {
    gitleaksWritesReport("");
    await derive(secretsRunner, ctx());
    const args = dockerRunMock.mock.calls[0]![0].args as string[];
    const path = args[args.indexOf("--report-path") + 1];
    expect(
      path,
      "asking gitleaks for --report-path /dev/stdout silently returns an empty " +
        "report for EVERY repo, leaks and all. The runner then reports zero " +
        "secrets, forever, and every mocked test still passes.",
    ).not.toBe("/dev/stdout");
    // It must land in a dir we actually bind-mount read-write and then read back.
    const mounts = (dockerRunMock.mock.calls[0]![0] as { mountsRW?: Record<string, string> })
      .mountsRW!;
    expect(Object.keys(mounts).some((m) => path!.startsWith(m))).toBe(true);
  });

  it("reports every leak as critical — a leaked credential has no lesser severity", async () => {
    gitleaksWritesReport(
      JSON.stringify([
        { RuleID: "aws-key", Description: "AWS key", File: "a.ts", StartLine: 3, Commit: "abcdef1234" },
        { RuleID: "stripe", Description: "Stripe key", File: "b.ts", StartLine: 9 },
      ]),
    );
    const r = await derive(secretsRunner, ctx());
    const leaks = r.findings.filter((f) => f.severity !== "info");
    expect(leaks).toHaveLength(2);
    expect(leaks.every((f) => f.severity === "critical")).toBe(true);
    expect(r.meta?.leakCount).toBe(2);
  });

  it("de-dupes the same rule+file+line repeated across git history", async () => {
    const leak = { RuleID: "aws-key", Description: "AWS key", File: "a.ts", StartLine: 3 };
    gitleaksWritesReport(
      JSON.stringify([{ ...leak, Commit: "aaa" }, { ...leak, Commit: "bbb" }]),
    );
    const r = await derive(secretsRunner, ctx());
    expect(r.findings.filter((f) => f.severity === "critical")).toHaveLength(1);
  });

  it("reports a clean repo as clean — gitleaks leaves the report file EMPTY when it finds nothing", async () => {
    gitleaksWritesReport("");
    const r = await derive(secretsRunner, ctx());
    expect(r.status).toBe("ok");
    expect(r.findings).toEqual([]);
    expect(r.meta?.leakCount).toBe(0);
    expect(r.coverage?.data.commits).toBe(14);
  });
});

// ── zap.ts ────────────────────────────────────────────────────────────────────

/** zap.ts reads report.json out of the host dir it bind-mounts at /zap/wrk. */
function zapWritesReport(alerts: unknown[], stdout: string = ZAP_CRAWLED) {
  dockerRunMock.mockImplementation(async (opts: { mountsRW?: Record<string, string> }) => {
    const dir = opts.mountsRW?.["/zap/wrk"]!;
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "report.json"), JSON.stringify({ site: [{ alerts }] }));
    return ok(stdout);
  });
}

describe("zap.ts — riskcode mapping", () => {
  it("maps riskcode 3/2/1 onto high/medium/low and drops riskcode 0 (informational)", async () => {
    zapWritesReport([
      { alert: "SQL Injection", riskcode: "3", desc: "d", solution: "s", instances: [{ uri: "u" }] },
      { alert: "Missing CSP", riskcode: "2", desc: "d", solution: "s", instances: [{ uri: "u" }] },
      { alert: "Cookie no HttpOnly", riskcode: "1", desc: "d", solution: "s", instances: [{ uri: "u" }] },
      { alert: "Informational thing", riskcode: "0", desc: "d", solution: "s", instances: [{ uri: "u" }] },
    ]);
    const r = await derive(zapRunner, ctx());
    const sevOf = (title: string) =>
      r.findings.find((f) => f.title.startsWith(title))?.severity;
    expect(sevOf("SQL Injection")).toBe("high");
    expect(sevOf("Missing CSP")).toBe("medium");
    expect(sevOf("Cookie no HttpOnly")).toBe("low");
    expect(sevOf("Informational thing")).toBeUndefined(); // riskcode 0 → not a finding
  });

  it("de-dupes repeated alerts of the same name", async () => {
    zapWritesReport([
      { alert: "Missing CSP", riskcode: "2", instances: [{ uri: "u1" }] },
      { alert: "Missing CSP", riskcode: "2", instances: [{ uri: "u2" }] },
    ]);
    const r = await derive(zapRunner, ctx());
    expect(r.findings.filter((f) => f.severity !== "info")).toHaveLength(1);
  });

  it("strips HTML out of ZAP's solution/description prose", async () => {
    zapWritesReport([
      {
        alert: "Missing CSP",
        riskcode: "2",
        desc: "<p>A <b>description</b></p>",
        solution: "<p>Set a <code>header</code></p>",
        instances: [{ uri: "u" }],
      },
    ]);
    const r = await derive(zapRunner, ctx());
    const f = r.findings.find((x) => x.severity === "medium")!;
    expect(f.remediation).not.toMatch(/<[^>]+>/);
    expect(f.evidence).not.toMatch(/<[^>]+>/);
  });

  it("runs the passive baseline (never the active full-scan) against a remote target", async () => {
    zapWritesReport([]);
    const r = await derive(zapRunner, ctx({ baseUrl: "https://example.com" }));
    const args = dockerRunMock.mock.calls[0]![0].args as string[];
    expect(args[0]).toBe("zap-baseline.py");
    expect(r.note).toMatch(/passive baseline/);
  });

  it("runs the active full-scan only when the target is localhost AND --allow-active was passed", async () => {
    zapWritesReport([]);
    const c = ctx({ baseUrl: "http://localhost:3000" });
    c.run.isLocalhost = true;
    c.run.allowActive = true;
    const r = await derive(zapRunner, c);
    const args = dockerRunMock.mock.calls[0]![0].args as string[];
    expect(args[0]).toBe("zap-full-scan.py");
    expect(r.note).toMatch(/active full-scan/);
  });

  it("does NOT run the active full-scan on localhost without --allow-active", async () => {
    zapWritesReport([]);
    const c = ctx({ baseUrl: "http://localhost:3000" });
    c.run.isLocalhost = true;
    c.run.allowActive = false;
    await derive(zapRunner, c);
    const args = dockerRunMock.mock.calls[0]![0].args as string[];
    expect(args[0]).toBe("zap-baseline.py");
  });

  it("errors when ZAP produces no report", async () => {
    dockerRunMock.mockResolvedValue(ok(""));
    const r = await derive(zapRunner, ctx());
    expect(r.status).toBe("error");
  });
});

// ── 42L-973 #7: multi-endpoint hosts ───────────────────────────────────────
//
// testssl.sh loops the whole scan over EVERY resolved address unless told
// otherwise, concatenating the results — which is exactly why ds.42labs.io and
// 42piratas.com (both Cloudflare, both multi-IP) reported every TLS finding
// twice. Adversarial review then pointed out that the first fix (`--ip one`)
// stops the duplication but picks whichever address DNS happens to return
// first: non-deterministic across CI machines, and silent about the fact that
// other endpoints exist. So: pin the lowest sorted address, and say so.

describe("tlsRunner — endpoint pinning on multi-IP hosts (bug #7)", () => {
  function tlsWrites(entries: unknown[]) {
    dockerRunMock.mockImplementation(async (opts: { mountsRW?: Record<string, string> }) => {
      const dir = opts.mountsRW?.["/wrk"]!;
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, "out.json"), JSON.stringify(entries));
      return ok("");
    });
  }

  it("pins ONE deterministic endpoint — the lowest address in sorted order, not 'whatever DNS said first'", async () => {
    resolvedIps = ["104.21.90.166", "172.67.158.51"];
    tlsWrites([]);
    await derive(tlsRunner, ctx());

    const args = (dockerRunMock.mock.calls[0]![0] as { args: string[] }).args;
    const ip = args[args.indexOf("--ip") + 1];
    expect(ip).toBe("104.21.90.166"); // lowest sorted, regardless of DNS order
    // The hostname is still the scan target, so SNI/cert checks see the real name.
    expect(args[args.length - 1]).toBe("example.com");
  });

  it("picks the same endpoint no matter what order DNS returns the addresses in", async () => {
    resolvedIps = ["172.67.158.51", "104.21.90.166"]; // reversed
    tlsWrites([]);
    await derive(tlsRunner, ctx());
    const args = (dockerRunMock.mock.calls[0]![0] as { args: string[] }).args;
    expect(args[args.indexOf("--ip") + 1]).toBe("104.21.90.166");
  });

  it("states its own coverage on a multi-endpoint host rather than implying it scanned everything", async () => {
    resolvedIps = ["104.21.90.166", "172.67.158.51"];
    tlsWrites([]);
    const r = await derive(tlsRunner, ctx());

    const coverage = r.findings.find((f) => f.id === "tls-endpoint-coverage")!;
    expect(coverage).toBeDefined();
    expect(coverage.severity).toBe("info"); // never fails the build
    expect(coverage.needsReview).toBe(true); // but stays visible
    expect(coverage.title).toMatch(/1 of 2 resolved endpoints/);
    expect(r.meta).toMatchObject({ endpointsResolved: 2, endpointScanned: "104.21.90.166" });
  });

  it("says nothing about endpoint coverage on an ordinary single-endpoint host — no noise", async () => {
    resolvedIps = ["93.184.216.34"];
    // testssl always emits a record per test it ran, OK ones included — an
    // empty array would mean it never reached the host.
    tlsWrites([{ id: "TLS1_3", severity: "OK", finding: "offered" }]);
    const r = await derive(tlsRunner, ctx());
    expect(r.findings.find((f) => f.id === "tls-endpoint-coverage")).toBeUndefined();
    expect(r.note).toBeUndefined();
  });

  it("de-dupes identical (id, finding) pairs even if the scanner still emits them twice", async () => {
    // Defense in depth: the --ip pin is not the only thing standing between us
    // and a duplicated report.
    tlsWrites([
      { id: "BREACH", severity: "MEDIUM", finding: "potentially VULNERABLE" },
      { id: "BREACH", severity: "MEDIUM", finding: "potentially VULNERABLE" },
    ]);
    const r = await derive(tlsRunner, ctx());
    expect(r.findings.filter((f) => f.id === "tls-BREACH")).toHaveLength(1);
  });
});

// The behaviour that was silently untested until CI caught it: zap.ts probes
// the target BEFORE spending a container run. Nothing exercised the refusal
// path, so nothing noticed the probe was making a real network call.
describe("zapRunner — refuses to scan a target that isn't the site", () => {
  it("errors, and never starts a container, when the probe says the target is auth-gated", async () => {
    probeResult = {
      ok: false,
      note: "refusing to score — redirected to a known auth gate (labs42.cloudflareaccess.com)",
    };
    dockerRunMock.mockResolvedValue(ok(""));

    const r = await derive(zapRunner, ctx({ baseUrl: "https://ds.example.com" }));

    expect(r.status).toBe("error");
    expect(r.note).toMatch(/auth gate/);
    expect(r.findings).toHaveLength(0);
    // The point of probing first: don't burn a ZAP run on someone's login page.
    expect(dockerRunMock).not.toHaveBeenCalled();
  });

  it("errors, and never starts a container, when the target returns a non-2xx status", async () => {
    probeResult = { ok: false, note: "refusing to score — HTTP 429 — could not fetch the real page" };
    dockerRunMock.mockResolvedValue(ok(""));

    const r = await derive(zapRunner, ctx());

    expect(r.status).toBe("error");
    expect(r.note).toMatch(/429/);
    expect(dockerRunMock).not.toHaveBeenCalled();
  });
});

// ── The coverage holes (42L-1003) ────────────────────────────────────────────
//
// Every one of these is a scan that ran, exited 0, reported nothing, and was
// read as a clean bill of health. None of them examined anything. They are the
// reason "clean" is no longer something a runner is allowed to claim: it has to
// be derived from what the tool can prove it looked at.
//
// The tool outputs below are real — captured from the actual container images,
// not invented — because a fixture that guesses at the shape is exactly how the
// bug survived the last round of tests.

describe("a scan that examined nothing is never a clean scan", () => {
  it("secrets: gitleaks pointed at a directory that is not a git repo scans 0 commits, says 'no leaks found', and exits 0 — REFUSE", async () => {
    gitleaksWritesReport("", "0 commits scanned.\nscanned ~0 bytes (0) in 25.4ms\nno leaks found\n");
    const r = await derive(secretsRunner, ctx());
    expect(r.status).toBe("error");
    expect(r.note).toMatch(/0 commits/i);
    expect(r.note).toMatch(/not a git repository/i);
  });

  it("secrets: a repo whose history was read is clean, and says how much it read", async () => {
    gitleaksWritesReport("");
    const r = await derive(secretsRunner, ctx());
    expect(r.status).toBe("ok");
    expect(r.coverage?.data.commits).toBe(14);
    expect(r.coverage?.data.bytes).toBe(554058);
  });

  it("sast: semgrep with no source it understands scans 0 files, returns results:[], exits 0 — REFUSE", async () => {
    dockerRunMock.mockResolvedValue(
      ok(JSON.stringify({ results: [], errors: [], paths: { scanned: [] } })),
    );
    const r = await derive(sastRunner, ctx());
    expect(r.status).toBe("error");
    expect(r.note).toMatch(/scanned 0 files/i);
  });

  it("sast: a repo semgrep actually read is clean, and says how many files it read", async () => {
    dockerRunMock.mockResolvedValue(
      ok(
        JSON.stringify({
          results: [],
          errors: [],
          paths: { scanned: ["/src/a.ts", "/src/b.ts"] },
        }),
      ),
    );
    const r = await derive(sastRunner, ctx());
    expect(r.status).toBe("ok");
    expect(r.findings).toEqual([]);
    expect(r.coverage?.data.filesScanned).toBe(2);
  });

  it("zap: a spider that reached 0 URLs found no alerts because it never entered the app — REFUSE", async () => {
    zapWritesReport([], "FAIL-NEW: 0\tFAIL-INPROG: 0\tWARN-NEW: 0\tWARN-INPROG: 0\tINFO: 0\tIGNORE: 0\tPASS: 58\n");
    const r = await derive(zapRunner, ctx());
    expect(r.status).toBe("error");
    expect(r.note).toMatch(/spider reached 0 URLs/i);
  });

  it("zap: a scan that crawled the app is clean, and says how far it got", async () => {
    zapWritesReport([]);
    const r = await derive(zapRunner, ctx());
    expect(r.status).toBe("ok");
    expect(r.findings).toEqual([]);
    expect(r.coverage?.data.urlsSpidered).toBe(12);
    expect(r.coverage?.data.rulesRun).toBe(61);
  });

  it("tls: testssl that performed no tests never reached the host — REFUSE", async () => {
    tlsWritesJson([]);
    const r = await derive(tlsRunner, ctx());
    expect(r.status).toBe("error");
    expect(r.note).toMatch(/performed no tests/i);
  });
});
