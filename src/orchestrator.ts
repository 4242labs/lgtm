import { existsSync } from "node:fs";
import pc from "picocolors";
import type {
  AuditReport,
  Capabilities,
  Runner,
  RunnerContext,
  RunnerResult,
  SiteConfig,
  RunContext,
} from "./types.js";
import { ALL_RUNNERS } from "./runners/index.js";
import { resolveUrls } from "./config.js";
import { hasDocker } from "./util/docker.js";
import { isLocalhostUrl } from "./util/http.js";
import { tallySeverities, computePass, realFindings, derive } from "./scoring.js";

export interface OrchestratorOptions {
  site: SiteConfig;
  /** Effective base URL (config or --url). */
  baseUrl: string;
  outDir: string;
  stamp: string;
  allowActive: boolean;
  /** Explicit runner subset (--only); defaults to all not in site.skip. */
  only?: string[];
  log?: (msg: string) => void;
}

/**
 * Decide whether a runner can run given site config + host capabilities.
 *
 * `excused` separates the two kinds of "did not run". A localhost-only probe
 * against production has nothing to audit — nothing was missed. A missing
 * repoPath or a missing Docker daemon means the domain applies perfectly well
 * and we simply never looked: that is a coverage hole, and the run must not
 * pass on it. Every requirement declared in `requires` is enforced here, once,
 * rather than re-implemented (and half-forgotten) inside each runner.
 */
function gate(
  runner: Runner,
  site: SiteConfig,
  caps: Capabilities,
  run: RunContext,
): { ok: true } | { ok: false; note: string; excused: boolean } {
  const req = runner.requires;
  if (req.repo && !site.repoPath) {
    return {
      ok: false,
      excused: false,
      note: "no repoPath configured — this domain was never scanned",
    };
  }
  if (req.repo && site.repoPath && !existsSync(site.repoPath)) {
    return {
      ok: false,
      excused: false,
      note: `repoPath does not exist: ${site.repoPath}`,
    };
  }
  if (req.docker && !caps.docker) {
    return {
      ok: false,
      excused: false,
      note: "docker unavailable — this containerised scanner never ran",
    };
  }
  if (req.browser && !caps.browser) {
    return {
      ok: false,
      excused: false,
      note: "no browser available — this domain was never audited",
    };
  }
  if (req.target && !run.baseUrl) {
    return {
      ok: false,
      excused: false,
      note: "no target URL — this domain was never audited",
    };
  }
  if (req.localhostOnly && !run.isLocalhost) {
    return {
      ok: false,
      excused: true,
      note: "not applicable — this probe only runs against localhost",
    };
  }
  return { ok: true };
}

/**
 * Thrown by assertKnownRunners, and only by it.
 *
 * The refusal itself is unchanged — a named type is what lets a caller tell
 * "the operator typed a runner id that does not exist" apart from "a runner
 * crashed mid-audit", without matching on message text. cli.ts uses it to
 * print this as an operator error and exit 2; every other caller keeps the
 * throw, and anything that is not this class keeps its stack trace.
 */
export class UnknownRunnerError extends Error {
  readonly name = "UnknownRunnerError";
}

/**
 * A runner id nobody recognises is a typo, and a typo must never quietly widen
 * into a waiver.
 *
 * `--only cookie` (for `cookies`) matched no runner, so EVERY runner failed the
 * `only.includes(r.id)` test, every one was waived, the run had ten waivers and
 * zero holes — and it printed "PASS: every domain audited". A green build in
 * which not one scanner executed, reachable by a single mistyped character.
 * Unknown ids are refused up front instead.
 */
function assertKnownRunners(kind: string, ids: string[] | undefined): void {
  const unknown = (ids ?? []).filter((id) => !ALL_RUNNERS.some((r) => r.id === id));
  if (unknown.length > 0) {
    throw new UnknownRunnerError(
      `unknown runner id${unknown.length === 1 ? "" : "s"} in ${kind}: ${unknown.join(", ")}. ` +
        `Known runners: ${ALL_RUNNERS.map((r) => r.id).join(", ")}`,
    );
  }
}

export async function runAudit(opts: OrchestratorOptions): Promise<AuditReport> {
  const log = opts.log ?? (() => {});
  const startedAt = new Date().toISOString();

  assertKnownRunners("--only", opts.only);
  assertKnownRunners("the site config's `skip:`", opts.site.skip);

  const run: RunContext = {
    baseUrl: opts.baseUrl,
    isLocalhost: isLocalhostUrl(opts.baseUrl),
    allowActive: opts.allowActive,
    outDir: opts.outDir,
    stamp: opts.stamp,
  };

  const caps: Capabilities = {
    docker: await hasDocker(),
    browser: true,
  };

  const urls = resolveUrls(opts.baseUrl, opts.site.routes);

  // Every runner is accounted for. One the operator excluded (`--only`, or
  // `skip:` in the site config) is a waiver — on the record, still reported,
  // and it does not fail the run. One that simply never ran is a coverage
  // hole, and does.
  const waived = (r: Runner): boolean =>
    opts.only?.length
      ? !opts.only.includes(r.id)
      : (opts.site.skip ?? []).includes(r.id);

  const ctx: RunnerContext = {
    site: opts.site,
    run,
    urls,
    caps,
    log,
  };

  const results: RunnerResult[] = [];
  for (const runner of ALL_RUNNERS) {
    if (waived(runner)) {
      results.push({
        runnerId: runner.id,
        domain: runner.domain,
        status: "skipped",
        note: "waived by the operator — this domain was not audited",
        findings: [],
        durationMs: 0,
        waived: true,
      });
      continue;
    }

    const g = gate(runner, opts.site, caps, run);
    if (!g.ok) {
      log(`${pc.dim("skip")}  ${runner.id} — ${g.note}`);
      results.push({
        runnerId: runner.id,
        domain: runner.domain,
        status: "skipped",
        note: g.note,
        findings: [],
        durationMs: 0,
        waived: g.excused,
      });
      continue;
    }

    log(`${pc.cyan("run ")}  ${runner.id} — ${runner.title}`);
    const start = Date.now();
    let res: RunnerResult;
    try {
      res = await derive(runner, ctx, start);
    } catch (err) {
      res = {
        runnerId: runner.id,
        domain: runner.domain,
        status: "error",
        note: (err as Error).message,
        findings: [],
        durationMs: Date.now() - start,
      };
    }
    const n = realFindings(res.findings).length;
    const tag =
      res.status === "error"
        ? pc.red("err ")
        : res.status === "skipped"
          ? pc.yellow("skip")
          : n > 0
            ? pc.yellow(`${n} issue${n === 1 ? "" : "s"}`)
            : pc.green("clean");
    log(
      `      ↳ ${tag} ${res.note ? pc.dim(`(${res.note})`) : ""} ${pc.dim(`${res.durationMs}ms`)}`,
    );
    results.push(res);
  }

  const totals = tallySeverities(results);
  const notAudited = results
    .filter((r) => r.status === "skipped")
    .map((r) => ({
      runnerId: r.runnerId,
      reason: r.note ?? "not run",
      waived: Boolean(r.waived),
    }));
  // A domain nobody audited cannot be reported as sound. An unwaived gap fails
  // the run for the same reason an empty scan does — no evidence, no pass.
  const complete = notAudited.every((n) => n.waived);
  const passed = computePass(results, opts.site.failOn) && complete;

  return {
    site: opts.site.name,
    label: opts.site.label,
    baseUrl: opts.baseUrl,
    stamp: opts.stamp,
    startedAt,
    finishedAt: new Date().toISOString(),
    isLocalhost: run.isLocalhost,
    allowActive: opts.allowActive,
    results,
    totals,
    passed,
    complete,
    notAudited,
    failOn: opts.site.failOn,
  };
}
