import type {
  Coverage,
  Finding,
  Runner,
  RunnerContext,
  RunnerOutcome,
} from "../types.js";
import { dockerRun } from "../util/docker.js";
import { exec } from "../util/exec.js";

// Static analysis via Semgrep (container) using curated security rulesets.
// White-box: needs the repo checkout. Ruleset fetch needs network.

const IMAGE = "semgrep/semgrep:latest";
const CONFIGS = ["p/security-audit", "p/secrets", "p/owasp-top-ten", "p/javascript", "p/typescript"];

// Scan scope. A PR gate answers "does THIS change add a finding" — so when the
// caller sets LGTM_SAST_BASELINE_REF (the gate sets it to the PR's base SHA),
// semgrep runs diff-aware (`--baseline-commit`): it scans HEAD and the baseline
// and reports only findings NEW since that ref, so pre-existing findings in
// untouched files never fail a PR. Unset (e.g. the scheduled sweep) → full-tree
// scan, which owns the backlog. Diff mode needs git inside the container to
// reach the baseline, so the checkout is mounted read-write and git safe.directory
// is pre-set to dodge the "dubious ownership" refusal on the foreign-uid mount.
//
// Read per-call (not hoisted to a module constant) so tests can set the env
// var per-case without fighting module-load ordering.
function baselineRef(): string {
  return process.env.LGTM_SAST_BASELINE_REF?.trim() || "";
}

/**
 * `git diff --numstat` renders a binary file's add/delete counts as the
 * literal string "-" — the only signal numstat gives for "no computable
 * content diff". That is exactly the class of change (a regenerated
 * screenshot, a deleted doc) a text-based scanner never had an opinion on.
 * True iff at least one line is a real, non-binary content change.
 */
export function numstatHasTextChanges(numstat: string): boolean {
  return numstat
    .split("\n")
    .filter(Boolean)
    .some((line) => {
      const [added, deleted] = line.split("\t");
      return added !== "-" && deleted !== "-";
    });
}

/**
 * Does the diff against `ref` touch any non-binary added/modified/renamed
 * file? `--diff-filter=ACMR` drops pure deletions — nothing is left at HEAD
 * for a scanner to read — so a diff that is entirely deletions and/or binary
 * assets comes back false. Returns null ("couldn't tell") on any git
 * failure, so the caller falls through to the real scan instead of silently
 * skipping it on an infra hiccup.
 */
async function diffTouchesText(repo: string, ref: string): Promise<boolean | null> {
  const r = await exec("git", ["diff", "--diff-filter=ACMR", "--numstat", ref, "HEAD"], {
    cwd: repo,
    timeoutMs: 30_000,
  });
  if (r.code !== 0) return null;
  return numstatHasTextChanges(r.stdout);
}

const SEVERITY_MAP: Record<string, Finding["severity"]> = {
  ERROR: "high",
  WARNING: "medium",
  INFO: "low",
};

interface SemgrepOutput {
  results?: Array<{
    check_id?: string;
    path?: string;
    start?: { line?: number };
    extra?: { severity?: string; message?: string; metadata?: { cwe?: string[] } };
  }>;
  errors?: Array<{ message?: string }>;
  /** Semgrep's own record of what it read. `scanned` is the file list. */
  paths?: { scanned?: string[] };
}

export const sastRunner: Runner = {
  id: "sast",
  domain: "sast",
  title: "Static analysis (Semgrep)",
  requires: { repo: true, docker: true },

  /**
   * Semgrep reports `results: []` whether it found nothing wrong or read
   * nothing at all — point it at a repo whose languages none of the rulesets
   * cover and it scans zero files, exits 0, and looks spotless. `paths.scanned`
   * is the file list it actually opened, and an empty one is not a pass.
   */
  sufficient(cov: Coverage): string | null {
    if (Number(cov.data.filesScanned ?? 0) === 0) {
      return "semgrep scanned 0 files — no source the rulesets understand was found";
    }
    return null;
  },

  async observe(ctx: RunnerContext): Promise<RunnerOutcome> {
    const repo = ctx.site.repoPath!;
    const ref = baselineRef();

    // Diff-aware mode: semgrep --baseline-commit only opens files that differ
    // from the baseline, so "0 files scanned" is the EXPECTED result when a
    // PR's diff is entirely deletions and/or binary assets (docs pruned,
    // screenshots regenerated) — there is no source a text-based scanner
    // could ever have an opinion on. Checked with plain git, before spending
    // a container run on a scan that can only come back empty. A full-tree
    // sweep (ref unset) always proceeds and keeps the original guard below:
    // that path is exactly what catches a repo whose language nothing here
    // understands, and it must keep failing on it.
    if (ref) {
      const hasText = await diffTouchesText(repo, ref);
      if (hasText === false) {
        return {
          kind: "notApplicable",
          note: `diff against ${ref.slice(0, 8)} touches no non-binary added/modified file — nothing for static analysis to scan`,
        };
      }
    }

    const findings: Finding[] = [];
    const configArgs = CONFIGS.flatMap((c) => ["--config", c]);
    const r = await dockerRun({
      image: IMAGE,
      // Bound semgrep's resource use so it degrades gracefully instead of
      // OOM-dying with no output — the failure mode that ran ~24 min then exited
      // by signal on a large TS repo (alfred-app), leaving the gate un-passable.
      //   --max-memory: per-rule×file RAM cap (MiB); an oversized target is
      //     SKIPPED (surfaced as a scan error) rather than blowing up the process.
      //   --jobs 1: this cap is PER WORKER, and semgrep otherwise forks
      //     ~cores workers — on a multi-core runner N × the cap can still exceed
      //     host RAM. Pinning one worker makes the ceiling deterministic
      //     (~4 GB + base) and safe on the 7 GB GitHub-hosted runner regardless
      //     of core count; a gate must be reliable before fast.
      //   --timeout / --timeout-threshold: bound pathological rule×file combos
      //     the previous `--timeout 0` (unbounded) let hang indefinitely.
      args: [
        "semgrep",
        "scan",
        ...configArgs,
        "--json",
        "--quiet",
        "--jobs",
        "1",
        "--timeout",
        "120",
        "--timeout-threshold",
        "3",
        "--max-memory",
        "4000",
        // Diff-aware when the caller passes a baseline: only findings introduced
        // since that ref are reported (the gate sets it to the PR base SHA).
        ...(ref ? ["--baseline-commit", ref] : []),
        "/src",
      ],
      // Full scan is read-only; diff mode needs git to reach the baseline commit,
      // so mount RW and pre-declare /src a safe.directory (foreign-uid mount).
      ...(ref
        ? {
            mountsRW: { "/src": repo },
            extra: [
              "-e",
              "GIT_CONFIG_COUNT=1",
              "-e",
              "GIT_CONFIG_KEY_0=safe.directory",
              "-e",
              "GIT_CONFIG_VALUE_0=/src",
            ],
          }
        : { mounts: { "/src": repo } }),
      timeoutMs: 900_000,
    });

    // A clean semgrep --json run always emits at least `{"results":[]}`. If
    // semgrep dies before writing anything, stdout has no `{` at all — the
    // old code's `if (s >= 0)` guard meant that case skipped the parse
    // entirely without throwing, `out` stayed `{}`, and a crashed scan
    // reported "No Semgrep findings": a gate going green on a repo that was
    // never scanned. Both "no `{` at all" and "what follows it doesn't
    // parse" are the same failure and must both error.
    const s = r.stdout.indexOf("{");
    if (s < 0) {
      return {
        kind: "failed",
        note: `semgrep produced no parseable output (exit ${r.code}): ${(r.stderr || r.stdout).slice(0, 300)}`,
      };
    }
    let out: SemgrepOutput;
    try {
      out = JSON.parse(r.stdout.slice(s));
    } catch (err) {
      return {
        kind: "failed",
        note: `semgrep produced unparseable JSON: ${(err as Error).message}`,
      };
    }

    // Collapse repeated rule hits to the top 100 by severity to keep signal.
    const seen = new Set<string>();
    for (const res of out.results ?? []) {
      const rel = (res.path ?? "").replace(/^\/src\/?/, "");
      const key = `${res.check_id}:${rel}:${res.start?.line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const sev = SEVERITY_MAP[res.extra?.severity ?? "INFO"] ?? "low";
      const cwe = res.extra?.metadata?.cwe?.[0];
      findings.push({
        id: `sast-${res.check_id ?? "rule"}`,
        title: `${(res.extra?.message ?? res.check_id ?? "").slice(0, 140)}`,
        severity: sev,
        standard: cwe ?? "Semgrep",
        location: `${rel}:${res.start?.line ?? ""}`,
        remediation: `Rule ${res.check_id}. Review and remediate per the rule guidance.`,
      });
    }

    const scanned = out.paths?.scanned ?? [];

    return {
      kind: "observed",
      note: out.errors?.length ? `${out.errors.length} scan error(s)` : undefined,
      findings,
      coverage: {
        trail: [
          `scanned ${scanned.length} file${scanned.length === 1 ? "" : "s"} against ${CONFIGS.length} rulesets (${CONFIGS.join(", ")})`,
        ],
        data: { filesScanned: scanned.length, rulesets: CONFIGS.length },
        provenance: "semgrep --json paths.scanned",
      },
      meta: { filesScanned: scanned.length },
    };
  },
};
