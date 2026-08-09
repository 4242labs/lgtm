import {
  mkdirSync,
  readFileSync,
  writeFileSync,
  existsSync,
  rmSync,
  chmodSync,
} from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import type {
  Coverage,
  Finding,
  Runner,
  RunnerContext,
  RunnerOutcome,
} from "../types.js";
import { dockerRun, transientInfraFailure } from "../util/docker.js";
import { exec } from "../util/exec.js";

// Leaked-credential scan via gitleaks (container), over the repo's git history
// and working tree. White-box: needs the repo checkout.

const IMAGE = "ghcr.io/gitleaks/gitleaks:latest";

// Scan scope. A PR gate answers one question — "does THIS change add a secret" —
// so it scans only the PR's commit range (base..head), set by the caller via
// LGTM_SECRETS_LOG_OPTS. That is O(PR size), not O(full history): seconds on any
// repo, and it does not fail a PR on a pre-existing secret it never touched.
// Unset (e.g. the scheduled full-history sweep) → gitleaks walks all history, the
// only place that catches a secret committed-then-deleted in old history.
const LOG_OPTS = process.env.LGTM_SECRETS_LOG_OPTS?.trim() || "";

// Baseline config shipped beside this file. `useDefault = true` keeps the full
// upstream ruleset and only adds an allowlist for hash-shaped literals (content
// hashes, SRI integrity) that the generic-api-key rule otherwise reports as
// critical secrets. Resolved from the module URL, not cwd, so it works whatever
// directory the CLI is invoked from.
const BASELINE_CONFIG = fileURLToPath(
  new URL("./gitleaks-baseline.toml", import.meta.url),
);

// gitleaks scans the FULL git history. On large repos (thousands of commits,
// 100 MB+ packs) the old 5-min cap killed the container before it wrote a
// report, which fail-closes the gate with an opaque "wrote no report (exit -1)"
// on EVERY run — a false fail, not a detected secret. Mirror the sast runner's
// large-repo hardening (PR #17: 15-min semgrep cap): default to 15 min, and let
// pathological histories raise it via LGTM_SECRETS_TIMEOUT_MS without a rebuild.
const DEFAULT_TIMEOUT_MS = 900_000;
const TIMEOUT_MS =
  Number(process.env.LGTM_SECRETS_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS;

interface Leak {
  Description?: string;
  File?: string;
  StartLine?: number;
  RuleID?: string;
  Commit?: string;
  Secret?: string;
}

/**
 * gitleaks says what it did on stderr and nowhere else:
 *
 *   INF 14 commits scanned.
 *   INF scanned ~554058 bytes (554.06 KB) in 338ms
 *   INF no leaks found
 *
 * Point it at a directory that is not a git repo and it prints "0 commits
 * scanned", "no leaks found", and exits 0 — a clean bill of health for a scan
 * that read nothing. The commit and byte counts are the only way to tell that
 * apart from a genuinely clean repo, so they are the coverage.
 */
function scanLog(stderr: string): { commits: number; bytes: number } {
  const commits = stderr.match(/(\d+) commits scanned/);
  const bytes = stderr.match(/scanned ~(\d+) bytes/);
  return {
    commits: commits ? Number(commits[1]) : 0,
    bytes: bytes ? Number(bytes[1]) : 0,
  };
}

/**
 * Corroborate an empty-evidence scoped scan against git.
 *
 * gitleaks in --log-opts mode scans only the ADDED TEXT of the diff. A file it
 * cannot diff — a binary/undiffable blob (keystore, archive, anything git marks
 * binary) — contributes no scannable bytes AND, when it is the only change in a
 * commit, is not even counted as a "commit scanned". So a range that *adds a
 * secret inside a binary file* comes back "0 commits / ~0 bytes / no leaks" —
 * indistinguishable, on gitleaks' output alone, from a range that added nothing
 * at all. Passing the gate on that absence is a bypass.
 *
 * git settles it, walked the SAME way gitleaks walks — commit by commit over
 * `git log <range>`, not a single net `git diff`. Per-commit matters: a binary
 * secret added in one commit of the range and deleted in a later one nets to
 * nothing in a `diff` but still ships in history under a merge/rebase-merge, and
 * `git log`'s two-dot range semantics match gitleaks' exactly (a net `diff`'s do
 * not). `--diff-filter=ACMRT` keeps every way content ENTERS the tree — added,
 * copied, modified, renamed, and TYPE-CHANGED (symlink/gitlink → regular file,
 * status `T`, which a bare ACMR silently drops) — and excludes pure deletions;
 * `-M` resolves renames so an unchanged rename reads 0/0, not a fake add. A
 * binary file shows its add-count as the literal "-"; a text file shows a
 * number. So the range added content gitleaks needed to read iff any numstat
 * line's add-count is anything other than "0" (a positive count = added text
 * gitleaks somehow missed; "-" = an unscannable file it never opened).
 *
 * Returns the split — text the range added (a positive add-count) and the
 * undiffable blobs it added (add-count "-"), each tagged with the commit that
 * introduced it so the blob can be read back even if a later commit in the
 * range deleted it. Null means the range could not be corroborated (log-opts is
 * not a plain base..head range, or git failed) and the caller fails closed.
 */
export interface RangeContent {
  /** Some file in the range gained readable text gitleaks should have seen. */
  addedText: boolean;
  /** Blobs git marks undiffable — gitleaks never opened these. */
  undiffable: { commit: string; path: string }[];
}

export async function rangeAddedContent(
  repo: string,
  logOpts: string,
): Promise<RangeContent | null> {
  // Only a plain `base..head` (or `base...head`) range is safe to hand to git.
  // Each endpoint must start alphanumeric and hold only ref-safe characters:
  // this rejects a leading "-" (which git parses as a FLAG, not a rev — e.g.
  // `--output=/tmp/x..y` would slip past a laxer `[^\s]+` and become an
  // arbitrary-file-write argv injection) as well as anything with whitespace.
  if (!/^[A-Za-z0-9][\w./-]*\.\.\.?[A-Za-z0-9][\w./-]*$/.test(logOpts)) return null;
  // `--format=%H` stamps each commit before its own numstat block, so an
  // undiffable path stays tied to the commit that introduced it.
  const r = await exec(
    "git",
    ["log", "--diff-filter=ACMRT", "--numstat", "--format=%H", "-M", logOpts],
    { cwd: repo, timeoutMs: 30_000 },
  );
  if (r.code !== 0) return null;

  const out: RangeContent = { addedText: false, undiffable: [] };
  let commit = "";
  for (const line of r.stdout.split("\n")) {
    if (!line) continue;
    if (/^[0-9a-f]{40}$/.test(line)) {
      commit = line;
      continue;
    }
    const cols = line.split("\t");
    const adds = cols[0];
    // `-M` renders a rename as "old => new" or "pre{old => new}post"; the blob
    // lives at the NEW path, which is what has to be read back.
    const path = renamedTo(cols[cols.length - 1] ?? "");
    if (adds === "-") {
      if (path) out.undiffable.push({ commit, path });
    } else if (adds !== "0") {
      out.addedText = true;
    }
  }
  return out;
}

/** Resolve git's rename notation to the path the blob ends up at. */
export function renamedTo(spec: string): string {
  const braced = spec.match(/^(.*)\{.* => (.*)\}(.*)$/);
  if (braced) return `${braced[1]}${braced[2]}${braced[3]}`.replace(/\/\//g, "/");
  const plain = spec.match(/^.* => (.*)$/);
  return plain?.[1] ?? spec;
}

/**
 * The boolean the gate used before blobs were read directly: did the range add
 * anything gitleaks needed to read but did not?
 */
export async function rangeAddsUnscannedContent(
  repo: string,
  logOpts: string,
): Promise<boolean | null> {
  const r = await rangeAddedContent(repo, logOpts);
  if (r === null) return null;
  return r.addedText || r.undiffable.length > 0;
}

/**
 * The `strings(1)` view of a blob: every run of printable ASCII at least
 * `min` long, one per line. Short runs are dropped because they are noise, not
 * credentials — every secret pattern gitleaks knows is longer than that.
 */
export function printableRuns(buf: Buffer, min = 6): string {
  const out: string[] = [];
  let run = "";
  for (const byte of buf) {
    // Printable ASCII plus tab: the bytes a credential can be written in.
    if ((byte >= 0x20 && byte <= 0x7e) || byte === 0x09) {
      run += String.fromCharCode(byte);
    } else {
      if (run.length >= min) out.push(run);
      run = "";
    }
  }
  if (run.length >= min) out.push(run);
  return out.length ? out.join("\n") + "\n" : "";
}

interface BlobScan {
  /** How many of the range's undiffable blobs were materialized and scanned. */
  scanned: number;
  /** Bytes the filesystem pass reported reading — the evidence of real work. */
  bytes: number;
  leaks: Leak[];
}

/**
 * Read the undiffable blobs back out of git and scan them directly.
 *
 * gitleaks in `--log-opts` mode only ever sees diff text, so a blob git marks
 * binary passes through the gate unread. Refusing on that absence is safe but
 * useless: it blocks every PR that ships a PDF, an image or a font, and it
 * still never looks inside the one file that could be hiding a key.
 *
 * Handing gitleaks the blob itself does not help — it skips binaries in every
 * mode (verified against the pinned image: a file holding a live-shaped AWS key
 * between NUL bytes scans as "~0 bytes, no leaks"). So the blob is reduced to
 * what a scanner can actually read: its printable runs, the `strings(1)` view,
 * written to a text sidecar that gitleaks then scans for real. A key pasted into
 * a PDF, a keystore, an image comment or a font table lands in those runs and is
 * caught — which the old refusal never did.
 *
 * The residual is compression: a secret inside a deflated PDF stream or a zip
 * member has no printable run to find, so a clean result here means "no secret
 * in the readable bytes", not "no secret". That is stated in the trail rather
 * than papered over, and it is strictly more evidence than refusing to look.
 *
 * `git cat-file` pulls each blob out of the commit that introduced it, so one
 * added and deleted inside the range is still examined. Returns null if any blob
 * could not be read or the scan produced no report — the caller then keeps the
 * old refusal rather than certifying on a partial look.
 */
async function scanUndiffableBlobs(
  repo: string,
  blobs: { commit: string; path: string }[],
  work: string,
): Promise<BlobScan | null> {
  const dir = join(work, "blobs");
  mkdirSync(dir, { recursive: true });
  chmodSync(dir, 0o777); // the image runs as a non-root uid

  let scanned = 0;
  for (const [i, blob] of blobs.entries()) {
    const r = await exec("git", ["cat-file", "blob", `${blob.commit}:${blob.path}`], {
      cwd: repo,
      timeoutMs: 30_000,
      encoding: "buffer",
    });
    if (r.code !== 0) return null;
    // Flatten to an index-prefixed basename: no path traversal out of the mount,
    // no collisions between same-named files from different directories.
    const safe = (blob.path.split("/").pop() || "blob").replace(/[^\w.-]/g, "_");
    const text = printableRuns(r.stdoutRaw ?? Buffer.from(r.stdout));
    writeFileSync(join(dir, `${i}-${safe}.strings.txt`), text);
    scanned++;
  }
  if (scanned === 0) return null;

  const reportPath = join(work, "gitleaks-blobs.json");
  const r = await dockerRun({
    image: IMAGE,
    args: [
      "dir",
      "/blobs",
      "--config",
      "/config/gitleaks.toml",
      "--report-format",
      "json",
      "--report-path",
      "/out/gitleaks-blobs.json",
      "--redact",
      "--no-banner",
      "--exit-code",
      "0",
    ],
    mounts: { "/config/gitleaks.toml": BASELINE_CONFIG },
    mountsRW: { "/out": work, "/blobs": dir },
    timeoutMs: TIMEOUT_MS,
    retryOn: (res) => !res.timedOut && transientInfraFailure(res),
  });
  if (!existsSync(reportPath)) return null;

  const raw = readFileSync(reportPath, "utf8").trim();
  let leaks: Leak[] = [];
  if (raw.length > 0) {
    try {
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) return null;
      leaks = parsed;
    } catch {
      return null;
    }
  }
  const { bytes } = scanLog(r.stderr);
  // A pass that read nothing is not evidence, whatever it reported.
  if (bytes === 0) return null;
  // Report the real path, not the flattened scratch name.
  for (const leak of leaks) {
    const m = leak.File?.match(/(?:^|\/)(\d+)-/);
    const src = m ? blobs[Number(m[1])] : undefined;
    if (src) leak.File = src.path;
  }
  return { scanned, bytes, leaks };
}

export const secretsRunner: Runner = {
  id: "secrets",
  domain: "secrets",
  title: "Leaked secrets (gitleaks)",
  requires: { repo: true, docker: true },

  sufficient(cov: Coverage): string | null {
    const commits = Number(cov.data.commits ?? 0);
    const bytes = Number(cov.data.bytes ?? 0);

    // The scan examined real content — gitleaks walked commits AND read bytes.
    if (commits > 0 && bytes > 0) return null;

    // Empty evidence: gitleaks examined no content (0 commits, or 0 scanned
    // bytes). For an UNSCOPED full-history scan that is a real anomaly — a path
    // that is not a git repo / has no history (0 commits), or blobs it could
    // not read (0 bytes) — so refuse.
    if (!cov.data.scoped) {
      return commits === 0
        ? "gitleaks scanned 0 commits — the path is not a git repository, or has no history"
        : "gitleaks read 0 bytes — nothing was actually examined";
    }

    // SCOPED PR gate with empty evidence. This is clean ONLY if the PR's range
    // added no content gitleaks needed to read: a range that is pure deletions
    // (or rename/mode-only) introduced nothing that could carry a secret. But
    // gitleaks reports "no content" identically whether the range added nothing
    // or added a file it could not scan (a binary/undiffable blob that may hide
    // a secret) — so absence of evidence alone must not pass. `addedContent` is
    // git's numstat corroboration of which case this is.
    if (cov.data.addedContent === false) return null;
    if (cov.data.addedContent === true) {
      // The blobs gitleaks could not diff were read back and scanned directly
      // (filesystem mode), so the range IS covered — by a second pass whose own
      // byte count is the evidence. Only certify when every undiffable blob was
      // scanned and that pass actually read bytes.
      const total = Number(cov.data.undiffableBlobs ?? 0);
      const scanned = Number(cov.data.undiffableScanned ?? 0);
      const blobBytes = Number(cov.data.undiffableBytes ?? 0);
      if (total > 0 && scanned === total && blobBytes > 0) return null;
      return "gitleaks examined no content, but the PR added a file it could not scan (binary/undiffable) — cannot certify no secret was introduced";
    }
    // null: the range could not be corroborated (log-opts is not a plain
    // base..head range, or git failed) — fail closed rather than certify blind.
    return "gitleaks examined no content and the PR range could not be corroborated — refusing to certify a clean result";
  },

  async observe(ctx: RunnerContext): Promise<RunnerOutcome> {
    const findings: Finding[] = [];
    const repo = ctx.site.repoPath!;

    // The report goes to a FILE in a bind-mounted work dir, never to
    // `--report-path /dev/stdout`.
    //
    // gitleaks accepts /dev/stdout without complaint and then writes nothing to
    // it — verified against the pinned image (v8.30.1): a repo with two planted
    // AWS keys logs "leaks found: 2" on stderr and delivers 0 bytes on stdout,
    // while the same scan pointed at a real path writes a 1223-byte JSON array.
    // This runner read stdout. It has therefore never reported a single leaked
    // secret: every repo, clean or compromised, came back with nothing to say.
    // The old code was accidentally shielded from shipping that as a pass (it
    // read empty stdout as a crash and errored); reading it as "clean" — which
    // is what an evidence contract SHOULD do with a scan that examined 14
    // commits and found nothing — would have turned a loud wrong answer into a
    // silent one. The bug is the flag, so fix the flag.
    const work = join(process.cwd(), "reports", ".work", `secrets-${ctx.run.stamp}`);
    mkdirSync(work, { recursive: true });
    chmodSync(work, 0o777); // the image runs as a non-root uid
    const reportPath = join(work, "gitleaks.json");

    try {
      const r = await dockerRun({
        image: IMAGE,
        args: [
          "detect",
          "--source",
          "/repo",
          "--config",
          "/config/gitleaks.toml",
          "--report-format",
          "json",
          "--report-path",
          "/out/gitleaks.json",
          "--redact",
          "--no-banner",
          "--exit-code",
          "0", // findings are not a failure — we read the report ourselves
          // Scope to the PR's commits when the caller sets a range; otherwise
          // full history (the scheduled sweep). One flag reused, never spliced.
          ...(LOG_OPTS ? ["--log-opts", LOG_OPTS] : []),
        ],
        mounts: { "/repo": repo, "/config/gitleaks.toml": BASELINE_CONFIG },
        mountsRW: { "/out": work },
        timeoutMs: TIMEOUT_MS,
        // A wall-clock timeout on this CPU-bound scan is deterministic, not a
        // transient blip — re-running the same too-big scan just burns another
        // full budget (the 3x-timeout amplification we saw on hiresling-meta:
        // 3 x 900s = 45min). Retry only genuine transients (OOM/network), never
        // the timeout itself.
        retryOn: (res) => !res.timedOut && transientInfraFailure(res),
      });

      const { commits, bytes } = scanLog(r.stderr);

      // No report file at all means gitleaks never got as far as writing one:
      // a bad flag, a crash, a killed container. That is unknown, not clean.
      if (!existsSync(reportPath)) {
        // Distinguish the large-repo timeout (the common false-fail) from a real
        // crash so the fix is actionable, not an opaque "exit -1".
        if (r.timedOut) {
          return {
            kind: "failed",
            note: `gitleaks timed out after ${Math.round(TIMEOUT_MS / 1000)}s scanning full history (${commits} commits, ${bytes} bytes read before the kill) — raise LGTM_SECRETS_TIMEOUT_MS for very large repos.`,
          };
        }
        return {
          kind: "failed",
          note: `gitleaks wrote no report (exit ${r.code}): ${(r.stderr || r.stdout).slice(0, 300)}`,
        };
      }

      const raw = readFileSync(reportPath, "utf8").trim();
      // A clean repo yields an empty file — not `[]`. That is a real result, and
      // `sufficient()` decides whether the scan behind it was real, using the
      // commit and byte counts.
      let leaks: Leak[] = [];
      if (raw.length > 0) {
        try {
          const parsed = JSON.parse(raw);
          if (!Array.isArray(parsed)) throw new Error("report was not a JSON array");
          leaks = parsed;
        } catch (err) {
          return {
            kind: "failed",
            note: `gitleaks produced unparseable output: ${(err as Error).message}`,
          };
        }
      }
      // Only the empty-evidence path (0 commits or 0 bytes) needs the git
      // corroboration; a scan that read real bytes is self-evidently sufficient,
      // so skip the extra git call. Unscoped sweeps are never corroborated —
      // their empty-evidence verdict does not depend on a diff range.
      const scoped = Boolean(LOG_OPTS);
      const range =
        scoped && (commits === 0 || bytes === 0)
          ? await rangeAddedContent(repo, LOG_OPTS)
          : null;
      const addedContent =
        range === null ? null : range.addedText || range.undiffable.length > 0;

      // The range added nothing but blobs gitleaks could not diff: read them
      // back and scan them directly rather than refusing on their silence. Skip
      // it when the range also added TEXT that gitleaks should have seen and
      // did not — that is a real anomaly in the scan, not a coverage gap.
      const blobScan =
        range && !range.addedText && range.undiffable.length > 0
          ? await scanUndiffableBlobs(repo, range.undiffable, work)
          : null;
      if (blobScan) leaks = leaks.concat(blobScan.leaks);

      return collect(leaks, commits, bytes, findings, scoped, addedContent, {
        total: range?.undiffable.length ?? 0,
        scan: blobScan,
      });
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  },
};

function collect(
  leaks: Leak[],
  commits: number,
  bytes: number,
  findings: Finding[],
  scoped: boolean,
  addedContent: boolean | null,
  blobs: { total: number; scan: BlobScan | null } = { total: 0, scan: null },
): RunnerOutcome {
  // Collapse duplicate rule+file pairs (a secret repeated across history).
  {
    const seen = new Set<string>();
    for (const leak of leaks) {
      const key = `${leak.RuleID}:${leak.File}:${leak.StartLine}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        id: `secret-${leak.RuleID ?? "generic"}`,
        title: `${leak.Description ?? "Potential secret"} in ${leak.File}:${leak.StartLine ?? "?"}`,
        severity: "critical",
        standard: "OWASP ASVS 2.10 / gitleaks",
        location: `${leak.File}:${leak.StartLine ?? ""}${leak.Commit ? ` @${leak.Commit.slice(0, 8)}` : ""}`,
        remediation:
          "Rotate the exposed credential immediately, then purge it from git history (git filter-repo / BFG).",
      });
    }

    const trail = [
      LOG_OPTS
        ? `scanned ${commits} commit${commits === 1 ? "" : "s"} in the PR range (${LOG_OPTS})`
        : `scanned ${commits} commit${commits === 1 ? "" : "s"} of history`,
      `read ${bytes} bytes of content`,
    ];
    // On the empty-evidence path, record what git's numstat said about the
    // range so the verdict is traceable to evidence, not just gitleaks' silence.
    if (addedContent === false) {
      trail.push("git corroboration: PR range added no scannable content (deletions / rename / mode only)");
    } else if (addedContent === true) {
      trail.push("git corroboration: PR range added a file gitleaks could not scan (binary/undiffable)");
    }
    if (blobs.scan) {
      trail.push(
        `read ${blobs.scan.scanned} of ${blobs.total} undiffable blob${blobs.total === 1 ? "" : "s"} back out of git and scanned their printable runs — ${blobs.scan.bytes} bytes (compressed content inside a blob has no readable run and is not covered)`,
      );
    } else if (blobs.total > 0) {
      trail.push(
        `${blobs.total} undiffable blob${blobs.total === 1 ? "" : "s"} in the range could not be read back and scanned`,
      );
    }

    // Omit addedContent when it could not be determined (null): sufficient()
    // then reads it as undefined and fails closed, rather than storing a null
    // the Coverage.data type does not allow.
    const data: Coverage["data"] = { commits, bytes, scoped };
    if (addedContent !== null) data.addedContent = addedContent;
    if (blobs.total > 0) {
      data.undiffableBlobs = blobs.total;
      data.undiffableScanned = blobs.scan?.scanned ?? 0;
      data.undiffableBytes = blobs.scan?.bytes ?? 0;
    }

    return {
      kind: "observed",
      findings,
      coverage: {
        trail,
        data,
        provenance: blobs.scan
        ? "gitleaks scan log (stderr), plus a filesystem pass over the range's undiffable blobs"
        : "gitleaks scan log (stderr)",
      },
      meta: { leakCount: findings.length, commits, bytes },
    };
  }
}
