import { mkdirSync, readFileSync, existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { promises as dns } from "node:dns";
import type {
  Coverage,
  Finding,
  Runner,
  RunnerContext,
  RunnerOutcome,
} from "../types.js";
import { dockerRun, transientInfraFailureUnless } from "../util/docker.js";
import { hostOf, isLocalhostUrl } from "../util/http.js";

// TLS/transport assessment via drwetter/testssl.sh in a container.
// Skipped for http/localhost targets (no TLS to inspect). Writes its JSON to a
// host-shared work dir under cwd (Docker Desktop won't bind-mount /var/folders).

const IMAGE = "drwetter/testssl.sh:latest";

const SEVERITY_MAP: Record<string, Finding["severity"]> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  WARN: "low",
};

/**
 * Which IP to hand testssl.sh, and how many the host actually has.
 *
 * Left to itself, testssl.sh loops the whole scan over EVERY resolved address
 * and concatenates the results — which is what produced the duplicated TLS
 * findings on ds.42labs.io and 42piratas.com (both Cloudflare-fronted, both
 * two A-records). `--ip one` fixes the duplication but picks whichever address
 * comes back first, so the scan is non-deterministic across CI machines and
 * silently says nothing about how many endpoints exist.
 *
 * So we resolve the addresses ourselves and pin the lowest one in sorted
 * order: same host, same IP, same result, on every machine. The count comes
 * back too, so the runner can state its own coverage honestly rather than
 * quietly implying it scanned everything.
 */
async function resolveScanTarget(
  host: string,
): Promise<{ ip: string | null; total: number }> {
  try {
    const [v4, v6] = await Promise.all([
      dns.resolve4(host).catch(() => [] as string[]),
      dns.resolve6(host).catch(() => [] as string[]),
    ]);
    const all = [...v4, ...v6].sort();
    return { ip: all[0] ?? null, total: all.length };
  } catch {
    return { ip: null, total: 0 };
  }
}

export const tlsRunner: Runner = {
  id: "tls",
  domain: "transport",
  title: "TLS / transport security",
  requires: { target: true, docker: true },

  /**
   * testssl.sh emits one JSON record per test it performed — the OK ones too.
   * An empty result set therefore does not mean "no TLS problems", it means
   * the scan never reached the host (DNS, firewall, handshake refused). Only
   * a run that actually performed tests can be read as clean.
   */
  sufficient(cov: Coverage): string | null {
    const tests = Number(cov.data.testsPerformed ?? 0);
    if (tests === 0) {
      return "testssl.sh performed no tests — the host was never reached";
    }
    return null;
  },

  async observe(ctx: RunnerContext): Promise<RunnerOutcome> {
    const findings: Finding[] = [];
    const url = ctx.run.baseUrl;

    // Two targets reach this runner with nothing to hand testssl.sh, and they
    // are opposites. Collapsing them into one branch is what made the harness
    // unusable locally; collapsing them the other way would be far worse.
    //
    // A dev server on localhost has no transport layer to form an opinion
    // about, so the domain does not exist for this target: `notApplicable`,
    // nothing missed, the run is free to reach a verdict. Reporting it as
    // `unavailable` made the project's own headline workflow impossible to
    // pass. sites/example.yaml ships baseUrl http://localhost:3000, so copying
    // the template as the README instructs produced an unwaived hole for a TLS
    // endpoint that was never there, and exit 1 until `tls` was waived by hand.
    if (isLocalhostUrl(url)) {
      return {
        kind: "notApplicable",
        note: "no TLS to inspect (http/localhost target)",
      };
    }

    // A public site served over plaintext is the opposite case. The transport
    // domain very much applies here, the site is simply failing it outright,
    // and nothing about that is excusable. `unavailable` keeps it an unwaived
    // coverage hole so the run cannot pass on it.
    //
    // The `headers` runner does raise this as the high-severity `no-tls`
    // finding, but only while `headers` is in the run: `--only tls` and
    // `--skip headers` are both supported, and either one leaves that verdict
    // with nobody to state it. An excuse that depends on another runner having
    // been invited is not an excuse, and a silent pass here is the exact
    // false all-clear this harness exists to refuse.
    if (!url.startsWith("https://")) {
      return {
        kind: "unavailable",
        note: "target is served over plaintext http — no TLS endpoint to audit",
      };
    }

    const host = hostOf(url);
    // Pin a single, deterministic endpoint (see resolveScanTarget). Falling
    // back to "one" keeps the runner working if DNS resolution fails here but
    // works inside the container.
    const { ip, total } = await resolveScanTarget(host);
    const work = join(process.cwd(), "reports", ".work", `tls-${ctx.run.stamp}`);
    mkdirSync(work, { recursive: true });
    const outPath = join(work, "out.json");
    try {
      await dockerRun({
        image: IMAGE,
        args: [
          "--quiet",
          "--fast",
          // Scan exactly one endpoint, chosen deterministically. Without this,
          // testssl.sh loops over every resolved address and concatenates the
          // results — which is what emitted every TLS finding twice for
          // ds.42labs.io and 42piratas.com (both Cloudflare, both dual-IP).
          // The hostname is still passed as the target, so SNI/cert validation
          // are done against the real name.
          "--ip",
          ip ?? "one",
          "--severity",
          "LOW",
          "--jsonfile",
          "/wrk/out.json",
          host,
        ],
        mountsRW: { "/wrk": work },
        // testssl runs as an unprivileged uid inside; make the dir writable.
        extra: ["--user", "0"],
        timeoutMs: 300_000,
        // testssl signals findings through its exit code, and its own output is
        // a FILE. If out.json exists, the scan ran and answered — retrying it
        // would just burn another couple of minutes to reach the same result.
        retryOn: transientInfraFailureUnless(() => existsSync(outPath)),
      });

      if (!existsSync(outPath)) {
        return {
          kind: "failed",
          note: "testssl.sh wrote no JSON (image/network/mount issue)",
        };
      }

      // The file existing is not the same guarantee as it containing a real
      // result: a killed/truncated write leaves a file that exists but
      // isn't valid JSON. Silently treating that as "parsed to nothing" (as
      // this code used to) is the same "absence of evidence" bug as every
      // other runner here — it must error, not report a clean scan.
      let parsed: Array<{ id: string; severity: string; finding: string }>;
      try {
        const raw = JSON.parse(readFileSync(outPath, "utf8"));
        // Flat --jsonfile is an array; --jsonfile-pretty nests under scanResult.
        parsed = Array.isArray(raw) ? raw : (raw?.scanResult ?? []);
      } catch (err) {
        return {
          kind: "failed",
          note: `testssl.sh wrote unparseable JSON: ${(err as Error).message}`,
        };
      }

      // Defense in depth: even pinned to one endpoint, collapse any
      // (id, finding) pair testssl reports more than once rather than trust a
      // single flag to be the only thing standing between us and a duplicated
      // report.
      const seen = new Set<string>();
      for (const item of parsed) {
        const sev = SEVERITY_MAP[item.severity?.toUpperCase?.() ?? ""];
        if (!sev) continue; // OK / INFO
        const key = `${item.id}::${item.finding}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          id: `tls-${item.id}`,
          title: `${item.id}: ${item.finding}`.slice(0, 200),
          severity: sev,
          standard: "testssl.sh / TLS best practice (Mozilla intermediate)",
          location: host,
        });
      }

      // Say out loud what was and wasn't covered. Scanning one endpoint of a
      // multi-endpoint host is the right default (every edge of a CDN serves
      // the same TLS config, and scanning all of them just duplicates the
      // report) — but "we only looked at one of N" is a fact the operator is
      // entitled to, not something to bury. If the endpoints ever genuinely
      // diverge, this line is the thread to pull.
      if (total > 1 && ip) {
        findings.push({
          id: "tls-endpoint-coverage",
          title: `Scanned 1 of ${total} resolved endpoints for ${host} (${ip}) — a divergent endpoint would not be seen`,
          severity: "info",
          needsReview: true,
          location: host,
          remediation:
            "Normal for a CDN/anycast host, where every edge serves the same TLS configuration. If this host fronts genuinely different origins per address, scan each address explicitly.",
        });
      }

      return {
        kind: "observed",
        note: total > 1 ? `1 of ${total} endpoints (${ip})` : undefined,
        findings,
        coverage: {
          trail: [
            `resolved ${host} → ${total} endpoint${total === 1 ? "" : "s"}; scanned ${ip ?? "first"}`,
            `testssl.sh performed ${parsed.length} test${parsed.length === 1 ? "" : "s"} (all severities, including the passing ones)`,
          ],
          data: {
            testsPerformed: parsed.length,
            endpointsResolved: total,
            endpointScanned: ip ?? "",
          },
          provenance: "testssl.sh --jsonfile output",
        },
        meta: { endpointScanned: ip, endpointsResolved: total },
      };
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  },
};
