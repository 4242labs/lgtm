#!/usr/bin/env -S npx tsx
import { Command } from "commander";
import { existsSync, readdirSync } from "node:fs";
import { resolve, join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import pc from "picocolors";
import { chromium } from "playwright";
import { loadSite } from "./config.js";
import { runAudit } from "./orchestrator.js";
import { writeReports, consoleSummary } from "./report.js";
import { ALL_RUNNERS } from "./runners/index.js";
import { SEVERITY_ORDER, type Severity } from "./types.js";

// The CLI-facing subset: `info` is a real Severity, but computePass() (see
// scoring.ts) already skips every info-severity finding regardless of
// failOn — an "info" threshold can never fail a run today, on the YAML path
// either. Excluding it here isn't about preventing a failure mode; it's
// that offering it as a choice would promise a behavior ("fail on
// informational findings") the scorer doesn't implement.
const FAIL_ON_CHOICES = SEVERITY_ORDER.filter((s) => s !== "info") as Severity[];

const HERE = dirname(fileURLToPath(import.meta.url));
const SITES_DIR = resolve(HERE, "..", "sites");

function sitePath(name: string): string {
  const direct = resolve(process.cwd(), name);
  if (existsSync(direct) && name.endsWith(".yaml")) return direct;
  const inDir = join(SITES_DIR, `${name}.yaml`);
  if (existsSync(inDir)) return inDir;
  throw new Error(`site config not found: ${name} (looked in ${SITES_DIR})`);
}

/** YYMMDD-HHMM in local time. */
function stamp(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, "0");
  return `${String(d.getFullYear()).slice(2)}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

const program = new Command();
program
  .name("lgtm")
  .description("Cross-site security / a11y / privacy / quality harness")
  .version("0.1.0");

program
  .command("run")
  .description("Run the audit for a site")
  .argument("<site>", "site slug (sites/<slug>.yaml) or a path to a config")
  .option("--url <url>", "override the site's baseUrl (e.g. http://localhost:3000)")
  .option("--only <ids>", "comma-separated runner ids to run (default: all)")
  .option("--skip <ids>", "comma-separated runner ids to skip")
  .option("--allow-active", "enable active/mutating scans (localhost only)", false)
  .option("--fail-on <sev>", "override failOn threshold (critical|high|medium|low)")
  .action(async (site: string, opts) => {
    const cfg = loadSite(sitePath(site));
    if (opts.url) cfg.baseUrl = opts.url;
    if (opts.failOn !== undefined) {
      // computePass()/atLeastAsSevere() index into SEVERITY_ORDER; a typo'd
      // value here is not "unknown severity" to them, it's -1 — every real
      // severity then reads as "less severe than the threshold" and the gate
      // passes silently. Unvalidated, this flag can disable the gate by typo.
      // `!== undefined` (not truthy) so an empty string is rejected too,
      // rather than silently falling back to the site's configured failOn.
      if (!FAIL_ON_CHOICES.includes(opts.failOn)) {
        console.error(
          pc.red(
            `--fail-on must be one of ${FAIL_ON_CHOICES.join("|")} (got "${opts.failOn}")`,
          ),
        );
        process.exit(2);
      }
      cfg.failOn = opts.failOn;
    }
    if (opts.skip) cfg.skip = [...(cfg.skip ?? []), ...String(opts.skip).split(",")];

    const isLocal = /^(https?:\/\/)?(localhost|127\.0\.0\.1)/.test(cfg.baseUrl);
    if (opts.allowActive && !isLocal) {
      console.error(
        pc.red("refusing --allow-active against a non-localhost target. Active scans are localhost-only."),
      );
      process.exit(2);
    }

    const only = opts.only ? String(opts.only).split(",").map((s: string) => s.trim()) : undefined;

    console.log(pc.bold(`\nlgtm ${cfg.name} → ${cfg.baseUrl}\n`));
    const report = await runAudit({
      site: cfg,
      baseUrl: cfg.baseUrl,
      outDir: process.cwd(),
      stamp: stamp(),
      allowActive: Boolean(opts.allowActive),
      only,
      log: (m) => console.log(m),
    });

    const paths = writeReports(report);
    console.log(consoleSummary(report));
    console.log(pc.dim(`  report: ${paths.html}`));
    console.log(pc.dim(`  json:   ${paths.json}\n`));
    process.exit(report.passed ? 0 : 1);
  });

program
  .command("auth")
  .description("Capture an authenticated session (storageState) for a site")
  .argument("<site>", "site slug")
  .option("--url <url>", "login start URL (defaults to site baseUrl)")
  .action(async (site: string, opts) => {
    const cfg = loadSite(sitePath(site));
    if (cfg.auth.type !== "storageState") {
      console.error(pc.red(`site '${cfg.name}' has auth.type != storageState; nothing to capture.`));
      process.exit(2);
    }
    const start = opts.url || cfg.baseUrl;
    console.log(pc.bold(`\nOpening a browser at ${start}`));
    console.log("Log in manually, then return here and press Enter to save the session.\n");
    const browser = await chromium.launch({ headless: false });
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto(start).catch(() => {});
    await new Promise<void>((res) => {
      process.stdin.resume();
      process.stdin.once("data", () => res());
    });
    await ctx.storageState({ path: cfg.auth.path });
    await browser.close();
    console.log(pc.green(`\nSaved session → ${cfg.auth.path}\n`));
    process.exit(0);
  });

program
  .command("list")
  .description("List available runners and site configs")
  .action(() => {
    console.log(pc.bold("\nRunners:"));
    for (const r of ALL_RUNNERS) {
      const req = Object.entries(r.requires)
        .filter(([, v]) => v)
        .map(([k]) => k)
        .join(",");
      console.log(`  ${pc.cyan(r.id.padEnd(12))} ${r.title} ${pc.dim(`[${req}]`)}`);
    }
    console.log(pc.bold("\nSites:"));
    if (existsSync(SITES_DIR)) {
      for (const f of readdirSync(SITES_DIR).filter((f) => f.endsWith(".yaml"))) {
        console.log(`  ${pc.cyan(f.replace(/\.yaml$/, ""))}`);
      }
    }
    console.log("");
  });

program.parseAsync(process.argv);
