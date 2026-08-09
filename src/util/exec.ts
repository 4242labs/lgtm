import { spawn } from "node:child_process";

export interface ExecResult {
  code: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  /**
   * Raw stdout bytes. Present only when the caller passes `encoding: "buffer"`,
   * which it must whenever stdout is not text: decoding arbitrary bytes as UTF-8
   * replaces every invalid sequence with U+FFFD, so a binary blob round-tripped
   * through `stdout` is not the blob any more. In buffer mode `stdout` is empty.
   */
  stdoutRaw?: Buffer;
}

/**
 * Run a command, capturing output. Never throws on non-zero exit — the caller
 * inspects `code`. Rejects only on spawn failure (binary missing).
 */
export function exec(
  cmd: string,
  args: string[],
  opts: {
    cwd?: string;
    timeoutMs?: number;
    env?: NodeJS.ProcessEnv;
    encoding?: "utf8" | "buffer";
  } = {},
): Promise<ExecResult> {
  const { cwd, timeoutMs = 300_000, env, encoding = "utf8" } = opts;
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, {
      cwd,
      env: env ? { ...process.env, ...env } : process.env,
    });
    let stdout = "";
    let stderr = "";
    const chunks: Buffer[] = [];
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);
    child.stdout.on("data", (d) =>
      encoding === "buffer" ? chunks.push(d as Buffer) : (stdout += d.toString()),
    );
    child.stderr.on("data", (d) => (stderr += d.toString()));
    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      const res: ExecResult = { code: code ?? -1, stdout, stderr, timedOut };
      if (encoding === "buffer") res.stdoutRaw = Buffer.concat(chunks);
      resolve(res);
    });
  });
}

/** True if a binary is resolvable on PATH. */
export async function which(bin: string): Promise<boolean> {
  try {
    const r = await exec("which", [bin], { timeoutMs: 5_000 });
    return r.code === 0 && r.stdout.trim().length > 0;
  } catch {
    return false;
  }
}
