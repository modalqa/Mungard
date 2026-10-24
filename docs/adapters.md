# Writing an adapter

Adapters connect Mungard to a security engine. Core orchestration does not change when you add one.

## Contract

```ts
// packages/adapters/src/types.ts
export interface SecurityAdapter<I> {
  id: string;                 // "semgrep"
  name: string;               // human name
  operation: Operation;       // policy operation it performs (add a new one to the policy if needed)
  inputSchema: ZodType<I>;    // validated before run()
  healthCheck(ctx): Promise<HealthStatus>;          // available? version? how (local/docker/builtin)? remedy?
  run(input: I, ctx: AdapterContext): Promise<AdapterResult>;
}
```

`AdapterResult` contains `status` (`succeeded | partial | failed | unavailable | skipped`), raw `findings`, `coverage[]` (what was actually checked), `gaps[]` (what was not), `error`, `rawOutputPath`, `durationMs` and optional `data`.

## Rules every adapter must follow

1. **Never use a shell.** Use `runCommand(bin, args, { timeoutMs, maxOutputBytes, signal })`. User/model input goes into arguments, never into a command string.
2. **Respect limits** from `ctx.policy.limits` (timeouts, file sizes, output size).
3. **Never claim success when the engine did not run.** Return `unavailable` or `failed` with a clear `error` and a `gaps` entry.
4. **Network targets** must use `ScopedHttpClient` (scope check per hop, rate limit, request budget) or re-check `checkTarget()`. The orchestrator authorizes the target first; this is defense in depth.
5. **Redact everything you persist.** `writeEvidence(ctx, name, data)` redacts for you; use `ctx.redact()` for excerpts.
6. **Drop PII** you don't need (e.g. Gitleaks author names and emails are removed).
7. **Map severities honestly** and keep the engine's own value in `originalSeverity`.
8. **Choose a stable `fingerprintHint`** (not a line number) so duplicates merge and retests can compare.
9. Only set `verified: true` for deterministic tests that prove a user-defined expectation was violated **and** captured evidence.
10. Prefer a local binary, then Docker with `dockerBaseArgs()` (dropped capabilities, no-new-privileges, limits).

## Minimal example

```ts
import { z } from "zod";
import { emptyResult, findExecutable, runCommand, writeEvidence, type SecurityAdapter } from "@mungard/adapters";

export const exampleAdapter: SecurityAdapter<{ strict: boolean }> = {
  id: "example",
  name: "Example scanner",
  operation: "static_scan",
  inputSchema: z.object({ strict: z.boolean().default(false) }),
  async healthCheck() {
    const bin = await findExecutable("example-scanner");
    return bin
      ? { engine: "example", available: true, via: "local", detail: bin }
      : { engine: "example", available: false, detail: "not installed", remedy: "brew install example-scanner" };
  },
  async run(input, ctx) {
    const started = Date.now();
    const bin = await findExecutable("example-scanner");
    if (!bin) return emptyResult("example", "unavailable", { error: "example-scanner not installed", gaps: ["Example checks did not run."] });
    const res = await runCommand(bin, ["--json", ...(input.strict ? ["--strict"] : []), "."], {
      cwd: ctx.projectRoot,
      timeoutMs: ctx.policy.limits.toolTimeoutSeconds * 1000,
      maxOutputBytes: ctx.policy.limits.maxOutputBytes,
      signal: ctx.signal,
    });
    const parsed = JSON.parse(res.stdout) as { issues: { rule: string; file: string; line: number; msg: string }[] };
    const rawOutputPath = await writeEvidence(ctx, "example.json", parsed);
    return {
      engine: "example",
      status: "succeeded",
      findings: parsed.issues.map((i) => ({
        title: `${i.rule} in ${i.file}`,
        description: i.msg,
        category: "sast",
        severity: "medium",
        confidence: "medium",
        ruleId: `example.${i.rule}`,
        locations: [{ kind: "file", path: i.file, startLine: i.line }],
        evidence: [{ kind: "scanner_output", description: "example output", path: rawOutputPath }],
      })),
      coverage: ["Example scanner on the project source."],
      gaps: [],
      rawOutputPath,
      durationMs: Date.now() - started,
    };
  },
};
```

Then:

1. add it to `BUILTIN_ADAPTERS` (`packages/adapters/src/index.ts`);
2. map a step to it in `planStep()` (`packages/core/src/orchestrator.ts`) and to its engine id in `ENGINE_STEP` (`retest.ts`);
3. add unit tests for the parser/normalizer with a recorded output fixture under `tests/`;
4. document coverage and limitations in `docs/coverage-and-limitations.md`, and the engine's license in `docs/licensing.md`.

Check the engine's license **before** integrating it. Invoking an external CLI keeps Mungard's license independent, but you must document restrictions that affect users (see the Semgrep Registry example in [licensing.md](licensing.md)).
