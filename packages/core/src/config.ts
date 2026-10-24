import { AuthorizationCheck, BusinessScenario, TestAccount } from "@mungard/adapters";
import { SecurityPolicy } from "@mungard/policy-engine";
import { z } from "zod";

export const CONFIG_VERSION = 1;

export const ProjectConfig = z.object({
  version: z.literal(CONFIG_VERSION).default(CONFIG_VERSION),
  project: z
    .object({
      name: z.string().default("project"),
      frameworks: z.array(z.string()).default([]),
    })
    .prefault({}),
  /** Runtime target (a locally running or staging app). Optional. */
  target: z
    .object({
      baseUrl: z.string().url().optional(),
      /** OpenAPI specification path, relative to the project root. */
      openapi: z.string().optional(),
    })
    .prefault({}),
  policy: SecurityPolicy.prefault({}),
  engines: z
    .object({
      semgrep: z
        .object({
          enabled: z.boolean().default(true),
          /**
           * Semgrep Registry packs. NOTE: registry rules are licensed under the
           * Semgrep Rules License v1.0, which restricts some commercial uses.
           * Leave empty to use only Mungard's bundled Apache-2.0 rules.
           */
          registryRules: z.array(z.string()).default([]),
          localRules: z.array(z.string()).default([]),
          exclude: z.array(z.string()).default([]),
        })
        .prefault({}),
      gitleaks: z
        .object({
          enabled: z.boolean().default(true),
          history: z.boolean().default(true),
          /** Path regexes to skip (Go RE2), e.g. "^tests/fixtures/". */
          excludePaths: z.array(z.string()).default([]),
        })
        .prefault({}),
      npmAudit: z.object({ enabled: z.boolean().default(true), omitDev: z.boolean().default(false) }).prefault({}),
      zap: z.object({ enabled: z.boolean().default(true) }).prefault({}),
    })
    .prefault({}),
  auth: z.object({ accounts: z.array(TestAccount).default([]) }).prefault({}),
  authorization: z
    .object({
      checks: z.array(AuthorizationCheck).default([]),
      scenarios: z.array(BusinessScenario).default([]),
    })
    .prefault({}),
  ai: z
    .object({
      provider: z.enum(["anthropic", "none"]).default("anthropic"),
      model: z.string().default("claude-opus-5-5"),
      effort: z.enum(["low", "medium", "high", "xhigh", "max"]).default("medium"),
    })
    .prefault({}),
});
export type ProjectConfig = z.infer<typeof ProjectConfig>;
export type ProjectConfigInput = z.input<typeof ProjectConfig>;

export function parseConfig(input: unknown): ProjectConfig {
  return ProjectConfig.parse(input ?? {});
}
