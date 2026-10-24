/** Statuses a human may set from the UI. `retested` is reserved for a passing retest run. */
export const HUMAN_STATUSES = ["new", "needs_review", "confirmed", "false_positive", "accepted_risk", "fixed"] as const;
export type HumanStatus = (typeof HUMAN_STATUSES)[number];

export const ALL_STATUSES = [...HUMAN_STATUSES, "retested"] as const;
export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];
export const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
