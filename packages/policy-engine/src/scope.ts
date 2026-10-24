import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import path from "node:path";
import type { SecurityPolicy } from "./policy.js";

export interface ScopeDecision {
  allowed: boolean;
  reasons: string[];
  url?: URL;
}

const ALWAYS_BLOCKED_HOSTS = new Set([
  "169.254.169.254", // cloud instance metadata
  "metadata.google.internal",
  "metadata",
  "fd00:ec2::254",
]);

function normalizeHost(host: string): string {
  return host.replace(/^\[|\]$/g, "").toLowerCase().replace(/\.$/, "");
}

export function hostMatches(host: string, pattern: string): boolean {
  const h = normalizeHost(host);
  const p = normalizeHost(pattern);
  if (p.startsWith("*.")) {
    const suffix = p.slice(1); // ".example.test"
    return h.endsWith(suffix) && h.length > suffix.length;
  }
  return h === p;
}

export function isLoopbackHost(host: string): boolean {
  const h = normalizeHost(host);
  return h === "localhost" || h.endsWith(".localhost") || h === "::1" || /^127\./.test(h);
}

/** Link-local / metadata ranges that are never valid targets. */
export function isBlockedAddress(address: string): boolean {
  const a = normalizeHost(address);
  if (ALWAYS_BLOCKED_HOSTS.has(a)) return true;
  if (isIP(a) === 4) return /^169\.254\./.test(a) || a === "0.0.0.0";
  if (isIP(a) === 6) return /^fe80:/i.test(a) || a === "::";
  return false;
}

function effectivePort(url: URL): number {
  if (url.port) return Number(url.port);
  return url.protocol === "https:" ? 443 : 80;
}

/**
 * Validate a target URL against the policy (SR-01). Pure and synchronous:
 * checks protocol, credentials-in-URL, host allowlist, production list and
 * port allowlist. Use {@link resolveAndCheckTarget} to also check DNS.
 */
export function checkTarget(rawUrl: string, policy: SecurityPolicy): ScopeDecision {
  const reasons: string[] = [];
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { allowed: false, reasons: [`"${rawUrl}" is not a valid absolute URL.`] };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    reasons.push(`Protocol ${url.protocol} is not allowed; only http and https targets can be tested.`);
  }
  if (url.username || url.password) {
    reasons.push("Credentials embedded in the URL are not allowed. Configure test accounts instead.");
  }
  const host = normalizeHost(url.hostname);
  if (isBlockedAddress(host)) {
    reasons.push(`Host ${host} is a link-local or cloud metadata address and is always blocked.`);
  }
  const t = policy.targets;
  if (!t.allowedHosts.some((p) => hostMatches(host, p))) {
    reasons.push(`Host ${host} is not in policy.targets.allowedHosts (${t.allowedHosts.join(", ") || "empty"}).`);
  }
  if (t.productionHosts.some((p) => hostMatches(host, p)) && !t.allowProduction) {
    reasons.push(`Host ${host} is listed as production and policy.targets.allowProduction is false.`);
  }
  const port = effectivePort(url);
  if (t.allowedPorts.length > 0 && !t.allowedPorts.includes(port)) {
    reasons.push(`Port ${port} is not in policy.targets.allowedPorts (${t.allowedPorts.join(", ")}).`);
  }
  return { allowed: reasons.length === 0, reasons, url };
}

/**
 * Like {@link checkTarget}, and additionally resolves the hostname so a name
 * that points at a metadata/link-local address is refused.
 */
export async function resolveAndCheckTarget(rawUrl: string, policy: SecurityPolicy): Promise<ScopeDecision> {
  const decision = checkTarget(rawUrl, policy);
  if (!decision.allowed || !decision.url) return decision;
  const host = normalizeHost(decision.url.hostname);
  if (isIP(host)) return decision;
  try {
    const addresses = await lookup(host, { all: true });
    const bad = addresses.filter((a) => isBlockedAddress(a.address));
    if (bad.length > 0) {
      return {
        allowed: false,
        url: decision.url,
        reasons: [`Host ${host} resolves to a blocked address (${bad.map((b) => b.address).join(", ")}).`],
      };
    }
  } catch {
    return { allowed: false, url: decision.url, reasons: [`Host ${host} could not be resolved.`] };
  }
  return decision;
}

/** Redirects are followed only when the destination is itself in scope (SR-01). */
export function checkRedirect(fromUrl: string, location: string, policy: SecurityPolicy): ScopeDecision {
  let target: string;
  try {
    target = new URL(location, fromUrl).toString();
  } catch {
    return { allowed: false, reasons: [`Invalid redirect location "${location}".`] };
  }
  const decision = checkTarget(target, policy);
  if (!decision.allowed) {
    decision.reasons.unshift(`Redirect from ${fromUrl} to ${target} leaves the approved scope.`);
  }
  return decision;
}

/** Confine a user- or model-supplied path to the project root. */
export function resolveWithinRoot(root: string, candidate: string): string {
  const absRoot = path.resolve(root);
  const resolved = path.resolve(absRoot, candidate);
  const rel = path.relative(absRoot, resolved);
  if (rel === ".." || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) {
    throw new Error(`Path "${candidate}" escapes the project root.`);
  }
  return resolved;
}
