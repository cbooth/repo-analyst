import { createRemoteJWKSet, jwtVerify } from "jose";
import type { Env } from "./env";

export type Principal =
  | { kind: "access"; identity: string }
  | { kind: "api-key" }
  | { kind: "dev" };

const TEAM_DOMAIN =
  /^https:\/\/[a-z0-9][a-z0-9-]*\.cloudflareaccess\.com$/i;

const jwksByDomain = new Map<
  string,
  ReturnType<typeof createRemoteJWKSet>
>();

function jwks(teamDomain: string) {
  let set = jwksByDomain.get(teamDomain);
  if (!set) {
    set = createRemoteJWKSet(
      new URL(`${teamDomain}/cdn-cgi/access/certs`),
    );
    jwksByDomain.set(teamDomain, set);
  }
  return set;
}

const sha256 = async (value: string) =>
  new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(value),
    ),
  );

/** Constant-time comparison (hashing hides length differences). */
export async function safeEqual(
  a: string,
  b: string,
): Promise<boolean> {
  const [x, y] = await Promise.all([sha256(a), sha256(b)]);
  let difference = 0;
  for (let i = 0; i < x.length; i++) difference |= x[i] ^ y[i];
  return difference === 0;
}

async function verifyAccess(
  request: Request,
  env: Env,
): Promise<Principal | null> {
  const teamDomain = env.ACCESS_TEAM_DOMAIN?.replace(/\/+$/, "");
  const audience = env.ACCESS_POLICY_AUD;
  if (!teamDomain || !audience || !TEAM_DOMAIN.test(teamDomain)) {
    return null;
  }

  const token = request.headers.get("cf-access-jwt-assertion");
  if (!token) return null;

  try {
    const { payload } = await jwtVerify(token, jwks(teamDomain), {
      issuer: teamDomain,
      audience,
      algorithms: ["RS256"],
    });
    const identity = payload.email ?? payload.common_name ?? payload.sub;
    return {
      kind: "access",
      identity: typeof identity === "string" ? identity : "unknown",
    };
  } catch {
    return null;
  }
}

/**
 * Fails closed: with neither Access configured nor a strong API key
 * set, every request is rejected.
 */
export async function authenticate(
  request: Request,
  env: Env,
): Promise<Principal | null> {
  const supplied = request.headers.get("authorization");
  const key = env.ANALYSIS_API_KEY;
  if (supplied?.startsWith("Bearer ") && key && key.length >= 32) {
    if (await safeEqual(supplied.slice(7), key)) {
      return { kind: "api-key" };
    }
  }

  const access = await verifyAccess(request, env);
  if (access) return access;

  const host = new URL(request.url).hostname;
  if (
    env.DEV_BYPASS_ACCESS === "true" &&
    (host === "localhost" || host === "127.0.0.1")
  ) {
    return { kind: "dev" };
  }

  return null;
}

/**
 * Browser sessions authenticate with cookies/headers the browser adds
 * itself, so state-changing requests must prove they are same-origin.
 */
export function sameOriginOk(
  request: Request,
  principal: Principal,
): boolean {
  if (principal.kind === "api-key") return true;
  const origin = request.headers.get("origin");
  return origin !== null && origin === new URL(request.url).origin;
}

const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "connect-src 'self'",
  "img-src 'self' data:",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

export function withSecurityHeaders(response: Response): Response {
  const out = new Response(response.body, response);
  out.headers.set("Content-Security-Policy", CSP);
  out.headers.set("X-Content-Type-Options", "nosniff");
  out.headers.set("X-Frame-Options", "DENY");
  out.headers.set("Referrer-Policy", "no-referrer");
  out.headers.set("Cross-Origin-Opener-Policy", "same-origin");
  out.headers.set(
    "Strict-Transport-Security",
    "max-age=31536000; includeSubDomains",
  );
  return out;
}

const SECRET_PATTERNS: [RegExp, string][] = [
  [
    /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g,
    "[REDACTED PRIVATE KEY]",
  ],
  [/\bgh[pousr]_[A-Za-z0-9]{30,}\b/g, "[REDACTED TOKEN]"],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, "[REDACTED TOKEN]"],
  [/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, "[REDACTED AWS KEY]"],
  [/\bsk-[A-Za-z0-9_-]{20,}\b/g, "[REDACTED TOKEN]"],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, "[REDACTED TOKEN]"],
  [
    /\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}\b/g,
    "[REDACTED JWT]",
  ],
  [
    /\b((?:api[_-]?key|secret|token|passw(?:or)?d)["']?\s*[:=]\s*["']?)[^\s"',;]{8,}/gi,
    "$1[REDACTED]",
  ],
];

/** Best-effort scrub so repository secrets don't land in D1 or the UI. */
export function redactSecrets(text: string): string {
  let out = text;
  for (const [pattern, replacement] of SECRET_PATTERNS) {
    out = out.replace(pattern, replacement);
  }
  return out;
}
