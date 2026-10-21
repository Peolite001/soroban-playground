// Copyright (c) 2026 StellarDevTools
// SPDX-License-Identifier: MIT

/**
 * Distributed token-bucket rate limiter (#1751, BE-03).
 *
 * An atomic, distributed sliding-window token bucket powered by a Redis Lua
 * script, enforcing tiered compute quotas keyed by IP or authenticated
 * Stellar Ed25519 public key:
 *
 *   anonymous      60 requests / minute   (unauthenticated, keyed by IP)
 *   authenticated 300 requests / minute   (Ed25519-signed or JWT-identified)
 *   enterprise    1200 requests / minute  (public key on the enterprise list)
 *
 * ## Atomicity & race safety
 * DISTRIBUTED_TOKEN_BUCKET_LUA runs as a single Redis script reading the Redis
 * server clock (TIME), so every backend instance shares one bucket state and
 * one time source. Signature replay dedup (SET NX) commits inside the same
 * script as the quota spend, so a signed request can never consume tokens
 * twice, even across concurrent instances. Bucket + dedup keys share a
 * `{...}` hash tag so they land on the same slot in Redis Cluster.
 *
 * ## Ed25519 authentication
 * Callers sign `buildSignedMessage(method, path, timestamp)` with the Ed25519
 * key matching their Stellar G... address and send:
 *   X-Stellar-Public-Key – G... identity (the "API key")
 *   X-Stellar-Signature  – base64 Ed25519 signature
 *   X-Timestamp          – unix seconds or milliseconds, within the
 *                          freshness window (default ±60s)
 * Verification uses @stellar/stellar-sdk Keypair.verify; the signature digest
 * is then atomically claimed in Redis so each signed request counts once.
 *
 * ## RFC 6585 headers
 *   X-RateLimit-Limit     – bucket capacity for the resolved tier
 *   X-RateLimit-Remaining – tokens left (floored)
 *   X-RateLimit-Reset     – unix epoch seconds when capacity/next token is back
 *   Retry-After           – seconds until a blocked caller may retry
 *   X-RateLimit-Tier      – resolved tier
 *   X-RateLimit-Fallback  – "local" when serving from the in-memory bucket
 *
 * ## Degradation
 * When Redis is unreachable (fallback mode, circuit breaker open, or command
 * errors) the limiter fails open onto a local in-memory token bucket that
 * mirrors the Lua math, so limits stay enforced per node and requests are
 * never hard-failed by the limiter itself.
 *
 * Usage:
 *   import { distributedRateLimiter } from './middleware/distributedRateLimiter.js';
 *   app.use(distributedRateLimiter());
 */

import { createHash } from 'crypto';
import { LRUCache } from 'lru-cache';
import { Keypair } from '@stellar/stellar-sdk';
import redisService from '../services/redisService.js';
import { resolveClientIp } from './clientIp.js';
import { createHttpError } from './errorHandler.js';

// ─── Tier configuration ───────────────────────────────────────────────────────

export type RateLimitTier = 'anonymous' | 'authenticated' | 'enterprise';

/** Requests per minute per tier (issue #1751). */
export const TIER_LIMITS_PER_MINUTE: Readonly<Record<RateLimitTier, number>> =
  Object.freeze({
    anonymous: 60,
    authenticated: 300,
    enterprise: 1200,
  });

const DEFAULT_WINDOW_MS = 60 * 1000;
const DEFAULT_TIMESTAMP_FRESHNESS_MS = 60 * 1000;
const DEFAULT_COST = 1;
const DEFAULT_SCOPE = 'dist';
const SLOW_CHECK_THRESHOLD_MS = 1; // acceptance target: < 1ms per check
const DEFAULT_SLOW_WARN_MS = 25;
const FALLBACK_WARN_INTERVAL_MS = 10 * 1000;
const MAX_LOCAL_BUCKETS = 50_000;
const MAX_PUBLIC_KEY_LENGTH = 64;
const MAX_SIGNATURE_LENGTH = 512;
const REPLAY_CODE = 2; // Lua return code for a replayed signature

/** Comma-separated enterprise G... addresses granting the top tier. */
function parseEnterprisePublicKeys(raw: string | undefined): Set<string> {
  return new Set(
    (raw ?? '')
      .split(',')
      .map((key) => key.trim())
      .filter(Boolean)
  );
}

const DEFAULT_ENTERPRISE_PUBLIC_KEYS = parseEnterprisePublicKeys(
  process.env.RATE_LIMIT_ENTERPRISE_PUBLIC_KEYS
);

// ─── Atomic Lua script ────────────────────────────────────────────────────────

/**
 * Atomic sliding-window token bucket with integrated signature replay dedup.
 *
 * KEYS[1] bucket state hash  {tokens, ts}
 * KEYS[2] signature dedup key (untouched when ARGV[4] is '')
 * ARGV[1] capacity (tokens per window)
 * ARGV[2] window_ms
 * ARGV[3] cost per request
 * ARGV[4] signature digest ('' disables replay protection)
 * ARGV[5] replay dedup TTL in seconds
 *
 * Returns {allowed (0|1), remaining tokens (floored), retryAfterSec,
 * resetAfterSec (time to a full bucket), code (0 ok, 2 replayed)}.
 * Uses the Redis server clock so all API nodes share one time source.
 */
export const DISTRIBUTED_TOKEN_BUCKET_LUA = `
  local bucket = KEYS[1]
  local capacity = tonumber(ARGV[1])
  local window_ms = tonumber(ARGV[2])
  local cost = tonumber(ARGV[3])
  local digest = ARGV[4]
  local replay_ttl = tonumber(ARGV[5])

  if digest ~= '' then
    if not redis.call('SET', KEYS[2], '1', 'NX', 'EX', replay_ttl) then
      return {0, 0, 0, 0, ${REPLAY_CODE}}
    end
  end

  local t = redis.call('TIME')
  local now_ms = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
  local rate = capacity / window_ms
  local state = redis.call('HMGET', bucket, 'tokens', 'ts')
  local tokens = tonumber(state[1])
  local ts = tonumber(state[2])
  if tokens == nil or ts == nil then
    tokens = capacity
    ts = now_ms
  end
  local elapsed = math.max(0, now_ms - ts)
  tokens = math.min(capacity, tokens + elapsed * rate)
  local allowed = 0
  local retry_after = 0
  if tokens >= cost then
    tokens = tokens - cost
    allowed = 1
  else
    retry_after = math.ceil((cost - tokens) / rate / 1000)
  end
  local reset_after = math.ceil((capacity - tokens) / rate / 1000)
  redis.call('HSET', bucket, 'tokens', tostring(tokens), 'ts', now_ms)
  redis.call('PEXPIRE', bucket, math.ceil(window_ms * 2))
  return {allowed, math.max(0, math.floor(tokens)), retry_after, reset_after, 0}
`;

let scriptSha1 = '';
function getScriptSha1(): string {
  if (!scriptSha1) {
    scriptSha1 = createHash('sha1')
      .update(DISTRIBUTED_TOKEN_BUCKET_LUA)
      .digest('hex');
  }
  return scriptSha1;
}

// ─── Ed25519 signature verification ───────────────────────────────────────────

export type SignatureErrorReason =
  | 'missing_public_key'
  | 'invalid_public_key'
  | 'invalid_signature'
  | 'stale_timestamp'
  | 'invalid_timestamp';

export interface SignatureVerificationResult {
  valid: boolean;
  reason?: SignatureErrorReason;
  /** sha256 of publicKey|timestamp|signature — used for replay dedup. */
  digest: string;
}

/** Canonical message callers sign: `<service>:v1:<METHOD>:<path>:<timestamp>`. */
export function buildSignedMessage(
  method: string,
  path: string,
  timestampMs: number
): string {
  return [
    'soroban-playground',
    'v1',
    method.toUpperCase(),
    path,
    String(timestampMs),
  ].join('\n');
}

/**
 * Verifies a Stellar Ed25519-signed request. Cheap checks (timestamp
 * freshness, key/signature shape) run before the crypto operation so garbage
 * headers never pay for signature math.
 */
export function verifyStellarEd25519Request(params: {
  publicKey: string;
  signature: string;
  timestampMs: number;
  method: string;
  path: string;
  freshnessMs: number;
}): SignatureVerificationResult {
  const { publicKey, signature, timestampMs, method, path, freshnessMs } =
    params;

  if (!publicKey) {
    return { valid: false, reason: 'missing_public_key', digest: '' };
  }
  if (publicKey.length > MAX_PUBLIC_KEY_LENGTH) {
    return { valid: false, reason: 'invalid_public_key', digest: '' };
  }
  if (!Number.isFinite(timestampMs) || timestampMs <= 0) {
    return { valid: false, reason: 'invalid_timestamp', digest: '' };
  }
  if (Math.abs(Date.now() - timestampMs) > freshnessMs) {
    return { valid: false, reason: 'stale_timestamp', digest: '' };
  }
  if (!signature || signature.length > MAX_SIGNATURE_LENGTH) {
    return { valid: false, reason: 'invalid_signature', digest: '' };
  }

  const digest = createHash('sha256')
    .update(`${publicKey}\n${timestampMs}\n${signature}`)
    .digest('hex');

  try {
    const sigBuffer = Buffer.from(signature, 'base64');
    // Ed25519 signatures are exactly 64 bytes; reject early.
    if (sigBuffer.length !== 64) {
      return { valid: false, reason: 'invalid_signature', digest };
    }
    const keypair = Keypair.fromPublicKey(publicKey);
    const valid = keypair.verify(
      Buffer.from(buildSignedMessage(method, path, timestampMs)),
      sigBuffer
    );
    if (!valid) {
      return { valid: false, reason: 'invalid_signature', digest };
    }
    return { valid: true, digest };
  } catch {
    return { valid: false, reason: 'invalid_public_key', digest };
  }
}

// ─── Minimal structural types (no express typings dependency) ────────────────

export interface RateLimitRequest {
  headers: Record<string, string | string[] | undefined>;
  method?: string;
  originalUrl?: string;
  url?: string;
  ip?: string;
  clientIp?: string;
  socket?: { remoteAddress?: string };
  user?: { id?: string | number; tier?: string } | null;
  rateLimit?: {
    scope: string;
    tier: RateLimitTier;
    identity: string;
    limit: number;
    remaining: number;
    fallback: boolean;
  };
}

export interface RateLimitResponse {
  set(name: string, value: string | number): unknown;
  set(headers: Record<string, string | number>): unknown;
}

export type NextFunction = (err?: unknown) => void;

export type RateLimitMiddleware = (
  req: RateLimitRequest,
  res: RateLimitResponse,
  next: NextFunction
) => Promise<void>;

// ─── Options ──────────────────────────────────────────────────────────────────

export interface DistributedRateLimiterOptions {
  /** Bucket namespace so distinct limiters never share counters. */
  scope?: string;
  /** Refill window in ms (capacity tokens refill per window). */
  windowMs?: number;
  /** Per-tier capacities (requests per `windowMs`). */
  tiers?: Partial<Record<RateLimitTier, number>>;
  /** G... addresses granted the enterprise tier. */
  enterprisePublicKeys?: string[];
  /** Max |now - X-Timestamp| for signed requests. */
  timestampFreshnessMs?: number;
  /** Atomically reject replayed signatures (default true). */
  replayProtection?: boolean;
  /** Tokens consumed per request. */
  cost?: number;
  /** Log a warning when a check is slower than this (ms). */
  slowWarnMs?: number;
  /** Inject for tests. */
  verifySignature?: typeof verifyStellarEd25519Request;
}

interface TokenBucketResult {
  allowed: boolean;
  remaining: number;
  retryAfterSec: number;
  resetAfterSec: number;
  replay: boolean;
  fallback: boolean;
}

// ─── Local in-memory fallback (mirrors the Lua math) ─────────────────────────

interface LocalBucketState {
  tokens: number;
  ts: number;
}

const localBuckets = new LRUCache<string, LocalBucketState>({
  max: MAX_LOCAL_BUCKETS,
});
const localSignatures = new LRUCache<string, true>({ max: MAX_LOCAL_BUCKETS });

function runLocalBucket(
  id: string,
  capacity: number,
  windowMs: number,
  cost: number,
  digest: string,
  replayTtlSec: number
): TokenBucketResult {
  if (digest) {
    if (localSignatures.has(digest)) {
      return {
        allowed: false,
        remaining: 0,
        retryAfterSec: 0,
        resetAfterSec: 0,
        replay: true,
        fallback: true,
      };
    }
    localSignatures.set(digest, true, { ttl: replayTtlSec * 1000 });
  }

  const now = Date.now();
  const rate = capacity / windowMs;
  const previous = localBuckets.get(id) || { tokens: capacity, ts: now };
  const elapsed = Math.max(0, now - previous.ts);
  let tokens = Math.min(capacity, previous.tokens + elapsed * rate);
  let allowed = 0;
  let retryAfterSec = 0;
  if (tokens >= cost) {
    tokens -= cost;
    allowed = 1;
  } else {
    retryAfterSec = Math.ceil((cost - tokens) / rate / 1000);
  }
  const resetAfterSec = Math.max(
    1,
    Math.ceil((capacity - tokens) / rate / 1000)
  );
  localBuckets.set(id, { tokens, ts: now }, { ttl: windowMs * 2 });
  return {
    allowed: allowed === 1,
    remaining: Math.max(0, Math.floor(tokens)),
    retryAfterSec,
    resetAfterSec,
    replay: false,
    fallback: true,
  };
}

// ─── Redis execution (EVALSHA with EVAL fallback on NOSCRIPT) ────────────────

interface RedisLike {
  evalsha: (...args: unknown[]) => Promise<unknown>;
  eval: (...args: unknown[]) => Promise<unknown>;
}

async function evalTokenBucketScript(
  client: RedisLike,
  bucketKey: string,
  sigKey: string,
  argv: unknown[]
): Promise<unknown[]> {
  try {
    return (await client.evalsha(
      getScriptSha1(),
      2,
      bucketKey,
      sigKey,
      ...argv
    )) as unknown[];
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (!message.toUpperCase().includes('NOSCRIPT')) throw err;
    return (await client.eval(
      DISTRIBUTED_TOKEN_BUCKET_LUA,
      2,
      bucketKey,
      sigKey,
      ...argv
    )) as unknown[];
  }
}

function parseScriptRows(rows: unknown[]): TokenBucketResult {
  const values = rows.map((value) => Number(value) || 0);
  return {
    allowed: values[0] === 1,
    remaining: values[1],
    retryAfterSec: values[2],
    resetAfterSec: values[3],
    replay: values[4] === REPLAY_CODE,
    fallback: false,
  };
}

// ─── Observability ────────────────────────────────────────────────────────────

export interface RateLimiterMetrics {
  checks: number;
  allowed: number;
  blocked: number;
  replaysBlocked: number;
  authFailures: number;
  localFallbacks: number;
  /** Checks slower than SLOW_CHECK_THRESHOLD_MS (1ms). */
  slowChecks: number;
  totalLatencyMs: number;
  maxLatencyMs: number;
  lastLatencyMs: number;
}

const metrics: RateLimiterMetrics = {
  checks: 0,
  allowed: 0,
  blocked: 0,
  replaysBlocked: 0,
  authFailures: 0,
  localFallbacks: 0,
  slowChecks: 0,
  totalLatencyMs: 0,
  maxLatencyMs: 0,
  lastLatencyMs: 0,
};

export function getRateLimiterMetrics(): RateLimiterMetrics {
  return { ...metrics };
}

/** Clears metrics and local fallback caches (tests / admin tooling). */
export function resetRateLimiterState(): void {
  (Object.keys(metrics) as (keyof RateLimiterMetrics)[]).forEach((key) => {
    metrics[key] = 0;
  });
  localBuckets.clear();
  localSignatures.clear();
}

let lastFallbackWarnAt = 0;
function warnFallbackThrottled(): void {
  const now = Date.now();
  if (now - lastFallbackWarnAt >= FALLBACK_WARN_INTERVAL_MS) {
    lastFallbackWarnAt = now;
    console.warn(
      '[DistributedRateLimiter] Redis unavailable — failing open to local in-memory token bucket (per-node enforcement).'
    );
  }
}

// ─── Identity & header helpers ────────────────────────────────────────────────

function firstHeader(value: string | string[] | undefined): string {
  const raw = Array.isArray(value) ? value[0] : value;
  return typeof raw === 'string' ? raw.trim() : '';
}

/**
 * X-Timestamp accepts unix seconds or milliseconds; sub-1e10 values are
 * treated as seconds (valid until the year 2286 in ms).
 */
function normalizeTimestampMs(raw: string): number {
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0) return NaN;
  return value < 10_000_000_000 ? value * 1000 : value;
}

function requestPath(req: RateLimitRequest): string {
  return req.originalUrl || req.url || '';
}

function resolveRequestIp(req: RateLimitRequest): string {
  if (req.clientIp) return req.clientIp;
  try {
    const ip = resolveClientIp(req);
    if (ip) return ip;
  } catch {
    // fall through to request-provided addresses
  }
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

/**
 * Bucket + signature dedup keys share a hash tag so they co-locate in Redis
 * Cluster while distinct identities shard independently.
 */
function bucketKeys(
  scope: string,
  id: string
): { bucketKey: string; sigKey: string } {
  const tag = `ratelimit:{${scope}:${id}}`;
  return { bucketKey: `${tag}:bucket`, sigKey: `${tag}:sig` };
}

const AUTH_ERROR_STATUS: Record<SignatureErrorReason, number> = {
  missing_public_key: 400,
  invalid_timestamp: 400,
  invalid_public_key: 401,
  invalid_signature: 401,
  stale_timestamp: 401,
};

// ─── Middleware factory ───────────────────────────────────────────────────────

export function distributedRateLimiter(
  options: DistributedRateLimiterOptions = {}
): RateLimitMiddleware {
  const {
    scope = DEFAULT_SCOPE,
    windowMs = DEFAULT_WINDOW_MS,
    tiers,
    enterprisePublicKeys,
    timestampFreshnessMs = DEFAULT_TIMESTAMP_FRESHNESS_MS,
    replayProtection = true,
    cost = DEFAULT_COST,
    slowWarnMs = DEFAULT_SLOW_WARN_MS,
    verifySignature = verifyStellarEd25519Request,
  } = options;

  const limits: Record<RateLimitTier, number> = {
    ...TIER_LIMITS_PER_MINUTE,
    ...(tiers ?? {}),
  };
  const enterpriseKeys = enterprisePublicKeys
    ? new Set(enterprisePublicKeys.map((key) => key.trim()).filter(Boolean))
    : DEFAULT_ENTERPRISE_PUBLIC_KEYS;
  const replayTtlSec = Math.max(
    1,
    Math.ceil((timestampFreshnessMs * 2) / 1000)
  );

  return async (req, res, next) => {
    const startedAt = performance.now();
    let tier: RateLimitTier = 'anonymous';
    try {
      // 1. Authenticate: Ed25519 signature headers → JWT user → IP.
      const signatureHeader = firstHeader(req.headers['x-stellar-signature']);
      let identityId: string;
      let digest = '';

      if (signatureHeader) {
        const publicKey = firstHeader(req.headers['x-stellar-public-key']);
        const timestampMs = normalizeTimestampMs(
          firstHeader(req.headers['x-timestamp'])
        );
        const verification = verifySignature({
          publicKey,
          signature: signatureHeader,
          timestampMs,
          method: req.method || 'GET',
          path: requestPath(req),
          freshnessMs: timestampFreshnessMs,
        });
        if (!verification.valid) {
          metrics.authFailures++;
          const reason = verification.reason || 'invalid_signature';
          const status = AUTH_ERROR_STATUS[reason] || 401;
          return next(
            createHttpError(
              status,
              `Stellar signature authentication failed: ${reason}`,
              { reason }
            )
          );
        }
        identityId = `ed25519:${publicKey}`;
        digest = replayProtection ? verification.digest : '';
        tier = enterpriseKeys.has(publicKey) ? 'enterprise' : 'authenticated';
      } else if (req.user?.id !== undefined && req.user.id !== null) {
        identityId = `user:${req.user.id}`;
        tier = req.user.tier === 'enterprise' ? 'enterprise' : 'authenticated';
      } else {
        identityId = `ip:${resolveRequestIp(req)}`;
        tier = 'anonymous';
      }

      // 2. Consume one token atomically (Redis, or local fallback).
      const capacity = Math.max(
        1,
        Math.round((limits[tier] * windowMs) / 60000)
      );
      const { bucketKey, sigKey } = bucketKeys(scope, identityId);
      const argv = [capacity, windowMs, cost, digest, replayTtlSec];

      let result: TokenBucketResult;
      const client = redisService.client as RedisLike | null | undefined;
      if (!redisService.isFallbackMode && client) {
        try {
          const rows = await redisService.executeWithCircuitBreaker(() =>
            evalTokenBucketScript(client, bucketKey, sigKey, argv)
          );
          result = parseScriptRows(rows);
        } catch {
          warnFallbackThrottled();
          result = runLocalBucket(
            identityId,
            capacity,
            windowMs,
            cost,
            digest,
            replayTtlSec
          );
        }
      } else {
        warnFallbackThrottled();
        result = runLocalBucket(
          identityId,
          capacity,
          windowMs,
          cost,
          digest,
          replayTtlSec
        );
      }
      if (result.fallback) metrics.localFallbacks++;

      // 3. RFC 6585 headers + response.
      const nowSec = Math.floor(Date.now() / 1000);
      const resetInSec = result.allowed
        ? Math.max(1, result.resetAfterSec)
        : Math.max(1, result.retryAfterSec);
      const headers: Record<string, string | number> = {
        'X-RateLimit-Limit': capacity,
        'X-RateLimit-Remaining': result.remaining,
        'X-RateLimit-Reset': nowSec + resetInSec,
        'X-RateLimit-Tier': tier,
      };
      if (result.fallback) headers['X-RateLimit-Fallback'] = 'local';
      res.set(headers);

      req.rateLimit = {
        scope,
        tier,
        identity: identityId,
        limit: capacity,
        remaining: result.remaining,
        fallback: result.fallback,
      };

      if (result.replay) {
        metrics.replaysBlocked++;
        return next(
          createHttpError(401, 'Replayed request signature', {
            reason: 'replay',
          })
        );
      }

      if (!result.allowed) {
        metrics.blocked++;
        res.set('Retry-After', String(Math.max(1, result.retryAfterSec)));
        return next(
          createHttpError(429, 'Too Many Requests', {
            retryAfter: Math.max(1, result.retryAfterSec),
            reset: nowSec + resetInSec,
            tier,
          })
        );
      }

      metrics.allowed++;
      return next();
    } catch (err) {
      // Fail open: availability beats enforcement for the limiter itself.
      console.error('[DistributedRateLimiter] unexpected error:', err);
      return next();
    } finally {
      const durationMs = performance.now() - startedAt;
      metrics.checks++;
      metrics.totalLatencyMs += durationMs;
      metrics.lastLatencyMs = durationMs;
      if (durationMs > metrics.maxLatencyMs) metrics.maxLatencyMs = durationMs;
      if (durationMs > SLOW_CHECK_THRESHOLD_MS) metrics.slowChecks++;
      if (durationMs > slowWarnMs) {
        console.warn(
          `[DistributedRateLimiter] slow check ${durationMs.toFixed(2)}ms exceeded ${slowWarnMs}ms budget`
        );
      }
    }
  };
}

export default distributedRateLimiter;
