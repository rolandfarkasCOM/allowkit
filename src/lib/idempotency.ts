// 24-hour idempotency window — long enough to dedupe client retries across
// flaky networks, short enough to keep KV from accumulating unbounded keys.
const IDEMPOTENCY_TTL_SECONDS = 86_400;

const idemKey = (subjectHash: string, key: string) => `idem:${subjectHash}:${key}`;

export type IdempotencyOutcome = 'fresh' | 'replay' | 'conflict';

// Body-bound idempotency check.
// `fresh`    — first time this (subject, key) pair has been seen → caller proceeds with write
// `replay`   — same (subject, key, body) seen before → caller skips write, returns cached state
// `conflict` — same (subject, key) but DIFFERENT body → caller returns 409
//
// KV is eventually consistent, so two parallel requests with the same key may
// both observe `fresh` and both proceed. Acceptable for this use case (audit
// log gets at most one extra row per replayed request); for strict atomicity
// migrate to a Durable Object.
export async function checkIdempotency(
  kv: KVNamespace,
  subjectHash: string,
  key: string,
  bodyHash: string,
): Promise<IdempotencyOutcome> {
  const fullKey = idemKey(subjectHash, key);
  const seen = await kv.get(fullKey);
  if (seen === null) {
    await kv.put(fullKey, bodyHash, { expirationTtl: IDEMPOTENCY_TTL_SECONDS });
    return 'fresh';
  }
  return seen === bodyHash ? 'replay' : 'conflict';
}
