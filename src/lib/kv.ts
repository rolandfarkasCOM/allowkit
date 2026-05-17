import type { Consent, ConsentRecord } from '../types';
import { DEFAULT_CONSENT } from '../types';

const consentKey = (subjectHash: string) => `consent:${subjectHash}`;

export async function getConsent(
  kv: KVNamespace,
  subjectHash: string,
): Promise<ConsentRecord | null> {
  return kv.get<ConsentRecord>(consentKey(subjectHash), 'json');
}

export async function putConsent(
  kv: KVNamespace,
  subjectHash: string,
  consent: Consent,
  appId: string,
  now: number,
): Promise<ConsentRecord> {
  const record: ConsentRecord = {
    ...consent,
    updatedAt: now,
    lastAppId: appId,
  };
  await kv.put(consentKey(subjectHash), JSON.stringify(record));
  return record;
}

export function defaultRecord(appId: string, now: number): ConsentRecord {
  return { ...DEFAULT_CONSENT, updatedAt: now, lastAppId: appId };
}
