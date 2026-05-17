import type { AuditRow } from '../types';

export async function appendAudit(db: D1Database, row: AuditRow): Promise<void> {
  await db
    .prepare(
      `INSERT INTO consent_audit
        (subject_hash, app_id, action, necessary, functional, analytics, marketing, ip_hash, user_agent, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      row.subjectHash,
      row.appId,
      row.action,
      row.consent.necessary ? 1 : 0,
      row.consent.functional ? 1 : 0,
      row.consent.analytics ? 1 : 0,
      row.consent.marketing ? 1 : 0,
      row.ipHash,
      row.userAgent,
      row.createdAt,
    )
    .run();
}
