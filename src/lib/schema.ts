import * as v from 'valibot';

const SubjectIdSchema = v.pipe(
  v.string('subjectId must be a string'),
  v.minLength(1, 'subjectId cannot be empty'),
  v.maxLength(512, 'subjectId too long'),
);

// Lowercase only — case-insensitive matching previously allowed `web` and
// `Web` to coexist as distinct app identifiers while sharing the same
// APP_SECRET_WEB env var. Lowercase-only eliminates that collision.
const AppIdSchema = v.pipe(
  v.string('appId must be a string'),
  v.minLength(1, 'appId cannot be empty'),
  v.maxLength(64, 'appId too long'),
  v.regex(/^[a-z0-9_-]+$/, 'appId must be lowercase alphanumeric, dashes, or underscores'),
);

// `strictObject` rejects unknown keys — defends against payload smuggling.
const CategoriesSchema = v.strictObject({
  necessary: v.literal(true, 'necessary must be true'),
  functional: v.boolean('functional must be a boolean'),
  analytics: v.boolean('analytics must be a boolean'),
  marketing: v.boolean('marketing must be a boolean'),
});

export const ConsentBodySchema = v.strictObject({
  appId: AppIdSchema,
  subjectId: SubjectIdSchema,
  consent: CategoriesSchema,
});

export const WithdrawBodySchema = v.strictObject({
  appId: AppIdSchema,
  subjectId: SubjectIdSchema,
});

export type ConsentBody = v.InferOutput<typeof ConsentBodySchema>;
export type WithdrawBody = v.InferOutput<typeof WithdrawBodySchema>;

export function flattenIssues(issues: readonly v.BaseIssue<unknown>[]): Array<{
  path: string;
  message: string;
}> {
  return issues.map((issue) => ({
    path: (issue.path ?? []).map((p) => String(p.key)).join('.') || '(root)',
    message: issue.message,
  }));
}
