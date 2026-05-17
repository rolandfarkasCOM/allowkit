import type { Env } from '../types';
import { parseAppList } from '../lib/security';

// Body's appId is already lowercase-only per schema; APP_IDS allowlist is
// lowercased by parseAppList. Comparison is therefore case-exact.
export function isAppIdAllowed(appId: string, env: Env): boolean {
  return parseAppList(env.APP_IDS).has(appId);
}
