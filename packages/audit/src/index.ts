/**
 * @sug/audit
 * Cryptographic audit chain and checkpoint verification contracts
 */

export const AuditPackageName = '@sug/audit' as const;

export interface AuditInfo {
  name: typeof AuditPackageName;
  version: string;
}

export const AuditInfo: AuditInfo = {
  name: AuditPackageName,
  version: '0.1.0',
};
