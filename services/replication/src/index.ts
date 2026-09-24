/**
 * @sug/service-replication
 * Cross-cloud write-once ciphertext replication service
 */

export const Service_ReplicationPackageName = '@sug/service-replication' as const;

export interface Service_ReplicationInfo {
  name: typeof Service_ReplicationPackageName;
  version: string;
}

export const Service_ReplicationInfo: Service_ReplicationInfo = {
  name: Service_ReplicationPackageName,
  version: '0.1.0',
};
