/**
 * @sug/service-scanner
 * Security analysis background worker service
 */

export const Service_ScannerPackageName = '@sug/service-scanner' as const;

export interface Service_ScannerInfo {
  name: typeof Service_ScannerPackageName;
  version: string;
}

export const Service_ScannerInfo: Service_ScannerInfo = {
  name: Service_ScannerPackageName,
  version: '0.1.0',
};
