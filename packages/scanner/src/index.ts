/**
 * @sug/scanner
 * Antivirus and YARA scanner adapters and protocol contracts
 */

export const ScannerPackageName = '@sug/scanner' as const;

export interface ScannerInfo {
  name: typeof ScannerPackageName;
  version: string;
}

export const ScannerInfo: ScannerInfo = {
  name: ScannerPackageName,
  version: '0.1.0',
};
