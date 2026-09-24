/**
 * @sug/crypto
 * SUG1 envelope encryption and key provider contracts
 */

export const CryptoPackageName = '@sug/crypto' as const;

export interface CryptoInfo {
  name: typeof CryptoPackageName;
  version: string;
}

export const CryptoInfo: CryptoInfo = {
  name: CryptoPackageName,
  version: '0.1.0',
};
