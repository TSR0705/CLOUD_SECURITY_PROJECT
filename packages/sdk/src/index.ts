/**
 * @sug/sdk
 * Client SDK for interacting with the Secure Upload Gateway
 */

export const SdkPackageName = '@sug/sdk' as const;

export interface SdkInfo {
  name: typeof SdkPackageName;
  version: string;
}

export const SdkInfo: SdkInfo = {
  name: SdkPackageName,
  version: '0.1.0',
};
