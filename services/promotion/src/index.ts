/**
 * @sug/service-promotion
 * Exact-artifact promotion and clean storage writer service
 */

export const Service_PromotionPackageName = '@sug/service-promotion' as const;

export interface Service_PromotionInfo {
  name: typeof Service_PromotionPackageName;
  version: string;
}

export const Service_PromotionInfo: Service_PromotionInfo = {
  name: Service_PromotionPackageName,
  version: '0.1.0',
};
