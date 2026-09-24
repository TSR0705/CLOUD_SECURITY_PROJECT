/**
 * @sug/dashboard
 * Administrative security dashboard web application
 */

export const DashboardPackageName = '@sug/dashboard' as const;

export interface DashboardInfo {
  name: typeof DashboardPackageName;
  version: string;
}

export const DashboardInfo: DashboardInfo = {
  name: DashboardPackageName,
  version: '0.1.0',
};
