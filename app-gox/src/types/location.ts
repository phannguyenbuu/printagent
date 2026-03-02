import type { RepairStatus } from './repair';

export interface Location {
  id: string;
  name: string;
  address: string;
  phone?: string;
  machineCount: number;
  workspaceId: string;
}

export interface LocationStats {
  locationId: string;
  totalRequests: number;
  byStatus: Record<RepairStatus, number>;
}
