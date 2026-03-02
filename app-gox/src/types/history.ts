import type { RepairRequest } from './repair';

export interface RepairHistoryEntry {
  repairRequest: RepairRequest;
  totalMaterialCost: number;
}

export interface MachineRepairHistory {
  machineName: string;
  locationId: string;
  entries: RepairHistoryEntry[];
  cumulativeCost: number;
}

export interface HistoryFilters {
  dateFrom?: string;
  dateTo?: string;
  locationId?: string;
  machineName?: string;
}
