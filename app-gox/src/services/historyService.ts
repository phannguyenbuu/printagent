import type { RepairRequest } from '../types/repair';
import type { RepairHistoryEntry, HistoryFilters } from '../types/history';
import { calculateTotalMaterialCost } from './materialService';

/**
 * Gets repair history for a specific machine.
 * Filters only completed requests matching the machine name,
 * sorted by completedAt descending (newest first).
 */
export function getRepairHistory(
  requests: RepairRequest[],
  machineName: string
): RepairHistoryEntry[] {
  return requests
    .filter(
      (r) => r.status === 'completed' && r.machineName === machineName
    )
    .sort((a, b) => {
      const dateA = a.completedAt ?? '';
      const dateB = b.completedAt ?? '';
      return dateB.localeCompare(dateA);
    })
    .map((r) => ({
      repairRequest: r,
      totalMaterialCost: calculateTotalMaterialCost(r.materials),
    }));
}

/**
 * Filters repair history entries by date range, locationId, and machineName.
 * All conditions use AND logic; only applied when the filter field is defined.
 */
export function filterHistory(
  history: RepairHistoryEntry[],
  filters: HistoryFilters
): RepairHistoryEntry[] {
  return history.filter((entry) => {
    const { repairRequest } = entry;

    if (filters.dateFrom) {
      const completedAt = repairRequest.completedAt ?? '';
      if (completedAt < filters.dateFrom) return false;
    }

    if (filters.dateTo) {
      const completedAt = repairRequest.completedAt ?? '';
      if (completedAt > filters.dateTo) return false;
    }

    if (filters.locationId) {
      if (repairRequest.locationId !== filters.locationId) return false;
    }

    if (filters.machineName) {
      if (repairRequest.machineName !== filters.machineName) return false;
    }

    return true;
  });
}
