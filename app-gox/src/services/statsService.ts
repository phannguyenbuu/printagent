import type { RepairRequest, RepairStatus } from '../types/repair';
import { calculateTotalMaterialCost } from './materialService';

const ALL_STATUSES: RepairStatus[] = ['new', 'accepted', 'in_progress', 'completed', 'cancelled'];

/**
 * Counts repair requests by status, filtered to only those in the user's locations.
 * Returns a Record with every RepairStatus key, defaulting to 0.
 */
export function calculateStatusStats(
  requests: RepairRequest[],
  userLocationIds: string[]
): Record<RepairStatus, number> {
  const locationSet = new Set(userLocationIds);

  const stats = Object.fromEntries(
    ALL_STATUSES.map((s) => [s, 0])
  ) as Record<RepairStatus, number>;

  for (const req of requests) {
    if (locationSet.has(req.locationId)) {
      stats[req.status]++;
    }
  }

  return stats;
}

/**
 * Calculates the cumulative material cost for a specific machine,
 * considering only completed repair requests.
 */
export function calculateCumulativeCost(
  requests: RepairRequest[],
  machineName: string
): number {
  return requests
    .filter((r) => r.status === 'completed' && r.machineName === machineName)
    .reduce((sum, r) => sum + calculateTotalMaterialCost(r.materials), 0);
}

export interface UserRepairStats {
  completedCount: number;
  cancelledCount: number;
  totalLaborCost: number;
  totalMaterialCost: number;
  totalCost: number;
  averageRating: number | null;
  ratingCount: number;
}

export type StatPeriod = 'month' | 'quarter' | 'year';

export interface DateRange {
  from: Date;
  to: Date;
}

export function getDateRangeForPeriod(period: StatPeriod, now = new Date()): DateRange {
  const y = now.getFullYear();
  const m = now.getMonth(); // 0-indexed
  if (period === 'month') {
    return { from: new Date(y, m, 1), to: new Date(y, m + 1, 0, 23, 59, 59, 999) };
  }
  if (period === 'quarter') {
    const q = Math.floor(m / 3);
    return { from: new Date(y, q * 3, 1), to: new Date(y, q * 3 + 3, 0, 23, 59, 59, 999) };
  }
  // year
  return { from: new Date(y, 0, 1), to: new Date(y, 11, 31, 23, 59, 59, 999) };
}

export function formatPeriodLabel(period: StatPeriod, now = new Date()): string {
  const y = now.getFullYear();
  const m = now.getMonth() + 1; // 1-indexed
  if (period === 'month') return `Tháng ${m}/${y}`;
  if (period === 'quarter') return `Quý ${Math.ceil(m / 3)}/${y}`;
  return `Năm ${y}`;
}

/**
 * Calculates repair statistics for a specific user (technician or supplier).
 * Optionally filtered by a date range (based on completedAt / updatedAt).
 */
export function calculateUserRepairStats(
  requests: RepairRequest[],
  userId: string,
  role: 'supplier' | 'technician',
  dateRange?: DateRange
): UserRepairStats {
  const userRequests = requests.filter((r) => {
    const matchUser = role === 'supplier' ? r.createdBy === userId : r.assignedTo === userId;
    if (!matchUser) return false;
    if (dateRange) {
      const d = new Date(r.completedAt ?? r.updatedAt);
      return d >= dateRange.from && d <= dateRange.to;
    }
    return true;
  });

  const completedRequests = userRequests.filter((r) => r.status === 'completed');
  const cancelledCount = userRequests.filter((r) => r.status === 'cancelled').length;

  const totalLaborCost = completedRequests.reduce((sum, r) => sum + (r.laborCost ?? 0), 0);
  const totalMaterialCost = completedRequests.reduce(
    (sum, r) => sum + calculateTotalMaterialCost(r.materials),
    0
  );

  const ratedRequests = completedRequests.filter((r) => r.rating != null);
  const averageRating = ratedRequests.length > 0
    ? ratedRequests.reduce((sum, r) => sum + (r.rating ?? 0), 0) / ratedRequests.length
    : null;

  return {
    completedCount: completedRequests.length,
    cancelledCount,
    totalLaborCost,
    totalMaterialCost,
    totalCost: totalLaborCost + totalMaterialCost,
    averageRating,
    ratingCount: ratedRequests.length,
  };
}

export interface ActivityEntry {
  requestId: string;
  machineName: string;
  locationId: string;
  status: RepairStatus;
  date: string;
  laborCost?: number;
  materialCost: number;
}

/**
 * Returns recent activity entries for a user, sorted by most recent first.
 */
export function getUserActivityHistory(
  requests: RepairRequest[],
  userId: string,
  role: 'supplier' | 'technician',
  limit = 20
): ActivityEntry[] {
  const userRequests = requests.filter((r) =>
    role === 'supplier' ? r.createdBy === userId : r.assignedTo === userId
  );

  return userRequests
    .sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime())
    .slice(0, limit)
    .map((r) => ({
      requestId: r.id,
      machineName: r.machineName,
      locationId: r.locationId,
      status: r.status,
      date: r.completedAt ?? r.updatedAt,
      laborCost: r.laborCost,
      materialCost: calculateTotalMaterialCost(r.materials),
    }));
}
