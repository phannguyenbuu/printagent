import type { RepairRequest, RepairRequestFilters, Priority } from '../types/repair';

const PRIORITY_ORDER: Record<Priority, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

/**
 * Sorts repair requests by createdAt descending (newest first).
 * Returns a new array — does not mutate the input.
 */
export function sortByCreatedDate(requests: RepairRequest[]): RepairRequest[] {
  return [...requests].sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
  );
}

/**
 * Sorts repair requests by priority descending: critical > high > medium > low.
 * Returns a new array — does not mutate the input.
 */
export function sortByPriority(requests: RepairRequest[]): RepairRequest[] {
  return [...requests].sort(
    (a, b) => PRIORITY_ORDER[a.priority] - PRIORITY_ORDER[b.priority]
  );
}

/**
 * Filters repair requests by the provided filters (AND logic).
 * Only applies a filter when the corresponding field is defined.
 * Returns a new array — does not mutate the input.
 */
export function filterRequests(
  requests: RepairRequest[],
  filters: RepairRequestFilters
): RepairRequest[] {
  return requests.filter((r) => {
    if (filters.status !== undefined && r.status !== filters.status) return false;
    if (filters.locationId !== undefined && r.locationId !== filters.locationId) return false;
    if (filters.priority !== undefined && r.priority !== filters.priority) return false;
    return true;
  });
}

/**
 * Returns at most `limit` most recent repair requests, sorted by createdAt descending.
 * Defaults to 10 if limit is not provided.
 * Returns a new array — does not mutate the input.
 */
export function getRecentRequests(
  requests: RepairRequest[],
  limit: number = 10
): RepairRequest[] {
  return sortByCreatedDate(requests).slice(0, limit);
}
