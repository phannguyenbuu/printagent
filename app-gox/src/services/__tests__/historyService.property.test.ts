import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { getRepairHistory, filterHistory } from '../historyService';
import type { RepairRequest, RepairStatus, Priority } from '../../types/repair';
import type { RepairHistoryEntry, HistoryFilters } from '../../types/history';

const STATUSES: RepairStatus[] = ['new', 'accepted', 'in_progress', 'completed', 'cancelled'];
const PRIORITIES: Priority[] = ['low', 'medium', 'high', 'critical'];

const isoDateArb = fc
  .date({ min: new Date('2020-01-01'), max: new Date('2030-12-31') })
  .map((d) => d.toISOString());

const machineNameArb = fc.constantFrom('CNC-01', 'CNC-02', 'LATHE-01', 'PRESS-01');
const locationIdArb = fc.constantFrom('loc-1', 'loc-2', 'loc-3');

const requestArb: fc.Arbitrary<RepairRequest> = fc.record({
  id: fc.uuid(),
  machineName: machineNameArb,
  locationId: locationIdArb,
  workspaceId: fc.constantFrom('ws-1', 'ws-2'),
  description: fc.string({ minLength: 1, maxLength: 100 }),
  priority: fc.constantFrom(...PRIORITIES),
  status: fc.constantFrom(...STATUSES),
  createdBy: fc.uuid(),
  assignedTo: fc.option(fc.uuid(), { nil: null }),
  attachments: fc.constant([]),
  progressNotes: fc.constant([]),
  materials: fc.constant([]),
  completionReport: fc.constant(null),
  createdAt: isoDateArb,
  updatedAt: isoDateArb,
  acceptedAt: fc.constant(null),
  completedAt: fc.option(isoDateArb, { nil: null }),
});

const historyEntryArb: fc.Arbitrary<RepairHistoryEntry> = fc.record({
  repairRequest: requestArb.map((r) => ({ ...r, status: 'completed' as RepairStatus })),
  totalMaterialCost: fc.float({ min: 0, max: 10000, noNaN: true }),
});

const historyFiltersArb: fc.Arbitrary<HistoryFilters> = fc.record(
  {
    dateFrom: isoDateArb,
    dateTo: isoDateArb,
    locationId: locationIdArb,
    machineName: machineNameArb,
  },
  { requiredKeys: [] }
);

/**
 * Property 15: Lịch sử sửa chữa chỉ chứa yêu cầu hoàn thành
 * Validates: Requirements 8.1
 */
describe('Property 15: Lịch sử sửa chữa chỉ chứa yêu cầu hoàn thành', () => {
  it('Feature: machine-repair-management, Property 15: Lịch sử sửa chữa chỉ chứa yêu cầu hoàn thành — Validates: Requirements 8.1', () => {
    fc.assert(
      fc.property(fc.array(requestArb), machineNameArb, (requests, machineName) => {
        const result = getRepairHistory(requests, machineName);

        // All returned entries must have status 'completed' and match machineName
        for (const entry of result) {
          expect(entry.repairRequest.status).toBe('completed');
          expect(entry.repairRequest.machineName).toBe(machineName);
        }

        // Must be sorted descending by completedAt
        for (let i = 0; i < result.length - 1; i++) {
          const dateA = result[i].repairRequest.completedAt ?? '';
          const dateB = result[i + 1].repairRequest.completedAt ?? '';
          expect(dateA >= dateB).toBe(true);
        }

        // Count of results must equal number of completed requests for this machine
        const expectedCount = requests.filter(
          (r) => r.status === 'completed' && r.machineName === machineName
        ).length;
        expect(result.length).toBe(expectedCount);
      }),
      { numRuns: 100 }
    );
  });
});

/**
 * Property 16: Lọc lịch sử sửa chữa chính xác
 * Validates: Requirements 8.3
 */
describe('Property 16: Lọc lịch sử sửa chữa chính xác', () => {
  it('Feature: machine-repair-management, Property 16: Lọc lịch sử sửa chữa chính xác — Validates: Requirements 8.3', () => {
    fc.assert(
      fc.property(fc.array(historyEntryArb), historyFiltersArb, (history, filters) => {
        const result = filterHistory(history, filters);

        // Every result must satisfy ALL active filter conditions simultaneously
        for (const entry of result) {
          const { repairRequest } = entry;
          const completedAt = repairRequest.completedAt ?? '';

          if (filters.dateFrom !== undefined) {
            expect(completedAt >= filters.dateFrom).toBe(true);
          }

          if (filters.dateTo !== undefined) {
            expect(completedAt <= filters.dateTo).toBe(true);
          }

          if (filters.locationId !== undefined) {
            expect(repairRequest.locationId).toBe(filters.locationId);
          }

          if (filters.machineName !== undefined) {
            expect(repairRequest.machineName).toBe(filters.machineName);
          }
        }

        // No entry excluded by the filter should appear in results
        const excluded = history.filter((entry) => {
          const { repairRequest } = entry;
          const completedAt = repairRequest.completedAt ?? '';

          if (filters.dateFrom && completedAt < filters.dateFrom) return true;
          if (filters.dateTo && completedAt > filters.dateTo) return true;
          if (filters.locationId && repairRequest.locationId !== filters.locationId) return true;
          if (filters.machineName && repairRequest.machineName !== filters.machineName) return true;
          return false;
        });

        for (const excludedEntry of excluded) {
          expect(result).not.toContain(excludedEntry);
        }
      }),
      { numRuns: 100 }
    );
  });
});
