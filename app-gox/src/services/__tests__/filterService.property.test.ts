import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import {
  filterRequests,
  sortByCreatedDate,
  sortByPriority,
  getRecentRequests,
} from '../filterService';
import type { RepairRequest, RepairRequestFilters, Priority, RepairStatus } from '../../types/repair';

const PRIORITIES: Priority[] = ['low', 'medium', 'high', 'critical'];
const STATUSES: RepairStatus[] = ['new', 'accepted', 'in_progress', 'completed', 'cancelled'];
const PRIORITY_ORDER: Record<Priority, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

// Arbitrary for a valid ISO date string
const isoDateArb = fc
  .date({ min: new Date('2020-01-01'), max: new Date('2030-12-31') })
  .map((d) => d.toISOString());

// Arbitrary for a RepairRequest
const requestArb: fc.Arbitrary<RepairRequest> = fc.record({
  id: fc.uuid(),
  machineName: fc.string({ minLength: 1, maxLength: 50 }),
  locationId: fc.constantFrom('loc-1', 'loc-2', 'loc-3'),
  workspaceId: fc.constantFrom('ws-1', 'ws-2'),
  description: fc.string({ minLength: 1, maxLength: 200 }),
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
  completedAt: fc.constant(null),
});

// Arbitrary for RepairRequestFilters (each field independently optional)
const filtersArb: fc.Arbitrary<RepairRequestFilters> = fc.record(
  {
    status: fc.constantFrom(...STATUSES),
    locationId: fc.constantFrom('loc-1', 'loc-2', 'loc-3'),
    priority: fc.constantFrom(...PRIORITIES),
  },
  { requiredKeys: [] }
);

/**
 * Property 6: Lọc và sắp xếp danh sách yêu cầu sửa chữa
 * Validates: Requirements 2.4, 4.2
 *
 * Feature: machine-repair-management, Property 6: Lọc và sắp xếp danh sách yêu cầu sửa chữa
 */
describe('Property 6: Lọc và sắp xếp danh sách yêu cầu sửa chữa', () => {
  it('Feature: machine-repair-management, Property 6: Lọc và sắp xếp danh sách yêu cầu sửa chữa — Validates: Requirements 2.4, 4.2', () => {
    fc.assert(
      fc.property(fc.array(requestArb), filtersArb, (requests, filters) => {
        const filtered = filterRequests(requests, filters);
        const sorted = sortByCreatedDate(filtered);

        // All results must satisfy the filter conditions
        for (const r of filtered) {
          if (filters.status !== undefined) {
            expect(r.status).toBe(filters.status);
          }
          if (filters.locationId !== undefined) {
            expect(r.locationId).toBe(filters.locationId);
          }
          if (filters.priority !== undefined) {
            expect(r.priority).toBe(filters.priority);
          }
        }

        // Results must be sorted descending by createdAt
        for (let i = 0; i < sorted.length - 1; i++) {
          const a = new Date(sorted[i].createdAt).getTime();
          const b = new Date(sorted[i + 1].createdAt).getTime();
          expect(a).toBeGreaterThanOrEqual(b);
        }
      }),
      { numRuns: 100 }
    );
  });
});

/**
 * Property 7: Danh sách kỹ thuật viên sắp xếp theo ưu tiên
 * Validates: Requirements 3.1
 *
 * Feature: machine-repair-management, Property 7: Danh sách kỹ thuật viên sắp xếp theo ưu tiên
 */
describe('Property 7: Danh sách kỹ thuật viên sắp xếp theo ưu tiên', () => {
  it('Feature: machine-repair-management, Property 7: Danh sách kỹ thuật viên sắp xếp theo ưu tiên — Validates: Requirements 3.1', () => {
    fc.assert(
      fc.property(fc.array(requestArb), (requests) => {
        const sorted = sortByPriority(requests);

        // Must be sorted descending by priority: critical > high > medium > low
        for (let i = 0; i < sorted.length - 1; i++) {
          const orderA = PRIORITY_ORDER[sorted[i].priority];
          const orderB = PRIORITY_ORDER[sorted[i + 1].priority];
          expect(orderA).toBeLessThanOrEqual(orderB);
        }
      }),
      { numRuns: 100 }
    );
  });
});

/**
 * Property 12: Danh sách gần đây giới hạn 10
 * Validates: Requirements 5.2
 *
 * Feature: machine-repair-management, Property 12: Danh sách gần đây giới hạn 10
 */
describe('Property 12: Danh sách gần đây giới hạn 10', () => {
  it('Feature: machine-repair-management, Property 12: Danh sách gần đây giới hạn 10 — Validates: Requirements 5.2', () => {
    fc.assert(
      fc.property(fc.array(requestArb, { minLength: 11 }), (requests) => {
        const result = getRecentRequests(requests, 10);

        // Must not exceed 10 items
        expect(result.length).toBeLessThanOrEqual(10);

        // Must be sorted descending by createdAt
        for (let i = 0; i < result.length - 1; i++) {
          const a = new Date(result[i].createdAt).getTime();
          const b = new Date(result[i + 1].createdAt).getTime();
          expect(a).toBeGreaterThanOrEqual(b);
        }
      }),
      { numRuns: 100 }
    );
  });
});
