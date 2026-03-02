import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { calculateStatusStats, calculateCumulativeCost } from '../statsService';
import type { RepairRequest, RepairStatus, Priority } from '../../types/repair';
import type { Material } from '../../types/material';

const STATUSES: RepairStatus[] = ['new', 'accepted', 'in_progress', 'completed', 'cancelled'];
const PRIORITIES: Priority[] = ['low', 'medium', 'high', 'critical'];

const materialArb: fc.Arbitrary<Material> = fc.record({
  id: fc.uuid(),
  repairRequestId: fc.uuid(),
  name: fc.string({ minLength: 1, maxLength: 50 }),
  quantity: fc.integer({ min: 1, max: 100 }),
  unitPrice: fc.integer({ min: 1, max: 10000 }),
  totalPrice: fc.integer({ min: 1, max: 1000000 }), // not used in cost calc
});

const isoDateArb = fc
  .date({ min: new Date('2020-01-01'), max: new Date('2030-12-31') })
  .map((d) => d.toISOString());

const requestArb: fc.Arbitrary<RepairRequest> = fc.record({
  id: fc.uuid(),
  machineName: fc.constantFrom('CNC-01', 'CNC-02', 'LATHE-01', 'DRILL-01'),
  locationId: fc.constantFrom('loc-1', 'loc-2', 'loc-3', 'loc-4'),
  workspaceId: fc.constantFrom('ws-1', 'ws-2'),
  description: fc.string({ minLength: 1, maxLength: 200 }),
  priority: fc.constantFrom(...PRIORITIES),
  status: fc.constantFrom(...STATUSES),
  createdBy: fc.uuid(),
  assignedTo: fc.option(fc.uuid(), { nil: null }),
  attachments: fc.constant([]),
  progressNotes: fc.constant([]),
  materials: fc.array(materialArb, { minLength: 0, maxLength: 5 }),
  completionReport: fc.constant(null),
  createdAt: isoDateArb,
  updatedAt: isoDateArb,
  acceptedAt: fc.constant(null),
  completedAt: fc.constant(null),
});

/**
 * Property 11: Thống kê Dashboard chính xác
 * Validates: Requirements 4.3, 5.1
 *
 * Feature: machine-repair-management, Property 11: Thống kê Dashboard chính xác
 */
describe('Property 11: Thống kê Dashboard chính xác', () => {
  it('Feature: machine-repair-management, Property 11: Thống kê Dashboard chính xác — Validates: Requirements 4.3, 5.1', () => {
    fc.assert(
      fc.property(
        fc.array(requestArb),
        fc.array(fc.constantFrom('loc-1', 'loc-2', 'loc-3', 'loc-4'), { minLength: 0, maxLength: 4 }),
        (requests, locationIds) => {
          const locationSet = new Set(locationIds);
          const result = calculateStatusStats(requests, locationIds);

          // Result must have all 5 status keys
          expect(Object.keys(result).sort()).toEqual(
            ['accepted', 'cancelled', 'completed', 'in_progress', 'new']
          );

          // Each status count must equal the number of requests in those locations with that status
          for (const status of STATUSES) {
            const expected = requests.filter(
              (r) => locationSet.has(r.locationId) && r.status === status
            ).length;
            expect(result[status]).toBe(expected);
          }

          // Total count must equal total requests in those locations
          const totalInLocations = requests.filter((r) => locationSet.has(r.locationId)).length;
          const totalFromStats = STATUSES.reduce((sum, s) => sum + result[s], 0);
          expect(totalFromStats).toBe(totalInLocations);
        }
      ),
      { numRuns: 100 }
    );
  });
});

/**
 * Property 17: Tổng chi phí tích lũy chính xác
 * Validates: Requirements 8.4
 *
 * Feature: machine-repair-management, Property 17: Tổng chi phí tích lũy chính xác
 */
describe('Property 17: Tổng chi phí tích lũy chính xác', () => {
  it('Feature: machine-repair-management, Property 17: Tổng chi phí tích lũy chính xác — Validates: Requirements 8.4', () => {
    fc.assert(
      fc.property(
        fc.array(requestArb),
        fc.constantFrom('CNC-01', 'CNC-02', 'LATHE-01', 'DRILL-01'),
        (requests, machineName) => {
          const result = calculateCumulativeCost(requests, machineName);

          // Manually compute expected: sum of (quantity * unitPrice) for all materials
          // in completed requests for this machine
          const expected = requests
            .filter((r) => r.status === 'completed' && r.machineName === machineName)
            .reduce((sum, r) => {
              const materialCost = r.materials.reduce(
                (mSum, m) => mSum + m.quantity * m.unitPrice,
                0
              );
              return sum + materialCost;
            }, 0);

          expect(result).toBe(expected);

          // Result must be non-negative
          expect(result).toBeGreaterThanOrEqual(0);
        }
      ),
      { numRuns: 100 }
    );
  });
});
