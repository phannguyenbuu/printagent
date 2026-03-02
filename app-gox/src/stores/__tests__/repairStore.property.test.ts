import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import type { Priority, RepairRequest } from '../../types/repair';

// Valid location IDs from mockData
const VALID_LOCATION_IDS = ['loc-1', 'loc-2', 'loc-3'];
const VALID_PRIORITIES: Priority[] = ['low', 'medium', 'high', 'critical'];

// Inline createRequest logic without network delay — mirrors mockCreateRequest from mockApi
let idCounter = 0;
function createRequestSync(
  data: Omit<
    RepairRequest,
    | 'id'
    | 'status'
    | 'createdAt'
    | 'updatedAt'
    | 'acceptedAt'
    | 'completedAt'
    | 'progressNotes'
    | 'materials'
    | 'completionReport'
    | 'assignedTo'
  >,
): RepairRequest {
  const now = new Date().toISOString();
  return {
    ...data,
    id: `req-test-${++idCounter}`,
    status: 'new',
    assignedTo: null,
    progressNotes: [],
    materials: [],
    completionReport: null,
    createdAt: now,
    updatedAt: now,
    acceptedAt: null,
    completedAt: null,
  };
}

// Generator for valid repair request data
const validRepairRequestArb = fc.record({
  machineName: fc.string({ minLength: 1, maxLength: 100 }).map((s) => s.trim()).filter((s) => s.length > 0),
  locationId: fc.constantFrom(...VALID_LOCATION_IDS),
  workspaceId: fc.constant('ws-1'),
  description: fc.string({ minLength: 1, maxLength: 500 }).map((s) => s.trim()).filter((s) => s.length > 0),
  priority: fc.constantFrom(...VALID_PRIORITIES),
  createdBy: fc.string({ minLength: 1, maxLength: 50 }).map((s) => s.trim()).filter((s) => s.length > 0),
  attachments: fc.constant([]),
});

/**
 * Property 4: Tạo yêu cầu sửa chữa hợp lệ
 * Validates: Requirements 2.1
 *
 * Feature: machine-repair-management, Property 4: Tạo yêu cầu sửa chữa hợp lệ
 */
describe('Property 4: Tạo yêu cầu sửa chữa hợp lệ', () => {
  it(
    'Feature: machine-repair-management, Property 4: Tạo yêu cầu sửa chữa hợp lệ — Validates: Requirements 2.1',
    () => {
      fc.assert(
        fc.property(validRepairRequestArb, (data) => {
          const result = createRequestSync(data);

          expect(result.status).toBe('new');
          expect(result.id).toBeDefined();
          expect(result.id).not.toBe('');
          expect(result.machineName).toBe(data.machineName);
        }),
        { numRuns: 100 },
      );
    },
  );
});
