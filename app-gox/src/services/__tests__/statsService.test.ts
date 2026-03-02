import { describe, it, expect } from 'vitest';
import { calculateStatusStats, calculateCumulativeCost } from '../statsService';
import type { RepairRequest } from '../../types/repair';
import type { Material } from '../../types/material';

function makeMaterial(overrides: Partial<Material> = {}): Material {
  return {
    id: 'mat-1',
    repairRequestId: 'req-1',
    name: 'Bolt',
    quantity: 2,
    unitPrice: 50,
    totalPrice: 100,
    ...overrides,
  };
}

function makeRequest(overrides: Partial<RepairRequest> = {}): RepairRequest {
  return {
    id: 'req-1',
    machineName: 'CNC-01',
    locationId: 'loc-1',
    workspaceId: 'ws-1',
    description: 'Broken',
    priority: 'medium',
    status: 'new',
    createdBy: 'user-1',
    assignedTo: null,
    attachments: [],
    progressNotes: [],
    materials: [],
    completionReport: null,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
    acceptedAt: null,
    completedAt: null,
    ...overrides,
  };
}

describe('calculateStatusStats', () => {
  it('returns all zeros for empty requests', () => {
    const result = calculateStatusStats([], ['loc-1']);
    expect(result).toEqual({
      new: 0,
      accepted: 0,
      in_progress: 0,
      completed: 0,
      cancelled: 0,
    });
  });

  it('returns all zeros when no locations match', () => {
    const requests = [
      makeRequest({ id: 'r1', locationId: 'loc-1', status: 'new' }),
      makeRequest({ id: 'r2', locationId: 'loc-2', status: 'completed' }),
    ];
    const result = calculateStatusStats(requests, ['loc-99']);
    expect(result).toEqual({
      new: 0,
      accepted: 0,
      in_progress: 0,
      completed: 0,
      cancelled: 0,
    });
  });

  it('counts requests only from user locations', () => {
    const requests = [
      makeRequest({ id: 'r1', locationId: 'loc-1', status: 'new' }),
      makeRequest({ id: 'r2', locationId: 'loc-2', status: 'new' }),
      makeRequest({ id: 'r3', locationId: 'loc-1', status: 'completed' }),
      makeRequest({ id: 'r4', locationId: 'loc-3', status: 'in_progress' }),
    ];
    const result = calculateStatusStats(requests, ['loc-1']);
    expect(result).toEqual({
      new: 1,
      accepted: 0,
      in_progress: 0,
      completed: 1,
      cancelled: 0,
    });
  });

  it('counts all statuses correctly across multiple locations', () => {
    const requests = [
      makeRequest({ id: 'r1', locationId: 'loc-1', status: 'new' }),
      makeRequest({ id: 'r2', locationId: 'loc-2', status: 'accepted' }),
      makeRequest({ id: 'r3', locationId: 'loc-1', status: 'in_progress' }),
      makeRequest({ id: 'r4', locationId: 'loc-2', status: 'completed' }),
      makeRequest({ id: 'r5', locationId: 'loc-1', status: 'cancelled' }),
      makeRequest({ id: 'r6', locationId: 'loc-3', status: 'new' }),
    ];
    const result = calculateStatusStats(requests, ['loc-1', 'loc-2']);
    expect(result).toEqual({
      new: 1,
      accepted: 1,
      in_progress: 1,
      completed: 1,
      cancelled: 1,
    });
  });

  it('returns all zeros when userLocationIds is empty', () => {
    const requests = [
      makeRequest({ id: 'r1', locationId: 'loc-1', status: 'new' }),
    ];
    const result = calculateStatusStats(requests, []);
    expect(result).toEqual({
      new: 0,
      accepted: 0,
      in_progress: 0,
      completed: 0,
      cancelled: 0,
    });
  });
});

describe('calculateCumulativeCost', () => {
  it('returns 0 for empty requests', () => {
    expect(calculateCumulativeCost([], 'CNC-01')).toBe(0);
  });

  it('returns 0 when no completed requests match the machine', () => {
    const requests = [
      makeRequest({ id: 'r1', machineName: 'CNC-01', status: 'new', materials: [makeMaterial()] }),
      makeRequest({ id: 'r2', machineName: 'CNC-02', status: 'completed', materials: [makeMaterial()] }),
    ];
    expect(calculateCumulativeCost(requests, 'CNC-01')).toBe(0);
  });

  it('sums material costs for completed requests of the given machine', () => {
    const requests = [
      makeRequest({
        id: 'r1',
        machineName: 'CNC-01',
        status: 'completed',
        materials: [
          makeMaterial({ quantity: 2, unitPrice: 100 }),
          makeMaterial({ id: 'mat-2', quantity: 3, unitPrice: 50 }),
        ],
      }),
      makeRequest({
        id: 'r2',
        machineName: 'CNC-01',
        status: 'completed',
        materials: [
          makeMaterial({ quantity: 1, unitPrice: 200 }),
        ],
      }),
    ];
    // r1: 2*100 + 3*50 = 350, r2: 1*200 = 200 => total 550
    expect(calculateCumulativeCost(requests, 'CNC-01')).toBe(550);
  });

  it('ignores non-completed requests', () => {
    const requests = [
      makeRequest({
        id: 'r1',
        machineName: 'CNC-01',
        status: 'completed',
        materials: [makeMaterial({ quantity: 1, unitPrice: 100 })],
      }),
      makeRequest({
        id: 'r2',
        machineName: 'CNC-01',
        status: 'in_progress',
        materials: [makeMaterial({ quantity: 5, unitPrice: 500 })],
      }),
    ];
    expect(calculateCumulativeCost(requests, 'CNC-01')).toBe(100);
  });

  it('returns 0 for completed requests with no materials', () => {
    const requests = [
      makeRequest({ id: 'r1', machineName: 'CNC-01', status: 'completed', materials: [] }),
    ];
    expect(calculateCumulativeCost(requests, 'CNC-01')).toBe(0);
  });
});
