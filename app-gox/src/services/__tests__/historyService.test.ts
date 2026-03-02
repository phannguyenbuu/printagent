import { describe, it, expect } from 'vitest';
import { getRepairHistory, filterHistory } from '../historyService';
import type { RepairRequest } from '../../types/repair';
import type { RepairHistoryEntry } from '../../types/history';

function makeRequest(overrides: Partial<RepairRequest> = {}): RepairRequest {
  return {
    id: 'req-1',
    machineName: 'CNC-01',
    locationId: 'loc-1',
    workspaceId: 'ws-1',
    description: 'Broken bearing',
    priority: 'high',
    status: 'completed',
    createdBy: 'user-1',
    assignedTo: 'tech-1',
    attachments: [],
    progressNotes: [],
    materials: [],
    completionReport: null,
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-02T00:00:00Z',
    acceptedAt: '2024-01-01T01:00:00Z',
    completedAt: '2024-01-02T00:00:00Z',
    ...overrides,
  };
}

describe('getRepairHistory', () => {
  it('returns empty array when no requests match', () => {
    const requests = [makeRequest({ machineName: 'CNC-02' })];
    expect(getRepairHistory(requests, 'CNC-01')).toEqual([]);
  });

  it('filters only completed requests for the given machine', () => {
    const requests = [
      makeRequest({ id: 'r1', status: 'completed', machineName: 'CNC-01' }),
      makeRequest({ id: 'r2', status: 'in_progress', machineName: 'CNC-01' }),
      makeRequest({ id: 'r3', status: 'completed', machineName: 'CNC-02' }),
      makeRequest({ id: 'r4', status: 'new', machineName: 'CNC-01' }),
    ];
    const result = getRepairHistory(requests, 'CNC-01');
    expect(result).toHaveLength(1);
    expect(result[0].repairRequest.id).toBe('r1');
  });

  it('sorts by completedAt descending', () => {
    const requests = [
      makeRequest({ id: 'r1', completedAt: '2024-01-01T00:00:00Z' }),
      makeRequest({ id: 'r2', completedAt: '2024-03-01T00:00:00Z' }),
      makeRequest({ id: 'r3', completedAt: '2024-02-01T00:00:00Z' }),
    ];
    const result = getRepairHistory(requests, 'CNC-01');
    expect(result.map((e) => e.repairRequest.id)).toEqual(['r2', 'r3', 'r1']);
  });

  it('calculates totalMaterialCost for each entry', () => {
    const requests = [
      makeRequest({
        id: 'r1',
        materials: [
          { id: 'm1', repairRequestId: 'r1', name: 'Bolt', quantity: 10, unitPrice: 5, totalPrice: 50 },
          { id: 'm2', repairRequestId: 'r1', name: 'Nut', quantity: 4, unitPrice: 2, totalPrice: 8 },
        ],
      }),
    ];
    const result = getRepairHistory(requests, 'CNC-01');
    expect(result[0].totalMaterialCost).toBe(58);
  });

  it('returns empty array for empty input', () => {
    expect(getRepairHistory([], 'CNC-01')).toEqual([]);
  });
});

describe('filterHistory', () => {
  const baseEntries: RepairHistoryEntry[] = [
    {
      repairRequest: makeRequest({ id: 'r1', machineName: 'CNC-01', locationId: 'loc-1', completedAt: '2024-01-15T00:00:00Z' }),
      totalMaterialCost: 100,
    },
    {
      repairRequest: makeRequest({ id: 'r2', machineName: 'CNC-02', locationId: 'loc-2', completedAt: '2024-02-15T00:00:00Z' }),
      totalMaterialCost: 200,
    },
    {
      repairRequest: makeRequest({ id: 'r3', machineName: 'CNC-01', locationId: 'loc-1', completedAt: '2024-03-15T00:00:00Z' }),
      totalMaterialCost: 150,
    },
  ];

  it('returns all entries when no filters applied', () => {
    expect(filterHistory(baseEntries, {})).toHaveLength(3);
  });

  it('filters by dateFrom', () => {
    const result = filterHistory(baseEntries, { dateFrom: '2024-02-01T00:00:00Z' });
    expect(result).toHaveLength(2);
  });

  it('filters by dateTo', () => {
    const result = filterHistory(baseEntries, { dateTo: '2024-02-01T00:00:00Z' });
    expect(result).toHaveLength(1);
    expect(result[0].repairRequest.id).toBe('r1');
  });

  it('filters by locationId', () => {
    const result = filterHistory(baseEntries, { locationId: 'loc-2' });
    expect(result).toHaveLength(1);
    expect(result[0].repairRequest.id).toBe('r2');
  });

  it('filters by machineName', () => {
    const result = filterHistory(baseEntries, { machineName: 'CNC-01' });
    expect(result).toHaveLength(2);
  });

  it('applies multiple filters with AND logic', () => {
    const result = filterHistory(baseEntries, {
      machineName: 'CNC-01',
      dateFrom: '2024-02-01T00:00:00Z',
    });
    expect(result).toHaveLength(1);
    expect(result[0].repairRequest.id).toBe('r3');
  });

  it('returns empty when no entries match', () => {
    const result = filterHistory(baseEntries, { machineName: 'CNC-01', locationId: 'loc-2' });
    expect(result).toHaveLength(0);
  });
});
