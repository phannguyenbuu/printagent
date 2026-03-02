import { describe, it, expect } from 'vitest';
import {
  sortByCreatedDate,
  sortByPriority,
  filterRequests,
  getRecentRequests,
} from '../filterService';
import type { RepairRequest } from '../../types/repair';

function makeRequest(overrides: Partial<RepairRequest> = {}): RepairRequest {
  return {
    id: 'req-1',
    machineName: 'Machine A',
    locationId: 'loc-1',
    workspaceId: 'ws-1',
    description: 'Broken belt',
    priority: 'medium',
    status: 'new',
    createdBy: 'user-1',
    assignedTo: null,
    attachments: [],
    progressNotes: [],
    materials: [],
    completionReport: null,
    createdAt: '2024-01-15T10:00:00Z',
    updatedAt: '2024-01-15T10:00:00Z',
    acceptedAt: null,
    completedAt: null,
    ...overrides,
  };
}

describe('sortByCreatedDate', () => {
  it('returns empty array for empty input', () => {
    expect(sortByCreatedDate([])).toEqual([]);
  });

  it('sorts newest first', () => {
    const requests = [
      makeRequest({ id: 'old', createdAt: '2024-01-01T00:00:00Z' }),
      makeRequest({ id: 'new', createdAt: '2024-03-01T00:00:00Z' }),
      makeRequest({ id: 'mid', createdAt: '2024-02-01T00:00:00Z' }),
    ];
    const sorted = sortByCreatedDate(requests);
    expect(sorted.map((r) => r.id)).toEqual(['new', 'mid', 'old']);
  });

  it('does not mutate the original array', () => {
    const requests = [
      makeRequest({ id: 'b', createdAt: '2024-01-01T00:00:00Z' }),
      makeRequest({ id: 'a', createdAt: '2024-06-01T00:00:00Z' }),
    ];
    const original = [...requests];
    sortByCreatedDate(requests);
    expect(requests).toEqual(original);
  });

  it('handles single element', () => {
    const requests = [makeRequest({ id: 'only' })];
    expect(sortByCreatedDate(requests)).toEqual(requests);
  });
});

describe('sortByPriority', () => {
  it('returns empty array for empty input', () => {
    expect(sortByPriority([])).toEqual([]);
  });

  it('sorts critical > high > medium > low', () => {
    const requests = [
      makeRequest({ id: 'low', priority: 'low' }),
      makeRequest({ id: 'critical', priority: 'critical' }),
      makeRequest({ id: 'medium', priority: 'medium' }),
      makeRequest({ id: 'high', priority: 'high' }),
    ];
    const sorted = sortByPriority(requests);
    expect(sorted.map((r) => r.id)).toEqual(['critical', 'high', 'medium', 'low']);
  });

  it('does not mutate the original array', () => {
    const requests = [
      makeRequest({ id: 'low', priority: 'low' }),
      makeRequest({ id: 'critical', priority: 'critical' }),
    ];
    const original = [...requests];
    sortByPriority(requests);
    expect(requests).toEqual(original);
  });

  it('preserves relative order for same priority', () => {
    const requests = [
      makeRequest({ id: 'a', priority: 'high' }),
      makeRequest({ id: 'b', priority: 'high' }),
    ];
    const sorted = sortByPriority(requests);
    expect(sorted.map((r) => r.id)).toEqual(['a', 'b']);
  });
});

describe('filterRequests', () => {
  const requests = [
    makeRequest({ id: '1', status: 'new', locationId: 'loc-1', priority: 'high' }),
    makeRequest({ id: '2', status: 'accepted', locationId: 'loc-1', priority: 'low' }),
    makeRequest({ id: '3', status: 'new', locationId: 'loc-2', priority: 'critical' }),
    makeRequest({ id: '4', status: 'completed', locationId: 'loc-2', priority: 'medium' }),
  ];

  it('returns all when no filters provided', () => {
    expect(filterRequests(requests, {})).toHaveLength(4);
  });

  it('filters by status', () => {
    const result = filterRequests(requests, { status: 'new' });
    expect(result.map((r) => r.id)).toEqual(['1', '3']);
  });

  it('filters by locationId', () => {
    const result = filterRequests(requests, { locationId: 'loc-2' });
    expect(result.map((r) => r.id)).toEqual(['3', '4']);
  });

  it('filters by priority', () => {
    const result = filterRequests(requests, { priority: 'high' });
    expect(result.map((r) => r.id)).toEqual(['1']);
  });

  it('applies AND logic for multiple filters', () => {
    const result = filterRequests(requests, { status: 'new', locationId: 'loc-1' });
    expect(result.map((r) => r.id)).toEqual(['1']);
  });

  it('applies all three filters together', () => {
    const result = filterRequests(requests, {
      status: 'new',
      locationId: 'loc-2',
      priority: 'critical',
    });
    expect(result.map((r) => r.id)).toEqual(['3']);
  });

  it('returns empty when no match', () => {
    const result = filterRequests(requests, { status: 'cancelled' });
    expect(result).toEqual([]);
  });

  it('returns empty for empty input', () => {
    expect(filterRequests([], { status: 'new' })).toEqual([]);
  });

  it('does not mutate the original array', () => {
    const original = [...requests];
    filterRequests(requests, { status: 'new' });
    expect(requests).toEqual(original);
  });
});

describe('getRecentRequests', () => {
  it('returns empty array for empty input', () => {
    expect(getRecentRequests([])).toEqual([]);
  });

  it('returns at most 10 by default', () => {
    const requests = Array.from({ length: 15 }, (_, i) =>
      makeRequest({
        id: `req-${i}`,
        createdAt: `2024-01-${String(i + 1).padStart(2, '0')}T00:00:00Z`,
      })
    );
    const result = getRecentRequests(requests);
    expect(result).toHaveLength(10);
  });

  it('returns all if fewer than limit', () => {
    const requests = [
      makeRequest({ id: 'a', createdAt: '2024-01-01T00:00:00Z' }),
      makeRequest({ id: 'b', createdAt: '2024-01-02T00:00:00Z' }),
    ];
    const result = getRecentRequests(requests, 5);
    expect(result).toHaveLength(2);
  });

  it('returns newest first', () => {
    const requests = [
      makeRequest({ id: 'old', createdAt: '2024-01-01T00:00:00Z' }),
      makeRequest({ id: 'new', createdAt: '2024-03-01T00:00:00Z' }),
      makeRequest({ id: 'mid', createdAt: '2024-02-01T00:00:00Z' }),
    ];
    const result = getRecentRequests(requests, 2);
    expect(result.map((r) => r.id)).toEqual(['new', 'mid']);
  });

  it('respects custom limit', () => {
    const requests = Array.from({ length: 5 }, (_, i) =>
      makeRequest({
        id: `req-${i}`,
        createdAt: `2024-01-${String(i + 1).padStart(2, '0')}T00:00:00Z`,
      })
    );
    const result = getRecentRequests(requests, 3);
    expect(result).toHaveLength(3);
    // Should be the 3 newest: req-4, req-3, req-2
    expect(result.map((r) => r.id)).toEqual(['req-4', 'req-3', 'req-2']);
  });

  it('does not mutate the original array', () => {
    const requests = [
      makeRequest({ id: 'b', createdAt: '2024-01-01T00:00:00Z' }),
      makeRequest({ id: 'a', createdAt: '2024-06-01T00:00:00Z' }),
    ];
    const original = [...requests];
    getRecentRequests(requests, 1);
    expect(requests).toEqual(original);
  });
});
