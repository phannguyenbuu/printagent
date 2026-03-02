import { describe, it, expect } from 'vitest';
import { getPermittedFeatures, getAccessibleLocations } from '../accessControl';
import type { Feature } from '../accessControl';
import type { User } from '../../types/auth';
import type { Location } from '../../types/location';

function makeUser(overrides: Partial<User> = {}): User {
  return {
    id: 'user-1',
    username: 'testuser',
    email: 'testuser@test.com',
    fullName: 'Test User',
    role: 'supplier',
    locationIds: ['loc-1'],
    companyId: 'CTY001',
    companyName: 'Test Company',
    workspaceIds: ['ws-1'],
    ...overrides,
  };
}

function makeLocation(overrides: Partial<Location> = {}): Location {
  return {
    id: 'loc-1',
    name: 'Location 1',
    address: '123 Main St',
    machineCount: 5,
    workspaceId: 'ws-1',
    ...overrides,
  };
}

describe('getPermittedFeatures', () => {
  it('returns supplier features for supplier role', () => {
    const features = getPermittedFeatures('supplier');
    expect(features).toContain('create_request');
    expect(features).toContain('view_requests');
    expect(features).toContain('track_status');
    expect(features).toContain('view_history');
    expect(features).toContain('cancel_request');
    expect(features).toHaveLength(5);
  });

  it('returns technician features for technician role', () => {
    const features = getPermittedFeatures('technician');
    expect(features).toContain('create_request');
    expect(features).toContain('accept_request');
    expect(features).toContain('update_progress');
    expect(features).toContain('complete_request');
    expect(features).toContain('add_materials');
    expect(features).toContain('view_requests');
    expect(features).toContain('view_history');
    expect(features).toHaveLength(7);
  });

  it('supplier does not have technician-only features', () => {
    const features = getPermittedFeatures('supplier');
    expect(features).not.toContain('accept_request');
    expect(features).not.toContain('update_progress');
    expect(features).not.toContain('complete_request');
    expect(features).not.toContain('add_materials');
  });

  it('technician does not have supplier-only features', () => {
    const features = getPermittedFeatures('technician');
    expect(features).not.toContain('track_status');
    expect(features).not.toContain('cancel_request');
  });

  it('both roles share view_requests and view_history', () => {
    const supplierFeatures = getPermittedFeatures('supplier');
    const technicianFeatures = getPermittedFeatures('technician');
    const common: Feature[] = ['view_requests', 'view_history'];
    for (const feature of common) {
      expect(supplierFeatures).toContain(feature);
      expect(technicianFeatures).toContain(feature);
    }
  });
});

describe('getAccessibleLocations', () => {
  const allLocations: Location[] = [
    makeLocation({ id: 'loc-1', name: 'HCM Branch' }),
    makeLocation({ id: 'loc-2', name: 'HN Branch' }),
    makeLocation({ id: 'loc-3', name: 'DN Branch' }),
  ];

  it('returns only locations matching user locationIds', () => {
    const user = makeUser({ locationIds: ['loc-1', 'loc-3'] });
    const result = getAccessibleLocations(user, allLocations);
    expect(result).toHaveLength(2);
    expect(result.map((l) => l.id)).toEqual(['loc-1', 'loc-3']);
  });

  it('returns empty array when user has no locationIds', () => {
    const user = makeUser({ locationIds: [] });
    const result = getAccessibleLocations(user, allLocations);
    expect(result).toEqual([]);
  });

  it('returns empty array when allLocations is empty', () => {
    const user = makeUser({ locationIds: ['loc-1'] });
    const result = getAccessibleLocations(user, []);
    expect(result).toEqual([]);
  });

  it('ignores locationIds that do not exist in allLocations', () => {
    const user = makeUser({ locationIds: ['loc-1', 'loc-999'] });
    const result = getAccessibleLocations(user, allLocations);
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe('loc-1');
  });

  it('returns all locations when user has access to all', () => {
    const user = makeUser({ locationIds: ['loc-1', 'loc-2', 'loc-3'] });
    const result = getAccessibleLocations(user, allLocations);
    expect(result).toHaveLength(3);
  });

  it('preserves full location objects in the result', () => {
    const user = makeUser({ locationIds: ['loc-2'] });
    const result = getAccessibleLocations(user, allLocations);
    expect(result).toHaveLength(1);
    expect(result[0]).toEqual(allLocations[1]);
  });

  it('does not mutate the original allLocations array', () => {
    const user = makeUser({ locationIds: ['loc-1'] });
    const original = [...allLocations];
    getAccessibleLocations(user, allLocations);
    expect(allLocations).toEqual(original);
  });
});
