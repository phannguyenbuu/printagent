import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { getPermittedFeatures, getAccessibleLocations } from '../accessControl';
import type { Feature } from '../accessControl';
import type { User } from '../../types/auth';
import type { Location } from '../../types/location';

const ROLES: User['role'][] = ['supplier', 'technician'];

const SUPPLIER_FEATURES: Feature[] = [
  'create_request',
  'view_requests',
  'track_status',
  'view_history',
  'cancel_request',
];

const TECHNICIAN_FEATURES: Feature[] = [
  'create_request',
  'accept_request',
  'update_progress',
  'complete_request',
  'add_materials',
  'view_requests',
  'view_history',
];

const FEATURES_BY_ROLE: Record<User['role'], Feature[]> = {
  supplier: SUPPLIER_FEATURES,
  technician: TECHNICIAN_FEATURES,
};

// Arbitrary for a valid User
const userArb: fc.Arbitrary<User> = fc.record({
  id: fc.uuid(),
  username: fc.string({ minLength: 1, maxLength: 30 }),
  email: fc.emailAddress(),
  fullName: fc.string({ minLength: 1, maxLength: 50 }),
  role: fc.constantFrom(...ROLES),
  locationIds: fc.array(fc.uuid(), { minLength: 0, maxLength: 10 }),
  companyId: fc.string({ minLength: 1, maxLength: 20 }),
  companyName: fc.string({ minLength: 1, maxLength: 50 }),
  workspaceIds: fc.array(fc.uuid(), { minLength: 0, maxLength: 5 }),
});

// Arbitrary for a valid Location
const locationArb: fc.Arbitrary<Location> = fc.record({
  id: fc.uuid(),
  name: fc.string({ minLength: 1, maxLength: 50 }),
  address: fc.string({ minLength: 1, maxLength: 100 }),
  machineCount: fc.nat({ max: 100 }),
  workspaceId: fc.uuid(),
});

/**
 * Property 1: Phân quyền theo vai trò
 * Validates: Requirements 1.3, 1.4
 *
 * Feature: machine-repair-management, Property 1: Phân quyền theo vai trò
 */
describe('Property 1: Phân quyền theo vai trò', () => {
  it('Feature: machine-repair-management, Property 1: Phân quyền theo vai trò — Validates: Requirements 1.3, 1.4', () => {
    fc.assert(
      fc.property(userArb, (user) => {
        const features = getPermittedFeatures(user.role);
        const expectedFeatures = FEATURES_BY_ROLE[user.role];

        // Must return exactly the features for the role — no more, no less
        expect(features).toHaveLength(expectedFeatures.length);
        for (const f of expectedFeatures) {
          expect(features).toContain(f);
        }

        // Must not contain features from the other role that are exclusive to it
        const otherRole = user.role === 'supplier' ? 'technician' : 'supplier';
        const otherFeatures = FEATURES_BY_ROLE[otherRole];
        const exclusiveToOther = otherFeatures.filter((f) => !expectedFeatures.includes(f));
        for (const f of exclusiveToOther) {
          expect(features).not.toContain(f);
        }
      }),
      { numRuns: 100 }
    );
  });
});

/**
 * Property 10: Quyền truy cập địa điểm khớp với user
 * Validates: Requirements 4.1
 *
 * Feature: machine-repair-management, Property 10: Quyền truy cập địa điểm khớp với user
 */
describe('Property 10: Quyền truy cập địa điểm khớp với user', () => {
  it('Feature: machine-repair-management, Property 10: Quyền truy cập địa điểm khớp với user — Validates: Requirements 4.1', () => {
    fc.assert(
      fc.property(userArb, fc.array(locationArb, { minLength: 0, maxLength: 20 }), (user, allLocations) => {
        const result = getAccessibleLocations(user, allLocations);
        const userLocationIdSet = new Set(user.locationIds);

        // Every returned location must be in user.locationIds
        for (const loc of result) {
          expect(userLocationIdSet.has(loc.id)).toBe(true);
        }

        // Every location in allLocations that matches user.locationIds must be in result
        const expectedIds = allLocations
          .filter((loc) => userLocationIdSet.has(loc.id))
          .map((loc) => loc.id);
        const resultIds = result.map((loc) => loc.id);

        expect(resultIds.sort()).toEqual(expectedIds.sort());
      }),
      { numRuns: 100 }
    );
  });
});
