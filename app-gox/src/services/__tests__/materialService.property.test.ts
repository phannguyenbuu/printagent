import { describe, it } from 'vitest';
import * as fc from 'fast-check';
import { calculateTotalMaterialCost } from '../materialService';
import type { Material } from '../../types/material';

/**
 * Property 13: Bất biến tổng chi phí vật tư
 * Validates: Requirements 7.1, 7.2, 7.5
 *
 * Feature: machine-repair-management, Property 13: Bất biến tổng chi phí vật tư
 */
describe('Property 13: Bất biến tổng chi phí vật tư', () => {
  // Arbitrary for a valid Material object (quantity > 0, unitPrice > 0)
  const materialArb: fc.Arbitrary<Material> = fc.record({
    id: fc.string({ minLength: 1, maxLength: 20 }),
    repairRequestId: fc.string({ minLength: 1, maxLength: 20 }),
    name: fc.string({ minLength: 1, maxLength: 50 }),
    quantity: fc.double({ min: 0.01, max: 10000, noNaN: true, noDefaultInfinity: true }),
    unitPrice: fc.double({ min: 0.01, max: 1000000, noNaN: true, noDefaultInfinity: true }),
    totalPrice: fc.double({ min: 0, noNaN: true, noDefaultInfinity: true }),
  });

  it('Feature: machine-repair-management, Property 13: Bất biến tổng chi phí vật tư — Validates: Requirements 7.1, 7.2, 7.5', () => {
    fc.assert(
      fc.property(fc.array(materialArb), (materials) => {
        const expected = materials.reduce((sum, m) => sum + m.quantity * m.unitPrice, 0);
        const actual = calculateTotalMaterialCost(materials);
        // Use approximate equality to handle floating-point precision
        const diff = Math.abs(actual - expected);
        const tolerance = Math.max(Math.abs(expected) * Number.EPSILON * 100, Number.EPSILON);
        return diff <= tolerance || actual === expected;
      }),
      { numRuns: 100 },
    );
  });
});
