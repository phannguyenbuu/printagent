import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import {
  validateRepairRequest,
  validateMaterial,
  validateProgressNote,
} from '../validation';

/**
 * Property 5: Yêu cầu sửa chữa thiếu thông tin bị từ chối
 * Validates: Requirements 2.2
 *
 * Feature: machine-repair-management, Property 5: Yêu cầu sửa chữa thiếu thông tin bị từ chối
 */
describe('Property 5: Yêu cầu sửa chữa thiếu thông tin bị từ chối', () => {
  const validPriorities = ['low', 'medium', 'high', 'critical'] as const;

  // Arbitrary for a non-empty, non-whitespace string
  const nonEmptyString = fc.string({ minLength: 1 }).filter((s) => s.trim().length > 0);

  it('Feature: machine-repair-management, Property 5: Yêu cầu sửa chữa thiếu thông tin bị từ chối — Validates: Requirements 2.2', () => {
    // Generate objects missing at least one required field
    const missingMachineName = fc.record({
      locationId: nonEmptyString,
      description: nonEmptyString,
      priority: fc.constantFrom(...validPriorities),
    });

    const missingLocationId = fc.record({
      machineName: nonEmptyString,
      description: nonEmptyString,
      priority: fc.constantFrom(...validPriorities),
    });

    const missingDescription = fc.record({
      machineName: nonEmptyString,
      locationId: nonEmptyString,
      priority: fc.constantFrom(...validPriorities),
    });

    const missingPriority = fc.record({
      machineName: nonEmptyString,
      locationId: nonEmptyString,
      description: nonEmptyString,
    });

    const incompleteArb = fc.oneof(
      missingMachineName,
      missingLocationId,
      missingDescription,
      missingPriority,
    );

    fc.assert(
      fc.property(incompleteArb, (data) => {
        const result = validateRepairRequest(data);
        expect(result.valid).toBe(false);
      }),
      { numRuns: 100 },
    );
  });
});

/**
 * Property 9: Cập nhật tiến độ thiếu ghi chú bị từ chối
 * Validates: Requirements 3.5
 *
 * Feature: machine-repair-management, Property 9: Cập nhật tiến độ thiếu ghi chú bị từ chối
 */
describe('Property 9: Cập nhật tiến độ thiếu ghi chú bị từ chối', () => {
  it('Feature: machine-repair-management, Property 9: Cập nhật tiến độ thiếu ghi chú bị từ chối — Validates: Requirements 3.5', () => {
    // Strings composed only of whitespace characters
    const whitespaceOnlyString = fc
      .array(fc.constantFrom(' ', '\t', '\n', '\r', '\f', '\v'), { minLength: 1, maxLength: 50 })
      .map((chars) => chars.join(''));

    fc.assert(
      fc.property(whitespaceOnlyString, (note) => {
        const result = validateProgressNote(note);
        expect(result.valid).toBe(false);
      }),
      { numRuns: 100 },
    );
  });
});

/**
 * Property 14: Giá trị vật tư không hợp lệ bị từ chối
 * Validates: Requirements 7.3
 *
 * Feature: machine-repair-management, Property 14: Giá trị vật tư không hợp lệ bị từ chối
 */
describe('Property 14: Giá trị vật tư không hợp lệ bị từ chối', () => {
  it('Feature: machine-repair-management, Property 14: Giá trị vật tư không hợp lệ bị từ chối — Validates: Requirements 7.3', () => {
    // Invalid quantity values: negative numbers, zero, or NaN
    const invalidQuantity = fc.oneof(
      fc.double({ max: 0, noNaN: true, noDefaultInfinity: true }).filter((n) => n <= 0),
      fc.constant(NaN),
      fc.constant(0),
    );

    fc.assert(
      fc.property(invalidQuantity, (quantity) => {
        const result = validateMaterial({ quantity });
        expect(result.valid).toBe(false);
      }),
      { numRuns: 100 },
    );
  });
});
