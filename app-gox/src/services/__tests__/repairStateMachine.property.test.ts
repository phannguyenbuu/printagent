import { describe, it } from 'vitest';
import * as fc from 'fast-check';
import { isValidTransition } from '../repairStateMachine';
import { validTransitions } from '../../types/repair';
import type { RepairStatus } from '../../types/repair';

/**
 * Feature: machine-repair-management
 * Property 8: Chuyển đổi trạng thái hợp lệ
 *
 * Validates: Requirements 3.2, 3.3, 3.4
 */

const allStatuses: RepairStatus[] = ['new', 'accepted', 'in_progress', 'completed', 'cancelled'];

const statusArb = fc.constantFrom(...allStatuses);

describe('Feature: machine-repair-management, Property 8: Chuyển đổi trạng thái hợp lệ', () => {
  it('isValidTransition(from, to) === validTransitions[from].includes(to) for all status pairs', () => {
    // Validates: Requirements 3.2, 3.3, 3.4
    fc.assert(
      fc.property(statusArb, statusArb, (from, to) => {
        const expected = validTransitions[from].includes(to);
        const actual = isValidTransition(from, to);
        return actual === expected;
      }),
      { numRuns: 100 },
    );
  });
});
