import { describe, it, expect } from 'vitest';
import {
  validateRepairRequest,
  validateMaterial,
  validateProgressNote,
} from '../validation';

describe('validateRepairRequest', () => {
  it('returns valid for complete valid data', () => {
    const result = validateRepairRequest({
      machineName: 'CNC Machine A1',
      locationId: 'loc-1',
      description: 'Motor overheating',
      priority: 'high',
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('returns errors for all empty fields', () => {
    const result = validateRepairRequest({});
    expect(result.valid).toBe(false);
    expect(result.errors).toHaveLength(4);
  });

  it('returns error when machineName is empty string', () => {
    const result = validateRepairRequest({
      machineName: '',
      locationId: 'loc-1',
      description: 'Broken',
      priority: 'low',
    });
    expect(result.valid).toBe(false);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toContain('Tên máy');
  });

  it('returns error when machineName is whitespace only', () => {
    const result = validateRepairRequest({
      machineName: '   ',
      locationId: 'loc-1',
      description: 'Broken',
      priority: 'low',
    });
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain('Tên máy');
  });

  it('returns error when locationId is missing', () => {
    const result = validateRepairRequest({
      machineName: 'Machine',
      description: 'Broken',
      priority: 'medium',
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Địa điểm'))).toBe(true);
  });

  it('returns error when description is missing', () => {
    const result = validateRepairRequest({
      machineName: 'Machine',
      locationId: 'loc-1',
      priority: 'medium',
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Mô tả'))).toBe(true);
  });

  it('returns error when priority is missing', () => {
    const result = validateRepairRequest({
      machineName: 'Machine',
      locationId: 'loc-1',
      description: 'Broken',
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('ưu tiên'))).toBe(true);
  });

  it('returns error for invalid priority value', () => {
    const result = validateRepairRequest({
      machineName: 'Machine',
      locationId: 'loc-1',
      description: 'Broken',
      priority: 'urgent',
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('không hợp lệ'))).toBe(true);
  });

  it('accepts all valid priority values', () => {
    for (const priority of ['low', 'medium', 'high', 'critical']) {
      const result = validateRepairRequest({
        machineName: 'Machine',
        locationId: 'loc-1',
        description: 'Broken',
        priority,
      });
      expect(result.valid).toBe(true);
    }
  });

  it('returns multiple errors for multiple missing fields', () => {
    const result = validateRepairRequest({
      machineName: '',
      locationId: '',
    });
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThanOrEqual(3);
  });
});

describe('validateMaterial', () => {
  it('returns valid for correct material data', () => {
    const result = validateMaterial({
      name: 'Bearing',
      quantity: 5,
      unitPrice: 100,
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('returns error when name is empty', () => {
    const result = validateMaterial({
      name: '',
      quantity: 1,
      unitPrice: 10,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Tên vật tư'))).toBe(true);
  });

  it('returns error when name is whitespace only', () => {
    const result = validateMaterial({
      name: '   ',
      quantity: 1,
      unitPrice: 10,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Tên vật tư'))).toBe(true);
  });

  it('returns error when quantity is 0', () => {
    const result = validateMaterial({
      name: 'Bolt',
      quantity: 0,
      unitPrice: 5,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Số lượng'))).toBe(true);
  });

  it('returns error when quantity is negative', () => {
    const result = validateMaterial({
      name: 'Bolt',
      quantity: -3,
      unitPrice: 5,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Số lượng'))).toBe(true);
  });

  it('returns error when quantity is NaN', () => {
    const result = validateMaterial({
      name: 'Bolt',
      quantity: NaN,
      unitPrice: 5,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Số lượng'))).toBe(true);
  });

  it('returns error when quantity is Infinity', () => {
    const result = validateMaterial({
      name: 'Bolt',
      quantity: Infinity,
      unitPrice: 5,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Số lượng'))).toBe(true);
  });

  it('returns error when unitPrice is 0', () => {
    const result = validateMaterial({
      name: 'Bolt',
      quantity: 1,
      unitPrice: 0,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Đơn giá'))).toBe(true);
  });

  it('returns error when unitPrice is negative', () => {
    const result = validateMaterial({
      name: 'Bolt',
      quantity: 1,
      unitPrice: -10,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Đơn giá'))).toBe(true);
  });

  it('returns error when unitPrice is NaN', () => {
    const result = validateMaterial({
      name: 'Bolt',
      quantity: 1,
      unitPrice: NaN,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Đơn giá'))).toBe(true);
  });

  it('returns error when unitPrice is Infinity', () => {
    const result = validateMaterial({
      name: 'Bolt',
      quantity: 1,
      unitPrice: Infinity,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Đơn giá'))).toBe(true);
  });

  it('returns error when unitPrice is -Infinity', () => {
    const result = validateMaterial({
      name: 'Bolt',
      quantity: 1,
      unitPrice: -Infinity,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('Đơn giá'))).toBe(true);
  });

  it('returns multiple errors for all invalid fields', () => {
    const result = validateMaterial({});
    expect(result.valid).toBe(false);
    expect(result.errors).toHaveLength(3);
  });

  it('accepts decimal quantities and prices', () => {
    const result = validateMaterial({
      name: 'Oil',
      quantity: 0.5,
      unitPrice: 12.99,
    });
    expect(result.valid).toBe(true);
  });
});

describe('validateProgressNote', () => {
  it('returns valid for non-empty note', () => {
    const result = validateProgressNote('Replaced the motor bearing');
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('returns error for empty string', () => {
    const result = validateProgressNote('');
    expect(result.valid).toBe(false);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toContain('ghi chú');
  });

  it('returns error for whitespace-only string', () => {
    const result = validateProgressNote('   \t\n  ');
    expect(result.valid).toBe(false);
    expect(result.errors).toHaveLength(1);
  });

  it('returns error for undefined', () => {
    const result = validateProgressNote(undefined);
    expect(result.valid).toBe(false);
    expect(result.errors).toHaveLength(1);
  });

  it('returns error for null', () => {
    const result = validateProgressNote(null);
    expect(result.valid).toBe(false);
    expect(result.errors).toHaveLength(1);
  });

  it('accepts note with leading/trailing whitespace if content exists', () => {
    const result = validateProgressNote('  Some progress  ');
    expect(result.valid).toBe(true);
  });
});
