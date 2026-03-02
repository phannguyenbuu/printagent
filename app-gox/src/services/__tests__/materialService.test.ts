import { describe, it, expect } from 'vitest';
import {
  calculateTotalMaterialCost,
  addMaterial,
  updateMaterial,
  removeMaterial,
} from '../materialService';
import type { Material } from '../../types/material';

function makeMaterial(overrides: Partial<Material> = {}): Material {
  return {
    id: 'mat-1',
    repairRequestId: 'req-1',
    name: 'Bearing',
    quantity: 2,
    unitPrice: 50,
    totalPrice: 100,
    ...overrides,
  };
}

describe('calculateTotalMaterialCost', () => {
  it('returns 0 for empty array', () => {
    expect(calculateTotalMaterialCost([])).toBe(0);
  });

  it('returns totalPrice for single material', () => {
    const materials = [makeMaterial({ quantity: 3, unitPrice: 100 })];
    expect(calculateTotalMaterialCost(materials)).toBe(300);
  });

  it('sums costs of multiple materials', () => {
    const materials = [
      makeMaterial({ id: 'mat-1', quantity: 2, unitPrice: 50 }),
      makeMaterial({ id: 'mat-2', quantity: 1, unitPrice: 200 }),
      makeMaterial({ id: 'mat-3', quantity: 5, unitPrice: 10 }),
    ];
    // 2*50 + 1*200 + 5*10 = 100 + 200 + 50 = 350
    expect(calculateTotalMaterialCost(materials)).toBe(350);
  });

  it('handles decimal quantities and prices', () => {
    const materials = [makeMaterial({ quantity: 0.5, unitPrice: 12.99 })];
    expect(calculateTotalMaterialCost(materials)).toBeCloseTo(6.495);
  });
});

describe('addMaterial', () => {
  it('adds a material with auto-calculated totalPrice', () => {
    const result = addMaterial([], {
      repairRequestId: 'req-1',
      name: 'Bolt',
      quantity: 10,
      unitPrice: 5,
    });

    expect(result.materials).toHaveLength(1);
    expect(result.materials[0].name).toBe('Bolt');
    expect(result.materials[0].quantity).toBe(10);
    expect(result.materials[0].unitPrice).toBe(5);
    expect(result.materials[0].totalPrice).toBe(50);
    expect(result.materials[0].id).toBeTruthy();
    expect(result.totalCost).toBe(50);
  });

  it('appends to existing materials and recalculates total', () => {
    const existing = [makeMaterial({ quantity: 2, unitPrice: 100 })];
    const result = addMaterial(existing, {
      repairRequestId: 'req-1',
      name: 'Oil',
      quantity: 1,
      unitPrice: 30,
    });

    expect(result.materials).toHaveLength(2);
    expect(result.totalCost).toBe(200 + 30);
  });

  it('generates unique ids', () => {
    const r1 = addMaterial([], {
      repairRequestId: 'req-1',
      name: 'A',
      quantity: 1,
      unitPrice: 1,
    });
    const r2 = addMaterial(r1.materials, {
      repairRequestId: 'req-1',
      name: 'B',
      quantity: 1,
      unitPrice: 1,
    });

    expect(r2.materials[0].id).not.toBe(r2.materials[1].id);
  });

  it('throws for invalid material (empty name)', () => {
    expect(() =>
      addMaterial([], {
        repairRequestId: 'req-1',
        name: '',
        quantity: 1,
        unitPrice: 10,
      })
    ).toThrow();
  });

  it('throws for invalid material (quantity <= 0)', () => {
    expect(() =>
      addMaterial([], {
        repairRequestId: 'req-1',
        name: 'Bolt',
        quantity: 0,
        unitPrice: 10,
      })
    ).toThrow();
  });

  it('throws for invalid material (negative unitPrice)', () => {
    expect(() =>
      addMaterial([], {
        repairRequestId: 'req-1',
        name: 'Bolt',
        quantity: 1,
        unitPrice: -5,
      })
    ).toThrow();
  });

  it('does not mutate the original array', () => {
    const original: Material[] = [];
    addMaterial(original, {
      repairRequestId: 'req-1',
      name: 'Bolt',
      quantity: 1,
      unitPrice: 10,
    });
    expect(original).toHaveLength(0);
  });
});

describe('updateMaterial', () => {
  it('updates quantity and recalculates totalPrice', () => {
    const materials = [makeMaterial({ id: 'mat-1', quantity: 2, unitPrice: 50 })];
    const result = updateMaterial(materials, 'mat-1', { quantity: 5 });

    expect(result.materials[0].quantity).toBe(5);
    expect(result.materials[0].totalPrice).toBe(250);
    expect(result.totalCost).toBe(250);
  });

  it('updates unitPrice and recalculates totalPrice', () => {
    const materials = [makeMaterial({ id: 'mat-1', quantity: 2, unitPrice: 50 })];
    const result = updateMaterial(materials, 'mat-1', { unitPrice: 75 });

    expect(result.materials[0].unitPrice).toBe(75);
    expect(result.materials[0].totalPrice).toBe(150);
    expect(result.totalCost).toBe(150);
  });

  it('updates name without changing cost', () => {
    const materials = [makeMaterial({ id: 'mat-1', quantity: 2, unitPrice: 50 })];
    const result = updateMaterial(materials, 'mat-1', { name: 'New Bearing' });

    expect(result.materials[0].name).toBe('New Bearing');
    expect(result.materials[0].totalPrice).toBe(100);
  });

  it('updates multiple fields at once', () => {
    const materials = [makeMaterial({ id: 'mat-1', quantity: 2, unitPrice: 50 })];
    const result = updateMaterial(materials, 'mat-1', {
      name: 'Premium Bearing',
      quantity: 3,
      unitPrice: 80,
    });

    expect(result.materials[0].name).toBe('Premium Bearing');
    expect(result.materials[0].totalPrice).toBe(240);
    expect(result.totalCost).toBe(240);
  });

  it('recalculates total cost across all materials', () => {
    const materials = [
      makeMaterial({ id: 'mat-1', quantity: 2, unitPrice: 50 }),
      makeMaterial({ id: 'mat-2', quantity: 1, unitPrice: 200 }),
    ];
    const result = updateMaterial(materials, 'mat-1', { quantity: 4 });

    // 4*50 + 1*200 = 200 + 200 = 400
    expect(result.totalCost).toBe(400);
  });

  it('throws for non-existent id', () => {
    const materials = [makeMaterial({ id: 'mat-1' })];
    expect(() => updateMaterial(materials, 'mat-999', { quantity: 5 })).toThrow(
      'Không tìm thấy vật tư'
    );
  });

  it('throws for invalid update (quantity <= 0)', () => {
    const materials = [makeMaterial({ id: 'mat-1' })];
    expect(() => updateMaterial(materials, 'mat-1', { quantity: -1 })).toThrow();
  });

  it('does not mutate the original array or material', () => {
    const original = [makeMaterial({ id: 'mat-1', quantity: 2, unitPrice: 50 })];
    updateMaterial(original, 'mat-1', { quantity: 10 });

    expect(original[0].quantity).toBe(2);
    expect(original[0].totalPrice).toBe(100);
  });
});

describe('removeMaterial', () => {
  it('removes a material by id', () => {
    const materials = [
      makeMaterial({ id: 'mat-1' }),
      makeMaterial({ id: 'mat-2' }),
    ];
    const result = removeMaterial(materials, 'mat-1');

    expect(result.materials).toHaveLength(1);
    expect(result.materials[0].id).toBe('mat-2');
  });

  it('recalculates total cost after removal', () => {
    const materials = [
      makeMaterial({ id: 'mat-1', quantity: 2, unitPrice: 50 }),
      makeMaterial({ id: 'mat-2', quantity: 1, unitPrice: 200 }),
    ];
    const result = removeMaterial(materials, 'mat-1');

    expect(result.totalCost).toBe(200);
  });

  it('returns empty array and 0 cost when removing last material', () => {
    const materials = [makeMaterial({ id: 'mat-1', quantity: 3, unitPrice: 100 })];
    const result = removeMaterial(materials, 'mat-1');

    expect(result.materials).toHaveLength(0);
    expect(result.totalCost).toBe(0);
  });

  it('throws for non-existent id', () => {
    const materials = [makeMaterial({ id: 'mat-1' })];
    expect(() => removeMaterial(materials, 'mat-999')).toThrow(
      'Không tìm thấy vật tư'
    );
  });

  it('does not mutate the original array', () => {
    const original = [makeMaterial({ id: 'mat-1' }), makeMaterial({ id: 'mat-2' })];
    removeMaterial(original, 'mat-1');

    expect(original).toHaveLength(2);
  });
});
