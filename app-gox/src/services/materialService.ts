import type { Material } from '../types/material';
import { validateMaterial } from './validation';

/**
 * Calculates the total cost of all materials.
 * Total = sum(quantity × unitPrice) for each material.
 */
export function calculateTotalMaterialCost(materials: Material[]): number {
  return materials.reduce((sum, m) => sum + m.quantity * m.unitPrice, 0);
}

let idCounter = 0;

function generateId(): string {
  idCounter++;
  return `mat-${Date.now()}-${idCounter}`;
}

/**
 * Adds a new material to the list with auto-calculated totalPrice and generated id.
 * Validates the material before adding. Throws if validation fails.
 */
export function addMaterial(
  materials: Material[],
  newMaterial: Omit<Material, 'id' | 'totalPrice'>
): { materials: Material[]; totalCost: number } {
  const validation = validateMaterial({
    name: newMaterial.name,
    quantity: newMaterial.quantity,
    unitPrice: newMaterial.unitPrice,
  });

  if (!validation.valid) {
    throw new Error(validation.errors.join(', '));
  }

  const material: Material = {
    ...newMaterial,
    id: generateId(),
    totalPrice: newMaterial.quantity * newMaterial.unitPrice,
  };

  const updated = [...materials, material];
  return { materials: updated, totalCost: calculateTotalMaterialCost(updated) };
}

/**
 * Updates an existing material by id. Recalculates totalPrice and totalCost.
 * Validates updated values. Throws if material not found or validation fails.
 */
export function updateMaterial(
  materials: Material[],
  id: string,
  updates: Partial<Pick<Material, 'name' | 'quantity' | 'unitPrice'>>
): { materials: Material[]; totalCost: number } {
  const index = materials.findIndex((m) => m.id === id);
  if (index === -1) {
    throw new Error(`Không tìm thấy vật tư với id: ${id}`);
  }

  const existing = materials[index];
  const merged = {
    name: updates.name ?? existing.name,
    quantity: updates.quantity ?? existing.quantity,
    unitPrice: updates.unitPrice ?? existing.unitPrice,
  };

  const validation = validateMaterial(merged);
  if (!validation.valid) {
    throw new Error(validation.errors.join(', '));
  }

  const updatedMaterial: Material = {
    ...existing,
    ...merged,
    totalPrice: merged.quantity * merged.unitPrice,
  };

  const updated = materials.map((m, i) => (i === index ? updatedMaterial : m));
  return { materials: updated, totalCost: calculateTotalMaterialCost(updated) };
}

/**
 * Removes a material by id and recalculates total cost.
 * Throws if material not found.
 */
export function removeMaterial(
  materials: Material[],
  id: string
): { materials: Material[]; totalCost: number } {
  const index = materials.findIndex((m) => m.id === id);
  if (index === -1) {
    throw new Error(`Không tìm thấy vật tư với id: ${id}`);
  }

  const updated = materials.filter((m) => m.id !== id);
  return { materials: updated, totalCost: calculateTotalMaterialCost(updated) };
}
