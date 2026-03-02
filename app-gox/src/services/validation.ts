import type { Priority } from '../types/repair';
import type { MaterialValidationResult } from '../types/material';

const VALID_PRIORITIES: Priority[] = ['low', 'medium', 'high', 'critical'];

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

/**
 * Validates a repair request's required fields.
 * Checks: machineName, locationId, description, priority are not empty,
 * and priority is one of the valid values.
 */
export function validateRepairRequest(data: {
  machineName?: string;
  locationId?: string;
  description?: string;
  priority?: string;
}): ValidationResult {
  const errors: string[] = [];

  if (!data.machineName || data.machineName.trim() === '') {
    errors.push('Tên máy không được để trống');
  }

  if (!data.locationId || data.locationId.trim() === '') {
    errors.push('Địa điểm không được để trống');
  }

  if (!data.description || data.description.trim() === '') {
    errors.push('Mô tả lỗi không được để trống');
  }

  if (!data.priority || data.priority.trim() === '') {
    errors.push('Mức độ ưu tiên không được để trống');
  } else if (!VALID_PRIORITIES.includes(data.priority as Priority)) {
    errors.push('Mức độ ưu tiên không hợp lệ');
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Validates material data.
 * Checks: name not empty, quantity > 0 and finite, unitPrice > 0 and finite.
 */
export function validateMaterial(material: {
  name?: string;
  quantity?: number;
  unitPrice?: number;
}): MaterialValidationResult {
  const errors: string[] = [];

  if (!material.name || material.name.trim() === '') {
    errors.push('Tên vật tư không được để trống');
  }

  if (material.quantity === undefined || material.quantity === null) {
    errors.push('Số lượng không được để trống');
  } else if (typeof material.quantity !== 'number' || isNaN(material.quantity) || !isFinite(material.quantity)) {
    errors.push('Số lượng phải là số hợp lệ');
  } else if (material.quantity <= 0) {
    errors.push('Số lượng phải lớn hơn 0');
  }

  if (material.unitPrice === undefined || material.unitPrice === null) {
    errors.push('Đơn giá không được để trống');
  } else if (typeof material.unitPrice !== 'number' || isNaN(material.unitPrice) || !isFinite(material.unitPrice)) {
    errors.push('Đơn giá phải là số hợp lệ');
  } else if (material.unitPrice <= 0) {
    errors.push('Đơn giá phải lớn hơn 0');
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Validates a progress note.
 * Checks: note is not empty or whitespace-only.
 */
export function validateProgressNote(note: string | undefined | null): ValidationResult {
  const errors: string[] = [];

  if (!note || note.trim() === '') {
    errors.push('Vui lòng nhập ghi chú mô tả tiến độ');
  }

  return { valid: errors.length === 0, errors };
}
