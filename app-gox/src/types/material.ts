export interface Material {
  id: string;
  repairRequestId: string;
  name: string;
  quantity: number;
  unitPrice: number;
  totalPrice: number;
}

export interface MaterialValidationResult {
  valid: boolean;
  errors: string[];
}
