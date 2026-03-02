import { create } from 'zustand';
import type { Material } from '../types/material';
import {
  addMaterial as addMaterialService,
  updateMaterial as updateMaterialService,
  removeMaterial as removeMaterialService,
  calculateTotalMaterialCost,
} from '../services/materialService';

interface MaterialStore {
  materials: Material[];
  totalCost: number;
  setMaterials: (materials: Material[]) => void;
  addMaterial: (data: Omit<Material, 'id' | 'totalPrice'>) => { success: boolean; error?: string };
  updateMaterial: (id: string, updates: Partial<Pick<Material, 'name' | 'quantity' | 'unitPrice'>>) => { success: boolean; error?: string };
  removeMaterial: (id: string) => { success: boolean; error?: string };
}

export const useMaterialStore = create<MaterialStore>((set, get) => ({
  materials: [],
  totalCost: 0,

  setMaterials: (materials) => {
    set({ materials, totalCost: calculateTotalMaterialCost(materials) });
  },

  addMaterial: (data) => {
    try {
      const result = addMaterialService(get().materials, data);
      set({ materials: result.materials, totalCost: result.totalCost });
      return { success: true };
    } catch (e: any) {
      return { success: false, error: e.message };
    }
  },

  updateMaterial: (id, updates) => {
    try {
      const result = updateMaterialService(get().materials, id, updates);
      set({ materials: result.materials, totalCost: result.totalCost });
      return { success: true };
    } catch (e: any) {
      return { success: false, error: e.message };
    }
  },

  removeMaterial: (id) => {
    try {
      const result = removeMaterialService(get().materials, id);
      set({ materials: result.materials, totalCost: result.totalCost });
      return { success: true };
    } catch (e: any) {
      return { success: false, error: e.message };
    }
  },
}));
