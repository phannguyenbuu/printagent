import { create } from 'zustand';
import type {
  RepairRequest,
  RepairRequestFilters,
  RepairStatus,
  Priority,
  Attachment,
} from '../types/repair';
import { mockGetRequests, mockCreateRequest, mockUpdateStatus } from '../api/mockApi';
import { validateRepairRequest, validateProgressNote } from '../services/validation';
import { transitionStatus } from '../services/repairStateMachine';
import { notifyStatusChange } from '../services/notificationService';

interface RepairStore {
  requests: RepairRequest[];
  filters: RepairRequestFilters;
  loading: boolean;
  error: string | null;
  fetchRequests: (filters?: RepairRequestFilters) => Promise<void>;
  createRequest: (data: {
    machineName: string;
    locationId: string;
    description: string;
    priority: Priority;
    createdBy: string;
    attachments: Attachment[];
    note?: string;
    contactPhone?: string;
  }) => Promise<{ success: boolean; error?: string }>;
  updateStatus: (
    requestId: string,
    newStatus: RepairStatus,
    data?: any,
  ) => Promise<{ success: boolean; error?: string }>;
  addProgressNote: (
    requestId: string,
    note: string,
    createdBy: string,
    images?: string[],
  ) => Promise<{ success: boolean; error?: string }>;
  completeRequest: (
    requestId: string,
    report: { description: string; attachments: Attachment[]; laborCost?: number },
  ) => Promise<{ success: boolean; error?: string }>;
  setFilters: (filters: RepairRequestFilters) => void;
}

export const useRepairStore = create<RepairStore>((set, get) => ({
  requests: [],
  filters: {},
  loading: false,
  error: null,

  fetchRequests: async (filters?: RepairRequestFilters) => {
    set({ loading: true, error: null });
    try {
      const activeFilters = filters ?? get().filters;
      const requests = await mockGetRequests(activeFilters);
      set({ requests, loading: false });
    } catch (e: any) {
      set({ error: e.message ?? 'Lỗi khi tải danh sách yêu cầu', loading: false });
    }
  },

  createRequest: async (data) => {
    const validation = validateRepairRequest(data);
    if (!validation.valid) {
      return { success: false, error: validation.errors.join(', ') };
    }

    set({ loading: true, error: null });
    try {
      const newRequest = await mockCreateRequest({
        machineName: data.machineName,
        locationId: data.locationId,
        description: data.description,
        priority: data.priority,
        createdBy: data.createdBy,
        attachments: data.attachments,
      });
      set((state) => ({
        requests: [newRequest, ...state.requests],
        loading: false,
      }));
      return { success: true };
    } catch (e: any) {
      set({ error: e.message ?? 'Lỗi khi tạo yêu cầu', loading: false });
      return { success: false, error: e.message ?? 'Lỗi khi tạo yêu cầu' };
    }
  },

  updateStatus: async (requestId, newStatus, data) => {
    const request = get().requests.find((r) => r.id === requestId);
    if (!request) {
      return { success: false, error: 'Không tìm thấy yêu cầu' };
    }

    const result = transitionStatus(request, newStatus, data);
    if (!result.success) {
      return { success: false, error: result.error };
    }

    set({ loading: true, error: null });
    try {
      const updated = await mockUpdateStatus(requestId, newStatus, data);
      set((state) => ({
        requests: state.requests.map((r) => (r.id === requestId ? updated : r)),
        loading: false,
      }));
      notifyStatusChange(request.status, newStatus);
      return { success: true };
    } catch (e: any) {
      set({ error: e.message ?? 'Lỗi khi cập nhật trạng thái', loading: false });
      return { success: false, error: e.message ?? 'Lỗi khi cập nhật trạng thái' };
    }
  },

  addProgressNote: async (requestId, note, createdBy, images) => {
    const noteValidation = validateProgressNote(note);
    if (!noteValidation.valid) {
      return { success: false, error: noteValidation.errors.join(', ') };
    }

    const request = get().requests.find((r) => r.id === requestId);
    if (!request) {
      return { success: false, error: 'Không tìm thấy yêu cầu' };
    }

    // Transition to in_progress (accepted→in_progress or in_progress→in_progress)
    const targetStatus: RepairStatus = 'in_progress';
    const transitionData = {
      progressNote: note,
      progressNoteCreatedBy: createdBy,
    };

    const result = transitionStatus(request, targetStatus, transitionData);
    if (!result.success) {
      return { success: false, error: result.error };
    }

    set({ loading: true, error: null });
    try {
      const updated = await mockUpdateStatus(requestId, targetStatus, {
        progressNote: note,
        progressNoteImages: images,
        progressNoteCreatedBy: createdBy,
        assignedTo: request.assignedTo ?? createdBy,
      });
      set((state) => ({
        requests: state.requests.map((r) => (r.id === requestId ? updated : r)),
        loading: false,
      }));
      notifyStatusChange(request.status, targetStatus);
      return { success: true };
    } catch (e: any) {
      set({ error: e.message ?? 'Lỗi khi thêm ghi chú', loading: false });
      return { success: false, error: e.message ?? 'Lỗi khi thêm ghi chú' };
    }
  },

  completeRequest: async (requestId, report) => {
    const request = get().requests.find((r) => r.id === requestId);
    if (!request) {
      return { success: false, error: 'Không tìm thấy yêu cầu' };
    }

    const result = transitionStatus(request, 'completed', {
      completionReport: report,
    });
    if (!result.success) {
      return { success: false, error: result.error };
    }

    set({ loading: true, error: null });
    try {
      const updated = await mockUpdateStatus(requestId, 'completed', {
        completionReport: { description: report.description, laborCost: report.laborCost },
      });
      set((state) => ({
        requests: state.requests.map((r) => (r.id === requestId ? updated : r)),
        loading: false,
      }));
      notifyStatusChange(request.status, 'completed');
      return { success: true };
    } catch (e: any) {
      set({ error: e.message ?? 'Lỗi khi hoàn thành yêu cầu', loading: false });
      return { success: false, error: e.message ?? 'Lỗi khi hoàn thành yêu cầu' };
    }
  },

  setFilters: (filters) => {
    set({ filters });
  },
}));
