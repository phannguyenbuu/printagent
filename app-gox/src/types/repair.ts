import type { Material } from './material';

export type RepairStatus = 'new' | 'accepted' | 'in_progress' | 'completed' | 'cancelled';

export type Priority = 'low' | 'medium' | 'high' | 'critical';

export interface Attachment {
  id: string;
  type: 'image' | 'video';
  url: string;
  name: string;
}

export interface ProgressNote {
  id: string;
  note: string;
  images?: string[];
  createdBy: string;
  createdAt: string;
}

export interface CompletionReport {
  description: string;
  attachments: Attachment[];
  completedAt: string;
  laborCost?: number;
}

export interface RepairRequest {
  id: string;
  machineName: string;
  locationId: string;
  workspaceId: string;
  description: string;
  priority: Priority;
  status: RepairStatus;
  createdBy: string;
  assignedTo: string | null;
  attachments: Attachment[];
  progressNotes: ProgressNote[];
  materials: Material[];
  completionReport: CompletionReport | null;
  laborCost?: number;
  rating?: number;
  note?: string;
  contactPhone?: string;
  createdAt: string;
  updatedAt: string;
  acceptedAt: string | null;
  completedAt: string | null;
}

export interface RepairRequestFilters {
  status?: RepairStatus;
  locationId?: string;
  priority?: Priority;
}

export const validTransitions: Record<RepairStatus, RepairStatus[]> = {
  new: ['accepted', 'cancelled'],
  accepted: ['in_progress'],
  in_progress: ['in_progress', 'completed'],
  completed: [],
  cancelled: [],
};
