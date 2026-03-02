import type { RepairRequest, RepairStatus, ProgressNote, CompletionReport } from '../types/repair';
import { validTransitions } from '../types/repair';

export type TransitionResult =
  | { success: true; request: RepairRequest }
  | { success: false; error: string };

export interface TransitionData {
  assignedTo?: string;
  progressNote?: string;
  progressNoteCreatedBy?: string;
  completionReport?: Omit<CompletionReport, 'completedAt'>;
}

/**
 * Checks whether a status transition is valid according to the state machine.
 */
export function isValidTransition(from: RepairStatus, to: RepairStatus): boolean {
  return validTransitions[from].includes(to);
}

/**
 * Attempts to transition a repair request to a new status.
 * Returns the updated request on success, or an error message on failure.
 */
export function transitionStatus(
  request: RepairRequest,
  newStatus: RepairStatus,
  data: TransitionData = {},
): TransitionResult {
  if (!isValidTransition(request.status, newStatus)) {
    const allowed = validTransitions[request.status];
    const allowedStr = allowed.length > 0 ? allowed.join(', ') : 'không có';
    return {
      success: false,
      error: `Không thể chuyển từ "${request.status}" sang "${newStatus}". Các trạng thái cho phép: ${allowedStr}`,
    };
  }

  const now = new Date().toISOString();
  let updated: RepairRequest = { ...request, updatedAt: now };

  switch (`${request.status}->${newStatus}`) {
    case 'new->accepted': {
      updated = {
        ...updated,
        status: 'accepted',
        assignedTo: data.assignedTo ?? request.assignedTo,
        acceptedAt: now,
      };
      break;
    }
    case 'accepted->in_progress': {
      const note = buildProgressNote(data, now);
      updated = {
        ...updated,
        status: 'in_progress',
        progressNotes: note
          ? [...request.progressNotes, note]
          : request.progressNotes,
      };
      break;
    }
    case 'in_progress->in_progress': {
      const note = buildProgressNote(data, now);
      updated = {
        ...updated,
        progressNotes: note
          ? [...request.progressNotes, note]
          : request.progressNotes,
      };
      break;
    }
    case 'in_progress->completed': {
      const completionReport: CompletionReport = {
        description: data.completionReport?.description ?? '',
        attachments: data.completionReport?.attachments ?? [],
        completedAt: now,
      };
      updated = {
        ...updated,
        status: 'completed',
        completionReport,
        completedAt: now,
      };
      break;
    }
    case 'new->cancelled': {
      updated = {
        ...updated,
        status: 'cancelled',
      };
      break;
    }
    default:
      break;
  }

  return { success: true, request: updated };
}

function buildProgressNote(data: TransitionData, timestamp: string): ProgressNote | null {
  if (!data.progressNote) return null;
  return {
    id: `note-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    note: data.progressNote,
    createdBy: data.progressNoteCreatedBy ?? '',
    createdAt: timestamp,
  };
}
