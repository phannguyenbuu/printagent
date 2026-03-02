import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { isValidTransition, transitionStatus } from '../repairStateMachine';
import type { RepairRequest, RepairStatus } from '../../types/repair';

function makeRequest(overrides: Partial<RepairRequest> = {}): RepairRequest {
  return {
    id: 'req-1',
    machineName: 'CNC Machine A1',
    locationId: 'loc-1',
    workspaceId: 'ws-1',
    description: 'Motor overheating',
    priority: 'high',
    status: 'new',
    createdBy: 'user-1',
    assignedTo: null,
    attachments: [],
    progressNotes: [],
    materials: [],
    completionReport: null,
    createdAt: '2024-01-01T00:00:00.000Z',
    updatedAt: '2024-01-01T00:00:00.000Z',
    acceptedAt: null,
    completedAt: null,
    ...overrides,
  };
}

describe('isValidTransition', () => {
  it.each<[RepairStatus, RepairStatus]>([
    ['new', 'accepted'],
    ['new', 'cancelled'],
    ['accepted', 'in_progress'],
    ['in_progress', 'in_progress'],
    ['in_progress', 'completed'],
  ])('allows %s -> %s', (from, to) => {
    expect(isValidTransition(from, to)).toBe(true);
  });

  it.each<[RepairStatus, RepairStatus]>([
    ['new', 'in_progress'],
    ['new', 'completed'],
    ['accepted', 'new'],
    ['accepted', 'completed'],
    ['accepted', 'cancelled'],
    ['in_progress', 'new'],
    ['in_progress', 'accepted'],
    ['in_progress', 'cancelled'],
    ['completed', 'new'],
    ['completed', 'accepted'],
    ['completed', 'in_progress'],
    ['completed', 'cancelled'],
    ['cancelled', 'new'],
    ['cancelled', 'accepted'],
    ['cancelled', 'in_progress'],
    ['cancelled', 'completed'],
  ])('rejects %s -> %s', (from, to) => {
    expect(isValidTransition(from, to)).toBe(false);
  });
});

describe('transitionStatus', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2024-06-15T10:00:00.000Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('new -> accepted', () => {
    it('sets status to accepted, assignedTo, and acceptedAt', () => {
      const request = makeRequest({ status: 'new' });
      const result = transitionStatus(request, 'accepted', { assignedTo: 'tech-1' });

      expect(result.success).toBe(true);
      if (!result.success) return;
      expect(result.request.status).toBe('accepted');
      expect(result.request.assignedTo).toBe('tech-1');
      expect(result.request.acceptedAt).toBe('2024-06-15T10:00:00.000Z');
      expect(result.request.updatedAt).toBe('2024-06-15T10:00:00.000Z');
    });

    it('keeps existing assignedTo when not provided in data', () => {
      const request = makeRequest({ status: 'new', assignedTo: 'existing-tech' });
      const result = transitionStatus(request, 'accepted', {});

      expect(result.success).toBe(true);
      if (!result.success) return;
      expect(result.request.assignedTo).toBe('existing-tech');
    });
  });

  describe('accepted -> in_progress', () => {
    it('sets status to in_progress and adds progress note', () => {
      const request = makeRequest({ status: 'accepted', assignedTo: 'tech-1' });
      const result = transitionStatus(request, 'in_progress', {
        progressNote: 'Started inspection',
        progressNoteCreatedBy: 'tech-1',
      });

      expect(result.success).toBe(true);
      if (!result.success) return;
      expect(result.request.status).toBe('in_progress');
      expect(result.request.progressNotes).toHaveLength(1);
      expect(result.request.progressNotes[0].note).toBe('Started inspection');
      expect(result.request.progressNotes[0].createdBy).toBe('tech-1');
    });

    it('does not add note when progressNote is not provided', () => {
      const request = makeRequest({ status: 'accepted' });
      const result = transitionStatus(request, 'in_progress', {});

      expect(result.success).toBe(true);
      if (!result.success) return;
      expect(result.request.status).toBe('in_progress');
      expect(result.request.progressNotes).toHaveLength(0);
    });
  });

  describe('in_progress -> in_progress', () => {
    it('adds another progress note without changing status', () => {
      const existingNote = {
        id: 'note-1',
        note: 'First note',
        createdBy: 'tech-1',
        createdAt: '2024-06-14T10:00:00.000Z',
      };
      const request = makeRequest({
        status: 'in_progress',
        progressNotes: [existingNote],
      });
      const result = transitionStatus(request, 'in_progress', {
        progressNote: 'Second update',
        progressNoteCreatedBy: 'tech-1',
      });

      expect(result.success).toBe(true);
      if (!result.success) return;
      expect(result.request.status).toBe('in_progress');
      expect(result.request.progressNotes).toHaveLength(2);
      expect(result.request.progressNotes[0]).toEqual(existingNote);
      expect(result.request.progressNotes[1].note).toBe('Second update');
    });
  });

  describe('in_progress -> completed', () => {
    it('sets status to completed with completion report', () => {
      const request = makeRequest({ status: 'in_progress', assignedTo: 'tech-1' });
      const result = transitionStatus(request, 'completed', {
        completionReport: {
          description: 'Replaced motor bearing',
          attachments: [],
        },
      });

      expect(result.success).toBe(true);
      if (!result.success) return;
      expect(result.request.status).toBe('completed');
      expect(result.request.completedAt).toBe('2024-06-15T10:00:00.000Z');
      expect(result.request.completionReport).not.toBeNull();
      expect(result.request.completionReport!.description).toBe('Replaced motor bearing');
      expect(result.request.completionReport!.completedAt).toBe('2024-06-15T10:00:00.000Z');
    });

    it('uses empty defaults when completionReport data is missing', () => {
      const request = makeRequest({ status: 'in_progress' });
      const result = transitionStatus(request, 'completed', {});

      expect(result.success).toBe(true);
      if (!result.success) return;
      expect(result.request.completionReport!.description).toBe('');
      expect(result.request.completionReport!.attachments).toEqual([]);
    });
  });

  describe('new -> cancelled', () => {
    it('sets status to cancelled', () => {
      const request = makeRequest({ status: 'new' });
      const result = transitionStatus(request, 'cancelled');

      expect(result.success).toBe(true);
      if (!result.success) return;
      expect(result.request.status).toBe('cancelled');
      expect(result.request.updatedAt).toBe('2024-06-15T10:00:00.000Z');
    });
  });

  describe('invalid transitions', () => {
    it('returns error for completed -> new', () => {
      const request = makeRequest({ status: 'completed' });
      const result = transitionStatus(request, 'new');

      expect(result.success).toBe(false);
      if (result.success) return;
      expect(result.error).toContain('completed');
      expect(result.error).toContain('new');
    });

    it('returns error for cancelled -> accepted', () => {
      const request = makeRequest({ status: 'cancelled' });
      const result = transitionStatus(request, 'accepted');

      expect(result.success).toBe(false);
      if (result.success) return;
      expect(result.error).toContain('cancelled');
    });

    it('returns error for new -> in_progress (must go through accepted)', () => {
      const request = makeRequest({ status: 'new' });
      const result = transitionStatus(request, 'in_progress');

      expect(result.success).toBe(false);
    });

    it('does not mutate the original request on invalid transition', () => {
      const request = makeRequest({ status: 'completed' });
      const originalStatus = request.status;
      transitionStatus(request, 'new');

      expect(request.status).toBe(originalStatus);
    });
  });

  describe('immutability', () => {
    it('does not mutate the original request on valid transition', () => {
      const request = makeRequest({ status: 'new' });
      const result = transitionStatus(request, 'accepted', { assignedTo: 'tech-1' });

      expect(request.status).toBe('new');
      expect(request.assignedTo).toBeNull();
      expect(request.acceptedAt).toBeNull();
      if (result.success) {
        expect(result.request).not.toBe(request);
      }
    });

    it('does not mutate progressNotes array', () => {
      const request = makeRequest({ status: 'in_progress', progressNotes: [] });
      const result = transitionStatus(request, 'in_progress', {
        progressNote: 'New note',
      });

      expect(request.progressNotes).toHaveLength(0);
      if (result.success) {
        expect(result.request.progressNotes).toHaveLength(1);
      }
    });
  });
});
