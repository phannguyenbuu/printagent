import { create } from 'zustand';
import type { Workspace } from '../types/workspace';
import { mockGetWorkspaces } from '../api/mockApi';

const WS_KEY = 'active_workspaces';
const WS_COLORS_KEY = 'workspace_colors';

interface WorkspaceStore {
  workspaces: Workspace[];
  activeIds: string[];          // multi-select: IDs đang active
  loading: boolean;
  fetchWorkspaces: (workspaceIds: string[]) => Promise<void>;
  toggleWorkspace: (id: string) => void;
  setActiveIds: (ids: string[]) => void;
  setWorkspaceColor: (id: string, color: string) => void;
  clear: () => void;
  /** Computed: danh sách workspace đang active */
  getActiveWorkspaces: () => Workspace[];
  /** Check xem đã chọn ít nhất 1 workspace chưa */
  hasSelection: () => boolean;
}

function saveIds(ids: string[]) {
  localStorage.setItem(WS_KEY, JSON.stringify(ids));
}

function loadIds(): string[] {
  try {
    const raw = localStorage.getItem(WS_KEY);
    if (!raw) return [];
    return JSON.parse(raw) as string[];
  } catch {
    return [];
  }
}

function saveColors(colors: Record<string, string>) {
  localStorage.setItem(WS_COLORS_KEY, JSON.stringify(colors));
}

function loadColors(): Record<string, string> {
  try {
    const raw = localStorage.getItem(WS_COLORS_KEY);
    if (!raw) return {};
    return JSON.parse(raw) as Record<string, string>;
  } catch {
    return {};
  }
}

export const useWorkspaceStore = create<WorkspaceStore>((set, get) => ({
  workspaces: [],
  activeIds: [],
  loading: false,

  fetchWorkspaces: async (workspaceIds) => {
    set({ loading: true });
    const list = await mockGetWorkspaces(workspaceIds);
    const saved = loadIds();
    const savedColors = loadColors();
    // Apply saved custom colors
    const coloredList = list.map((ws) => savedColors[ws.id] ? { ...ws, color: savedColors[ws.id] } : ws);
    // Restore only IDs that still exist in the fetched list
    const validIds = saved.filter((id) => coloredList.some((ws) => ws.id === id));
    set({ workspaces: coloredList, activeIds: validIds, loading: false });
  },

  toggleWorkspace: (id) => {
    const { activeIds } = get();
    const next = activeIds.includes(id)
      ? activeIds.filter((x) => x !== id)
      : [...activeIds, id];
    saveIds(next);
    set({ activeIds: next });
  },

  setActiveIds: (ids) => {
    saveIds(ids);
    set({ activeIds: ids });
  },

  setWorkspaceColor: (id, color) => {
    const { workspaces } = get();
    const updated = workspaces.map((ws) => ws.id === id ? { ...ws, color } : ws);
    const savedColors = loadColors();
    savedColors[id] = color;
    saveColors(savedColors);
    set({ workspaces: updated });
  },

  clear: () => {
    localStorage.removeItem(WS_KEY);
    set({ workspaces: [], activeIds: [], loading: false });
  },

  getActiveWorkspaces: () => {
    const { workspaces, activeIds } = get();
    return workspaces.filter((ws) => activeIds.includes(ws.id));
  },

  hasSelection: () => get().activeIds.length > 0,
}));
