import { create } from 'zustand';
import type { Location, LocationStats } from '../types/location';
import type { RepairRequest, RepairStatus } from '../types/repair';
import { mockGetLocations, mockAddLocation } from '../api/mockApi';

const ALL_STATUSES: RepairStatus[] = ['new', 'accepted', 'in_progress', 'completed', 'cancelled'];

function emptyByStatus(): Record<RepairStatus, number> {
  return { new: 0, accepted: 0, in_progress: 0, completed: 0, cancelled: 0 };
}

interface LocationStore {
  locations: Location[];
  selectedLocationId: string | null;
  stats: LocationStats[];
  loading: boolean;
  fetchLocations: () => Promise<void>;
  addLocation: (name: string, address: string, phone?: string) => Promise<Location>;
  selectLocation: (locationId: string | null) => void;
  fetchStats: (requests: RepairRequest[]) => void;
}

export const useLocationStore = create<LocationStore>((set) => ({
  locations: [],
  selectedLocationId: null,
  stats: [],
  loading: false,

  fetchLocations: async () => {
    set({ loading: true });
    try {
      const locations = await mockGetLocations();
      set({ locations, loading: false });
    } catch {
      set({ loading: false });
    }
  },

  selectLocation: (locationId) => {
    set({ selectedLocationId: locationId });
  },

  addLocation: async (name, address, phone?: string) => {
    const newLocation = await mockAddLocation({ name, address, phone });
    set((state) => ({
      locations: [...state.locations, newLocation],
    }));
    return newLocation;
  },

  fetchStats: (requests) => {
    const statsMap = new Map<string, Record<RepairStatus, number>>();

    for (const req of requests) {
      if (!statsMap.has(req.locationId)) {
        statsMap.set(req.locationId, emptyByStatus());
      }
      const byStatus = statsMap.get(req.locationId)!;
      byStatus[req.status] += 1;
    }

    const stats: LocationStats[] = Array.from(statsMap.entries()).map(
      ([locationId, byStatus]) => ({
        locationId,
        totalRequests: ALL_STATUSES.reduce((sum, s) => sum + byStatus[s], 0),
        byStatus,
      }),
    );

    set({ stats });
  },
}));
