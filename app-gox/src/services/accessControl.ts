import type { User } from '../types/auth';
import type { Location } from '../types/location';

export type Feature =
  | 'create_request'
  | 'view_requests'
  | 'track_status'
  | 'view_history'
  | 'cancel_request'
  | 'accept_request'
  | 'update_progress'
  | 'complete_request'
  | 'add_materials';

const SUPPLIER_FEATURES: Feature[] = [
  'create_request',
  'view_requests',
  'track_status',
  'view_history',
  'cancel_request',
];

const TECHNICIAN_FEATURES: Feature[] = [
  'create_request',
  'accept_request',
  'update_progress',
  'complete_request',
  'add_materials',
  'view_requests',
  'view_history',
];

const featuresByRole: Record<User['role'], Feature[]> = {
  supplier: SUPPLIER_FEATURES,
  technician: TECHNICIAN_FEATURES,
};

export function getPermittedFeatures(role: User['role']): Feature[] {
  return featuresByRole[role] ?? [];
}

export function getAccessibleLocations(user: User, allLocations: Location[]): Location[] {
  const locationIdSet = new Set(user.locationIds);
  return allLocations.filter((loc) => locationIdSet.has(loc.id));
}
