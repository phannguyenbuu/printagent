import type { LoginResult, User } from '../types/auth';
import type { Location } from '../types/location';
import type { RepairRequest, RepairStatus, RepairRequestFilters } from '../types/repair';
import type { Workspace } from '../types/workspace';
import { mockUsers, mockLocations, mockRepairRequests, mockWorkspaces } from './mockData';

// Mutable copy of requests so create/update operations persist in-memory
let requests: RepairRequest[] = [...mockRepairRequests];

function delay(ms?: number): Promise<void> {
  const time = ms ?? (300 + Math.random() * 200);
  return new Promise((resolve) => setTimeout(resolve, time));
}

function generateId(): string {
  return `req-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
}

// --- User Lookup ---

export function mockGetUserName(userId: string): string {
  const user = mockUsers.find((u) => u.id === userId);
  return user?.fullName ?? userId;
}

export function mockGetUserPhone(userId: string): string | undefined {
  const user = mockUsers.find((u) => u.id === userId);
  return user?.phone;
}

// --- Auth ---

export async function mockLogin(
  email: string,
  password: string,
): Promise<LoginResult> {
  await delay(500);

  const found = mockUsers.find(
    (u) => u.email === email && u.password === password,
  );

  if (!found) {
    return { success: false, error: 'Email hoặc mật khẩu không đúng' };
  }

  const { password: _, ...user } = found;
  return { success: true, user: user as User };
}

export async function mockRegister(
  email: string,
  password: string,
  fullName: string,
): Promise<LoginResult> {
  await delay(500);

  // Check if email already exists
  const exists = mockUsers.find((u) => u.email === email);
  if (exists) {
    return { success: false, error: 'Email đã được sử dụng' };
  }

  if (password.length < 6) {
    return { success: false, error: 'Mật khẩu phải có ít nhất 6 ký tự' };
  }

  const newUser = {
    id: `user-${Date.now()}`,
    username: email.split('@')[0],
    email,
    password,
    fullName: fullName.trim(),
    role: 'technician' as const,
    locationIds: [] as string[],
    phone: undefined,
    companyId: '',
    companyName: '',
    workspaceIds: [] as string[],
  };

  mockUsers.push(newUser);

  const { password: _, ...user } = newUser;
  return { success: true, user: user as User };
}

export async function mockLoginWithGoogle(
  googleEmail: string,
): Promise<LoginResult> {
  await delay(500);

  // Find existing user by email
  let found = mockUsers.find((u) => u.email === googleEmail);

  if (!found) {
    // Auto-register with Google
    const newUser = {
      id: `user-${Date.now()}`,
      username: googleEmail.split('@')[0],
      email: googleEmail,
      password: '',
      fullName: googleEmail.split('@')[0],
      role: 'technician' as const,
      locationIds: [] as string[],
      phone: undefined,
      companyId: '',
      companyName: '',
      workspaceIds: [] as string[],
    };
    mockUsers.push(newUser);
    found = newUser;
  }

  const { password: _, ...user } = found;
  return { success: true, user: user as User };
}

export async function mockChangePassword(
  userId: string,
  currentPassword: string,
  newPassword: string,
): Promise<{ success: boolean; error?: string }> {
  await delay(400);
  const idx = mockUsers.findIndex((u) => u.id === userId);
  if (idx === -1) return { success: false, error: 'Không tìm thấy tài khoản' };
  if (mockUsers[idx].password !== currentPassword) return { success: false, error: 'Mật khẩu hiện tại không đúng' };
  if (newPassword.length < 6) return { success: false, error: 'Mật khẩu mới phải có ít nhất 6 ký tự' };
  mockUsers[idx] = { ...mockUsers[idx], password: newPassword };
  return { success: true };
}

// --- Repair Requests ---

export async function mockGetRequests(
  filters?: RepairRequestFilters,
): Promise<RepairRequest[]> {
  await delay();

  let result = [...requests];

  if (filters?.status) {
    result = result.filter((r) => r.status === filters.status);
  }
  if (filters?.locationId) {
    result = result.filter((r) => r.locationId === filters.locationId);
  }
  if (filters?.priority) {
    result = result.filter((r) => r.priority === filters.priority);
  }

  // Sort by createdAt descending (newest first)
  result.sort(
    (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
  );

  return result;
}

export async function mockGetRequestById(
  id: string,
): Promise<RepairRequest | null> {
  await delay();
  return requests.find((r) => r.id === id) ?? null;
}

export async function mockCreateRequest(
  data: Omit<
    RepairRequest,
    | 'id'
    | 'status'
    | 'createdAt'
    | 'updatedAt'
    | 'acceptedAt'
    | 'completedAt'
    | 'progressNotes'
    | 'materials'
    | 'completionReport'
    | 'assignedTo'
  >,
): Promise<RepairRequest> {
  await delay();

  const now = new Date().toISOString();
  const newRequest: RepairRequest = {
    ...data,
    id: generateId(),
    status: 'new',
    assignedTo: null,
    progressNotes: [],
    materials: [],
    completionReport: null,
    note: data.note,
    contactPhone: data.contactPhone,
    createdAt: now,
    updatedAt: now,
    acceptedAt: null,
    completedAt: null,
  };

  requests = [newRequest, ...requests];
  return newRequest;
}

export async function mockUpdateStatus(
  requestId: string,
  newStatus: RepairStatus,
  data?: {
    assignedTo?: string;
    progressNote?: string;
    progressNoteCreatedBy?: string;
    progressNoteImages?: string[];
    completionReport?: { description: string; laborCost?: number };
    materials?: RepairRequest['materials'];
  },
): Promise<RepairRequest> {
  await delay();

  const index = requests.findIndex((r) => r.id === requestId);
  if (index === -1) {
    throw new Error(`Không tìm thấy yêu cầu với id: ${requestId}`);
  }

  const request = { ...requests[index] };
  const now = new Date().toISOString();

  request.status = newStatus;
  request.updatedAt = now;

  if (newStatus === 'accepted' && data?.assignedTo) {
    request.assignedTo = data.assignedTo;
    request.acceptedAt = now;
  }

  if (data?.progressNote) {
    request.progressNotes = [
      ...request.progressNotes,
      {
        id: `note-${Date.now()}`,
        note: data.progressNote,
        images: data.progressNoteImages,
        createdBy: data.progressNoteCreatedBy ?? data.assignedTo ?? request.assignedTo ?? '',
        createdAt: now,
      },
    ];
  }

  if (newStatus === 'completed' && data?.completionReport) {
    request.completionReport = {
      description: data.completionReport.description,
      attachments: [],
      completedAt: now,
      laborCost: data.completionReport.laborCost,
    };
    request.completedAt = now;
    request.laborCost = data.completionReport.laborCost;
    if (data.materials) {
      request.materials = data.materials;
    }
  }

  requests[index] = request;
  return request;
}

// --- Locations ---

let locations: Location[] = [...mockLocations];

export async function mockGetLocations(): Promise<Location[]> {
  await delay();
  return [...locations];
}

export async function mockAddLocation(data: {
  name: string;
  address: string;
  phone?: string;
  workspaceId?: string;
}): Promise<Location> {
  await delay();
  const newLocation: Location = {
    id: `loc-${Date.now()}-${Math.random().toString(36).slice(2, 5)}`,
    name: data.name,
    address: data.address,
    phone: data.phone,
    machineCount: 0,
    workspaceId: data.workspaceId ?? '',
  };
  locations = [...locations, newLocation];
  return newLocation;
}

// --- Workspaces ---

export async function mockGetWorkspaces(workspaceIds: string[]): Promise<Workspace[]> {
  await delay(200);
  return mockWorkspaces.filter((ws) => workspaceIds.includes(ws.id));
}
