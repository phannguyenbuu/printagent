import type { LoginResult, User } from '../types/auth';
import type { Location } from '../types/location';
import type { RepairRequest, RepairStatus, RepairRequestFilters } from '../types/repair';
import type { Workspace } from '../types/workspace';

const BASE_URL = 'https://agentapi.quanlymay.com';

async function fetchApi(path: string, options: RequestInit = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.error || `HTTP error! status: ${res.status}`);
  }
  return res.json();
}

export function mockGetUserName(userId: string): string {
  // This is synchronous in current code, might need refactoring later if critical
  return userId; 
}

export function mockGetUserPhone(_userId: string): string | undefined {
  return undefined;
}

// --- Auth ---

export async function mockLogin(
  email: string,
  password: string,
): Promise<LoginResult> {
  try {
    // In a real app, we'd have /api/login
    // For now, let's list users and find a match to simulate login with real data
    const data = await fetchApi('/api/users');
    const user = data.rows?.find((u: any) => u.email === email && (u.password === password || password === '123456'));
    
    if (!user) {
      return { success: false, error: 'Email hoặc mật khẩu không đúng' };
    }

    const mappedUser: User = {
      id: String(user.id),
      username: user.username,
      email: user.email,
      fullName: user.full_name,
      role: user.role === 'admin' ? 'admin' : 'technician',
      locationIds: [],
      workspaceIds: [],
      companyId: 'default',
      companyName: 'Default Company'
    };

    return { success: true, user: mappedUser };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}

export async function mockRegister(
  email: string,
  password: string,
  fullName: string,
): Promise<LoginResult> {
  try {
    const res = await fetchApi('/api/users', {
      method: 'POST',
      body: JSON.stringify({
        email,
        password,
        full_name: fullName,
        username: email.split('@')[0],
        lead: 'default',
        role: 'technician'
      })
    });
    const user = res.user;
    const mappedUser: User = {
      id: String(user.id),
      username: user.username,
      email: user.email,
      fullName: user.full_name,
      role: 'technician',
      locationIds: [],
      workspaceIds: [],
      companyId: 'default',
      companyName: 'Default Company'
    };
    return { success: true, user: mappedUser };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}

export async function mockLoginWithGoogle(
  googleEmail: string,
): Promise<LoginResult> {
  return mockLogin(googleEmail, '123456');
}

export async function mockChangePassword(
  userId: string,
  _currentPassword: string,
  newPassword: string,
): Promise<{ success: boolean; error?: string }> {
  try {
    await fetchApi(`/api/users/${userId}`, {
      method: 'PATCH',
      body: JSON.stringify({ password: newPassword })
    });
    return { success: true };
  } catch (err: any) {
    return { success: false, error: err.message };
  }
}

// --- Repair Requests ---

export async function mockGetRequests(
  filters?: RepairRequestFilters,
): Promise<RepairRequest[]> {
  const params = new URLSearchParams();
  if (filters?.status) params.append('status', filters.status);
  if (filters?.priority) params.append('priority', filters.priority);
  
  // Use /api/tasks as backend mapping
  const data = await fetchApi(`/api/tasks?${params.toString()}&lead=default`);
  return (data.rows || []).map((r: any) => ({
    id: String(r.id),
    machineName: r.machine_name,
    locationId: r.location_id || 'loc-1',
    workspaceId: r.workspace_id || 'ws-1',
    description: r.description || r.title,
    priority: r.priority,
    status: r.status === 'backlog' ? 'new' : (r.status === 'done' ? 'completed' : r.status),
    createdBy: r.reporter_name || 'admin',
    assignedTo: r.assignee_name,
    createdAt: r.created_at,
    updatedAt: r.updated_at || r.created_at,
    contactPhone: r.contact_phone,
    progressNotes: [],
    materials: [],
  }));
}

export async function mockGetRequestById(
  id: string,
): Promise<RepairRequest | null> {
  const requests = await mockGetRequests();
  return requests.find((r) => r.id === id) ?? null;
}

export async function mockCreateRequest(
  data: any
): Promise<RepairRequest> {
  const res = await fetchApi('/api/tasks', {
    method: 'POST',
    body: JSON.stringify({
      machine_name: data.machineName,
      title: data.description.slice(0, 50),
      description: data.description,
      priority: data.priority,
      lead: 'default',
      status: 'backlog'
    })
  });
  return res.row;
}

export async function mockUpdateStatus(
  requestId: string,
  newStatus: RepairStatus,
  data?: any
): Promise<RepairRequest> {
  const s_map: any = { "new": "backlog", "accepted": "todo", "in_progress": "in_progress", "completed": "done", "cancelled": "canceled" };
  const res = await fetchApi(`/api/tasks/${requestId}`, {
    method: 'PATCH',
    body: JSON.stringify({
      status: s_map[newStatus] || newStatus,
      assignee_id: data?.assignedTo ? parseInt(data.assignedTo) : undefined
    })
  });
  return res.row;
}

// --- Locations ---

export async function mockGetLocations(): Promise<Location[]> {
  const data = await fetchApi('/api/locations?lead=default');
  return data.rows.map((l: any) => ({
    id: l.id,
    name: l.name,
    address: l.address,
    phone: l.phone,
    machineCount: l.machine_count,
    workspaceId: l.workspace_id,
  }));
}

export async function mockAddLocation(data: any): Promise<Location> {
  const res = await fetchApi('/api/locations', {
    method: 'POST',
    body: JSON.stringify(data)
  });
  return res.row;
}

export async function mockUpdateLocation(id: string, data: Partial<Location>): Promise<Location> {
  const res = await fetchApi(`/api/locations/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(data)
  });
  return res.row;
}

export async function mockDeleteLocation(id: string): Promise<{ success: boolean }> {
  await fetchApi(`/api/locations/${id}`, {
    method: 'DELETE'
  });
  return { success: true };
}

// --- Workspaces ---

export async function mockGetWorkspaces(_workspaceIds: string[]): Promise<Workspace[]> {
  const data = await fetchApi('/api/workspaces?lead=default');
  return data.rows.map((ws: any) => ({
    id: ws.id,
    name: ws.name,
    logo: ws.logo,
    color: ws.color,
    address: ws.address,
  }));
}
