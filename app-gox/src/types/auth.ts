export interface User {
  id: string;
  username: string;
  email: string;
  fullName: string;
  role: 'supplier' | 'technician' | 'admin' | 'user';
  locationIds: string[];
  phone?: string;
  companyId?: string;
  companyName?: string;
  workspaceIds: string[];
  joinedAt?: string; // ISO date string, e.g. "2021-03-15"
  workHistory?: WorkHistoryEntry[];
}

export interface WorkHistoryEntry {
  companyName: string;
  role: string;
  from: string;   // ISO date "YYYY-MM-DD"
  to?: string;    // ISO date, omit if currently active at this company
  isCurrent?: boolean; // explicit flag, fallback to !to
}

export interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<LoginResult>;
  register: (email: string, password: string, fullName: string) => Promise<LoginResult>;
  logout: () => void;
}

export type LoginResult =
  | { success: true; user: User }
  | { success: false; error: string };
