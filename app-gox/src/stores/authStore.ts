import { create } from 'zustand';
import type { User, LoginResult } from '../types/auth';
import { mockLogin, mockRegister, mockLoginWithGoogle, mockChangePassword } from '../api/mockApi';
import { mockUsers } from '../api/mockData';
import { useWorkspaceStore } from './workspaceStore';

const AUTH_SESSION_KEY = 'auth_session';
const SESSION_DURATION_MS = 24 * 60 * 60 * 1000; // 24 hours

interface AuthSession {
  token: string;
  user: User;
  expiresAt: number;
}

interface AuthStore {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<LoginResult>;
  register: (email: string, password: string, fullName: string) => Promise<LoginResult>;
  loginWithGoogle: (email: string) => Promise<LoginResult>;
  logout: () => void;
  checkSession: () => void;
  updateProfile: (data: { fullName?: string; phone?: string }) => void;
  changePassword: (currentPassword: string, newPassword: string) => Promise<{ success: boolean; error?: string }>;
}

function generateToken(userId: string): string {
  const payload = `${userId}:${Date.now()}`;
  return btoa(payload);
}

function saveSession(token: string, user: User): void {
  const session: AuthSession = {
    token,
    user,
    expiresAt: Date.now() + SESSION_DURATION_MS,
  };
  localStorage.setItem(AUTH_SESSION_KEY, JSON.stringify(session));
}

function loadSession(): AuthSession | null {
  const raw = localStorage.getItem(AUTH_SESSION_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as AuthSession;
  } catch {
    return null;
  }
}

function clearSession(): void {
  localStorage.removeItem(AUTH_SESSION_KEY);
}

export const useAuthStore = create<AuthStore>((set, get) => ({
  user: null,
  token: null,
  isAuthenticated: false,

  login: async (email: string, password: string): Promise<LoginResult> => {
    const result = await mockLogin(email, password);
    if (result.success) {
      const token = generateToken(result.user.id);
      saveSession(token, result.user);
      set({ user: result.user, token, isAuthenticated: true });
    }
    return result;
  },

  register: async (email: string, password: string, fullName: string): Promise<LoginResult> => {
    const result = await mockRegister(email, password, fullName);
    if (result.success) {
      const token = generateToken(result.user.id);
      saveSession(token, result.user);
      set({ user: result.user, token, isAuthenticated: true });
    }
    return result;
  },

  loginWithGoogle: async (email: string): Promise<LoginResult> => {
    const result = await mockLoginWithGoogle(email);
    if (result.success) {
      const token = generateToken(result.user.id);
      saveSession(token, result.user);
      set({ user: result.user, token, isAuthenticated: true });
    }
    return result;
  },

  logout: () => {
    clearSession();
    useWorkspaceStore.getState().clear();
    set({ user: null, token: null, isAuthenticated: false });
  },

  checkSession: () => {
    const session = loadSession();
    if (!session) {
      set({ user: null, token: null, isAuthenticated: false });
      return;
    }
    if (Date.now() >= session.expiresAt) {
      clearSession();
      set({ user: null, token: null, isAuthenticated: false });
      return;
    }
    // Merge with latest mock data so new fields (workHistory, joinedAt, etc.) are always fresh
    const fresh = mockUsers.find((u) => u.id === session.user.id);
    const mergedUser = fresh
      ? { ...session.user, workHistory: fresh.workHistory, joinedAt: fresh.joinedAt }
      : session.user;
    set({ user: mergedUser, token: session.token, isAuthenticated: true });
  },

  updateProfile: (data) => {
    set((state) => {
      if (!state.user || !state.token) return state;
      const updated = { ...state.user, ...data };
      saveSession(state.token, updated);
      return { user: updated };
    });
  },

  changePassword: async (currentPassword, newPassword) => {
    const user = get().user;
    if (!user) return { success: false, error: 'Chưa đăng nhập' };
    return mockChangePassword(user.id, currentPassword, newPassword);
  },
}));
