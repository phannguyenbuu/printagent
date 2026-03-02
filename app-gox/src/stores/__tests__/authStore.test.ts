import { describe, it, expect, beforeEach, vi } from 'vitest';
import { useAuthStore } from '../authStore';

vi.mock('../../api/mockApi', () => ({
  mockLogin: vi.fn(),
  mockRegister: vi.fn(),
  mockLoginWithGoogle: vi.fn(),
}));

import { mockLogin } from '../../api/mockApi';
const mockLoginFn = vi.mocked(mockLogin);

const fakeUser = {
  id: 'user-s1',
  username: 'supplier1',
  email: 'supplier1@goxprint.vn',
  fullName: 'Nguyễn Văn An',
  role: 'supplier' as const,
  locationIds: ['loc-1', 'loc-2'],
  companyId: 'CTY001',
  companyName: 'Test Company',
  workspaceIds: ['ws-1'],
};

function createLocalStorageMock() {
  const store: Record<string, string> = {};
  return {
    getItem: vi.fn((key: string) => store[key] ?? null),
    setItem: vi.fn((key: string, value: string) => { store[key] = value; }),
    removeItem: vi.fn((key: string) => { delete store[key]; }),
    clear: vi.fn(() => { for (const key of Object.keys(store)) delete store[key]; }),
    get length() { return Object.keys(store).length; },
    key: vi.fn((_index: number) => null),
    _store: store,
  };
}

describe('authStore', () => {
  let storageMock: ReturnType<typeof createLocalStorageMock>;

  beforeEach(() => {
    useAuthStore.setState({ user: null, token: null, isAuthenticated: false });
    storageMock = createLocalStorageMock();
    Object.defineProperty(globalThis, 'localStorage', { value: storageMock, writable: true });
    vi.clearAllMocks();
  });

  describe('initial state', () => {
    it('starts with no user, no token, not authenticated', () => {
      const state = useAuthStore.getState();
      expect(state.user).toBeNull();
      expect(state.token).toBeNull();
      expect(state.isAuthenticated).toBe(false);
    });
  });

  describe('login', () => {
    it('sets user, token, and isAuthenticated on successful login', async () => {
      mockLoginFn.mockResolvedValue({ success: true, user: fakeUser });
      const result = await useAuthStore.getState().login('supplier1@goxprint.vn', 'password123');
      expect(result.success).toBe(true);
      const state = useAuthStore.getState();
      expect(state.user).toEqual(fakeUser);
      expect(state.token).toBeTruthy();
      expect(state.isAuthenticated).toBe(true);
    });

    it('saves session to localStorage on successful login', async () => {
      mockLoginFn.mockResolvedValue({ success: true, user: fakeUser });
      await useAuthStore.getState().login('supplier1@goxprint.vn', 'password123');
      expect(storageMock.setItem).toHaveBeenCalledWith('auth_session', expect.any(String));
      const saved = JSON.parse(storageMock.setItem.mock.calls[0][1]);
      expect(saved.user).toEqual(fakeUser);
      expect(saved.token).toBeTruthy();
      expect(saved.expiresAt).toBeGreaterThan(Date.now());
    });

    it('does not change state on failed login', async () => {
      mockLoginFn.mockResolvedValue({ success: false, error: 'Email hoặc mật khẩu không đúng' });
      const result = await useAuthStore.getState().login('wrong@test.com', 'wrong');
      expect(result.success).toBe(false);
      if (!result.success) expect(result.error).toBe('Email hoặc mật khẩu không đúng');
      const state = useAuthStore.getState();
      expect(state.user).toBeNull();
      expect(state.isAuthenticated).toBe(false);
    });

    it('does not save to localStorage on failed login', async () => {
      mockLoginFn.mockResolvedValue({ success: false, error: 'Invalid' });
      await useAuthStore.getState().login('wrong@test.com', 'wrong');
      expect(storageMock.setItem).not.toHaveBeenCalled();
    });

    it('generates a base64 token containing user id', async () => {
      mockLoginFn.mockResolvedValue({ success: true, user: fakeUser });
      await useAuthStore.getState().login('supplier1@goxprint.vn', 'password123');
      const token = useAuthStore.getState().token!;
      const decoded = atob(token);
      expect(decoded).toContain(fakeUser.id);
    });
  });

  describe('logout', () => {
    it('clears user, token, and isAuthenticated', async () => {
      mockLoginFn.mockResolvedValue({ success: true, user: fakeUser });
      await useAuthStore.getState().login('supplier1@goxprint.vn', 'password123');
      useAuthStore.getState().logout();
      const state = useAuthStore.getState();
      expect(state.user).toBeNull();
      expect(state.token).toBeNull();
      expect(state.isAuthenticated).toBe(false);
    });

    it('removes session from localStorage', async () => {
      mockLoginFn.mockResolvedValue({ success: true, user: fakeUser });
      await useAuthStore.getState().login('supplier1@goxprint.vn', 'password123');
      useAuthStore.getState().logout();
      expect(storageMock.removeItem).toHaveBeenCalledWith('auth_session');
    });
  });

  describe('checkSession', () => {
    it('restores state from valid localStorage session', () => {
      const session = { token: 'valid-token', user: fakeUser, expiresAt: Date.now() + 60 * 60 * 1000 };
      storageMock._store['auth_session'] = JSON.stringify(session);
      useAuthStore.getState().checkSession();
      const state = useAuthStore.getState();
      expect(state.user).toEqual(fakeUser);
      expect(state.token).toBe('valid-token');
      expect(state.isAuthenticated).toBe(true);
    });

    it('clears state when session is expired', () => {
      const session = { token: 'expired-token', user: fakeUser, expiresAt: Date.now() - 1000 };
      storageMock._store['auth_session'] = JSON.stringify(session);
      useAuthStore.getState().checkSession();
      const state = useAuthStore.getState();
      expect(state.user).toBeNull();
      expect(state.isAuthenticated).toBe(false);
      expect(storageMock.removeItem).toHaveBeenCalledWith('auth_session');
    });

    it('clears state when no session exists', () => {
      useAuthStore.getState().checkSession();
      const state = useAuthStore.getState();
      expect(state.user).toBeNull();
      expect(state.isAuthenticated).toBe(false);
    });

    it('clears state when localStorage contains invalid JSON', () => {
      storageMock._store['auth_session'] = 'not-valid-json{{{';
      useAuthStore.getState().checkSession();
      expect(useAuthStore.getState().isAuthenticated).toBe(false);
    });

    it('session expiry is set to 24 hours from login time', async () => {
      mockLoginFn.mockResolvedValue({ success: true, user: fakeUser });
      const now = Date.now();
      await useAuthStore.getState().login('supplier1@goxprint.vn', 'password123');
      const saved = JSON.parse(storageMock.setItem.mock.calls[0][1]);
      const expectedExpiry = now + 24 * 60 * 60 * 1000;
      expect(saved.expiresAt).toBeGreaterThanOrEqual(expectedExpiry - 1000);
      expect(saved.expiresAt).toBeLessThanOrEqual(expectedExpiry + 1000);
    });
  });
});
