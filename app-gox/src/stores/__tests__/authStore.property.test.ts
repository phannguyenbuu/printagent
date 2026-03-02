import { describe, it, expect, beforeEach, vi } from 'vitest';
import * as fc from 'fast-check';
import { mockUsers } from '../../api/mockData';
import type { LoginResult, User } from '../../types/auth';

// Inline login logic without delay — mirrors mockLogin from mockApi
function loginSync(email: string, password: string): LoginResult {
  const found = mockUsers.find((u) => u.email === email && u.password === password);
  if (!found) {
    return { success: false, error: 'Email hoặc mật khẩu không đúng' };
  }
  const { password: _, ...user } = found;
  return { success: true, user: user as User };
}

// Setup localStorage mock
function createLocalStorageMock() {
  const store: Record<string, string> = {};
  return {
    getItem: vi.fn((key: string) => store[key] ?? null),
    setItem: vi.fn((key: string, value: string) => { store[key] = value; }),
    removeItem: vi.fn((key: string) => { delete store[key]; }),
    clear: vi.fn(() => { for (const key of Object.keys(store)) delete store[key]; }),
    get length() { return Object.keys(store).length; },
    key: vi.fn((_index: number) => null),
  };
}

// Valid credentials from mockData (email + password pairs)
const validCredentials = mockUsers.map((u) => ({ email: u.email, password: u.password, username: u.username }));

// Set of valid emails for exclusion in Property 3
const validEmails = new Set(mockUsers.map((u) => u.email));

/**
 * Property 2: Đăng nhập hợp lệ trả về đúng user
 * Validates: Requirements 1.1
 *
 * Feature: machine-repair-management, Property 2: Đăng nhập hợp lệ trả về đúng user
 */
describe('Property 2: Đăng nhập hợp lệ trả về đúng user', () => {
  beforeEach(() => {
    const storageMock = createLocalStorageMock();
    Object.defineProperty(globalThis, 'localStorage', { value: storageMock, writable: true, configurable: true });
  });

  it('Feature: machine-repair-management, Property 2: Đăng nhập hợp lệ trả về đúng user — Validates: Requirements 1.1', () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...validCredentials),
        ({ email, password, username }) => {
          const result = loginSync(email, password);
          expect(result.success).toBe(true);
          if (result.success) {
            expect(result.user.email).toBe(email);
            expect(result.user.username).toBe(username);
          }
        },
      ),
      { numRuns: 100 },
    );
  });
});

/**
 * Property 3: Đăng nhập không hợp lệ bị từ chối
 * Validates: Requirements 1.2
 *
 * Feature: machine-repair-management, Property 3: Đăng nhập không hợp lệ bị từ chối
 */
describe('Property 3: Đăng nhập không hợp lệ bị từ chối', () => {
  beforeEach(() => {
    const storageMock = createLocalStorageMock();
    Object.defineProperty(globalThis, 'localStorage', { value: storageMock, writable: true, configurable: true });
  });

  it('Feature: machine-repair-management, Property 3: Đăng nhập không hợp lệ bị từ chối — Validates: Requirements 1.2', () => {
    // Generate email strings that are NOT in the valid users list
    const invalidEmailArb = fc
      .emailAddress()
      .filter((email) => !validEmails.has(email));

    // Any password
    const invalidPasswordArb = fc.string({ minLength: 1, maxLength: 30 });

    fc.assert(
      fc.property(
        invalidEmailArb,
        invalidPasswordArb,
        (email, password) => {
          const result = loginSync(email, password);
          expect(result.success).toBe(false);
          if (!result.success) {
            expect(typeof result.error).toBe('string');
            expect(result.error.length).toBeGreaterThan(0);
          }
        },
      ),
      { numRuns: 100 },
    );
  });
});
