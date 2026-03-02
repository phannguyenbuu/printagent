import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import { useAuthStore } from '../../stores/authStore';
import { useWorkspaceStore } from '../../stores/workspaceStore';
import { ProtectedRoute } from '../index';

// Stub out framer-motion to avoid animation issues in tests
vi.mock('framer-motion', () => ({
  motion: {
    div: (props: Record<string, unknown>) => {
      const { animate, transition, initial, whileHover, whileTap, variants, ...rest } = props as Record<string, unknown>;
      return <div {...(rest as React.HTMLAttributes<HTMLDivElement>)} />;
    },
  },
  AnimatePresence: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

const fakeSupplier = {
  id: 'user-s1',
  username: 'supplier1',
  email: 'supplier1@goxprint.vn',
  fullName: 'Nguyễn Văn An',
  role: 'supplier' as const,
  locationIds: ['loc-1'],
  companyId: 'CTY001',
  companyName: 'Test Company',
  workspaceIds: ['ws-1'],
};

const fakeTechnician = {
  id: 'user-t1',
  username: 'tech1',
  email: 'tech1@kythuat.vn',
  fullName: 'Trần Văn Bình',
  role: 'technician' as const,
  locationIds: ['loc-1'],
  companyId: 'CTY002',
  companyName: 'Test Tech',
  workspaceIds: ['ws-1', 'ws-2'],
};

function renderWithRouter(initialPath: string, routes: React.ReactNode) {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <Routes>{routes}</Routes>
    </MemoryRouter>
  );
}

describe('ProtectedRoute', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: null,
      token: null,
      isAuthenticated: false,
    });
    useWorkspaceStore.setState({
      workspaces: [],
      activeIds: [],
      loading: false,
    });
  });

  it('redirects to /login when not authenticated', async () => {
    renderWithRouter('/dashboard', <>
      <Route path="/login" element={<div>Login Page</div>} />
      <Route element={<ProtectedRoute />}>
        <Route path="/dashboard" element={<div>Dashboard</div>} />
      </Route>
    </>);

    await waitFor(() => {
      expect(screen.getByText('Login Page')).toBeInTheDocument();
    });
  });

  it('renders child route when authenticated', async () => {
    useAuthStore.setState({
      user: fakeSupplier,
      token: 'valid-token',
      isAuthenticated: true,
    });
    useWorkspaceStore.setState({ activeIds: ['ws-1'] });

    // Mock localStorage so checkSession keeps the state
    const session = {
      token: 'valid-token',
      user: fakeSupplier,
      expiresAt: Date.now() + 60 * 60 * 1000,
    };
    vi.spyOn(Storage.prototype, 'getItem').mockReturnValue(JSON.stringify(session));

    renderWithRouter('/dashboard', <>
      <Route path="/login" element={<div>Login Page</div>} />
      <Route element={<ProtectedRoute />}>
        <Route path="/dashboard" element={<div>Dashboard</div>} />
      </Route>
    </>);

    await waitFor(() => {
      expect(screen.getByText('Dashboard')).toBeInTheDocument();
    });

    vi.restoreAllMocks();
  });

  it('redirects to /dashboard when role is not allowed', async () => {
    useAuthStore.setState({
      user: fakeSupplier,
      token: 'valid-token',
      isAuthenticated: true,
    });
    useWorkspaceStore.setState({ activeIds: ['ws-1'] });

    const session = {
      token: 'valid-token',
      user: fakeSupplier,
      expiresAt: Date.now() + 60 * 60 * 1000,
    };
    vi.spyOn(Storage.prototype, 'getItem').mockReturnValue(JSON.stringify(session));

    renderWithRouter('/admin-area', <>
      <Route path="/dashboard" element={<div>Dashboard Redirect</div>} />
      <Route element={<ProtectedRoute allowedRoles={['technician']} />}>
        <Route path="/admin-area" element={<div>Admin Area</div>} />
      </Route>
    </>);

    await waitFor(() => {
      expect(screen.getByText('Dashboard Redirect')).toBeInTheDocument();
    });

    vi.restoreAllMocks();
  });

  it('allows access when user role matches allowedRoles', async () => {
    useAuthStore.setState({
      user: fakeTechnician,
      token: 'valid-token',
      isAuthenticated: true,
    });
    useWorkspaceStore.setState({ activeIds: ['ws-1'] });

    const session = {
      token: 'valid-token',
      user: fakeTechnician,
      expiresAt: Date.now() + 60 * 60 * 1000,
    };
    vi.spyOn(Storage.prototype, 'getItem').mockReturnValue(JSON.stringify(session));

    renderWithRouter('/tech-only', <>
      <Route path="/dashboard" element={<div>Dashboard Redirect</div>} />
      <Route element={<ProtectedRoute allowedRoles={['technician']} />}>
        <Route path="/tech-only" element={<div>Tech Only Page</div>} />
      </Route>
    </>);

    await waitFor(() => {
      expect(screen.getByText('Tech Only Page')).toBeInTheDocument();
    });

    vi.restoreAllMocks();
  });

  it('redirects to /login when session is expired', async () => {
    // Start as authenticated in store, but session is expired in localStorage
    useAuthStore.setState({
      user: fakeSupplier,
      token: 'expired-token',
      isAuthenticated: true,
    });

    const expiredSession = {
      token: 'expired-token',
      user: fakeSupplier,
      expiresAt: Date.now() - 1000, // expired
    };
    vi.spyOn(Storage.prototype, 'getItem').mockReturnValue(JSON.stringify(expiredSession));
    vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => {});

    renderWithRouter('/dashboard', <>
      <Route path="/login" element={<div>Login Page</div>} />
      <Route element={<ProtectedRoute />}>
        <Route path="/dashboard" element={<div>Dashboard</div>} />
      </Route>
    </>);

    await waitFor(() => {
      expect(screen.getByText('Login Page')).toBeInTheDocument();
    });

    vi.restoreAllMocks();
  });
});
