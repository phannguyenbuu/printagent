import React, { Suspense, useEffect, useState } from 'react';
import {
  BrowserRouter,
  Routes,
  Route,
  Navigate,
  Outlet,
} from 'react-router-dom';
import { useAuthStore } from '../stores/authStore';
import { useWorkspaceStore } from '../stores/workspaceStore';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { AppLayout } from '../components/layout/AppLayout';
import type { User } from '../types/auth';

// Lazy-loaded pages (named exports → default re-export)
const LoginPage = React.lazy(() =>
  import('../pages/LoginPage').then((m) => ({ default: m.LoginPage }))
);
const DashboardPage = React.lazy(() =>
  import('../pages/DashboardPage').then((m) => ({ default: m.DashboardPage }))
);
const RequestListPage = React.lazy(() =>
  import('../pages/RequestListPage').then((m) => ({
    default: m.RequestListPage,
  }))
);
const CreateRequestPage = React.lazy(() =>
  import('../pages/CreateRequestPage').then((m) => ({
    default: m.CreateRequestPage,
  }))
);
const RequestDetailPage = React.lazy(() =>
  import('../pages/RequestDetailPage').then((m) => ({
    default: m.RequestDetailPage,
  }))
);
const LocationListPage = React.lazy(() =>
  import('../pages/LocationListPage').then((m) => ({
    default: m.LocationListPage,
  }))
);
const LocationDetailPage = React.lazy(() =>
  import('../pages/LocationDetailPage').then((m) => ({
    default: m.LocationDetailPage,
  }))
);
const RepairHistoryPage = React.lazy(() =>
  import('../pages/RepairHistoryPage').then((m) => ({
    default: m.RepairHistoryPage,
  }))
);
const AccountPage = React.lazy(() =>
  import('../pages/AccountPage').then((m) => ({ default: m.AccountPage }))
);
const AgentPage = React.lazy(() =>
  import('../pages/AgentPage').then((m) => ({ default: m.AgentPage }))
);
const WorkspacePage = React.lazy(() =>
  import('../pages/WorkspacePage').then((m) => ({ default: m.WorkspacePage }))
);

// ---------- Loading fallback ----------
function PageLoading() {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '100vh',
      }}
    >
      <LoadingSpinner size="lg" />
    </div>
  );
}

// ---------- ProtectedRoute ----------
interface ProtectedRouteProps {
  allowedRoles?: User['role'][];
}

export function ProtectedRoute({ allowedRoles }: ProtectedRouteProps) {
  const { isAuthenticated, user } = useAuthStore();
  const checkSession = useAuthStore((s) => s.checkSession);
  const hasSelection = useWorkspaceStore((s) => s.activeIds.length > 0);
  const [checked, setChecked] = useState(false);

  useEffect(() => {
    checkSession();
    setChecked(true);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // run once on mount only

  if (!checked) {
    return <PageLoading />;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  // Must select workspace before accessing app pages
  if (!hasSelection) {
    return <Navigate to="/workspace" replace />;
  }

  if (allowedRoles && user && !allowedRoles.includes(user.role)) {
    return <Navigate to="/dashboard" replace />;
  }

  return <Outlet />;
}

// ---------- App Router ----------
export function AppRouter() {
  return (
    <BrowserRouter>
      <Suspense fallback={<PageLoading />}>
        <Routes>
          {/* Public route – no AppLayout */}
          <Route path="/login" element={<LoginPage />} />
          <Route path="/workspace" element={<WorkspacePage />} />

          {/* Protected routes – wrapped in AppLayout */}
          <Route element={<ProtectedRoute />}>
            <Route
              element={
                <AppLayout>
                  <Outlet />
                </AppLayout>
              }
            >
              <Route path="/dashboard" element={<DashboardPage />} />
              <Route path="/requests" element={<RequestListPage />} />
              <Route
                path="/requests/new"
                element={<CreateRequestPage />}
              />
              <Route path="/requests/:id" element={<RequestDetailPage />} />
              <Route path="/locations" element={<LocationListPage />} />
              <Route path="/locations/:id" element={<LocationDetailPage />} />
              <Route path="/history" element={<RepairHistoryPage />} />
              <Route path="/agents" element={<AgentPage />} />
              <Route path="/account" element={<AccountPage />} />
            </Route>
          </Route>

          {/* Default redirect */}
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </Suspense>
    </BrowserRouter>
  );
}
