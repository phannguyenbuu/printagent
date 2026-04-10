import { useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';

import { motion } from 'framer-motion';

import { mockGetUserName } from '../api/mockApi';
import { RequestCard } from '../components/requests/RequestCard';
import { RequestLocationBlock } from '../components/requests/RequestLocationBlock';
import { ALL_STATUSES } from '../components/requests/repairVisuals';
import { StatusStatCard } from '../components/requests/StatusStatCard';
import { AnimatedList } from '../components/ui/AnimatedList';
import { EmptyState, PageLoading } from '../components/ui/PageState';
import { GlowCard } from '../components/ui/GlowCard';
import { calculateStatusStats } from '../services/statsService';
import { useAuthStore } from '../stores/authStore';
import { useLocationStore } from '../stores/locationStore';
import { useRepairStore } from '../stores/repairStore';

function formatDateTime(value: string): string {
  return new Date(value).toLocaleDateString('vi-VN', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function DashboardPage() {
  const navigate = useNavigate();
  const user = useAuthStore((s) => s.user);
  const { requests, loading: requestsLoading, fetchRequests } = useRepairStore();
  const { locations, fetchLocations } = useLocationStore();

  useEffect(() => {
    fetchRequests();
    fetchLocations();
  }, [fetchLocations, fetchRequests]);

  const userLocationIds = useMemo(
    () => user?.locationIds ?? [],
    [user],
  );

  const locationMap = useMemo(
    () => new Map(locations.map((location) => [location.id, location])),
    [locations],
  );

  const statusStats = useMemo(
    () => calculateStatusStats(requests, userLocationIds),
    [requests, userLocationIds],
  );

  const recentRequests = useMemo(
    () => requests.filter((request) => request.status === 'new'),
    [requests],
  );

  const otherInProgressRequests = useMemo(() => {
    const priorityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

    return requests
      .filter((request) => {
        if (request.status !== 'accepted' && request.status !== 'in_progress') return false;
        return request.assignedTo !== user?.id;
      })
      .sort((a, b) => (priorityOrder[a.priority] ?? 9) - (priorityOrder[b.priority] ?? 9));
  }, [requests, user]);

  const inProgressRequests = useMemo(() => {
    const priorityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

    return requests
      .filter((request) => {
        if (request.status !== 'accepted' && request.status !== 'in_progress') return false;
        if (user?.role === 'technician') return request.assignedTo === user.id;
        return true;
      })
      .sort((a, b) => (priorityOrder[a.priority] ?? 9) - (priorityOrder[b.priority] ?? 9));
  }, [requests, user]);

  if (requestsLoading && requests.length === 0) {
    return <PageLoading message="Đang tải dashboard..." />;
  }

  return (
    <div style={styles.container}>
      <motion.div
        style={styles.content}
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease: [0.4, 0, 0.2, 1] }}
      >
        <div style={styles.header}>
          <h1 style={styles.title}>Dashboard</h1>
          <p style={styles.subtitle}>Xin chào, {user?.fullName ?? 'Người dùng'}</p>
        </div>

        <GlowCard>
          <h2 style={styles.sectionTitle}>Thống kê yêu cầu</h2>
          <div style={styles.statsGrid}>
            {ALL_STATUSES.map((status) => (
              <StatusStatCard key={status} status={status} value={statusStats[status]} compact />
            ))}
          </div>
        </GlowCard>

        {inProgressRequests.length > 0 && (
          <div style={styles.recentSection}>
            <h2 style={styles.sectionTitle}>🔧 Đang xử lý ({inProgressRequests.length})</h2>
            <AnimatedList>
              {inProgressRequests.map((request) => {
                const location = locationMap.get(request.locationId);
                return (
                  <RequestCard
                    key={request.id}
                    request={request}
                    onClick={() => navigate(`/requests/${request.id}`)}
                    metaTrailing={
                      request.assignedTo
                        ? <span style={styles.assigneeText}>👤 {mockGetUserName(request.assignedTo)}</span>
                        : undefined
                    }
                    locationContent={
                      <RequestLocationBlock
                        location={location}
                        fallbackLabel={`📍 ${request.locationId}`}
                      />
                    }
                    footer={
                      request.acceptedAt
                        ? <span style={styles.dateText}>{formatDateTime(request.acceptedAt)}</span>
                        : undefined
                    }
                  />
                );
              })}
            </AnimatedList>
          </div>
        )}

        <div style={styles.recentSection}>
          <h2 style={styles.sectionTitle}>📋 Yêu cầu mới ({recentRequests.length})</h2>
          {recentRequests.length === 0 ? (
            <EmptyState message="Không có yêu cầu mới." centered />
          ) : (
            <AnimatedList>
              {recentRequests.map((request) => {
                const location = locationMap.get(request.locationId);
                return (
                  <RequestCard
                    key={request.id}
                    request={request}
                    onClick={() => navigate(`/requests/${request.id}`)}
                    locationContent={
                      <RequestLocationBlock
                        location={location}
                        fallbackLabel={`📍 ${request.locationId}`}
                      />
                    }
                    footer={<span style={styles.dateText}>{formatDateTime(request.createdAt)}</span>}
                  />
                );
              })}
            </AnimatedList>
          )}
        </div>

        {otherInProgressRequests.length > 0 && (
          <div style={styles.recentSection}>
            <h2 style={styles.sectionTitle}>👥 Các yêu cầu đang xử lý khác ({otherInProgressRequests.length})</h2>
            <AnimatedList>
              {otherInProgressRequests.map((request) => {
                const location = locationMap.get(request.locationId);
                return (
                  <RequestCard
                    key={request.id}
                    request={request}
                    onClick={() => navigate(`/requests/${request.id}`)}
                    metaTrailing={
                      request.assignedTo
                        ? <span style={styles.assigneeText}>👤 {mockGetUserName(request.assignedTo)}</span>
                        : undefined
                    }
                    locationContent={
                      <RequestLocationBlock
                        location={location}
                        fallbackLabel={`📍 ${request.locationId}`}
                      />
                    }
                    footer={<span style={styles.dateText}>{formatDateTime(request.updatedAt)}</span>}
                  />
                );
              })}
            </AnimatedList>
          </div>
        )}
      </motion.div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    minHeight: '100vh',
    position: 'relative',
    paddingBottom: '80px',
  },
  content: {
    position: 'relative',
    zIndex: 1,
    padding: '20px 16px',
    display: 'flex',
    flexDirection: 'column',
    gap: '20px',
  },
  header: {
    marginBottom: '4px',
  },
  title: {
    fontSize: '1.5rem',
    fontWeight: 700,
    color: 'var(--color-primary)',
    margin: 0,
  },
  subtitle: {
    fontSize: '0.875rem',
    color: 'var(--color-text-secondary)',
    margin: '4px 0 0',
  },
  sectionTitle: {
    fontSize: '1rem',
    fontWeight: 600,
    color: 'var(--color-text)',
    margin: '0 0 12px',
  },
  statsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(5, 1fr)',
    gap: '8px',
  },
  recentSection: {
    display: 'flex',
    flexDirection: 'column',
    gap: '12px',
  },
  dateText: {
    fontSize: '0.75rem',
    color: 'var(--color-text-secondary)',
  },
  assigneeText: {
    fontSize: '0.8rem',
    color: 'var(--color-secondary)',
    fontWeight: 500,
  },
};
