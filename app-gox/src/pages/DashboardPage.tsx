import { useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useRepairStore } from '../stores/repairStore';
import { useLocationStore } from '../stores/locationStore';
import { useAuthStore } from '../stores/authStore';
import { calculateStatusStats } from '../services/statsService';
import { mockGetUserName } from '../api/mockApi';
import { GlowCard } from '../components/ui/GlowCard';
import { AnimatedList } from '../components/ui/AnimatedList';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { WorkspaceBadge } from '../components/ui/WorkspaceBadge';
import type { RepairStatus, Priority } from '../types/repair';

const STATUS_COLORS: Record<RepairStatus, string> = {
  new: 'var(--color-primary)',
  accepted: 'var(--color-secondary)',
  in_progress: 'var(--color-warning)',
  completed: 'var(--color-success)',
  cancelled: 'var(--color-error)',
};

const STATUS_LABELS: Record<RepairStatus, string> = {
  new: 'Mới tạo',
  accepted: 'Đã tiếp nhận',
  in_progress: 'Đang xử lý',
  completed: 'Hoàn thành',
  cancelled: 'Đã hủy',
};

const PRIORITY_COLORS: Record<Priority, string> = {
  critical: 'var(--color-error)',
  high: 'var(--color-warning)',
  medium: 'var(--color-primary)',
  low: 'var(--color-text-secondary)',
};

const PRIORITY_LABELS: Record<Priority, string> = {
  critical: 'Khẩn cấp',
  high: 'Cao',
  medium: 'Trung bình',
  low: 'Thấp',
};

export function DashboardPage() {
  const navigate = useNavigate();
  const user = useAuthStore((s) => s.user);
  const { requests, loading: requestsLoading, fetchRequests } = useRepairStore();
  const { locations, fetchLocations } = useLocationStore();

  useEffect(() => {
    fetchRequests();
    fetchLocations();
  }, [fetchRequests, fetchLocations]);

  const userLocationIds = useMemo(
    () => user?.locationIds ?? [],
    [user],
  );

  const statusStats = useMemo(
    () => calculateStatusStats(requests, userLocationIds),
    [requests, userLocationIds],
  );

  const recentRequests = useMemo(
    () => requests.filter((r) => r.status === 'new'),
    [requests],
  );

  // Requests being handled by OTHER people (not current user)
  const otherInProgressRequests = useMemo(() => {
    const priorityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    return requests
      .filter((r) => {
        if (r.status !== 'accepted' && r.status !== 'in_progress') return false;
        return r.assignedTo !== user?.id;
      })
      .sort((a, b) => (priorityOrder[a.priority] ?? 9) - (priorityOrder[b.priority] ?? 9));
  }, [requests, user]);

  // TOP requests that are accepted or in_progress (not yet completed)
  const inProgressRequests = useMemo(() => {
    const priorityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    return requests
      .filter((r) => {
        if (r.status !== 'accepted' && r.status !== 'in_progress') return false;
        // Kỹ thuật viên chỉ thấy yêu cầu của mình
        if (user?.role === 'technician') return r.assignedTo === user.id;
        return true;
      })
      .sort((a, b) => (priorityOrder[a.priority] ?? 9) - (priorityOrder[b.priority] ?? 9));
  }, [requests, user]);

  if (requestsLoading && requests.length === 0) {
    return (
      <div style={styles.loadingContainer}>
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  return (
    <div style={styles.container}>

      <motion.div
        style={styles.content}
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease: [0.4, 0, 0.2, 1] }}
      >
        {/* Header */}
        <div style={styles.header}>
          <h1 style={styles.title}>Dashboard</h1>
          <p style={styles.subtitle}>
            Xin chào, {user?.fullName ?? 'Người dùng'}
          </p>
        </div>

        {/* Statistics Numbers */}
        <GlowCard>
          <h2 style={styles.sectionTitle}>Thống kê yêu cầu</h2>
          <div style={styles.statsGrid}>
            {(['in_progress', 'completed', 'cancelled'] as RepairStatus[]).map((status) => (
              <div key={status} style={{
                ...styles.statCard,
                borderColor: `${STATUS_COLORS[status]}40`,
                background: `${STATUS_COLORS[status]}0d`,
              }}>
                <span style={{ ...styles.statNumber, color: STATUS_COLORS[status] }}>
                  {statusStats[status]}
                </span>
                <span style={styles.statLabel}>{STATUS_LABELS[status]}</span>
              </div>
            ))}
          </div>
        </GlowCard>

        {/* TOP In-Progress Requests */}
        {inProgressRequests.length > 0 && (
          <div style={styles.recentSection}>
            <h2 style={styles.sectionTitle}>🔧 Đang xử lý ({inProgressRequests.length})</h2>
            <AnimatedList>
              {inProgressRequests.map((req) => (
                <GlowCard
                  key={req.id}
                  onClick={() => navigate(`/requests/${req.id}`)}
                >
                  <div style={styles.cardHeader}>
                    <span style={styles.machineName}>{req.machineName}</span>
                    <span
                      style={{
                        ...styles.badge,
                        background: `${STATUS_COLORS[req.status]}20`,
                        color: STATUS_COLORS[req.status],
                        borderColor: `${STATUS_COLORS[req.status]}40`,
                      }}
                    >
                      {STATUS_LABELS[req.status]}
                    </span>
                  </div>
                  <WorkspaceBadge workspaceId={req.workspaceId} />
                  <div style={styles.cardBody}>
                    <div style={styles.cardMeta}>
                      <span
                        style={{
                          ...styles.priorityBadge,
                          background: `${PRIORITY_COLORS[req.priority]}20`,
                          color: PRIORITY_COLORS[req.priority],
                          borderColor: `${PRIORITY_COLORS[req.priority]}40`,
                        }}
                      >
                        {PRIORITY_LABELS[req.priority]}
                      </span>
                      {req.assignedTo && (
                        <span style={styles.assigneeText}>
                          👤 {mockGetUserName(req.assignedTo)}
                        </span>
                      )}
                    </div>
                    {req.acceptedAt && (
                      <span style={styles.dateText}>
                        {new Date(req.acceptedAt).toLocaleDateString('vi-VN', {
                          day: '2-digit',
                          month: '2-digit',
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
                      </span>
                    )}
                  </div>
                  {(() => {
                    const loc = locations.find((l) => l.id === req.locationId);
                    return loc ? (
                      <div style={styles.locationInfo}>
                        <span style={styles.locationName}>📍 {loc.name}</span>
                        {loc.address && <span style={styles.locationDetail}>{loc.address}</span>}
                        {loc.phone && <span style={styles.locationDetail}>📞 {loc.phone}</span>}
                      </div>
                    ) : null;
                  })()}
                </GlowCard>
              ))}
            </AnimatedList>
          </div>
        )}

        {/* Recent Requests - only NEW */}
        <div style={styles.recentSection}>
          <h2 style={styles.sectionTitle}>📋 Yêu cầu mới ({recentRequests.length})</h2>
          {recentRequests.length === 0 ? (
            <p style={styles.emptyText}>Không có yêu cầu mới.</p>
          ) : (
            <AnimatedList>
              {recentRequests.map((req) => (
                <GlowCard
                  key={req.id}
                  onClick={() => navigate(`/requests/${req.id}`)}
                >
                  <div style={styles.cardHeader}>
                    <span style={styles.machineName}>{req.machineName}</span>
                    <span
                      style={{
                        ...styles.badge,
                        background: `${STATUS_COLORS[req.status]}20`,
                        color: STATUS_COLORS[req.status],
                        borderColor: `${STATUS_COLORS[req.status]}40`,
                      }}
                    >
                      {STATUS_LABELS[req.status]}
                    </span>
                  </div>
                  <WorkspaceBadge workspaceId={req.workspaceId} />
                  <div style={styles.cardBody}>
                    <div style={styles.cardMeta}>
                      <span
                        style={{
                          ...styles.priorityBadge,
                          background: `${PRIORITY_COLORS[req.priority]}20`,
                          color: PRIORITY_COLORS[req.priority],
                          borderColor: `${PRIORITY_COLORS[req.priority]}40`,
                        }}
                      >
                        {PRIORITY_LABELS[req.priority]}
                      </span>
                      <span style={styles.locationText}>
                        {(() => {
                          const loc = locations.find((l) => l.id === req.locationId);
                          return loc ? `📍 ${loc.name}` : `📍 ${req.locationId}`;
                        })()}
                      </span>
                    </div>
                    <span style={styles.dateText}>
                      {new Date(req.createdAt).toLocaleDateString('vi-VN', {
                        day: '2-digit',
                        month: '2-digit',
                        year: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </span>
                  </div>
                  {(() => {
                    const loc = locations.find((l) => l.id === req.locationId);
                    return loc ? (
                      <div style={styles.locationInfo}>
                        {loc.address && <span style={styles.locationDetail}>🏠 {loc.address}</span>}
                        {loc.phone && <span style={styles.locationDetail}>📞 {loc.phone}</span>}
                      </div>
                    ) : null;
                  })()}
                </GlowCard>
              ))}
            </AnimatedList>
          )}
        </div>

        {/* Other in-progress requests (handled by others) */}
        {otherInProgressRequests.length > 0 && (
          <div style={styles.recentSection}>
            <h2 style={styles.sectionTitle}>👥 Các yêu cầu đang xử lý khác ({otherInProgressRequests.length})</h2>
            <AnimatedList>
              {otherInProgressRequests.map((req) => (
                <GlowCard
                  key={req.id}
                  onClick={() => navigate(`/requests/${req.id}`)}
                >
                  <div style={styles.cardHeader}>
                    <span style={styles.machineName}>{req.machineName}</span>
                    <span
                      style={{
                        ...styles.badge,
                        background: `${STATUS_COLORS[req.status]}20`,
                        color: STATUS_COLORS[req.status],
                        borderColor: `${STATUS_COLORS[req.status]}40`,
                      }}
                    >
                      {STATUS_LABELS[req.status]}
                    </span>
                  </div>
                  <WorkspaceBadge workspaceId={req.workspaceId} />
                  <div style={styles.cardBody}>
                    <div style={styles.cardMeta}>
                      <span
                        style={{
                          ...styles.priorityBadge,
                          background: `${PRIORITY_COLORS[req.priority]}20`,
                          color: PRIORITY_COLORS[req.priority],
                          borderColor: `${PRIORITY_COLORS[req.priority]}40`,
                        }}
                      >
                        {PRIORITY_LABELS[req.priority]}
                      </span>
                      {req.assignedTo && (
                        <span style={styles.assigneeText}>
                          👤 {mockGetUserName(req.assignedTo)}
                        </span>
                      )}
                    </div>
                    <span style={styles.dateText}>
                      {new Date(req.updatedAt).toLocaleDateString('vi-VN', {
                        day: '2-digit',
                        month: '2-digit',
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </span>
                  </div>
                  {(() => {
                    const loc = locations.find((l) => l.id === req.locationId);
                    return loc ? (
                      <div style={styles.locationInfo}>
                        <span style={styles.locationName}>📍 {loc.name}</span>
                        {loc.address && <span style={styles.locationDetail}>{loc.address}</span>}
                        {loc.phone && <span style={styles.locationDetail}>📞 {loc.phone}</span>}
                      </div>
                    ) : null;
                  })()}
                </GlowCard>
              ))}
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
  loadingContainer: {
    minHeight: '100vh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    position: 'relative',
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
    gridTemplateColumns: 'repeat(3, 1fr)',
    gap: '8px',
  },
  statCard: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    gap: '4px',
    padding: '12px 8px',
    borderRadius: '10px',
    border: '1px solid',
  },
  statNumber: {
    fontSize: '1.75rem',
    fontWeight: 700,
    lineHeight: 1,
  },
  statLabel: {
    fontSize: '0.65rem',
    color: 'var(--color-text-secondary)',
    textAlign: 'center' as const,
    fontWeight: 500,
  },
  recentSection: {
    display: 'flex',
    flexDirection: 'column',
    gap: '12px',
  },
  emptyText: {
    color: 'var(--color-text-secondary)',
    fontSize: '0.875rem',
    textAlign: 'center',
    padding: '24px 0',
  },
  cardHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '8px',
  },
  machineName: {
    fontSize: '0.95rem',
    fontWeight: 600,
    color: 'var(--color-text)',
  },
  badge: {
    fontSize: '0.7rem',
    fontWeight: 600,
    padding: '3px 8px',
    borderRadius: '6px',
    border: '1px solid',
    whiteSpace: 'nowrap',
  },
  cardBody: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  cardMeta: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
  },
  priorityBadge: {
    fontSize: '0.65rem',
    fontWeight: 600,
    padding: '2px 6px',
    borderRadius: '4px',
    border: '1px solid',
  },
  locationText: {
    fontSize: '0.8rem',
    color: 'var(--color-text-secondary)',
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
  locationInfo: {
    display: 'flex',
    flexDirection: 'column',
    gap: '2px',
    marginTop: '6px',
  },
  locationName: {
    fontSize: '0.8rem',
    color: 'var(--color-text)',
    fontWeight: 500,
  },
  locationDetail: {
    fontSize: '0.75rem',
    color: 'var(--color-text-secondary)',
    paddingLeft: '20px',
  },
};
