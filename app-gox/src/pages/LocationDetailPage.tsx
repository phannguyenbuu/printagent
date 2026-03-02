import { useEffect, useMemo, useCallback } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useLocationStore } from '../stores/locationStore';
import { useRepairStore } from '../stores/repairStore';
import { GlowCard } from '../components/ui/GlowCard';
import { AnimatedList } from '../components/ui/AnimatedList';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { PullToRefresh } from '../components/layout/PullToRefresh';
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

const ALL_STATUSES: RepairStatus[] = ['new', 'accepted', 'in_progress', 'completed', 'cancelled'];

export function LocationDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { locations, loading: locLoading, fetchLocations } = useLocationStore();
  const { requests, loading: reqLoading, fetchRequests } = useRepairStore();

  useEffect(() => {
    fetchLocations();
    fetchRequests();
  }, [fetchLocations, fetchRequests]);

  const location = useMemo(
    () => locations.find((l) => l.id === id),
    [locations, id],
  );

  const locationRequests = useMemo(
    () => requests.filter((r) => r.locationId === id),
    [requests, id],
  );

  const statusCounts = useMemo(() => {
    const counts: Record<RepairStatus, number> = {
      new: 0, accepted: 0, in_progress: 0, completed: 0, cancelled: 0,
    };
    for (const req of locationRequests) {
      counts[req.status] += 1;
    }
    return counts;
  }, [locationRequests]);

  const handleRefresh = useCallback(async () => {
    await Promise.all([fetchLocations(), fetchRequests()]);
  }, [fetchLocations, fetchRequests]);

  if ((locLoading || reqLoading) && locations.length === 0) {
    return (
      <div style={styles.loadingContainer}>
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  if (!location) {
    return (
      <div style={styles.container}>
        <p style={styles.emptyText}>Không tìm thấy địa điểm.</p>
      </div>
    );
  }

  return (
    <motion.div
      style={styles.container}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: [0.4, 0, 0.2, 1] }}
    >
      {/* Back button */}
      <motion.button
        style={styles.backButton}
        onClick={() => navigate('/locations')}
        whileTap={{ scale: 0.95 }}
      >
        ← Quay lại
      </motion.button>

      {/* Location Info */}
      <GlowCard>
        <h1 style={styles.title}>{location.name}</h1>
        <p style={styles.address}>📍 {location.address}</p>
        {location.phone && (
          <p style={styles.phone}>📞 {location.phone}</p>
        )}
        <span style={styles.machineCount}>🖥 {location.machineCount} máy</span>
      </GlowCard>

      {/* Status Stats */}
      <GlowCard>
        <h2 style={styles.sectionTitle}>Thống kê yêu cầu</h2>
        <div style={styles.statsGrid}>
          {ALL_STATUSES.map((status) => (
            <div key={status} style={styles.statItem}>
              <span
                style={{
                  ...styles.statValue,
                  color: STATUS_COLORS[status],
                }}
              >
                {statusCounts[status]}
              </span>
              <span style={styles.statLabel}>{STATUS_LABELS[status]}</span>
            </div>
          ))}
        </div>
      </GlowCard>

      {/* Repair Requests */}
      <div style={styles.requestsSection}>
        <h2 style={styles.sectionTitle}>
          Yêu cầu sửa chữa ({locationRequests.length})
        </h2>

        <PullToRefresh onRefresh={handleRefresh}>
          {locationRequests.length === 0 ? (
            <p style={styles.emptyText}>Chưa có yêu cầu sửa chữa nào.</p>
          ) : (
            <AnimatedList>
              {locationRequests.map((req) => (
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
                  </div>
                  <WorkspaceBadge workspaceId={req.workspaceId} />
                  <p style={styles.description}>
                    {req.description.length > 80
                      ? `${req.description.slice(0, 80)}…`
                      : req.description}
                  </p>
                  <span style={styles.dateText}>
                    {new Date(req.createdAt).toLocaleDateString('vi-VN', {
                      day: '2-digit',
                      month: '2-digit',
                      year: 'numeric',
                      hour: '2-digit',
                      minute: '2-digit',
                    })}
                  </span>
                </GlowCard>
              ))}
            </AnimatedList>
          )}
        </PullToRefresh>
      </div>
    </motion.div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    minHeight: '100vh',
    position: 'relative',
    padding: '20px 16px',
    paddingBottom: '100px',
    display: 'flex',
    flexDirection: 'column',
    gap: '16px',
  },
  loadingContainer: {
    minHeight: '100vh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  },
  backButton: {
    background: 'none',
    border: 'none',
    color: 'var(--color-primary)',
    fontSize: '0.9rem',
    fontWeight: 600,
    cursor: 'pointer',
    padding: '4px 0',
    alignSelf: 'flex-start',
  },
  title: {
    fontSize: '1.3rem',
    fontWeight: 700,
    color: 'var(--color-primary)',
    margin: '0 0 6px',
  },
  address: {
    fontSize: '0.85rem',
    color: 'var(--color-text-secondary)',
    margin: '0 0 8px',
    lineHeight: 1.4,
  },
  phone: {
    fontSize: '0.85rem',
    color: 'var(--color-primary)',
    margin: '0 0 8px',
  },
  machineCount: {
    fontSize: '0.8rem',
    color: 'var(--color-primary)',
    fontWeight: 600,
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
    gap: '12px',
  },
  statItem: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    gap: '4px',
  },
  statValue: {
    fontSize: '1.3rem',
    fontWeight: 700,
  },
  statLabel: {
    fontSize: '0.65rem',
    color: 'var(--color-text-secondary)',
    textAlign: 'center',
  },
  requestsSection: {
    display: 'flex',
    flexDirection: 'column',
    gap: '12px',
  },
  emptyText: {
    color: 'var(--color-text-secondary)',
    fontSize: '0.875rem',
    textAlign: 'center',
    padding: '40px 0',
  },
  cardHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '6px',
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
  cardMeta: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    marginBottom: '6px',
  },
  priorityBadge: {
    fontSize: '0.65rem',
    fontWeight: 600,
    padding: '2px 6px',
    borderRadius: '4px',
    border: '1px solid',
  },
  description: {
    fontSize: '0.8rem',
    color: 'var(--color-text-secondary)',
    margin: '0 0 6px',
    lineHeight: 1.4,
  },
  dateText: {
    fontSize: '0.75rem',
    color: 'var(--color-text-secondary)',
  },
};
