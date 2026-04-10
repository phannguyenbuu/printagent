import { useCallback, useEffect, useMemo } from 'react';
import { motion } from 'framer-motion';
import { useNavigate, useParams } from 'react-router-dom';

import { PullToRefresh } from '../components/layout/PullToRefresh';
import { RequestCard } from '../components/requests/RequestCard';
import { ALL_STATUSES } from '../components/requests/repairVisuals';
import { StatusStatCard } from '../components/requests/StatusStatCard';
import { AnimatedList } from '../components/ui/AnimatedList';
import { EmptyState, PageLoading } from '../components/ui/PageState';
import { GlowCard } from '../components/ui/GlowCard';
import { useLocationStore } from '../stores/locationStore';
import { useRepairStore } from '../stores/repairStore';
import type { RepairStatus } from '../types/repair';

function formatDateTime(value: string): string {
  return new Date(value).toLocaleDateString('vi-VN', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function LocationDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { locations, loading: locationLoading, fetchLocations } = useLocationStore();
  const { requests, loading: requestLoading, fetchRequests } = useRepairStore();

  useEffect(() => {
    fetchLocations();
    fetchRequests();
  }, [fetchLocations, fetchRequests]);

  const location = useMemo(
    () => locations.find((item) => item.id === id),
    [id, locations],
  );

  const locationRequests = useMemo(
    () => requests.filter((request) => request.locationId === id),
    [id, requests],
  );

  const statusCounts = useMemo(() => {
    const counts: Record<RepairStatus, number> = {
      new: 0,
      accepted: 0,
      in_progress: 0,
      completed: 0,
      cancelled: 0,
    };

    for (const request of locationRequests) {
      counts[request.status] += 1;
    }

    return counts;
  }, [locationRequests]);

  const handleRefresh = useCallback(async () => {
    await Promise.all([fetchLocations(), fetchRequests()]);
  }, [fetchLocations, fetchRequests]);

  if ((locationLoading || requestLoading) && locations.length === 0) {
    return <PageLoading message="Đang tải địa điểm..." />;
  }

  if (!location) {
    return (
      <div style={styles.container}>
        <motion.button
          style={styles.backButton}
          onClick={() => navigate('/locations')}
          whileTap={{ scale: 0.95 }}
        >
          ← Quay lại
        </motion.button>
        <EmptyState message="Không tìm thấy địa điểm." centered />
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
      <motion.button
        style={styles.backButton}
        onClick={() => navigate('/locations')}
        whileTap={{ scale: 0.95 }}
      >
        ← Quay lại
      </motion.button>

      <GlowCard>
        <h1 style={styles.title}>{location.name}</h1>
        <p style={styles.address}>📍 {location.address}</p>
        {location.phone && <p style={styles.phone}>📞 {location.phone}</p>}
        <span style={styles.machineCount}>🖥 {location.machineCount} máy</span>
      </GlowCard>

      <GlowCard>
        <h2 style={styles.sectionTitle}>Thống kê yêu cầu</h2>
        <div style={styles.statsGrid}>
          {ALL_STATUSES.map((status) => (
            <StatusStatCard key={status} status={status} value={statusCounts[status]} compact />
          ))}
        </div>
      </GlowCard>

      <div style={styles.requestsSection}>
        <h2 style={styles.sectionTitle}>Yêu cầu sửa chữa ({locationRequests.length})</h2>

        <PullToRefresh onRefresh={handleRefresh}>
          {locationRequests.length === 0 ? (
            <EmptyState message="Chưa có yêu cầu sửa chữa nào." centered />
          ) : (
            <AnimatedList>
              {locationRequests.map((request) => (
                <RequestCard
                  key={request.id}
                  request={request}
                  onClick={() => navigate(`/requests/${request.id}`)}
                  description={request.description}
                  footer={<span style={styles.dateText}>{formatDateTime(request.createdAt)}</span>}
                />
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
  requestsSection: {
    display: 'flex',
    flexDirection: 'column',
    gap: '12px',
  },
  dateText: {
    fontSize: '0.75rem',
    color: 'var(--color-text-secondary)',
  },
};
