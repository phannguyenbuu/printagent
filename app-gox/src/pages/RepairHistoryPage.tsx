import { useEffect, useMemo, useCallback, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useRepairStore } from '../stores/repairStore';
import { useLocationStore } from '../stores/locationStore';
import { filterHistory } from '../services/historyService';
import { calculateCumulativeCost } from '../services/statsService';
import { GlowCard } from '../components/ui/GlowCard';
import { AnimatedList } from '../components/ui/AnimatedList';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { PullToRefresh } from '../components/layout/PullToRefresh';
import type { HistoryFilters } from '../types/history';

const STATUS_COLORS = {
  completed: 'var(--color-success)',
} as const;

const STATUS_LABELS = {
  completed: 'Hoàn thành',
} as const;

export function RepairHistoryPage() {
  const navigate = useNavigate();
  const { requests, loading, fetchRequests } = useRepairStore();
  const { locations, fetchLocations } = useLocationStore();

  const [machineNameFilter, setMachineNameFilter] = useState('');
  const [locationFilter, setLocationFilter] = useState('');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');

  useEffect(() => {
    fetchRequests();
    fetchLocations();
  }, [fetchRequests, fetchLocations]);

  // Build history: get all completed requests, then apply filters
  const filteredHistory = useMemo(() => {
    // Get all completed requests as history entries
    const allCompleted = requests
      .filter((r) => r.status === 'completed')
      .sort((a, b) => {
        const dateA = a.completedAt ?? '';
        const dateB = b.completedAt ?? '';
        return dateB.localeCompare(dateA);
      });

    // Get history entries for all machines (or filtered machine)
    const allHistory = allCompleted.map((r) => ({
      repairRequest: r,
      totalMaterialCost: r.materials.reduce(
        (sum, m) => sum + m.quantity * m.unitPrice,
        0
      ),
    }));

    // Apply filters
    const filters: HistoryFilters = {};
    if (dateFrom) filters.dateFrom = dateFrom;
    if (dateTo) filters.dateTo = dateTo;
    if (locationFilter) filters.locationId = locationFilter;
    if (machineNameFilter) filters.machineName = machineNameFilter;

    return filterHistory(allHistory, filters);
  }, [requests, dateFrom, dateTo, locationFilter, machineNameFilter]);

  // Calculate cumulative cost based on current filter
  const cumulativeCost = useMemo(() => {
    if (machineNameFilter) {
      return calculateCumulativeCost(requests, machineNameFilter);
    }
    // If no machine filter, sum all filtered entries
    return filteredHistory.reduce(
      (sum, entry) => sum + entry.totalMaterialCost,
      0
    );
  }, [requests, machineNameFilter, filteredHistory]);

  const handleRefresh = useCallback(async () => {
    await fetchRequests();
  }, [fetchRequests]);

  const formatCurrency = (value: number) =>
    value.toLocaleString('vi-VN') + ' đ';

  if (loading && requests.length === 0) {
    return (
      <div style={styles.loadingContainer}>
        <LoadingSpinner size="lg" />
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
      {/* Header */}
      <div style={styles.header}>
        <h1 style={styles.title}>Lịch sử sửa chữa</h1>
      </div>

      {/* Cumulative Cost */}
      <GlowCard>
        <div style={styles.costSection}>
          <span style={styles.costLabel}>Tổng chi phí tích lũy</span>
          <span style={styles.costValue}>{formatCurrency(cumulativeCost)}</span>
        </div>
      </GlowCard>

      {/* Filter Bar */}
      <div style={styles.filterBar}>
        <div style={styles.filterRow}>
          <input
            type="date"
            value={dateFrom}
            onChange={(e) => setDateFrom(e.target.value)}
            style={styles.dateInput}
            aria-label="Từ ngày"
            placeholder="Từ ngày"
          />
          <input
            type="date"
            value={dateTo}
            onChange={(e) => setDateTo(e.target.value)}
            style={styles.dateInput}
            aria-label="Đến ngày"
            placeholder="Đến ngày"
          />
        </div>
        <div style={styles.filterRow}>
          <select
            value={locationFilter}
            onChange={(e) => setLocationFilter(e.target.value)}
            style={styles.select}
            aria-label="Lọc theo địa điểm"
          >
            <option value="">Tất cả địa điểm</option>
            {locations.map((loc) => (
              <option key={loc.id} value={loc.id}>
                {loc.name}
              </option>
            ))}
          </select>
          <input
            type="text"
            value={machineNameFilter}
            onChange={(e) => setMachineNameFilter(e.target.value)}
            style={styles.textInput}
            placeholder="Tên máy..."
            aria-label="Lọc theo tên máy"
          />
        </div>
      </div>

      {/* History List */}
      <PullToRefresh onRefresh={handleRefresh}>
        {filteredHistory.length === 0 ? (
          <p style={styles.emptyText}>Không có lịch sử sửa chữa nào.</p>
        ) : (
          <AnimatedList>
            {filteredHistory.map((entry) => (
              <GlowCard
                key={entry.repairRequest.id}
                onClick={() => navigate(`/requests/${entry.repairRequest.id}`)}
              >
                <div style={styles.cardHeader}>
                  <span style={styles.machineName}>
                    {entry.repairRequest.machineName}
                  </span>
                  <span style={styles.badge}>
                    {STATUS_LABELS.completed}
                  </span>
                </div>
                <div style={styles.cardBody}>
                  <span style={styles.locationText}>
                    📍 {entry.repairRequest.locationId}
                  </span>
                  <span style={styles.dateText}>
                    {entry.repairRequest.completedAt
                      ? new Date(entry.repairRequest.completedAt).toLocaleDateString(
                          'vi-VN',
                          {
                            day: '2-digit',
                            month: '2-digit',
                            year: 'numeric',
                          }
                        )
                      : '—'}
                  </span>
                </div>
                <div style={styles.cardFooter}>
                  <span style={styles.costText}>
                    Chi phí vật tư: {formatCurrency(entry.totalMaterialCost)}
                  </span>
                </div>
              </GlowCard>
            ))}
          </AnimatedList>
        )}
      </PullToRefresh>
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
  header: {
    marginBottom: '4px',
  },
  title: {
    fontSize: '1.5rem',
    fontWeight: 700,
    color: 'var(--color-primary)',
    margin: 0,
  },
  costSection: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    gap: '4px',
  },
  costLabel: {
    fontSize: '0.8rem',
    color: 'var(--color-text-secondary)',
  },
  costValue: {
    fontSize: '1.4rem',
    fontWeight: 700,
    color: 'var(--color-success)',
  },
  filterBar: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
  },
  filterRow: {
    display: 'flex',
    gap: '8px',
  },
  dateInput: {
    flex: 1,
    background: 'var(--color-surface)',
    color: 'var(--color-text)',
    border: '1px solid var(--color-surface-light)',
    borderRadius: '8px',
    padding: '10px 12px',
    fontSize: '0.85rem',
    outline: 'none',
    colorScheme: 'dark',
  },
  select: {
    flex: 1,
    background: 'var(--color-surface)',
    color: 'var(--color-text)',
    border: '1px solid var(--color-surface-light)',
    borderRadius: '8px',
    padding: '10px 12px',
    fontSize: '0.85rem',
    outline: 'none',
    appearance: 'auto' as React.CSSProperties['appearance'],
  },
  textInput: {
    flex: 1,
    background: 'var(--color-surface)',
    color: 'var(--color-text)',
    border: '1px solid var(--color-surface-light)',
    borderRadius: '8px',
    padding: '10px 12px',
    fontSize: '0.85rem',
    outline: 'none',
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
    background: `${STATUS_COLORS.completed}20`,
    color: STATUS_COLORS.completed,
    borderColor: `${STATUS_COLORS.completed}40`,
  },
  cardBody: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '6px',
  },
  locationText: {
    fontSize: '0.8rem',
    color: 'var(--color-text-secondary)',
  },
  dateText: {
    fontSize: '0.75rem',
    color: 'var(--color-text-secondary)',
  },
  cardFooter: {
    borderTop: '1px solid var(--color-surface-light)',
    paddingTop: '6px',
  },
  costText: {
    fontSize: '0.8rem',
    fontWeight: 600,
    color: 'var(--color-primary)',
  },
};
