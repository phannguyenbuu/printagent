import { useCallback, useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';

import { PullToRefresh } from '../components/layout/PullToRefresh';
import { RequestCard } from '../components/requests/RequestCard';
import { RequestLocationBlock } from '../components/requests/RequestLocationBlock';
import { AnimatedList } from '../components/ui/AnimatedList';
import { EmptyState, PageLoading } from '../components/ui/PageState';
import { GlowCard } from '../components/ui/GlowCard';
import { filterHistory } from '../services/historyService';
import { calculateCumulativeCost } from '../services/statsService';
import { useLocationStore } from '../stores/locationStore';
import { useRepairStore } from '../stores/repairStore';
import type { HistoryFilters } from '../types/history';

function formatDate(value: string | null | undefined): string {
  if (!value) return '—';
  return new Date(value).toLocaleDateString('vi-VN', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
  });
}

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
  }, [fetchLocations, fetchRequests]);

  const locationMap = useMemo(
    () => new Map(locations.map((location) => [location.id, location])),
    [locations],
  );

  const filteredHistory = useMemo(() => {
    const allCompleted = requests
      .filter((request) => request.status === 'completed')
      .sort((a, b) => {
        const dateA = a.completedAt ?? '';
        const dateB = b.completedAt ?? '';
        return dateB.localeCompare(dateA);
      });

    const allHistory = allCompleted.map((request) => ({
      repairRequest: request,
      totalMaterialCost: request.materials.reduce(
        (sum, material) => sum + material.quantity * material.unitPrice,
        0,
      ),
    }));

    const filters: HistoryFilters = {};
    if (dateFrom) filters.dateFrom = dateFrom;
    if (dateTo) filters.dateTo = dateTo;
    if (locationFilter) filters.locationId = locationFilter;
    if (machineNameFilter) filters.machineName = machineNameFilter;

    return filterHistory(allHistory, filters);
  }, [dateFrom, dateTo, locationFilter, machineNameFilter, requests]);

  const cumulativeCost = useMemo(() => {
    if (machineNameFilter) {
      return calculateCumulativeCost(requests, machineNameFilter);
    }

    return filteredHistory.reduce(
      (sum, entry) => sum + entry.totalMaterialCost,
      0,
    );
  }, [filteredHistory, machineNameFilter, requests]);

  const handleRefresh = useCallback(async () => {
    await fetchRequests();
  }, [fetchRequests]);

  const formatCurrency = (value: number) => `${value.toLocaleString('vi-VN')} đ`;

  if (loading && requests.length === 0) {
    return <PageLoading message="Đang tải lịch sử sửa chữa..." />;
  }

  return (
    <motion.div
      style={styles.container}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: [0.4, 0, 0.2, 1] }}
    >
      <div style={styles.header}>
        <h1 style={styles.title}>Lịch sử sửa chữa</h1>
      </div>

      <GlowCard>
        <div style={styles.costSection}>
          <span style={styles.costLabel}>Tổng chi phí tích lũy</span>
          <span style={styles.costValue}>{formatCurrency(cumulativeCost)}</span>
        </div>
      </GlowCard>

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
            {locations.map((location) => (
              <option key={location.id} value={location.id}>
                {location.name}
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

      <PullToRefresh onRefresh={handleRefresh}>
        {filteredHistory.length === 0 ? (
          <EmptyState message="Không có lịch sử sửa chữa nào." centered />
        ) : (
          <AnimatedList>
            {filteredHistory.map((entry) => {
              const request = entry.repairRequest;
              const location = locationMap.get(request.locationId);
              return (
                <RequestCard
                  key={request.id}
                  request={request}
                  status="completed"
                  onClick={() => navigate(`/requests/${request.id}`)}
                  showWorkspace={false}
                  showPriority={false}
                  locationContent={
                    <RequestLocationBlock
                      location={location}
                      fallbackLabel={`📍 ${request.locationId}`}
                      showAddress={false}
                      showPhone={false}
                    />
                  }
                  description={request.description}
                  footer={
                    <>
                      <span style={styles.costText}>Chi phí vật tư: {formatCurrency(entry.totalMaterialCost)}</span>
                      <span style={styles.dateText}>{formatDate(request.completedAt)}</span>
                    </>
                  }
                />
              );
            })}
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
    appearance: 'auto',
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
  costText: {
    fontSize: '0.8rem',
    fontWeight: 600,
    color: 'var(--color-primary)',
  },
  dateText: {
    fontSize: '0.75rem',
    color: 'var(--color-text-secondary)',
  },
};
