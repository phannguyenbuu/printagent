import { useEffect, useMemo, useCallback, useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useRepairStore } from '../stores/repairStore';
import { useAuthStore } from '../stores/authStore';
import { useLocationStore } from '../stores/locationStore';
import { filterRequests } from '../services/filterService';
import { mockGetUserName } from '../api/mockApi';
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

// Status sort order: new & in_progress first
const STATUS_SORT_ORDER: Record<RepairStatus, number> = {
  new: 0,
  in_progress: 1,
  accepted: 2,
  completed: 3,
  cancelled: 4,
};

function removeDiacritics(str: string): string {
  return str
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/đ/g, 'd')
    .replace(/Đ/g, 'D')
    .toLowerCase();
}

export function RequestListPage() {
  const navigate = useNavigate();
  const user = useAuthStore((s) => s.user);
  const { requests, loading, fetchRequests, filters, setFilters } = useRepairStore();
  const { locations, fetchLocations } = useLocationStore();

  const [statusFilter, setStatusFilter] = useState<RepairStatus | ''>('');
  const [locationFilter, setLocationFilter] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState('');
  const [locationSearchQuery, setLocationSearchQuery] = useState('');
  const [showLocationDropdown, setShowLocationDropdown] = useState(false);
  const locationPickerRef = useRef<HTMLDivElement>(null);

  // Close location dropdown on outside click
  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (locationPickerRef.current && !locationPickerRef.current.contains(e.target as Node)) {
        setShowLocationDropdown(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  useEffect(() => {
    fetchRequests();
    fetchLocations();
  }, [fetchRequests, fetchLocations]);

  useEffect(() => {
    const newFilters: typeof filters = {};
    if (statusFilter) newFilters.status = statusFilter;
    if (locationFilter) newFilters.locationId = locationFilter;
    setFilters(newFilters);
  }, [statusFilter, locationFilter, setFilters]);

  const filteredLocations = useMemo(() => {
    if (!locationSearchQuery.trim()) return locations;
    const q = removeDiacritics(locationSearchQuery.trim());
    return locations.filter((loc) => {
      const name = removeDiacritics(loc.name);
      const addr = removeDiacritics(loc.address);
      const phone = loc.phone ? removeDiacritics(loc.phone) : '';
      return name.includes(q) || addr.includes(q) || phone.includes(q);
    });
  }, [locations, locationSearchQuery]);

  const filteredAndSortedRequests = useMemo(() => {
    const activeFilters: { status?: RepairStatus; locationId?: string } = {};
    if (statusFilter) activeFilters.status = statusFilter;
    if (locationFilter) activeFilters.locationId = locationFilter;

    let filtered = filterRequests(requests, activeFilters);

    // Text search
    if (searchQuery.trim()) {
      const q = removeDiacritics(searchQuery.trim());
      filtered = filtered.filter((req) => {
        const machine = removeDiacritics(req.machineName);
        const desc = removeDiacritics(req.description);
        const note = removeDiacritics(req.note ?? '');
        const assignee = req.assignedTo ? removeDiacritics(mockGetUserName(req.assignedTo)) : '';
        return machine.includes(q) || desc.includes(q) || note.includes(q) || assignee.includes(q);
      });
    }

    // Sort: status priority first, then by createdAt desc within same status group
    return [...filtered].sort((a, b) => {
      const statusDiff = STATUS_SORT_ORDER[a.status] - STATUS_SORT_ORDER[b.status];
      if (statusDiff !== 0) return statusDiff;
      return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
    });
  }, [requests, statusFilter, locationFilter, searchQuery]);

  const handleRefresh = useCallback(async () => {
    await fetchRequests();
  }, [fetchRequests]);

  const canCreateRequest = user?.role === 'supplier' || user?.role === 'technician';

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
      <div style={styles.header}>
        <h1 style={styles.title}>Yêu cầu sửa chữa</h1>
      </div>

      {/* Search */}
      <input
        type="text"
        value={searchQuery}
        onChange={(e) => setSearchQuery(e.target.value)}
        placeholder="🔍 Tìm theo tên máy, mô tả, người nhận..."
        style={styles.searchInput}
        aria-label="Tìm kiếm yêu cầu"
      />

      {/* Filter Bar */}
      <div style={styles.filterBar}>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value as RepairStatus | '')}
          style={styles.select}
          aria-label="Lọc theo trạng thái"
        >
          <option value="">Tất cả trạng thái</option>
          {ALL_STATUSES.map((s) => (
            <option key={s} value={s}>{STATUS_LABELS[s]}</option>
          ))}
        </select>
        <div ref={locationPickerRef} style={{ flex: 1, position: 'relative' }}>
          <input
            type="text"
            value={locationSearchQuery}
            onChange={(e) => {
              setLocationSearchQuery(e.target.value);
              setShowLocationDropdown(true);
              if (!e.target.value.trim()) {
                setLocationFilter('');
              }
            }}
            onFocus={() => setShowLocationDropdown(true)}
            placeholder={locationFilter ? locations.find((l) => l.id === locationFilter)?.name ?? 'Tất cả địa điểm' : '📍 Tất cả địa điểm'}
            style={styles.select}
            aria-label="Lọc theo địa điểm"
            autoComplete="off"
          />
          {showLocationDropdown && (
            <div style={styles.locationDropdown}>
              <div
                style={{
                  ...styles.locationDropdownItem,
                  background: !locationFilter ? 'rgba(0, 212, 255, 0.1)' : 'transparent',
                }}
                onClick={() => {
                  setLocationFilter('');
                  setLocationSearchQuery('');
                  setShowLocationDropdown(false);
                }}
              >
                <span style={{ fontSize: '0.85rem', color: 'var(--color-primary)' }}>Tất cả địa điểm</span>
              </div>
              {filteredLocations.map((loc) => (
                <div
                  key={loc.id}
                  style={{
                    ...styles.locationDropdownItem,
                    background: locationFilter === loc.id ? 'rgba(0, 212, 255, 0.1)' : 'transparent',
                  }}
                  onClick={() => {
                    setLocationFilter(loc.id);
                    setLocationSearchQuery(loc.name);
                    setShowLocationDropdown(false);
                  }}
                >
                  <div style={{ fontSize: '0.85rem', color: 'var(--color-text)', fontWeight: 500 }}>{loc.name}</div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--color-text-secondary)' }}>
                    {loc.address}{loc.phone ? ` · ${loc.phone}` : ''}
                  </div>
                </div>
              ))}
              {filteredLocations.length === 0 && (
                <div style={styles.locationDropdownItem}>
                  <span style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)' }}>Không tìm thấy</span>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      <PullToRefresh onRefresh={handleRefresh}>
        {filteredAndSortedRequests.length === 0 ? (
          <p style={styles.emptyText}>Không có yêu cầu sửa chữa nào.</p>
        ) : (
          <AnimatedList>
            {filteredAndSortedRequests.map((req) => (
              <GlowCard key={req.id} onClick={() => navigate(`/requests/${req.id}`)}>
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
                {/* Location info */}
                {(() => {
                  const loc = locations.find((l) => l.id === req.locationId);
                  return loc ? (
                    <div style={styles.locationInfo}>
                      <span style={styles.locationName}>📍 {loc.name}</span>
                      {loc.address && <span style={styles.locationDetail}>{loc.address}</span>}
                      {loc.phone && <span style={styles.locationDetail}>📞 {loc.phone}</span>}
                    </div>
                  ) : (
                    <span style={styles.locationDetail}>📍 {req.locationId}</span>
                  );
                })()}
                <p style={styles.description}>
                  {req.description.length > 80 ? `${req.description.slice(0, 80)}…` : req.description}
                </p>
                <div style={styles.cardFooter}>
                  <span style={styles.dateText}>
                    {new Date(req.createdAt).toLocaleDateString('vi-VN', {
                      day: '2-digit', month: '2-digit', year: 'numeric',
                      hour: '2-digit', minute: '2-digit',
                    })}
                  </span>
                  {req.assignedTo && (
                    <span style={styles.assigneeText}>👤 {mockGetUserName(req.assignedTo)}</span>
                  )}
                </div>
              </GlowCard>
            ))}
          </AnimatedList>
        )}
      </PullToRefresh>

      {canCreateRequest && (
        <motion.button
          style={styles.fab}
          onClick={() => navigate('/requests/new')}
          whileHover={{ scale: 1.1, boxShadow: '0 0 30px rgba(0, 212, 255, 0.5)' }}
          whileTap={{ scale: 0.95 }}
          initial={{ scale: 0, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ delay: 0.3, type: 'spring', stiffness: 260, damping: 20 }}
          aria-label="Tạo yêu cầu mới"
        >
          +
        </motion.button>
      )}
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
  header: { marginBottom: '4px' },
  title: {
    fontSize: '1.5rem',
    fontWeight: 700,
    color: 'var(--color-primary)',
    margin: 0,
  },
  searchInput: {
    background: 'var(--color-surface)',
    color: 'var(--color-text)',
    border: '1px solid var(--color-surface-light)',
    borderRadius: '10px',
    padding: '12px 14px',
    fontSize: '0.9rem',
    width: '100%',
    boxSizing: 'border-box' as const,
    outline: 'none',
  },
  filterBar: { display: 'flex', gap: '8px' },
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
  cardFooter: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  assigneeText: {
    fontSize: '0.75rem',
    color: 'var(--color-secondary)',
    fontWeight: 500,
  },
  locationInfo: {
    display: 'flex',
    flexDirection: 'column',
    gap: '2px',
    marginBottom: '6px',
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
  locationDropdown: {
    position: 'absolute' as const,
    top: '100%',
    left: 0,
    right: 0,
    background: 'var(--color-surface, #12121a)',
    border: '1px solid var(--color-surface-light)',
    borderRadius: '0 0 8px 8px',
    maxHeight: '200px',
    overflowY: 'auto' as const,
    zIndex: 20,
  },
  locationDropdownItem: {
    padding: '8px 12px',
    cursor: 'pointer',
    borderBottom: '1px solid var(--color-surface-light)',
  },
  fab: {
    position: 'fixed',
    bottom: '90px',
    right: '20px',
    width: '56px',
    height: '56px',
    borderRadius: '50%',
    background: 'var(--color-primary)',
    color: '#0a0a0f',
    border: 'none',
    fontSize: '1.8rem',
    fontWeight: 700,
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    boxShadow: '0 0 20px rgba(0, 212, 255, 0.4)',
    zIndex: 10,
  },
};
