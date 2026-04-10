import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';

import { mockGetUserName } from '../api/mockApi';
import { PullToRefresh } from '../components/layout/PullToRefresh';
import { RequestCard } from '../components/requests/RequestCard';
import { RequestLocationBlock } from '../components/requests/RequestLocationBlock';
import { ALL_STATUSES, STATUS_LABELS, STATUS_SORT_ORDER } from '../components/requests/repairVisuals';
import { AnimatedList } from '../components/ui/AnimatedList';
import { EmptyState, PageLoading } from '../components/ui/PageState';
import { filterRequests } from '../services/filterService';
import { useAuthStore } from '../stores/authStore';
import { useLocationStore } from '../stores/locationStore';
import { useRepairStore } from '../stores/repairStore';
import type { RepairStatus } from '../types/repair';

function removeDiacritics(str: string): string {
  return str
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/đ/g, 'd')
    .replace(/Đ/g, 'D')
    .toLowerCase();
}

function formatDateTime(value: string): string {
  return new Date(value).toLocaleDateString('vi-VN', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function RequestListPage() {
  const navigate = useNavigate();
  const user = useAuthStore((s) => s.user);
  const { requests, loading, fetchRequests, setFilters } = useRepairStore();
  const { locations, fetchLocations } = useLocationStore();

  const [statusFilter, setStatusFilter] = useState<RepairStatus | ''>('');
  const [locationFilter, setLocationFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [locationSearchQuery, setLocationSearchQuery] = useState('');
  const [showLocationDropdown, setShowLocationDropdown] = useState(false);
  const locationPickerRef = useRef<HTMLDivElement>(null);

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
    const nextFilters: { status?: RepairStatus; locationId?: string } = {};
    if (statusFilter) nextFilters.status = statusFilter;
    if (locationFilter) nextFilters.locationId = locationFilter;
    setFilters(nextFilters);
  }, [locationFilter, setFilters, statusFilter]);

  const locationMap = useMemo(
    () => new Map(locations.map((location) => [location.id, location])),
    [locations],
  );

  const filteredLocations = useMemo(() => {
    if (!locationSearchQuery.trim()) return locations;

    const query = removeDiacritics(locationSearchQuery.trim());
    return locations.filter((location) => {
      const name = removeDiacritics(location.name);
      const address = removeDiacritics(location.address);
      const phone = location.phone ? removeDiacritics(location.phone) : '';
      return name.includes(query) || address.includes(query) || phone.includes(query);
    });
  }, [locationSearchQuery, locations]);

  const filteredAndSortedRequests = useMemo(() => {
    const activeFilters: { status?: RepairStatus; locationId?: string } = {};
    if (statusFilter) activeFilters.status = statusFilter;
    if (locationFilter) activeFilters.locationId = locationFilter;

    let filtered = filterRequests(requests, activeFilters);

    if (user && user.role !== 'admin') {
      filtered = filtered.filter((request) => {
        if (user.role === 'technician') {
          return request.assignedTo === user.id || (request.status === 'new' && !request.assignedTo);
        }
        if (user.role === 'supplier') {
          return request.createdBy === user.id;
        }
        return true;
      });
    }

    if (searchQuery.trim()) {
      const query = removeDiacritics(searchQuery.trim());
      filtered = filtered.filter((request) => {
        const machine = removeDiacritics(request.machineName);
        const description = removeDiacritics(request.description);
        const note = removeDiacritics(request.note ?? '');
        const assignee = request.assignedTo ? removeDiacritics(mockGetUserName(request.assignedTo)) : '';
        return machine.includes(query) || description.includes(query) || note.includes(query) || assignee.includes(query);
      });
    }

    return [...filtered].sort((a, b) => {
      const statusDiff = STATUS_SORT_ORDER[a.status] - STATUS_SORT_ORDER[b.status];
      if (statusDiff !== 0) return statusDiff;
      return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
    });
  }, [locationFilter, requests, searchQuery, statusFilter, user]);

  const handleRefresh = useCallback(async () => {
    await fetchRequests();
  }, [fetchRequests]);

  const canCreateRequest = user?.role === 'supplier' || user?.role === 'technician';

  if (loading && requests.length === 0) {
    return <PageLoading message="Đang tải yêu cầu..." />;
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

      <input
        type="text"
        value={searchQuery}
        onChange={(e) => setSearchQuery(e.target.value)}
        placeholder="🔍 Tìm theo tên máy, mô tả, người nhận..."
        style={styles.searchInput}
        aria-label="Tìm kiếm yêu cầu"
      />

      <div style={styles.filterBar}>
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value as RepairStatus | '')}
          style={styles.select}
          aria-label="Lọc theo trạng thái"
        >
          <option value="">Tất cả trạng thái</option>
          {ALL_STATUSES.map((status) => (
            <option key={status} value={status}>{STATUS_LABELS[status]}</option>
          ))}
        </select>

        <div ref={locationPickerRef} style={styles.locationPicker}>
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
            placeholder={
              locationFilter
                ? locations.find((location) => location.id === locationFilter)?.name ?? 'Tất cả địa điểm'
                : '📍 Tất cả địa điểm'
            }
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
                <span style={styles.locationDropdownPrimary}>Tất cả địa điểm</span>
              </div>

              {filteredLocations.map((location) => (
                <div
                  key={location.id}
                  style={{
                    ...styles.locationDropdownItem,
                    background: locationFilter === location.id ? 'rgba(0, 212, 255, 0.1)' : 'transparent',
                  }}
                  onClick={() => {
                    setLocationFilter(location.id);
                    setLocationSearchQuery(location.name);
                    setShowLocationDropdown(false);
                  }}
                >
                  <div style={styles.locationDropdownName}>{location.name}</div>
                  <div style={styles.locationDropdownMeta}>
                    {location.address}
                    {location.phone ? ` · ${location.phone}` : ''}
                  </div>
                </div>
              ))}

              {filteredLocations.length === 0 && (
                <div style={styles.locationDropdownItem}>
                  <span style={styles.locationDropdownEmpty}>Không tìm thấy</span>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      <PullToRefresh onRefresh={handleRefresh}>
        {filteredAndSortedRequests.length === 0 ? (
          <EmptyState message="Không có yêu cầu sửa chữa nào." centered />
        ) : (
          <AnimatedList>
            {filteredAndSortedRequests.map((request) => {
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
                  description={request.description}
                  footer={
                    <>
                      <span style={styles.dateText}>{formatDateTime(request.createdAt)}</span>
                      {request.assignedTo && (
                        <span style={styles.assigneeText}>👤 {mockGetUserName(request.assignedTo)}</span>
                      )}
                    </>
                  }
                />
              );
            })}
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
  header: {
    marginBottom: '4px',
  },
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
    boxSizing: 'border-box',
    outline: 'none',
  },
  filterBar: {
    display: 'flex',
    gap: '8px',
  },
  locationPicker: {
    flex: 1,
    position: 'relative',
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
    width: '100%',
    boxSizing: 'border-box',
  },
  dateText: {
    fontSize: '0.75rem',
    color: 'var(--color-text-secondary)',
  },
  assigneeText: {
    fontSize: '0.75rem',
    color: 'var(--color-secondary)',
    fontWeight: 500,
  },
  locationDropdown: {
    position: 'absolute',
    top: '100%',
    left: 0,
    right: 0,
    background: 'var(--color-surface, #12121a)',
    border: '1px solid var(--color-surface-light)',
    borderRadius: '0 0 8px 8px',
    maxHeight: '200px',
    overflowY: 'auto',
    zIndex: 20,
  },
  locationDropdownItem: {
    padding: '8px 12px',
    cursor: 'pointer',
    borderBottom: '1px solid var(--color-surface-light)',
  },
  locationDropdownPrimary: {
    fontSize: '0.85rem',
    color: 'var(--color-primary)',
  },
  locationDropdownName: {
    fontSize: '0.85rem',
    color: 'var(--color-text)',
    fontWeight: 500,
  },
  locationDropdownMeta: {
    fontSize: '0.7rem',
    color: 'var(--color-text-secondary)',
  },
  locationDropdownEmpty: {
    fontSize: '0.8rem',
    color: 'var(--color-text-secondary)',
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
