import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useLocationStore } from '../stores/locationStore';
import { useAuthStore } from '../stores/authStore';
import { getAccessibleLocations } from '../services/accessControl';
import { GlowCard } from '../components/ui/GlowCard';
import { AnimatedList } from '../components/ui/AnimatedList';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { WorkspaceBadge } from '../components/ui/WorkspaceBadge';

function removeDiacritics(str: string): string {
  return str
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/đ/g, 'd')
    .replace(/Đ/g, 'D')
    .toLowerCase();
}

export function LocationListPage() {
  const navigate = useNavigate();
  const user = useAuthStore((s) => s.user);
  const { locations, loading, fetchLocations } = useLocationStore();
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    fetchLocations();
  }, [fetchLocations]);

  const accessibleLocations = useMemo(() => {
    if (!user) return [];
    return getAccessibleLocations(user, locations);
  }, [user, locations]);

  const filteredLocations = useMemo(() => {
    if (!searchQuery.trim()) return [];
    const q = removeDiacritics(searchQuery.trim());
    return accessibleLocations.filter((loc) => {
      const name = removeDiacritics(loc.name);
      const address = removeDiacritics(loc.address);
      const phone = removeDiacritics(loc.phone ?? '');
      return name.includes(q) || address.includes(q) || phone.includes(q);
    });
  }, [accessibleLocations, searchQuery]);

  if (loading && locations.length === 0) {
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
        <h1 style={styles.title}>Địa điểm</h1>
        <p style={styles.subtitle}>
          {filteredLocations.length} / {accessibleLocations.length} địa điểm
        </p>
      </div>

      {/* Search */}
      <input
        type="text"
        value={searchQuery}
        onChange={(e) => setSearchQuery(e.target.value)}
        placeholder="🔍 Tìm theo tên, địa chỉ, SĐT..."
        style={styles.searchInput}
        aria-label="Tìm kiếm địa điểm"
      />

      {filteredLocations.length === 0 ? (
        <p style={styles.emptyText}>
          {searchQuery.trim() ? 'Không tìm thấy địa điểm nào.' : 'Nhập từ khóa để tìm kiếm địa điểm.'}
        </p>
      ) : (
        <AnimatedList>
          {filteredLocations.map((loc) => (
            <GlowCard
              key={loc.id}
              onClick={() => navigate(`/locations/${loc.id}`)}
            >
              <div style={styles.cardHeader}>
                <span style={styles.locationName}>{loc.name}</span>
                <span style={styles.machineCount}>
                  🖥 {loc.machineCount} máy
                </span>
              </div>
              <WorkspaceBadge workspaceId={loc.workspaceId} />
              <p style={styles.address}>📍 {loc.address}</p>
              {loc.phone && (
                <p style={styles.phone}>📞 {loc.phone}</p>
              )}
            </GlowCard>
          ))}
        </AnimatedList>
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
  locationName: {
    fontSize: '0.95rem',
    fontWeight: 600,
    color: 'var(--color-text)',
  },
  machineCount: {
    fontSize: '0.8rem',
    color: 'var(--color-primary)',
    fontWeight: 600,
  },
  address: {
    fontSize: '0.8rem',
    color: 'var(--color-text-secondary)',
    margin: 0,
    lineHeight: 1.4,
  },
  phone: {
    fontSize: '0.8rem',
    color: 'var(--color-primary)',
    margin: '4px 0 0',
  },
};
