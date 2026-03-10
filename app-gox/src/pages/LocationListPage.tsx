import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { useLocationStore } from '../stores/locationStore';
import { useAuthStore } from '../stores/authStore';
import { getAccessibleLocations } from '../services/accessControl';
import { GlowCard } from '../components/ui/GlowCard';
import { AnimatedList } from '../components/ui/AnimatedList';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { WorkspaceBadge } from '../components/ui/WorkspaceBadge';
import { AnimatedButton } from '../components/ui/AnimatedButton';
import { mockAddLocation, mockUpdateLocation, mockDeleteLocation } from '../api/mockApi';
import type { Location } from '../types/location';

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

  // CRUD state
  const [modal, setModal] = useState<'add' | 'edit' | 'delete' | null>(null);
  const [selectedLoc, setSelectedLoc] = useState<Location | null>(null);
  const [locName, setLocName] = useState('');
  const [locAddress, setLocAddress] = useState('');
  const [locPhone, setLocPhone] = useState('');
  const [locWorkspace, setLocWorkspace] = useState('');
  const [actionLoading, setActionLoading] = useState(false);

  useEffect(() => {
    fetchLocations();
  }, [fetchLocations]);

  const accessibleLocations = useMemo(() => {
    if (!user) return [];
    return getAccessibleLocations(user, locations);
  }, [user, locations]);

  const filteredLocations = useMemo(() => {
    const q = removeDiacritics(searchQuery.trim());
    const base = searchQuery.trim() ? accessibleLocations.filter((loc) => {
      const name = removeDiacritics(loc.name);
      const address = removeDiacritics(loc.address);
      const phone = removeDiacritics(loc.phone ?? '');
      return name.includes(q) || address.includes(q) || phone.includes(q);
    }) : accessibleLocations;
    return base;
  }, [accessibleLocations, searchQuery]);

  const openAdd = () => {
    setLocName(''); setLocAddress(''); setLocPhone(''); setLocWorkspace('ws-1');
    setModal('add');
  };

  const openEdit = (loc: Location, e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedLoc(loc);
    setLocName(loc.name);
    setLocAddress(loc.address);
    setLocPhone(loc.phone ?? '');
    setLocWorkspace(loc.workspaceId);
    setModal('edit');
  };

  const openDelete = (loc: Location, e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedLoc(loc);
    setModal('delete');
  };

  const handleAdd = async () => {
    if (!locName.trim()) return;
    setActionLoading(true);
    await mockAddLocation({ name: locName, address: locAddress, phone: locPhone, workspace_id: locWorkspace });
    setActionLoading(false);
    setModal(null);
    fetchLocations();
  };

  const handleUpdate = async () => {
    if (!selectedLoc || !locName.trim()) return;
    setActionLoading(true);
    await mockUpdateLocation(selectedLoc.id, { name: locName, address: locAddress, phone: locPhone, workspaceId: locWorkspace });
    setActionLoading(false);
    setModal(null);
    fetchLocations();
  };

  const handleDelete = async () => {
    if (!selectedLoc) return;
    setActionLoading(true);
    await mockDeleteLocation(selectedLoc.id);
    setActionLoading(false);
    setModal(null);
    fetchLocations();
  };

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
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h1 style={styles.title}>Địa điểm</h1>
            <p style={styles.subtitle}>
              {filteredLocations.length} / {accessibleLocations.length} địa điểm
            </p>
          </div>
          <button style={styles.addBtn} onClick={openAdd}>➕ Thêm</button>
        </div>
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
          {searchQuery.trim() ? 'Không tìm thấy địa điểm nào.' : 'Chưa có địa điểm nào.'}
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
                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                  <span style={styles.machineCount}>🖥 {loc.machineCount}</span>
                  <button style={styles.iconBtn} onClick={(e) => openEdit(loc, e)}>✏️</button>
                  <button style={{ ...styles.iconBtn, color: 'var(--color-error)' }} onClick={(e) => openDelete(loc, e)}>🗑️</button>
                </div>
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

      {/* Modals */}
      <AnimatePresence>
        {modal && (
          <div style={styles.overlay} onClick={() => setModal(null)}>
            <motion.div
              style={styles.modal}
              onClick={(e) => e.stopPropagation()}
              initial={{ opacity: 0, scale: 0.9, y: 20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.9, y: 20 }}
            >
              <h3 style={styles.modalTitle}>
                {modal === 'add' ? 'Thêm địa điểm mới' : modal === 'edit' ? 'Chỉnh sửa địa điểm' : 'Xác nhận xóa'}
              </h3>

              {modal === 'delete' ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  <p style={{ fontSize: '0.9rem', color: 'var(--color-text)', margin: 0 }}>
                    Bạn có chắc chắn muốn xóa địa điểm <strong>{selectedLoc?.name}</strong>?
                  </p>
                  <div style={styles.modalActions}>
                    <AnimatedButton onClick={handleDelete} disabled={actionLoading}>
                      {actionLoading ? 'Đang xóa...' : 'Xác nhận xóa'}
                    </AnimatedButton>
                    <AnimatedButton variant="secondary" onClick={() => setModal(null)}>Hủy</AnimatedButton>
                  </div>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  <div style={styles.field}>
                    <label style={styles.label}>Tên địa điểm *</label>
                    <input type="text" value={locName} onChange={(e) => setLocName(e.target.value)}
                      placeholder="VD: Nhà máy Bắc Ninh" style={styles.input} />
                  </div>
                  <div style={styles.field}>
                    <label style={styles.label}>Địa chỉ</label>
                    <input type="text" value={locAddress} onChange={(e) => setLocAddress(e.target.value)}
                      placeholder="VD: 123 Đường Lý Thái Tổ..." style={styles.input} />
                  </div>
                  <div style={styles.field}>
                    <label style={styles.label}>Số điện thoại</label>
                    <input type="text" value={locPhone} onChange={(e) => setLocPhone(e.target.value)}
                      placeholder="VD: 0222-3456-789" style={styles.input} />
                  </div>
                  <div style={styles.field}>
                    <label style={styles.label}>Workspace</label>
                    <select value={locWorkspace} onChange={(e) => setLocWorkspace(e.target.value)} style={styles.input}>
                      <option value="ws-1">Gox Print</option>
                      <option value="ws-2">Kỹ thuật VN</option>
                      <option value="ws-3">Hòa Phát</option>
                    </select>
                  </div>
                  <div style={styles.modalActions}>
                    <AnimatedButton onClick={modal === 'add' ? handleAdd : handleUpdate} disabled={actionLoading}>
                      {actionLoading ? 'Đang xử lý...' : modal === 'add' ? 'Thêm' : 'Cập nhật'}
                    </AnimatedButton>
                    <AnimatedButton variant="secondary" onClick={() => setModal(null)}>Hủy</AnimatedButton>
                  </div>
                </div>
              )}
            </motion.div>
          </div>
        )}
      </AnimatePresence>
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
  addBtn: {
    background: 'color-mix(in srgb, var(--color-primary) 10%, var(--color-surface))',
    color: 'var(--color-primary)',
    border: '1px solid var(--color-primary)',
    borderRadius: '8px',
    padding: '6px 14px',
    fontSize: '0.85rem',
    fontWeight: 600,
    cursor: 'pointer',
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
  iconBtn: {
    background: 'none', border: 'none', cursor: 'pointer', fontSize: '1rem', padding: '4px',
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
  overlay: {
    position: 'fixed' as const, inset: 0, zIndex: 1000,
    background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)',
    display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '20px',
  },
  modal: {
    width: '100%', maxWidth: '420px', background: 'var(--color-surface)',
    borderRadius: '16px', padding: '24px', display: 'flex', flexDirection: 'column' as const, gap: '16px',
    border: '1px solid var(--color-surface-light)',
  },
  modalTitle: { fontSize: '1.1rem', fontWeight: 700, color: 'var(--color-text)', margin: 0 },
  field: { display: 'flex', flexDirection: 'column' as const, gap: '6px' },
  label: { fontSize: '0.85rem', color: 'var(--color-text-secondary)', fontWeight: 500 },
  input: {
    background: 'var(--color-bg)', color: 'var(--color-text)',
    border: '1px solid var(--color-surface-light)', borderRadius: '10px',
    padding: '12px', fontSize: '0.95rem', outline: 'none',
  },
  modalActions: { display: 'flex', gap: '12px', marginTop: '8px' },
};
