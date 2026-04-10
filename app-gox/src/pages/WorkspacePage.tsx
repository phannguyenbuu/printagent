import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { useAuthStore } from '../stores/authStore';
import { useWorkspaceStore } from '../stores/workspaceStore';
import { AnimatedButton } from '../components/ui/AnimatedButton';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';

const PRESET_COLORS = [
  '#2196F3', '#1976D2', '#0D47A1',
  '#4CAF50', '#388E3C', '#1B5E20',
  '#FF9800', '#F57C00', '#E65100',
  '#F44336', '#D32F2F', '#B71C1C',
  '#9C27B0', '#7B1FA2', '#4A148C',
  '#00BCD4', '#0097A7', '#006064',
  '#795548', '#5D4037', '#3E2723',
  '#607D8B', '#455A64', '#263238',
];

export function WorkspacePage() {
  const user = useAuthStore((s) => s.user);
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const checkSession = useAuthStore((s) => s.checkSession);
  const logout = useAuthStore((s) => s.logout);
  const { workspaces, activeIds, loading, fetchWorkspaces, toggleWorkspace, setActiveIds, setWorkspaceColor } = useWorkspaceStore();
  const navigate = useNavigate();
  const [colorPickerWsId, setColorPickerWsId] = useState<string | null>(null);

  useEffect(() => { checkSession(); }, [checkSession]);

  useEffect(() => {
    if (!isAuthenticated) {
      navigate('/login', { replace: true });
    }
  }, [isAuthenticated, navigate]);

  useEffect(() => {
    if (user) {
      fetchWorkspaces(user.workspaceIds || []);
    }
  }, [user, fetchWorkspaces]);

  // Auto-enter if only 1 workspace
  useEffect(() => {
    if (!loading && workspaces.length === 1 && activeIds.length === 0) {
      setActiveIds([workspaces[0].id]);
      navigate('/dashboard', { replace: true });
    }
  }, [loading, workspaces, activeIds, setActiveIds, navigate]);

  const handleConfirm = () => {
    if (activeIds.length > 0) {
      navigate('/dashboard', { replace: true });
    }
  };

  const handleSelectAll = () => {
    if (activeIds.length === workspaces.length) {
      setActiveIds([]);
    } else {
      setActiveIds(workspaces.map((ws) => ws.id));
    }
  };

  if (loading) {
    return <div style={styles.loadingContainer}><LoadingSpinner size="lg" /></div>;
  }

  const allSelected = activeIds.length === workspaces.length;

  return (
    <motion.div style={styles.container}
      initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}>
      <div style={styles.header}>
        <h1 style={styles.title}>Chọn Workspace</h1>
        <p style={styles.subtitle}>Xin chào, {user?.fullName}</p>
        <p style={styles.hint}>Chọn một hoặc nhiều công ty để làm việc đồng thời</p>
      </div>

      {/* Select all */}
      {workspaces.length > 1 && (
        <button style={styles.selectAllBtn} onClick={handleSelectAll}>
          <span style={{
            ...styles.checkbox,
            background: allSelected ? 'var(--color-primary)' : 'transparent',
            borderColor: allSelected ? 'var(--color-primary)' : 'var(--color-surface-light)',
          }}>
            {allSelected && '✓'}
          </span>
          <span style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)' }}>Chọn tất cả</span>
        </button>
      )}

      <div style={styles.list}>
        {workspaces.map((ws) => {
          const checked = activeIds.includes(ws.id);
          return (
            <div key={ws.id}>
            <motion.button
              style={{
                ...styles.card,
                borderColor: checked ? (ws.color || 'var(--color-primary)') : 'var(--color-surface-light)',
                borderLeftColor: ws.color || 'var(--color-primary)',
                borderLeftWidth: '4px',
                background: checked
                  ? `${ws.color || 'var(--color-primary)'}0d`
                  : 'var(--color-surface)',
              }}
              whileTap={{ scale: 0.97 }}
              onClick={() => toggleWorkspace(ws.id)}
            >
              <span style={{
                ...styles.checkbox,
                background: checked ? (ws.color || 'var(--color-primary)') : 'transparent',
                borderColor: checked ? (ws.color || 'var(--color-primary)') : 'var(--color-surface-light)',
              }}>
                {checked && '✓'}
              </span>
              <span style={styles.logo}>{ws.logo || '🏢'}</span>
              <div style={styles.cardInfo}>
                <span style={styles.cardName}>{ws.name}</span>
                {ws.address && <span style={styles.cardAddr}>{ws.address}</span>}
              </div>
              <button
                style={{
                  ...styles.colorDot,
                  background: ws.color || '#888',
                }}
                onClick={(e) => {
                  e.stopPropagation();
                  setColorPickerWsId(colorPickerWsId === ws.id ? null : ws.id);
                }}
                aria-label="Chọn màu"
                title="Chọn màu"
              />
            </motion.button>
            <AnimatePresence>
              {colorPickerWsId === ws.id && (
                <motion.div
                  style={styles.colorPalette}
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  transition={{ duration: 0.2 }}
                >
                  {PRESET_COLORS.map((c) => (
                    <button
                      key={c}
                      style={{
                        ...styles.colorSwatch,
                        background: c,
                        outline: ws.color === c ? '2px solid var(--color-text)' : 'none',
                        outlineOffset: '2px',
                      }}
                      onClick={() => {
                        setWorkspaceColor(ws.id, c);
                        setColorPickerWsId(null);
                      }}
                      aria-label={`Màu ${c}`}
                    />
                  ))}
                </motion.div>
              )}
            </AnimatePresence>
            </div>
          );
        })}
      </div>

      <div style={styles.actions}>
        <AnimatedButton onClick={handleConfirm} disabled={activeIds.length === 0}>
          Tiếp tục ({activeIds.length}/{workspaces.length})
        </AnimatedButton>
      </div>

      <button style={styles.logoutBtn} onClick={() => { logout(); navigate('/login', { replace: true }); }}>
        Đăng xuất
      </button>
    </motion.div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    minHeight: '100vh', padding: '40px 20px', display: 'flex',
    flexDirection: 'column', gap: '16px', maxWidth: '428px', margin: '0 auto',
  },
  loadingContainer: { minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' },
  header: { textAlign: 'center' },
  title: { fontSize: '1.5rem', fontWeight: 700, color: 'var(--color-primary)', margin: '0 0 4px' },
  subtitle: { fontSize: '0.9rem', color: 'var(--color-text-secondary)', margin: 0 },
  hint: { fontSize: '0.78rem', color: 'var(--color-text-secondary)', margin: '4px 0 0', opacity: 0.8 },
  selectAllBtn: {
    display: 'flex', alignItems: 'center', gap: '10px',
    background: 'none', border: 'none', padding: '4px 0', cursor: 'pointer',
  },
  list: { display: 'flex', flexDirection: 'column', gap: '10px' },
  card: {
    display: 'flex', alignItems: 'center', gap: '12px',
    padding: '14px 16px', borderRadius: '12px', cursor: 'pointer',
    border: '1.5px solid', textAlign: 'left', width: '100%',
    transition: 'border-color 150ms, background 150ms',
  },
  checkbox: {
    width: '22px', height: '22px', borderRadius: '6px',
    border: '2px solid', flexShrink: 0,
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    fontSize: '0.75rem', fontWeight: 700, color: '#fff',
    transition: 'background 150ms, border-color 150ms',
  },
  logo: { fontSize: '1.6rem', flexShrink: 0 },
  cardInfo: { display: 'flex', flexDirection: 'column', gap: '2px', flex: 1, minWidth: 0 },
  cardName: { fontSize: '0.95rem', fontWeight: 600, color: 'var(--color-text)' },
  cardAddr: {
    fontSize: '0.75rem', color: 'var(--color-text-secondary)',
    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
  },
  actions: { marginTop: '8px' },
  colorDot: {
    width: '24px', height: '24px', borderRadius: '50%',
    border: '2px solid var(--color-surface-light)', flexShrink: 0,
    cursor: 'pointer', padding: 0,
    transition: 'transform 150ms',
  },
  colorPalette: {
    display: 'flex', flexWrap: 'wrap' as const, gap: '8px',
    padding: '10px 12px', marginTop: '-4px',
    background: 'var(--color-surface)',
    border: '1px solid var(--color-surface-light)',
    borderRadius: '0 0 12px 12px',
    overflow: 'hidden',
  },
  colorSwatch: {
    width: '28px', height: '28px', borderRadius: '6px',
    border: 'none', cursor: 'pointer', padding: 0,
    transition: 'transform 100ms',
  },
  logoutBtn: {
    background: 'none', border: '1px solid var(--color-surface-light)',
    borderRadius: '8px', padding: '10px', color: 'var(--color-text-secondary)',
    fontSize: '0.85rem', cursor: 'pointer', marginTop: 'auto',
  },
};
