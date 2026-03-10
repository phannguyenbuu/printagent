import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useAuthStore } from '../stores/authStore';
import { useRepairStore } from '../stores/repairStore';
import { GlowCard } from '../components/ui/GlowCard';
import { AnimatedButton } from '../components/ui/AnimatedButton';
import { useTheme } from '../theme/ThemeContext';
import {
  calculateUserRepairStats,
  getUserActivityHistory,
  getDateRangeForPeriod,
  formatPeriodLabel,
  type StatPeriod,
} from '../services/statsService';
import { useLocationStore } from '../stores/locationStore';
import type { RepairStatus } from '../types/repair';
import type { WorkHistoryEntry } from '../types/auth';

const ROLE_LABELS: Record<string, string> = {
  supplier: 'Nhà cung cấp',
  technician: 'Kỹ thuật viên',
};

const STATUS_LABELS: Record<RepairStatus, string> = {
  new: 'Mới tạo',
  accepted: 'Đã tiếp nhận',
  in_progress: 'Đang xử lý',
  completed: 'Hoàn thành',
  cancelled: 'Đã hủy',
};

const STATUS_COLORS: Record<RepairStatus, string> = {
  new: 'var(--color-primary)',
  accepted: 'var(--color-secondary)',
  in_progress: 'var(--color-warning)',
  completed: 'var(--color-success)',
  cancelled: 'var(--color-error)',
};

function formatCurrency(amount: number): string {
  return amount.toLocaleString('vi-VN') + ' ₫';
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString('vi-VN', {
    day: '2-digit', month: '2-digit', year: 'numeric',
  });
}

function StarRating({ rating }: { rating: number | null }) {
  if (rating == null) return <span style={{ color: 'var(--color-text-secondary)', fontSize: '0.8rem' }}>Chưa có đánh giá</span>;
  return (
    <span style={{ fontSize: '1.1rem', letterSpacing: '3px' }}>
      {[1, 2, 3, 4, 5].map((s) => (
        <span key={s} style={{ color: s <= Math.round(rating) ? '#FFD700' : 'var(--color-surface-light)' }}>★</span>
      ))}
      <span style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)', marginLeft: '8px' }}>
        {rating.toFixed(1)}
      </span>
    </span>
  );
}

function WorkHistoryCard({ history }: { history: WorkHistoryEntry[] }) {
  const now = new Date();

  // Sort: current entries first, then by from desc
  const sorted = [...history].sort((a, b) => {
    const aCurrent = a.isCurrent ?? !a.to;
    const bCurrent = b.isCurrent ?? !b.to;
    if (aCurrent !== bCurrent) return aCurrent ? -1 : 1;
    return new Date(b.from).getTime() - new Date(a.from).getTime();
  });

  // Detect concurrent entries: entries whose active periods overlap with another current entry
  const currentEntries = sorted.filter((e) => e.isCurrent ?? !e.to);
  const isConcurrent = currentEntries.length > 1;

  return (
    <div style={{ display: 'flex', flexDirection: 'column' as const, gap: '0' }}>
      {isConcurrent && (
        <div style={whStyles.concurrentBanner}>
          ⚡ Đang làm việc song song tại {currentEntries.length} công ty
        </div>
      )}
      {sorted.map((entry, i) => {
        const from = new Date(entry.from);
        const to = entry.to ? new Date(entry.to) : now;
        const totalMonths =
          (to.getFullYear() - from.getFullYear()) * 12 + (to.getMonth() - from.getMonth());
        const years = Math.floor(totalMonths / 12);
        const months = totalMonths % 12;
        const duration = years > 0
          ? (months > 0 ? `${years} năm ${months} tháng` : `${years} năm`)
          : `${months} tháng`;
        const active = entry.isCurrent ?? !entry.to;
        const isLast = i === sorted.length - 1;

        return (
          <div key={i} style={whStyles.row}>
            {/* Timeline */}
            <div style={whStyles.timeline}>
              <div style={{
                ...whStyles.dot,
                background: active ? 'var(--color-primary)' : 'var(--color-surface-light)',
                border: `2px solid ${active ? 'var(--color-primary)' : 'var(--color-text-secondary)'}`,
                boxShadow: active ? '0 0 6px var(--color-primary)' : 'none',
              }} />
              {!isLast && <div style={whStyles.line} />}
            </div>
            {/* Content */}
            <div style={whStyles.content}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '8px' }}>
                <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--color-text)', flex: 1 }}>
                  {entry.companyName}
                </span>
                <div style={{ display: 'flex', gap: '4px', flexShrink: 0 }}>
                  {active && <span style={whStyles.currentBadge}>Hiện tại</span>}
                  {active && isConcurrent && <span style={whStyles.concurrentBadge}>Song song</span>}
                </div>
              </div>
              <span style={{ fontSize: '0.78rem', color: 'var(--color-text-secondary)', marginTop: '2px', display: 'block' }}>
                {entry.role}
              </span>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginTop: '4px' }}>
                <span style={{ fontSize: '0.72rem', color: 'var(--color-text-secondary)' }}>
                  {from.toLocaleDateString('vi-VN', { month: '2-digit', year: 'numeric' })}
                  {' – '}
                  {active ? 'nay' : to.toLocaleDateString('vi-VN', { month: '2-digit', year: 'numeric' })}
                </span>
                <span style={{ fontSize: '0.72rem', color: 'var(--color-accent)', fontWeight: 600 }}>
                  · {duration}
                </span>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

const whStyles: Record<string, React.CSSProperties> = {
  row: { display: 'flex', gap: '12px', alignItems: 'stretch' },
  timeline: { display: 'flex', flexDirection: 'column', alignItems: 'center', width: '16px', flexShrink: 0 },
  dot: { width: '12px', height: '12px', borderRadius: '50%', flexShrink: 0, marginTop: '4px' },
  line: { width: '2px', flex: 1, background: 'var(--color-surface-light)', margin: '4px 0' },
  content: { flex: 1, paddingBottom: '16px', display: 'flex', flexDirection: 'column' },
  currentBadge: {
    fontSize: '0.65rem', fontWeight: 700, padding: '2px 7px', borderRadius: '8px',
    background: 'color-mix(in srgb, var(--color-primary) 15%, var(--color-surface))',
    color: 'var(--color-primary)',
    border: '1px solid color-mix(in srgb, var(--color-primary) 30%, transparent)',
    flexShrink: 0,
  },
  concurrentBadge: {
    fontSize: '0.65rem', fontWeight: 700, padding: '2px 7px', borderRadius: '8px',
    background: 'color-mix(in srgb, var(--color-warning) 15%, var(--color-surface))',
    color: 'var(--color-warning)',
    border: '1px solid color-mix(in srgb, var(--color-warning) 30%, transparent)',
    flexShrink: 0,
  },
  concurrentBanner: {
    fontSize: '0.78rem', fontWeight: 600, padding: '7px 12px', borderRadius: '8px',
    background: 'color-mix(in srgb, var(--color-warning) 10%, var(--color-surface))',
    color: 'var(--color-warning)',
    border: '1px solid color-mix(in srgb, var(--color-warning) 25%, transparent)',
    marginBottom: '14px',
  },
};

function ActivityItem({ entry, locName, onClick }: {
  entry: ReturnType<typeof getUserActivityHistory>[number];
  locName: string;
  onClick: () => void;
}) {
  return (
    <motion.div
      style={styles.activityItem}
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      whileTap={{ scale: 0.98 }}
      onClick={onClick}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <span style={styles.activityMachine}>{entry.machineName}</span>
        <span style={{
          ...styles.activityBadge,
          background: `${STATUS_COLORS[entry.status]}20`,
          color: STATUS_COLORS[entry.status],
          borderColor: `${STATUS_COLORS[entry.status]}40`,
        }}>
          {STATUS_LABELS[entry.status]}
        </span>
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '4px' }}>
        <span style={styles.activityMeta}>
          📍 {locName} · {formatDate(entry.date)}
        </span>
        {entry.status === 'completed' && (entry.laborCost != null || entry.materialCost > 0) && (
          <span style={{ fontSize: '0.75rem', color: 'var(--color-accent)', fontWeight: 600 }}>
            {formatCurrency((entry.laborCost ?? 0) + entry.materialCost)}
          </span>
        )}
      </div>
    </motion.div>
  );
}

export function AccountPage() {
  const navigate = useNavigate();
  const user = useAuthStore((s) => s.user);
  const logout = useAuthStore((s) => s.logout);
  const updateProfile = useAuthStore((s) => s.updateProfile);
  const changePassword = useAuthStore((s) => s.changePassword);
  const { theme, toggleTheme } = useTheme();
  const { requests, fetchRequests } = useRepairStore();
  const { locations, fetchLocations } = useLocationStore();

  useEffect(() => {
    fetchRequests();
    fetchLocations();
  }, [fetchRequests, fetchLocations]);

  // Activity modal
  const [showAllActivity, setShowAllActivity] = useState(false);
  const [activitySearch, setActivitySearch] = useState('');

  // Stat period filter
  const [statPeriod, setStatPeriod] = useState<StatPeriod | 'custom'>('month');
  const [customFrom, setCustomFrom] = useState('');
  const [customTo, setCustomTo] = useState('');

  const statDateRange = statPeriod === 'custom'
    ? (customFrom && customTo ? { from: new Date(customFrom), to: new Date(customTo + 'T23:59:59') } : undefined)
    : getDateRangeForPeriod(statPeriod);

  const stats = user ? calculateUserRepairStats(requests, user.id, user.role, statDateRange) : null;

  const activity = user ? getUserActivityHistory(requests, user.id, user.role, 50) : [];

  // Rating
  // (read-only, populated from API)

  const filteredActivity = activitySearch.trim()
    ? activity.filter((e) => {
        const q = activitySearch.toLowerCase();
        const loc = locations.find((l) => l.id === e.locationId);
        return (
          e.machineName.toLowerCase().includes(q) ||
          (loc?.name ?? e.locationId).toLowerCase().includes(q) ||
          STATUS_LABELS[e.status].toLowerCase().includes(q)
        );
      })
    : activity;

  // Edit profile
  const [editing, setEditing] = useState(false);
  const [fullName, setFullName] = useState(user?.fullName ?? '');
  const [phone, setPhone] = useState(user?.phone ?? '');
  const [saved, setSaved] = useState(false);

  // Change password
  const [changingPw, setChangingPw] = useState(false);
  const [currentPw, setCurrentPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [pwError, setPwError] = useState('');
  const [pwSuccess, setPwSuccess] = useState(false);
  const [pwLoading, setPwLoading] = useState(false);

  const handleLogout = () => { logout(); navigate('/login'); };

  const handleEdit = () => {
    setFullName(user?.fullName ?? '');
    setPhone(user?.phone ?? '');
    setEditing(true);
    setSaved(false);
  };

  const handleSave = () => {
    updateProfile({ fullName: fullName.trim(), phone: phone.trim() || undefined });
    setEditing(false);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const handleChangePw = async () => {
    setPwError('');
    if (!currentPw) { setPwError('Vui lòng nhập mật khẩu hiện tại'); return; }
    if (newPw.length < 6) { setPwError('Mật khẩu mới phải có ít nhất 6 ký tự'); return; }
    if (newPw !== confirmPw) { setPwError('Mật khẩu xác nhận không khớp'); return; }
    setPwLoading(true);
    const result = await changePassword(currentPw, newPw);
    setPwLoading(false);
    if (result.success) {
      setPwSuccess(true);
      setCurrentPw(''); setNewPw(''); setConfirmPw('');
      setTimeout(() => { setPwSuccess(false); setChangingPw(false); }, 2000);
    } else {
      setPwError(result.error ?? 'Lỗi đổi mật khẩu');
    }
  };

  const cancelChangePw = () => {
    setChangingPw(false);
    setCurrentPw(''); setNewPw(''); setConfirmPw('');
    setPwError(''); setPwSuccess(false);
  };

  return (
    <div style={styles.container}>
      <motion.div style={styles.content}
        initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease: [0.4, 0, 0.2, 1] }}>

        <div style={styles.header}>
          <h1 style={styles.title}>Tài khoản</h1>
        </div>

        {/* Avatar */}
        <div style={styles.avatarSection}>
          <motion.div style={styles.avatar}
            initial={{ scale: 0.8, opacity: 0 }} animate={{ scale: 1, opacity: 1 }}
            transition={{ duration: 0.4, delay: 0.15 }}>
            <span style={styles.avatarText}>{user?.fullName?.charAt(0)?.toUpperCase() ?? '?'}</span>
          </motion.div>
          <motion.p style={styles.fullName} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.25 }}>
            {user?.fullName ?? 'Người dùng'}
          </motion.p>
          <motion.span style={styles.roleBadge} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.3 }}>
            {ROLE_LABELS[user?.role ?? ''] ?? user?.role ?? ''}
          </motion.span>
        </div>

        {/* User Info */}
        <GlowCard>
          <div style={styles.sectionHeader}>
            <h2 style={styles.sectionTitle}>Thông tin cá nhân</h2>
            {!editing && <button style={styles.editButton} onClick={handleEdit}>✏️ Sửa</button>}
          </div>

          {editing ? (
            <div style={styles.editForm}>
              <div style={styles.field}>
                <label style={styles.label}>Họ và tên</label>
                <input type="text" value={fullName} onChange={(e) => setFullName(e.target.value)} style={styles.input} />
              </div>
              <div style={styles.field}>
                <label style={styles.label}>Số điện thoại</label>
                <input type="tel" value={phone} onChange={(e) => setPhone(e.target.value)}
                  placeholder="Nhập số điện thoại" style={styles.input} />
              </div>
              <div style={styles.editActions}>
                <AnimatedButton onClick={handleSave}>Lưu</AnimatedButton>
                <AnimatedButton variant="secondary" onClick={() => setEditing(false)}>Hủy</AnimatedButton>
              </div>
            </div>
          ) : (
            <>
              <div style={styles.infoRow}>
                <span style={styles.infoLabel}>Tên đăng nhập</span>
                <span style={styles.infoValue}>{user?.username ?? '—'}</span>
              </div>
              <div style={styles.infoRow}>
                <span style={styles.infoLabel}>Email</span>
                <span style={styles.infoValue}>{user?.email ?? '—'}</span>
              </div>
              <div style={styles.infoRow}>
                <span style={styles.infoLabel}>Họ và tên</span>
                <span style={styles.infoValue}>{user?.fullName ?? '—'}</span>
              </div>
              <div style={styles.infoRow}>
                <span style={styles.infoLabel}>Số điện thoại</span>
                <span style={styles.infoValue}>{user?.phone ?? '—'}</span>
              </div>
              <div style={{ ...styles.infoRow, borderBottom: 'none' }}>
                <span style={styles.infoLabel}>Vai trò</span>
                <span style={styles.infoValue}>{ROLE_LABELS[user?.role ?? ''] ?? '—'}</span>
              </div>


            </>
          )}

          {saved && (
            <motion.div style={styles.successBanner} initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }}>
              ✅ Đã lưu thành công
            </motion.div>
          )}
        </GlowCard>

        {/* Work History */}
        {user?.workHistory && user.workHistory.length > 0 && (
          <GlowCard>
            <h2 style={styles.sectionTitle}>🏢 Lịch sử công tác</h2>
            <div style={{ marginTop: '14px' }}>
              <WorkHistoryCard history={user.workHistory} />
            </div>
          </GlowCard>
        )}

        {/* Change Password */}
        <GlowCard>
          <div style={styles.sectionHeader}>
            <h2 style={styles.sectionTitle}>Đổi mật khẩu</h2>
            {!changingPw && (
              <button style={styles.editButton} onClick={() => setChangingPw(true)}>🔑 Đổi</button>
            )}
          </div>

          {changingPw ? (
            <div style={styles.editForm}>
              <div style={styles.field}>
                <label style={styles.label}>Mật khẩu hiện tại</label>
                <input type="password" value={currentPw} onChange={(e) => setCurrentPw(e.target.value)}
                  placeholder="Nhập mật khẩu hiện tại" style={styles.input} autoComplete="current-password" />
              </div>
              <div style={styles.field}>
                <label style={styles.label}>Mật khẩu mới</label>
                <input type="password" value={newPw} onChange={(e) => setNewPw(e.target.value)}
                  placeholder="Tối thiểu 6 ký tự" style={styles.input} autoComplete="new-password" />
              </div>
              <div style={styles.field}>
                <label style={styles.label}>Xác nhận mật khẩu mới</label>
                <input type="password" value={confirmPw} onChange={(e) => setConfirmPw(e.target.value)}
                  placeholder="Nhập lại mật khẩu mới" style={styles.input} autoComplete="new-password" />
              </div>
              {pwError && (
                <motion.div style={styles.errorBanner} initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }}>
                  {pwError}
                </motion.div>
              )}
              {pwSuccess && (
                <motion.div style={styles.successBanner} initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }}>
                  ✅ Đổi mật khẩu thành công
                </motion.div>
              )}
              <div style={styles.editActions}>
                <AnimatedButton onClick={handleChangePw} disabled={pwLoading}>
                  {pwLoading ? 'Đang xử lý...' : 'Xác nhận'}
                </AnimatedButton>
                <AnimatedButton variant="secondary" onClick={cancelChangePw} disabled={pwLoading}>Hủy</AnimatedButton>
              </div>
            </div>
          ) : (
            <p style={styles.pwHint}>Mật khẩu được bảo mật. Nhấn "Đổi" để thay đổi.</p>
          )}
        </GlowCard>

        {/* Theme Toggle */}
        <GlowCard>
          <div style={styles.sectionHeader}>
            <h2 style={styles.sectionTitle}>Giao diện</h2>
          </div>
          <div style={styles.themeRow}>
            <span style={styles.infoLabel}>{theme === 'dark' ? '🌙 Tối' : '☀️ Sáng'}</span>
            <button
              onClick={toggleTheme}
              style={{
                ...styles.themeToggle,
                background: theme === 'dark'
                  ? 'linear-gradient(135deg, var(--color-primary) 0%, var(--color-secondary) 100%)'
                  : 'linear-gradient(135deg, #0077cc 0%, #6a1fd0 100%)',
              }}
              aria-label="Chuyển đổi giao diện"
            >
              <motion.div
                style={styles.themeThumb}
                animate={{ x: theme === 'dark' ? 0 : 22 }}
                transition={{ type: 'spring', stiffness: 500, damping: 30 }}
              />
            </button>
          </div>
        </GlowCard>

        {/* Repair Statistics */}
        {stats && (
          <GlowCard>
            <div style={styles.sectionHeader}>
              <h2 style={styles.sectionTitle}>📊 Thống kê sửa chữa</h2>
              <span style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>
                {statPeriod === 'custom'
                  ? (customFrom && customTo ? `${formatDate(customFrom)} – ${formatDate(customTo)}` : 'Chọn khoảng thời gian')
                  : formatPeriodLabel(statPeriod)}
              </span>
            </div>
            {/* Period tabs */}
            <div style={styles.periodTabs}>
              {(['month', 'quarter', 'year', 'custom'] as const).map((p) => (
                <button
                  key={p}
                  style={{
                    ...styles.periodTab,
                    ...(statPeriod === p ? styles.periodTabActive : {}),
                  }}
                  onClick={() => setStatPeriod(p)}
                >
                  {p === 'month' ? 'Tháng' : p === 'quarter' ? 'Quý' : p === 'year' ? 'Năm' : '⚙️'}
                </button>
              ))}
            </div>
            {/* Custom date range */}
            {statPeriod === 'custom' && (
              <div style={styles.customRange}>
                <div style={styles.customRangeField}>
                  <label style={styles.label}>Từ ngày</label>
                  <input
                    type="date"
                    value={customFrom}
                    onChange={(e) => setCustomFrom(e.target.value)}
                    style={styles.input}
                  />
                </div>
                <div style={styles.customRangeField}>
                  <label style={styles.label}>Đến ngày</label>
                  <input
                    type="date"
                    value={customTo}
                    onChange={(e) => setCustomTo(e.target.value)}
                    style={styles.input}
                  />
                </div>
              </div>
            )}
            <div style={styles.statsGrid}>
              <div style={styles.statCard}>
                <span style={{ ...styles.statValue, color: 'var(--color-success)' }}>{stats.completedCount}</span>
                <span style={styles.statLabel}>Đơn hoàn thành</span>
              </div>
              <div style={styles.statCard}>
                <span style={{ ...styles.statValue, color: 'var(--color-error)' }}>{stats.cancelledCount}</span>
                <span style={styles.statLabel}>Đơn đã hủy</span>
              </div>
            </div>
            <div style={{ marginTop: '12px', display: 'flex', flexDirection: 'column' as const, gap: '8px' }}>
              {user?.role === 'technician' && (
                <div style={styles.infoRow}>
                  <span style={styles.infoLabel}>💰 Tổng tiền công</span>
                  <span style={{ ...styles.infoValue, color: 'var(--color-accent)', fontWeight: 700 }}>
                    {formatCurrency(stats.totalLaborCost)}
                  </span>
                </div>
              )}
              <div style={styles.infoRow}>
                <span style={styles.infoLabel}>🔧 Tổng chi phí vật tư</span>
                <span style={{ ...styles.infoValue, color: 'var(--color-primary)', fontWeight: 600 }}>
                  {formatCurrency(stats.totalMaterialCost)}
                </span>
              </div>
              {user?.role === 'technician' && (
                <div style={{ ...styles.infoRow, borderBottom: 'none' }}>
                  <span style={styles.infoLabel}>📦 Tổng chi phí</span>
                  <span style={{ ...styles.infoValue, color: 'var(--color-warning)', fontWeight: 700 }}>
                    {formatCurrency(stats.totalCost)}
                  </span>
                </div>
              )}
            </div>
          </GlowCard>
        )}

        {/* Rating */}
        {stats && user?.role === 'technician' && (
          <GlowCard>
            <h2 style={styles.sectionTitle}>⭐ Xếp hạng từ khách hàng</h2>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: '8px' }}>
              <StarRating rating={stats.averageRating} />
              <span style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)' }}>
                {stats.ratingCount > 0 ? `${stats.ratingCount} đánh giá` : 'Chưa có đánh giá'}
              </span>
            </div>
          </GlowCard>
        )}

        {/* Activity History */}
        {activity.length > 0 && (
          <GlowCard>
            <div style={styles.sectionHeader}>
              <h2 style={styles.sectionTitle}>🕐 Lịch sử hoạt động</h2>
              {activity.length > 3 && (
                <button style={styles.editButton} onClick={() => { setShowAllActivity(true); setActivitySearch(''); }}>
                  Xem toàn bộ ({activity.length})
                </button>
              )}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column' as const, gap: '10px' }}>
              {activity.slice(0, 3).map((entry) => {
                const loc = locations.find((l) => l.id === entry.locationId);
                return (
                  <ActivityItem
                    key={entry.requestId}
                    entry={entry}
                    locName={loc?.name ?? entry.locationId}
                    onClick={() => navigate(`/requests/${entry.requestId}`)}
                  />
                );
              })}
            </div>
          </GlowCard>
        )}

        {/* Activity Modal */}
        {showAllActivity && (
          <motion.div
            style={styles.modalOverlay}
            initial={{ opacity: 0 }} animate={{ opacity: 1 }}
            onClick={(e) => { if (e.target === e.currentTarget) setShowAllActivity(false); }}
          >
            <motion.div
              style={styles.modalSheet}
              initial={{ y: '100%' }} animate={{ y: 0 }}
              transition={{ type: 'spring', stiffness: 300, damping: 30 }}
            >
              <div style={styles.modalHeader}>
                <h2 style={{ ...styles.sectionTitle, fontSize: '1.05rem' }}>🕐 Toàn bộ lịch sử hoạt động</h2>
                <button style={styles.closeBtn} onClick={() => setShowAllActivity(false)} aria-label="Đóng">✕</button>
              </div>
              <div style={{ padding: '0 16px 12px' }}>
                <input
                  type="text"
                  value={activitySearch}
                  onChange={(e) => setActivitySearch(e.target.value)}
                  placeholder="🔍 Tìm theo tên máy, địa điểm, trạng thái..."
                  style={styles.searchInput}
                  autoFocus
                />
              </div>
              <div style={styles.modalList}>
                {filteredActivity.length === 0 ? (
                  <p style={{ ...styles.emptyText, padding: '24px 16px' }}>Không tìm thấy kết quả.</p>
                ) : (
                  filteredActivity.map((entry) => {
                    const loc = locations.find((l) => l.id === entry.locationId);
                    return (
                      <div key={entry.requestId} style={{ padding: '0 16px 10px' }}>
                        <ActivityItem
                          entry={entry}
                          locName={loc?.name ?? entry.locationId}
                          onClick={() => { setShowAllActivity(false); navigate(`/requests/${entry.requestId}`); }}
                        />
                      </div>
                    );
                  })
                )}
              </div>
            </motion.div>
          </motion.div>
        )}

        {/* Logout */}
        <div style={styles.logoutSection}>
          <AnimatedButton variant="danger" onClick={handleLogout}>Đăng xuất</AnimatedButton>
        </div>
      </motion.div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: { minHeight: '100vh', position: 'relative', paddingBottom: '80px' },
  content: { position: 'relative', zIndex: 1, padding: '20px 16px', display: 'flex', flexDirection: 'column', gap: '20px' },
  header: { marginBottom: '4px' },
  title: { fontSize: '1.5rem', fontWeight: 700, color: 'var(--color-primary)', margin: 0 },
  avatarSection: { display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px' },
  avatar: {
    width: 80, height: 80, borderRadius: '50%',
    background: 'linear-gradient(135deg, var(--color-primary) 0%, var(--color-secondary) 100%)',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    boxShadow: 'var(--glow-primary)',
  },
  avatarText: { fontSize: '2rem', fontWeight: 700, color: '#fff' },
  fullName: { fontSize: '1.15rem', fontWeight: 600, color: 'var(--color-text)', margin: 0 },
  roleBadge: {
    fontSize: '0.75rem', fontWeight: 600, padding: '4px 12px', borderRadius: '12px',
    background: 'color-mix(in srgb, var(--color-primary) 12%, var(--color-surface))', color: 'var(--color-primary)',
    border: '1px solid color-mix(in srgb, var(--color-primary) 25%, transparent)',
  },
  sectionHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' },
  sectionTitle: { fontSize: '1rem', fontWeight: 600, color: 'var(--color-text)', margin: 0 },
  editButton: {
    background: 'none', border: '1px solid var(--color-surface-light)', borderRadius: '6px',
    color: 'var(--color-primary)', fontSize: '0.8rem', padding: '4px 10px', cursor: 'pointer',
  },
  infoRow: {
    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
    padding: '10px 0', borderBottom: '1px solid var(--color-surface-light)',
  },
  infoLabel: { fontSize: '0.85rem', color: 'var(--color-text-secondary)' },
  infoValue: { fontSize: '0.85rem', fontWeight: 500, color: 'var(--color-text)' },
  editForm: { display: 'flex', flexDirection: 'column', gap: '12px' },
  field: { display: 'flex', flexDirection: 'column', gap: '4px' },
  label: { fontSize: '0.8rem', color: 'var(--color-text-secondary)', fontWeight: 500 },
  input: {
    background: 'var(--color-bg, #0a0a0f)', color: 'var(--color-text)',
    border: '1px solid var(--color-surface-light)', borderRadius: '8px',
    padding: '10px 12px', fontSize: '0.9rem', width: '100%', boxSizing: 'border-box' as const,
  },
  editActions: { display: 'flex', gap: '8px', marginTop: '4px' },
  successBanner: {
    marginTop: '8px', padding: '8px 12px', borderRadius: '8px',
    background: 'color-mix(in srgb, var(--color-success) 10%, var(--color-surface))', color: 'var(--color-success)',
    fontSize: '0.85rem', border: '1px solid color-mix(in srgb, var(--color-success) 25%, transparent)',
  },
  errorBanner: {
    padding: '8px 12px', borderRadius: '8px',
    background: 'color-mix(in srgb, var(--color-error) 10%, var(--color-surface))', color: 'var(--color-error)',
    fontSize: '0.85rem', border: '1px solid color-mix(in srgb, var(--color-error) 25%, transparent)',
  },
  pwHint: { fontSize: '0.85rem', color: 'var(--color-text-secondary)', margin: 0 },
  locationHint: { fontSize: '0.8rem', color: 'var(--color-text-secondary)', margin: '0 0 12px' },
  locationList: { display: 'flex', flexDirection: 'column', gap: '8px' },
  locationCard: {
    display: 'flex', flexDirection: 'column', gap: '2px',
    padding: '10px 12px', borderRadius: '8px',
    background: 'var(--color-bg)', border: '1px solid var(--color-surface-light)',
  },
  locationName: { fontSize: '0.85rem', fontWeight: 600, color: 'var(--color-text)' },
  locationAddr: { fontSize: '0.75rem', color: 'var(--color-text-secondary)', paddingLeft: '20px' },
  emptyText: { color: 'var(--color-text-secondary)', fontSize: '0.875rem', textAlign: 'center', padding: '12px 0', margin: 0 },
  logoutSection: { marginTop: '8px' },
  themeRow: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '4px 0' },
  themeToggle: {
    width: 48, height: 26, borderRadius: 13, border: 'none', cursor: 'pointer',
    position: 'relative', padding: 0, flexShrink: 0,
  },
  themeThumb: {
    position: 'absolute', top: 3, left: 3,
    width: 20, height: 20, borderRadius: '50%', background: '#fff',
    boxShadow: '0 1px 4px rgba(0,0,0,0.3)',
  },
  statsGrid: {
    display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginBottom: '4px',
  },
  periodTabs: {
    display: 'flex', gap: '6px', marginBottom: '14px',
  },
  periodTab: {
    flex: 1, padding: '6px 0', borderRadius: '8px', fontSize: '0.8rem', fontWeight: 500,
    cursor: 'pointer', border: '1px solid var(--color-surface-light)',
    background: 'var(--color-bg)', color: 'var(--color-text-secondary)',
    transition: 'all 0.15s',
  },
  periodTabActive: {
    background: 'color-mix(in srgb, var(--color-primary) 15%, var(--color-surface))',
    color: 'var(--color-primary)',
    border: '1px solid color-mix(in srgb, var(--color-primary) 40%, transparent)',
    fontWeight: 700,
  },
  customRange: {
    display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginBottom: '14px',
  },
  customRangeField: { display: 'flex', flexDirection: 'column' as const, gap: '4px' },
  statCard: {
    display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '4px',
    padding: '12px 8px', borderRadius: '10px',
    background: 'var(--color-bg)', border: '1px solid var(--color-surface-light)',
  },
  statValue: { fontSize: '1.6rem', fontWeight: 700 },
  statLabel: { fontSize: '0.72rem', color: 'var(--color-text-secondary)', textAlign: 'center' as const },
  activityItem: {
    padding: '10px 12px', borderRadius: '10px', cursor: 'pointer',
    background: 'var(--color-bg)', border: '1px solid var(--color-surface-light)',
    transition: 'border-color 0.2s',
  },
  activityMachine: { fontSize: '0.85rem', fontWeight: 600, color: 'var(--color-text)' },
  activityBadge: {
    fontSize: '0.7rem', fontWeight: 600, padding: '2px 8px', borderRadius: '8px',
    border: '1px solid', flexShrink: 0,
  },
  activityMeta: { fontSize: '0.75rem', color: 'var(--color-text-secondary)' },
  modalOverlay: {
    position: 'fixed' as const, inset: 0, zIndex: 1000,
    background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)',
    display: 'flex', alignItems: 'flex-end',
  },
  modalSheet: {
    width: '100%', maxHeight: '85vh', borderRadius: '20px 20px 0 0',
    background: 'var(--color-surface)', border: '1px solid var(--color-surface-light)',
    display: 'flex', flexDirection: 'column' as const, overflow: 'hidden',
  },
  modalHeader: {
    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
    padding: '16px 16px 12px', borderBottom: '1px solid var(--color-surface-light)',
  },
  closeBtn: {
    background: 'none', border: 'none', color: 'var(--color-text-secondary)',
    fontSize: '1.1rem', cursor: 'pointer', padding: '4px 8px', borderRadius: '6px',
  },
  searchInput: {
    width: '100%', boxSizing: 'border-box' as const,
    background: 'var(--color-bg)', color: 'var(--color-text)',
    border: '1px solid var(--color-surface-light)', borderRadius: '10px',
    padding: '10px 14px', fontSize: '0.9rem',
  },
  modalList: {
    overflowY: 'auto' as const, flex: 1, paddingTop: '4px', paddingBottom: '24px',
  },
};
