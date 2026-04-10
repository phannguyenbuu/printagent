import { useEffect, useState, useMemo, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useRepairStore } from '../stores/repairStore';
import { useAuthStore } from '../stores/authStore';
import { useMaterialStore } from '../stores/materialStore';
import { mockGetRequestById, mockGetUserName, mockGetUserPhone } from '../api/mockApi';
import { useLocationStore } from '../stores/locationStore';
import { PriorityBadge } from '../components/requests/PriorityBadge';
import { StatusBadge } from '../components/requests/StatusBadge';
import { AnimatedButton } from '../components/ui/AnimatedButton';
import { AnimatedList } from '../components/ui/AnimatedList';
import { PageLoading } from '../components/ui/PageState';
import { GlowCard } from '../components/ui/GlowCard';
import { WorkspaceBadge } from '../components/ui/WorkspaceBadge';
import { validateMaterial } from '../services/validation';
import type { Priority, RepairRequest, RepairStatus } from '../types/repair';

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

const PRIORITY_LABELS: Record<Priority, string> = {
  critical: 'Khẩn cấp',
  high: 'Cao',
  medium: 'Trung bình',
  low: 'Thấp',
};

const STATUS_ORDER: RepairStatus[] = ['new', 'accepted', 'in_progress', 'completed'];

function formatDate(iso: string | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('vi-VN', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function formatCurrency(amount: number): string {
  return amount.toLocaleString('vi-VN') + ' ₫';
}

export function RequestDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const user = useAuthStore((s) => s.user);
  const { requests, updateStatus, addProgressNote, completeRequest } = useRepairStore();
  const { materials, totalCost, setMaterials, addMaterial, updateMaterial, removeMaterial } = useMaterialStore();
  const { locations, fetchLocations } = useLocationStore();

  const [request, setRequest] = useState<RepairRequest | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [actionError, setActionError] = useState('');

  // Progress note form
  const [progressNote, setProgressNote] = useState('');
  const [noteImages, setNoteImages] = useState<string[]>([]);
  const [noteError, setNoteError] = useState('');

  // Material form
  const [materialName, setMaterialName] = useState('');
  const [materialQuantity, setMaterialQuantity] = useState('');
  const [materialUnitPrice, setMaterialUnitPrice] = useState('');
  const [materialErrors, setMaterialErrors] = useState<string[]>([]);
  const [editingMaterialId, setEditingMaterialId] = useState<string | null>(null);

  // Completion report form
  const [reportDescription, setReportDescription] = useState('');
  const [reportLaborCost, setReportLaborCost] = useState('');
  const [reportError, setReportError] = useState('');

  // Fetch request data
  useEffect(() => {
    fetchLocations();
    async function loadRequest() {
      if (!id) return;
      setLoading(true);
      try {
        const data = await mockGetRequestById(id);
        if (data) {
          setRequest(data);
          setMaterials(data.materials ?? []);
        }
      } finally {
        setLoading(false);
      }
    }
    loadRequest();
  }, [id, setMaterials]);

  // Resolve location info
  const requestLocation = useMemo(() => {
    if (!request) return null;
    return locations.find((l) => l.id === request.locationId) ?? null;
  }, [request, locations]);

  // Sync with store updates
  useEffect(() => {
    if (!id) return;
    const storeRequest = requests.find((r) => r.id === id);
    if (storeRequest) {
      setRequest(storeRequest);
      setMaterials(storeRequest.materials ?? []);
    }
  }, [requests, id, setMaterials]);

  const canAccept = request?.status === 'new';
  const canAddProgress = (request?.status === 'accepted' || request?.status === 'in_progress');
  const canComplete = request?.status === 'in_progress';
  const canCancel = request?.status === 'new' && user?.role !== 'technician';
  const canManageMaterials = request?.status === 'in_progress';
  const isParticipant = request?.assignedTo === user?.id;
  const canJoin = canAddProgress && !isParticipant && user != null;

  // Status timeline
  const timelineStatuses = useMemo(() => {
    if (!request) return [];
    const isCancelled = request.status === 'cancelled';
    const statuses = isCancelled ? ['new', 'cancelled'] as RepairStatus[] : STATUS_ORDER;
    const currentIndex = statuses.indexOf(request.status);

    return statuses.map((status, i) => ({
      status,
      label: STATUS_LABELS[status],
      color: STATUS_COLORS[status],
      reached: i <= currentIndex,
      current: status === request.status,
      time: status === 'new' ? request.createdAt
        : status === 'accepted' ? request.acceptedAt
        : status === 'completed' ? request.completedAt
        : status === 'in_progress' && request.progressNotes.length > 0
          ? request.progressNotes[0].createdAt
        : null,
    }));
  }, [request]);

  const handleAccept = useCallback(async () => {
    if (!request || !user) return;
    setActionLoading(true);
    setActionError('');
    const result = await updateStatus(request.id, 'accepted', { assignedTo: user.id });
    if (!result.success) setActionError(result.error ?? 'Lỗi khi tiếp nhận');
    setActionLoading(false);
  }, [request, user, updateStatus]);

  const handleJoinRepair = useCallback(async () => {
    if (!request || !user) return;
    setActionLoading(true);
    setActionError('');
    const result = await addProgressNote(request.id, `${user.fullName} tham gia sửa chữa`, user.id);
    if (!result.success) setActionError(result.error ?? 'Lỗi khi tham gia');
    setActionLoading(false);
  }, [request, user, addProgressNote]);

  const handleCancel = useCallback(async () => {
    if (!request) return;
    setActionLoading(true);
    setActionError('');
    const result = await updateStatus(request.id, 'cancelled');
    if (!result.success) setActionError(result.error ?? 'Lỗi khi hủy yêu cầu');
    setActionLoading(false);
  }, [request, updateStatus]);

  const handleAddNote = useCallback(async () => {
    if (!request || !user) return;
    setNoteError('');
    if (!progressNote.trim()) {
      setNoteError('Vui lòng nhập ghi chú mô tả tiến độ');
      return;
    }
    setActionLoading(true);
    const result = await addProgressNote(request.id, progressNote.trim(), user.id, noteImages.length > 0 ? noteImages : undefined);
    if (result.success) {
      setProgressNote('');
      setNoteImages([]);
    } else {
      setNoteError(result.error ?? 'Lỗi khi thêm ghi chú');
    }
    setActionLoading(false);
  }, [request, user, progressNote, noteImages, addProgressNote]);

  const handleNoteImageUpload = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files) return;
    Array.from(files).forEach((file) => {
      const reader = new FileReader();
      reader.onload = () => {
        setNoteImages((prev) => [...prev, reader.result as string]);
      };
      reader.readAsDataURL(file);
    });
    e.target.value = '';
  }, []);

  const handleRemoveNoteImage = useCallback((index: number) => {
    setNoteImages((prev) => prev.filter((_, i) => i !== index));
  }, []);

  const handleAddMaterial = useCallback(() => {
    setMaterialErrors([]);
    const qty = Number(materialQuantity);
    const price = Number(materialUnitPrice);

    const validation = validateMaterial({
      name: materialName,
      quantity: materialQuantity === '' ? undefined : qty,
      unitPrice: materialUnitPrice === '' ? undefined : price,
    });

    if (!validation.valid) {
      setMaterialErrors(validation.errors);
      return;
    }

    if (editingMaterialId) {
      const result = updateMaterial(editingMaterialId, {
        name: materialName.trim(),
        quantity: qty,
        unitPrice: price,
      });
      if (!result.success) {
        setMaterialErrors([result.error ?? 'Lỗi khi cập nhật vật tư']);
        return;
      }
      setEditingMaterialId(null);
    } else {
      const result = addMaterial({
        repairRequestId: request?.id ?? '',
        name: materialName.trim(),
        quantity: qty,
        unitPrice: price,
      });
      if (!result.success) {
        setMaterialErrors([result.error ?? 'Lỗi khi thêm vật tư']);
        return;
      }
    }

    setMaterialName('');
    setMaterialQuantity('');
    setMaterialUnitPrice('');
  }, [materialName, materialQuantity, materialUnitPrice, editingMaterialId, request, addMaterial, updateMaterial]);

  const handleEditMaterial = useCallback((mat: { id: string; name: string; quantity: number; unitPrice: number }) => {
    setEditingMaterialId(mat.id);
    setMaterialName(mat.name);
    setMaterialQuantity(String(mat.quantity));
    setMaterialUnitPrice(String(mat.unitPrice));
    setMaterialErrors([]);
  }, []);

  const handleRemoveMaterial = useCallback((matId: string) => {
    removeMaterial(matId);
  }, [removeMaterial]);

  const handleCancelEdit = useCallback(() => {
    setEditingMaterialId(null);
    setMaterialName('');
    setMaterialQuantity('');
    setMaterialUnitPrice('');
    setMaterialErrors([]);
  }, []);

  const handleComplete = useCallback(async () => {
    if (!request) return;
    setReportError('');
    if (!reportDescription.trim()) {
      setReportError('Vui lòng nhập mô tả công việc đã thực hiện');
      return;
    }
    const laborCostNum = reportLaborCost ? Number(reportLaborCost) : undefined;
    if (reportLaborCost && (isNaN(laborCostNum!) || laborCostNum! < 0)) {
      setReportError('Tiền công không hợp lệ');
      return;
    }
    setActionLoading(true);
    const result = await completeRequest(request.id, {
      description: reportDescription.trim(),
      attachments: [],
      laborCost: laborCostNum,
    });
    if (result.success) {
      setReportDescription('');
      setReportLaborCost('');
    } else {
      setReportError(result.error ?? 'Lỗi khi hoàn thành');
    }
    setActionLoading(false);
  }, [request, reportDescription, reportLaborCost, completeRequest]);

  if (loading) {
    return <PageLoading message="Đang tải chi tiết yêu cầu..." />;
  }

  if (!request) {
    return (
      <div style={styles.container}>
        <motion.button style={styles.backButton} onClick={() => navigate(-1)} whileTap={{ scale: 0.95 }} aria-label="Quay lại">
          ← Quay lại
        </motion.button>
        <p style={styles.emptyText}>Không tìm thấy yêu cầu sửa chữa.</p>
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
      <motion.button style={styles.backButton} onClick={() => navigate(-1)} whileTap={{ scale: 0.95 }} aria-label="Quay lại">
        ← Quay lại
      </motion.button>

      {/* 1. Request Header */}
      <GlowCard>
        <div style={styles.headerRow}>
          <h1 style={styles.machineName}>{request.machineName}</h1>
          <StatusBadge status={request.status} />
        </div>
        <WorkspaceBadge workspaceId={request.workspaceId} />
        <div style={styles.metaRow}>
          <span title={PRIORITY_LABELS[request.priority]}>
            <PriorityBadge priority={request.priority} />
          </span>
          <span style={styles.metaText}>📍 {requestLocation ? requestLocation.name : request.locationId}</span>
          <span style={styles.metaText}>{formatDate(request.createdAt)}</span>
        </div>
        {/* Location details */}
        {requestLocation && (
          <div style={{ marginTop: '8px', display: 'flex', flexDirection: 'column' as const, gap: '3px' }}>
            {requestLocation.address && (
              <span style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)' }}>
                🏠 {requestLocation.address}
              </span>
            )}
            {requestLocation.phone && (
              <span style={{ fontSize: '0.8rem' }}>
                📞{' '}
                <a href={`tel:${requestLocation.phone}`} style={{ color: 'var(--color-primary)', textDecoration: 'none', fontSize: '0.8rem' }}>
                  {requestLocation.phone}
                </a>
              </span>
            )}
          </div>
        )}
      </GlowCard>

      {/* Assignee Info */}
      {request.assignedTo && (
        <GlowCard>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ fontSize: '1.2rem' }}>👤</span>
            <div>
              <div style={{ fontSize: '0.85rem', color: 'var(--color-text)', fontWeight: 600 }}>
                Người tiếp nhận: {mockGetUserName(request.assignedTo)}
              </div>
              {mockGetUserPhone(request.assignedTo) && (
                <div style={{ fontSize: '0.8rem', marginTop: '2px' }}>
                  📞{' '}
                  <a href={`tel:${mockGetUserPhone(request.assignedTo)}`} style={{ color: 'var(--color-primary)', textDecoration: 'none' }}>
                    {mockGetUserPhone(request.assignedTo)}
                  </a>
                </div>
              )}
              {request.acceptedAt && (
                <div style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)', marginTop: '2px' }}>
                  Tiếp nhận lúc: {formatDate(request.acceptedAt)}
                </div>
              )}
            </div>
          </div>

          {/* Participants - people who contributed notes besides the assignee */}
          {(() => {
            const participantIds = Array.from(
              new Set(request.progressNotes.map((n) => n.createdBy).filter((id) => id && id !== request.assignedTo))
            );
            if (participantIds.length === 0) return null;
            return (
              <div style={{ marginTop: '12px', paddingTop: '10px', borderTop: '1px solid var(--color-surface-light)' }}>
                <div style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', marginBottom: '8px', fontWeight: 500 }}>
                  🤝 Người tham gia sửa chữa ({participantIds.length})
                </div>
                {participantIds.map((pid) => (
                  <div key={pid} style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                    <span style={{ fontSize: '0.9rem' }}>👤</span>
                    <div>
                      <div style={{ fontSize: '0.85rem', color: 'var(--color-text)', fontWeight: 500 }}>
                        {mockGetUserName(pid)}
                      </div>
                      {mockGetUserPhone(pid) && (
                        <div style={{ fontSize: '0.75rem' }}>
                          📞{' '}
                          <a href={`tel:${mockGetUserPhone(pid)}`} style={{ color: 'var(--color-primary)', textDecoration: 'none', fontSize: '0.75rem' }}>
                            {mockGetUserPhone(pid)}
                          </a>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            );
          })()}
        </GlowCard>
      )}

      {/* 2. Description */}
      <GlowCard>
        <h2 style={styles.sectionTitle}>Mô tả lỗi</h2>
        <p style={styles.descriptionText}>{request.description}</p>
        {request.note && (
          <div style={{ marginTop: '10px' }}>
            <span style={styles.metaText}>📝 Ghi chú: </span>
            <span style={{ ...styles.metaText, color: 'var(--color-text)' }}>{request.note}</span>
          </div>
        )}
        {request.contactPhone && (
          <div style={{ marginTop: '6px' }}>
            <span style={styles.metaText}>📞 Liên hệ: </span>
            <a href={`tel:${request.contactPhone}`} style={{ color: 'var(--color-primary)', fontSize: '0.85rem', textDecoration: 'none' }}>
              {request.contactPhone}
            </a>
          </div>
        )}
      </GlowCard>

      {/* 3. Status Timeline */}
      <GlowCard>
        <h2 style={styles.sectionTitle}>Tiến trình xử lý</h2>
        <div style={styles.timeline}>
          {timelineStatuses.map((item, i) => (
            <div key={item.status} style={styles.timelineItem}>
              <div style={styles.timelineLeft}>
                <div
                  style={{
                    ...styles.timelineDot,
                    background: item.reached ? item.color : 'var(--color-surface-light)',
                    boxShadow: item.current ? `0 0 12px ${item.color}` : 'none',
                  }}
                />
                {i < timelineStatuses.length - 1 && (
                  <div
                    style={{
                      ...styles.timelineLine,
                      background: item.reached && timelineStatuses[i + 1]?.reached
                        ? item.color
                        : 'var(--color-surface-light)',
                    }}
                  />
                )}
              </div>
              <div style={styles.timelineContent}>
                <span
                  style={{
                    ...styles.timelineLabel,
                    color: item.reached ? item.color : 'var(--color-text-secondary)',
                    fontWeight: item.current ? 700 : 500,
                  }}
                >
                  {item.label}
                </span>
                {item.time && (
                  <span style={styles.timelineTime}>{formatDate(item.time)}</span>
                )}
              </div>
            </div>
          ))}
        </div>
      </GlowCard>

      {/* 4. Action Buttons */}
      {(canAccept || canCancel) && (
        <div style={styles.actionRow}>
          {canAccept && (
            <AnimatedButton onClick={handleAccept} disabled={actionLoading}>
              Tiếp nhận yêu cầu
            </AnimatedButton>
          )}
          {canCancel && (
            <AnimatedButton onClick={handleCancel} variant="danger" disabled={actionLoading}>
              Hủy yêu cầu
            </AnimatedButton>
          )}
        </div>
      )}

      {/* Join repair button for non-assignees */}
      {canJoin && (
        <div style={styles.actionRow}>
          <AnimatedButton onClick={handleJoinRepair} disabled={actionLoading} variant="secondary">
            🤝 Tham gia sửa chữa
          </AnimatedButton>
        </div>
      )}

      {actionError && (
        <motion.div style={styles.errorBanner} initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}>
          {actionError}
        </motion.div>
      )}

      {/* 5. Progress Notes */}
      <GlowCard>
        <h2 style={styles.sectionTitle}>Ghi chú tiến độ</h2>
        {request.progressNotes.length === 0 ? (
          <p style={styles.emptyText}>Chưa có ghi chú tiến độ.</p>
        ) : (
          <AnimatedList>
            {request.progressNotes.map((note) => (
              <div key={note.id} style={styles.noteItem}>
                <p style={styles.noteText}>{note.note}</p>
                {note.images && note.images.length > 0 && (
                  <div style={styles.noteImageGrid}>
                    {note.images.map((img, i) => (
                      <img
                        key={i}
                        src={img}
                        alt={`Ảnh ghi chú ${i + 1}`}
                        style={styles.noteImage}
                        onClick={() => window.open(img, '_blank')}
                      />
                    ))}
                  </div>
                )}
                <span style={styles.noteMeta}>
                  {mockGetUserName(note.createdBy)} · {formatDate(note.createdAt)}
                </span>
              </div>
            ))}
          </AnimatedList>
        )}

        {canAddProgress && (
          <div style={styles.noteForm}>
            <textarea
              value={progressNote}
              onChange={(e) => setProgressNote(e.target.value)}
              placeholder="Nhập ghi chú tiến độ..."
              rows={3}
              style={styles.textarea}
              disabled={actionLoading}
            />

            {/* Image upload */}
            <div>
              <label style={styles.uploadLabel}>
                📷 Thêm ảnh
                <input
                  type="file"
                  accept="image/*"
                  multiple
                  onChange={handleNoteImageUpload}
                  style={{ display: 'none' }}
                  disabled={actionLoading}
                />
              </label>
            </div>

            {noteImages.length > 0 && (
              <div style={styles.noteImageGrid}>
                {noteImages.map((img, i) => (
                  <div key={i} style={styles.imagePreviewWrapper}>
                    <img src={img} alt={`Preview ${i + 1}`} style={styles.noteImage} />
                    <button
                      style={styles.removeImageBtn}
                      onClick={() => handleRemoveNoteImage(i)}
                      aria-label={`Xóa ảnh ${i + 1}`}
                    >
                      ✕
                    </button>
                  </div>
                ))}
              </div>
            )}

            {noteError && (
              <motion.span style={styles.errorText} initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }}>
                {noteError}
              </motion.span>
            )}
            <AnimatedButton onClick={handleAddNote} disabled={actionLoading}>
              Thêm ghi chú
            </AnimatedButton>
          </div>
        )}
      </GlowCard>

      {/* 6. Materials Section */}
      <GlowCard>
        <h2 style={styles.sectionTitle}>Vật tư thay thế</h2>
        {materials.length === 0 ? (
          <p style={styles.emptyText}>Chưa có vật tư nào.</p>
        ) : (
          <>
            <AnimatedList>
              {materials.map((mat) => (
                <div key={mat.id} style={styles.materialItem}>
                  <div style={styles.materialInfo}>
                    <span style={styles.materialName}>{mat.name}</span>
                    <span style={styles.materialDetail}>
                      SL: {mat.quantity} × {formatCurrency(mat.unitPrice)} = {formatCurrency(mat.totalPrice)}
                    </span>
                  </div>
                  {canManageMaterials && (
                    <div style={styles.materialActions}>
                      <button
                        style={styles.iconButton}
                        onClick={() => handleEditMaterial(mat)}
                        aria-label={`Sửa ${mat.name}`}
                      >
                        ✏️
                      </button>
                      <button
                        style={styles.iconButton}
                        onClick={() => handleRemoveMaterial(mat.id)}
                        aria-label={`Xóa ${mat.name}`}
                      >
                        🗑️
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </AnimatedList>
            <div style={styles.totalCostRow}>
              <span style={styles.totalCostLabel}>Tổng chi phí vật tư:</span>
              <span style={styles.totalCostValue}>{formatCurrency(totalCost)}</span>
            </div>
          </>
        )}

        {canManageMaterials && (
          <div style={styles.materialForm}>
            <h3 style={styles.subSectionTitle}>
              {editingMaterialId ? 'Sửa vật tư' : 'Thêm vật tư'}
            </h3>
            <div style={styles.field}>
              <label htmlFor="materialName" style={styles.label}>Tên vật tư</label>
              <input
                id="materialName"
                type="text"
                value={materialName}
                onChange={(e) => setMaterialName(e.target.value)}
                placeholder="Nhập tên vật tư"
                style={styles.input}
              />
            </div>
            <div style={styles.fieldRow}>
              <div style={{ ...styles.field, flex: 1 }}>
                <label htmlFor="materialQuantity" style={styles.label}>Số lượng</label>
                <input
                  id="materialQuantity"
                  type="number"
                  value={materialQuantity}
                  onChange={(e) => setMaterialQuantity(e.target.value)}
                  placeholder="0"
                  style={styles.input}
                  min="0"
                  step="any"
                />
              </div>
              <div style={{ ...styles.field, flex: 1 }}>
                <label htmlFor="materialUnitPrice" style={styles.label}>Đơn giá (₫)</label>
                <input
                  id="materialUnitPrice"
                  type="number"
                  value={materialUnitPrice}
                  onChange={(e) => setMaterialUnitPrice(e.target.value)}
                  placeholder="0"
                  style={styles.input}
                  min="0"
                  step="any"
                />
              </div>
            </div>
            {materialErrors.length > 0 && (
              <motion.div style={styles.errorBanner} initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }}>
                {materialErrors.map((err, i) => (
                  <div key={i}>{err}</div>
                ))}
              </motion.div>
            )}
            <div style={styles.materialFormActions}>
              <AnimatedButton onClick={handleAddMaterial}>
                {editingMaterialId ? 'Cập nhật' : 'Thêm vật tư'}
              </AnimatedButton>
              {editingMaterialId && (
                <AnimatedButton onClick={handleCancelEdit} variant="secondary">
                  Hủy sửa
                </AnimatedButton>
              )}
            </div>
          </div>
        )}
      </GlowCard>

      {/* 7. Completion Report Form (technician, in_progress) */}
      {canComplete && (
        <GlowCard>
          <h2 style={styles.sectionTitle}>Báo cáo hoàn thành</h2>
          <div style={styles.noteForm}>
            <textarea
              value={reportDescription}
              onChange={(e) => setReportDescription(e.target.value)}
              placeholder="Mô tả công việc đã thực hiện..."
              rows={4}
              style={styles.textarea}
              disabled={actionLoading}
            />
            <div style={styles.field}>
              <label htmlFor="laborCost" style={styles.label}>Tiền công thợ (₫) — tùy chọn</label>
              <input
                id="laborCost"
                type="number"
                value={reportLaborCost}
                onChange={(e) => setReportLaborCost(e.target.value)}
                placeholder="0"
                style={styles.input}
                min="0"
                step="any"
                disabled={actionLoading}
              />
            </div>
            {reportError && (
              <motion.span style={styles.errorText} initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }}>
                {reportError}
              </motion.span>
            )}
            <AnimatedButton onClick={handleComplete} disabled={actionLoading} variant="primary">
              Hoàn thành sửa chữa
            </AnimatedButton>
          </div>
        </GlowCard>
      )}

      {/* 8. Completion Report Display (when completed) */}
      {request.status === 'completed' && request.completionReport && (
        <GlowCard>
          <h2 style={styles.sectionTitle}>Báo cáo hoàn thành</h2>
          <p style={styles.descriptionText}>{request.completionReport.description}</p>
          {request.completionReport.laborCost != null && (
            <div style={styles.totalCostRow}>
              <span style={styles.totalCostLabel}>Tiền công thợ:</span>
              <span style={{ ...styles.totalCostValue, color: 'var(--color-accent)' }}>
                {formatCurrency(request.completionReport.laborCost)}
              </span>
            </div>
          )}
          <span style={styles.metaText}>
            Hoàn thành lúc: {formatDate(request.completionReport.completedAt)}
          </span>
        </GlowCard>
      )}
    </motion.div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    minHeight: '100vh',
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
    fontWeight: 500,
    cursor: 'pointer',
    padding: '4px 0',
    alignSelf: 'flex-start',
  },
  headerRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    gap: '12px',
    marginBottom: '8px',
  },
  machineName: {
    fontSize: '1.25rem',
    fontWeight: 700,
    color: 'var(--color-text)',
    margin: 0,
    flex: 1,
  },
  badge: {
    fontSize: '0.7rem',
    fontWeight: 600,
    padding: '3px 8px',
    borderRadius: '6px',
    border: '1px solid',
    whiteSpace: 'nowrap' as const,
    flexShrink: 0,
  },
  metaRow: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    flexWrap: 'wrap' as const,
  },
  priorityBadge: {
    fontSize: '0.65rem',
    fontWeight: 600,
    padding: '2px 6px',
    borderRadius: '4px',
    border: '1px solid',
  },
  metaText: {
    fontSize: '0.8rem',
    color: 'var(--color-text-secondary)',
  },
  sectionTitle: {
    fontSize: '1rem',
    fontWeight: 600,
    color: 'var(--color-text)',
    margin: '0 0 12px',
  },
  subSectionTitle: {
    fontSize: '0.9rem',
    fontWeight: 600,
    color: 'var(--color-text-secondary)',
    margin: '12px 0 8px',
  },
  descriptionText: {
    fontSize: '0.9rem',
    color: 'var(--color-text)',
    lineHeight: 1.6,
    margin: 0,
  },
  emptyText: {
    color: 'var(--color-text-secondary)',
    fontSize: '0.85rem',
    textAlign: 'center' as const,
    padding: '12px 0',
    margin: 0,
  },
  // Timeline
  timeline: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '0px',
  },
  timelineItem: {
    display: 'flex',
    gap: '12px',
    minHeight: '48px',
  },
  timelineLeft: {
    display: 'flex',
    flexDirection: 'column' as const,
    alignItems: 'center',
    width: '20px',
    flexShrink: 0,
  },
  timelineDot: {
    width: '14px',
    height: '14px',
    borderRadius: '50%',
    flexShrink: 0,
    transition: 'all 0.3s ease',
  },
  timelineLine: {
    width: '2px',
    flex: 1,
    minHeight: '20px',
    transition: 'background 0.3s ease',
  },
  timelineContent: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '2px',
    paddingBottom: '12px',
  },
  timelineLabel: {
    fontSize: '0.85rem',
  },
  timelineTime: {
    fontSize: '0.75rem',
    color: 'var(--color-text-secondary)',
  },
  // Action buttons
  actionRow: {
    display: 'flex',
    gap: '10px',
  },
  errorBanner: {
    color: 'var(--color-error)',
    fontSize: '0.85rem',
    padding: '10px 12px',
    background: 'rgba(255, 68, 102, 0.1)',
    borderRadius: '8px',
    border: '1px solid rgba(255, 68, 102, 0.25)',
  },
  errorText: {
    color: 'var(--color-error)',
    fontSize: '0.8rem',
  },
  // Notes
  noteItem: {
    background: 'var(--color-bg, #0a0a0f)',
    borderRadius: '8px',
    padding: '10px 12px',
    border: '1px solid var(--color-surface-light)',
  },
  noteText: {
    fontSize: '0.85rem',
    color: 'var(--color-text)',
    margin: '0 0 4px',
    lineHeight: 1.5,
  },
  noteMeta: {
    fontSize: '0.75rem',
    color: 'var(--color-text-secondary)',
  },
  noteForm: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '10px',
    marginTop: '12px',
  },
  textarea: {
    background: 'var(--color-bg, #0a0a0f)',
    color: 'var(--color-text)',
    border: '1px solid var(--color-surface-light)',
    borderRadius: '8px',
    padding: '12px',
    fontSize: '0.9rem',
    width: '100%',
    resize: 'vertical' as const,
    fontFamily: 'inherit',
    boxSizing: 'border-box' as const,
    minHeight: '80px',
  },
  uploadLabel: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '4px',
    padding: '8px 14px',
    borderRadius: '8px',
    border: '1px dashed var(--color-surface-light)',
    color: 'var(--color-primary)',
    fontSize: '0.85rem',
    cursor: 'pointer',
    background: 'transparent',
  },
  noteImageGrid: {
    display: 'flex',
    flexWrap: 'wrap' as const,
    gap: '8px',
  },
  noteImage: {
    width: '80px',
    height: '80px',
    objectFit: 'cover' as const,
    borderRadius: '8px',
    border: '1px solid var(--color-surface-light)',
    cursor: 'pointer',
  },
  imagePreviewWrapper: {
    position: 'relative' as const,
    display: 'inline-block',
  },
  removeImageBtn: {
    position: 'absolute' as const,
    top: '-6px',
    right: '-6px',
    width: '20px',
    height: '20px',
    borderRadius: '50%',
    background: 'var(--color-error)',
    color: '#fff',
    border: 'none',
    fontSize: '0.7rem',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    lineHeight: 1,
  },
  // Materials
  materialItem: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    background: 'var(--color-bg, #0a0a0f)',
    borderRadius: '8px',
    padding: '10px 12px',
    border: '1px solid var(--color-surface-light)',
  },
  materialInfo: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '2px',
    flex: 1,
  },
  materialName: {
    fontSize: '0.9rem',
    fontWeight: 600,
    color: 'var(--color-text)',
  },
  materialDetail: {
    fontSize: '0.8rem',
    color: 'var(--color-text-secondary)',
  },
  materialActions: {
    display: 'flex',
    gap: '4px',
    flexShrink: 0,
  },
  iconButton: {
    background: 'none',
    border: 'none',
    cursor: 'pointer',
    fontSize: '1rem',
    padding: '4px',
    borderRadius: '4px',
  },
  totalCostRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginTop: '12px',
    padding: '10px 0',
    borderTop: '1px solid var(--color-surface-light)',
  },
  totalCostLabel: {
    fontSize: '0.9rem',
    fontWeight: 600,
    color: 'var(--color-text)',
  },
  totalCostValue: {
    fontSize: '1rem',
    fontWeight: 700,
    color: 'var(--color-primary)',
  },
  materialForm: {
    marginTop: '12px',
    paddingTop: '12px',
    borderTop: '1px solid var(--color-surface-light)',
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '8px',
  },
  materialFormActions: {
    display: 'flex',
    gap: '8px',
    marginTop: '4px',
  },
  field: {
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '4px',
  },
  fieldRow: {
    display: 'flex',
    gap: '10px',
  },
  label: {
    fontSize: '0.8rem',
    color: 'var(--color-text-secondary)',
    fontWeight: 500,
  },
  input: {
    background: 'var(--color-bg, #0a0a0f)',
    color: 'var(--color-text)',
    border: '1px solid var(--color-surface-light)',
    borderRadius: '8px',
    padding: '10px 12px',
    fontSize: '0.9rem',
    width: '100%',
    boxSizing: 'border-box' as const,
  },
};
