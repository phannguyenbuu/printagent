import { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useRepairStore } from '../stores/repairStore';
import { useAuthStore } from '../stores/authStore';
import { useLocationStore } from '../stores/locationStore';
import { getAccessibleLocations } from '../services/accessControl';
import { validateRepairRequest } from '../services/validation';
import { AnimatedButton } from '../components/ui/AnimatedButton';
import { GlowCard } from '../components/ui/GlowCard';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import type { Priority, Attachment } from '../types/repair';

function removeDiacritics(str: string): string {
  return str
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/đ/g, 'd')
    .replace(/Đ/g, 'D')
    .toLowerCase();
}

const PRIORITY_OPTIONS: { value: Priority; label: string }[] = [
  { value: 'low', label: 'Thấp' },
  { value: 'medium', label: 'Trung bình' },
  { value: 'high', label: 'Cao' },
  { value: 'critical', label: 'Khẩn cấp' },
];

interface FieldErrors {
  machineName?: string;
  locationId?: string;
  description?: string;
  priority?: string;
}

export function CreateRequestPage() {
  const navigate = useNavigate();
  const user = useAuthStore((s) => s.user);
  const createRequest = useRepairStore((s) => s.createRequest);
  const updateStatus = useRepairStore((s) => s.updateStatus);
  const { locations, fetchLocations, addLocation } = useLocationStore();

  const [machineName, setMachineName] = useState('');
  const [locationId, setLocationId] = useState('');
  const [description, setDescription] = useState('');
  const [priority, setPriority] = useState<Priority | ''>('');
  const [attachments, setAttachments] = useState<Attachment[]>([]);
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  const [submitError, setSubmitError] = useState('');
  const [loading, setLoading] = useState(false);

  // Location search
  const [locationSearch, setLocationSearch] = useState('');
  const [showLocationResults, setShowLocationResults] = useState(false);

  // New location fields
  const [showNewLocation, setShowNewLocation] = useState(false);
  const [newLocationName, setNewLocationName] = useState('');
  const [newLocationAddress, setNewLocationAddress] = useState('');
  const [newLocationPhone, setNewLocationPhone] = useState('');
  const [autoAccept, setAutoAccept] = useState(false);

  // Optional fields
  const [note, setNote] = useState('');
  const [contactPhone, setContactPhone] = useState('');

  useEffect(() => {
    fetchLocations();
  }, [fetchLocations]);

  const accessibleLocations = useMemo(() => {
    if (!user) return [];
    return getAccessibleLocations(user, locations);
  }, [user, locations]);

  // Filtered locations based on search
  const filteredLocations = useMemo(() => {
    if (!locationSearch.trim()) return [];
    const q = removeDiacritics(locationSearch.trim());
    return accessibleLocations.filter((loc) => {
      const name = removeDiacritics(loc.name);
      const addr = removeDiacritics(loc.address);
      const phone = loc.phone ? removeDiacritics(loc.phone) : '';
      return name.includes(q) || addr.includes(q) || phone.includes(q);
    });
  }, [accessibleLocations, locationSearch]);

  // Selected location name for display
  const selectedLocationName = useMemo(() => {
    if (!locationId) return '';
    const loc = accessibleLocations.find((l) => l.id === locationId);
    return loc ? loc.name : '';
  }, [locationId, accessibleLocations]);

  const handleSelectLocation = (locId: string, locName: string) => {
    setLocationId(locId);
    setLocationSearch(locName);
    setShowLocationResults(false);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files) return;

    const newAttachments: Attachment[] = Array.from(files).map((file, i) => ({
      id: `att-${Date.now()}-${i}`,
      type: file.type.startsWith('video/') ? 'video' : 'image',
      url: URL.createObjectURL(file),
      name: file.name,
    }));

    setAttachments((prev) => [...prev, ...newAttachments]);
    e.target.value = '';
  };

  const removeAttachment = (id: string) => {
    setAttachments((prev) => prev.filter((a) => a.id !== id));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitError('');
    setFieldErrors({});

    let finalLocationId = locationId;

    // If adding new location, create it first
    if (showNewLocation) {
      if (!newLocationName.trim()) {
        setFieldErrors((prev) => ({ ...prev, locationId: 'Vui lòng nhập tên địa điểm mới' }));
        return;
      }
      try {
        const newLoc = await addLocation(
          newLocationName.trim(),
          newLocationAddress.trim(),
          newLocationPhone.trim() || undefined,
        );
        finalLocationId = newLoc.id;
      } catch {
        setSubmitError('Lỗi khi tạo địa điểm mới');
        return;
      }
    }

    // Validate using the validation service
    const validation = validateRepairRequest({
      machineName,
      locationId: finalLocationId,
      description,
      priority,
    });

    if (!validation.valid) {
      const errors: FieldErrors = {};
      for (const err of validation.errors) {
        if (err.includes('Tên máy')) errors.machineName = err;
        else if (err.includes('Địa điểm')) errors.locationId = err;
        else if (err.includes('Mô tả')) errors.description = err;
        else if (err.includes('ưu tiên')) errors.priority = err;
      }
      setFieldErrors(errors);
      return;
    }

    if (!user) return;

    setLoading(true);
    try {
      const result = await createRequest({
        machineName: machineName.trim(),
        locationId: finalLocationId,
        workspaceId: (() => {
          const loc = accessibleLocations.find((l) => l.id === finalLocationId);
          return loc?.workspaceId ?? '';
        })(),
        description: description.trim(),
        priority: priority as Priority,
        createdBy: user.id,
        attachments,
        note: note.trim() || undefined,
        contactPhone: contactPhone.trim() || undefined,
      });

      if (result.success) {
        // If technician and auto-accept is checked, accept the request immediately
        if (user.role === 'technician' && autoAccept) {
          const requests = useRepairStore.getState().requests;
          const newReq = requests[0]; // newest request is first
          if (newReq) {
            await updateStatus(newReq.id, 'accepted', { assignedTo: user.id });
          }
        }
        navigate('/requests');
      } else {
        setSubmitError(result.error ?? 'Lỗi khi tạo yêu cầu');
      }
    } catch {
      setSubmitError('Đã xảy ra lỗi. Vui lòng thử lại.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <motion.div
      style={styles.container}
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: [0.4, 0, 0.2, 1] }}
    >
      {/* Back button */}
      <motion.button
        style={styles.backButton}
        onClick={() => navigate(-1)}
        whileTap={{ scale: 0.95 }}
        aria-label="Quay lại"
      >
        ← Quay lại
      </motion.button>

      <h1 style={styles.title}>Tạo yêu cầu sửa chữa</h1>

      <GlowCard>
        <form onSubmit={handleSubmit} style={styles.form}>
          {/* Machine Name */}
          <div style={styles.field}>
            <label htmlFor="machineName" style={styles.label}>
              Tên máy <span style={styles.required}>*</span>
            </label>
            <input
              id="machineName"
              type="text"
              value={machineName}
              onChange={(e) => setMachineName(e.target.value)}
              placeholder="Nhập tên máy"
              style={{
                ...styles.input,
                ...(fieldErrors.machineName ? styles.inputError : {}),
              }}
              disabled={loading}
            />
            {fieldErrors.machineName && (
              <motion.span style={styles.errorText} initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }}>
                {fieldErrors.machineName}
              </motion.span>
            )}
          </div>

          {/* Location - Search based */}
          <div style={styles.field}>
            <label htmlFor="locationSearch" style={styles.label}>
              Địa điểm <span style={styles.required}>*</span>
            </label>
            {!showNewLocation ? (
              <>
                <div style={{ position: 'relative' }}>
                  <input
                    id="locationSearch"
                    type="text"
                    value={locationSearch}
                    onChange={(e) => {
                      setLocationSearch(e.target.value);
                      setLocationId('');
                      setShowLocationResults(true);
                    }}
                    onFocus={() => setShowLocationResults(true)}
                    placeholder="Tìm kiếm địa điểm (tên, địa chỉ, SĐT)..."
                    style={{
                      ...styles.input,
                      ...(fieldErrors.locationId ? styles.inputError : {}),
                    }}
                    disabled={loading}
                    autoComplete="off"
                  />
                  {showLocationResults && locationSearch.trim() && (
                    <div style={styles.searchResults}>
                      {filteredLocations.length === 0 ? (
                        <div style={styles.searchResultItem}>
                          <span style={{ color: 'var(--color-text-secondary)', fontSize: '0.85rem' }}>
                            Không tìm thấy địa điểm
                          </span>
                        </div>
                      ) : (
                        filteredLocations.map((loc) => (
                          <div
                            key={loc.id}
                            style={{
                              ...styles.searchResultItem,
                              background: locationId === loc.id ? 'rgba(0, 212, 255, 0.1)' : 'transparent',
                            }}
                            onClick={() => handleSelectLocation(loc.id, loc.name)}
                          >
                            <div style={{ fontSize: '0.9rem', color: 'var(--color-text)', fontWeight: 500 }}>
                              {loc.name}
                            </div>
                            <div style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>
                              {loc.address}
                              {loc.phone && ` · ${loc.phone}`}
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  )}
                </div>
                {selectedLocationName && (
                  <span style={{ fontSize: '0.8rem', color: 'var(--color-primary)' }}>
                    ✓ Đã chọn: {selectedLocationName}
                  </span>
                )}
                <button
                  type="button"
                  onClick={() => { setShowNewLocation(true); setLocationId(''); setLocationSearch(''); }}
                  style={styles.linkButton}
                >
                  + Thêm địa điểm mới
                </button>
              </>
            ) : (
              <>
                <input
                  type="text"
                  value={newLocationName}
                  onChange={(e) => setNewLocationName(e.target.value)}
                  placeholder="Tên địa điểm mới *"
                  style={{
                    ...styles.input,
                    ...(fieldErrors.locationId ? styles.inputError : {}),
                  }}
                  disabled={loading}
                />
                <input
                  type="text"
                  value={newLocationAddress}
                  onChange={(e) => setNewLocationAddress(e.target.value)}
                  placeholder="Địa chỉ (tùy chọn)"
                  style={styles.input}
                  disabled={loading}
                />
                <input
                  type="tel"
                  value={newLocationPhone}
                  onChange={(e) => setNewLocationPhone(e.target.value)}
                  placeholder="Số điện thoại (tùy chọn)"
                  style={styles.input}
                  disabled={loading}
                />
                <button
                  type="button"
                  onClick={() => { setShowNewLocation(false); setNewLocationName(''); setNewLocationAddress(''); setNewLocationPhone(''); }}
                  style={styles.linkButton}
                >
                  ← Chọn địa điểm có sẵn
                </button>
              </>
            )}
            {fieldErrors.locationId && (
              <motion.span style={styles.errorText} initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }}>
                {fieldErrors.locationId}
              </motion.span>
            )}
          </div>

          {/* Description */}
          <div style={styles.field}>
            <label htmlFor="description" style={styles.label}>
              Mô tả lỗi <span style={styles.required}>*</span>
            </label>
            <textarea
              id="description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Mô tả chi tiết lỗi của máy"
              rows={4}
              style={{
                ...styles.input,
                ...styles.textarea,
                ...(fieldErrors.description ? styles.inputError : {}),
              }}
              disabled={loading}
            />
            {fieldErrors.description && (
              <motion.span style={styles.errorText} initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }}>
                {fieldErrors.description}
              </motion.span>
            )}
          </div>

          {/* Priority */}
          <div style={styles.field}>
            <label htmlFor="priority" style={styles.label}>
              Mức độ ưu tiên <span style={styles.required}>*</span>
            </label>
            <select
              id="priority"
              value={priority}
              onChange={(e) => setPriority(e.target.value as Priority | '')}
              style={{
                ...styles.input,
                ...styles.select,
                ...(fieldErrors.priority ? styles.inputError : {}),
              }}
              disabled={loading}
            >
              <option value="">Chọn mức độ ưu tiên</option>
              {PRIORITY_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
            {fieldErrors.priority && (
              <motion.span style={styles.errorText} initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }}>
                {fieldErrors.priority}
              </motion.span>
            )}
          </div>

          {/* Note (optional) */}
          <div style={styles.field}>
            <label htmlFor="note" style={styles.label}>
              Ghi chú
            </label>
            <textarea
              id="note"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Ghi chú thêm (không bắt buộc)"
              rows={2}
              style={{ ...styles.input, ...styles.textarea, minHeight: '60px' }}
              disabled={loading}
            />
          </div>

          {/* Contact Phone (optional) */}
          <div style={styles.field}>
            <label htmlFor="contactPhone" style={styles.label}>
              Số điện thoại liên hệ
            </label>
            <input
              id="contactPhone"
              type="tel"
              value={contactPhone}
              onChange={(e) => setContactPhone(e.target.value)}
              placeholder="Nhập số điện thoại (không bắt buộc)"
              style={styles.input}
              disabled={loading}
            />
          </div>

          {/* File Attachment with preview */}
          <div style={styles.field}>
            <label style={styles.label}>
              Đính kèm hình ảnh / video
            </label>
            <label style={styles.uploadLabel}>
              📷 Chọn ảnh / video
              <input
                type="file"
                accept="image/*,video/*"
                multiple
                onChange={handleFileChange}
                style={{ display: 'none' }}
                disabled={loading}
              />
            </label>
            {attachments.length > 0 && (
              <div style={styles.previewGrid}>
                {attachments.map((att) => (
                  <div key={att.id} style={styles.previewWrapper}>
                    {att.type === 'image' ? (
                      <img
                        src={att.url}
                        alt={att.name}
                        style={styles.previewImage}
                        onClick={() => window.open(att.url, '_blank')}
                      />
                    ) : (
                      <video
                        src={att.url}
                        style={styles.previewImage}
                        onClick={() => window.open(att.url, '_blank')}
                      />
                    )}
                    <button
                      type="button"
                      onClick={() => removeAttachment(att.id)}
                      style={styles.removeImageBtn}
                      aria-label={`Xóa ${att.name}`}
                    >
                      ✕
                    </button>
                    <span style={styles.previewName}>{att.name}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Auto-accept for technician */}
          {user?.role === 'technician' && (
            <div style={styles.checkboxField}>
              <label style={styles.checkboxLabel}>
                <input
                  type="checkbox"
                  checked={autoAccept}
                  onChange={(e) => setAutoAccept(e.target.checked)}
                  style={styles.checkbox}
                  disabled={loading}
                />
                Tự động tiếp nhận đơn này
              </label>
            </div>
          )}

          {/* Submit Error */}
          {submitError && (
            <motion.div style={styles.submitError} initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}>
              {submitError}
            </motion.div>
          )}

          {/* Submit Button */}
          <div style={styles.buttonWrapper}>
            {loading ? (
              <div style={styles.spinnerWrapper}>
                <LoadingSpinner size="sm" />
              </div>
            ) : (
              <AnimatedButton>Tạo yêu cầu</AnimatedButton>
            )}
          </div>
        </form>
      </GlowCard>
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
  title: {
    fontSize: '1.5rem',
    fontWeight: 700,
    color: 'var(--color-primary)',
    margin: 0,
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: '18px',
  },
  field: {
    display: 'flex',
    flexDirection: 'column',
    gap: '6px',
  },
  label: {
    fontSize: '0.85rem',
    color: 'var(--color-text-secondary)',
    fontWeight: 500,
  },
  required: {
    color: 'var(--color-error)',
  },
  input: {
    background: 'var(--color-bg)',
    color: 'var(--color-text)',
    border: '1px solid var(--color-surface-light)',
    borderRadius: '8px',
    padding: '12px',
    fontSize: '1rem',
    width: '100%',
    transition: 'border-color var(--anim-fast) var(--anim-easing)',
    boxSizing: 'border-box' as const,
  },
  inputError: {
    borderColor: 'var(--color-error)',
  },
  select: {
    appearance: 'auto' as React.CSSProperties['appearance'],
  },
  textarea: {
    resize: 'vertical' as const,
    minHeight: '100px',
    fontFamily: 'inherit',
  },
  searchResults: {
    position: 'absolute' as const,
    top: '100%',
    left: 0,
    right: 0,
    background: 'var(--color-surface, #12121a)',
    border: '1px solid var(--color-surface-light)',
    borderRadius: '0 0 8px 8px',
    maxHeight: '200px',
    overflowY: 'auto' as const,
    zIndex: 10,
  },
  searchResultItem: {
    padding: '10px 12px',
    cursor: 'pointer',
    borderBottom: '1px solid var(--color-surface-light)',
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
    alignSelf: 'flex-start',
  },
  previewGrid: {
    display: 'flex',
    flexWrap: 'wrap' as const,
    gap: '8px',
    marginTop: '4px',
  },
  previewWrapper: {
    position: 'relative' as const,
    display: 'flex',
    flexDirection: 'column' as const,
    alignItems: 'center',
    width: '80px',
  },
  previewImage: {
    width: '80px',
    height: '80px',
    objectFit: 'cover' as const,
    borderRadius: '8px',
    border: '1px solid var(--color-surface-light)',
    cursor: 'pointer',
  },
  previewName: {
    fontSize: '0.65rem',
    color: 'var(--color-text-secondary)',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap' as const,
    width: '80px',
    textAlign: 'center' as const,
    marginTop: '2px',
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
  errorText: {
    color: 'var(--color-error)',
    fontSize: '0.8rem',
  },
  submitError: {
    color: 'var(--color-error)',
    fontSize: '0.875rem',
    padding: '10px 12px',
    background: 'rgba(255, 68, 102, 0.1)',
    borderRadius: '8px',
    border: '1px solid rgba(255, 68, 102, 0.25)',
  },
  buttonWrapper: {
    marginTop: '4px',
  },
  spinnerWrapper: {
    display: 'flex',
    justifyContent: 'center',
    padding: '8px 0',
  },
  linkButton: {
    background: 'none',
    border: 'none',
    color: 'var(--color-primary)',
    fontSize: '0.8rem',
    fontWeight: 500,
    cursor: 'pointer',
    padding: '4px 0',
    alignSelf: 'flex-start',
    textDecoration: 'none',
  },
  checkboxField: {
    display: 'flex',
    alignItems: 'center',
  },
  checkboxLabel: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    fontSize: '0.9rem',
    color: 'var(--color-text)',
    cursor: 'pointer',
  },
  checkbox: {
    width: '18px',
    height: '18px',
    accentColor: 'var(--color-primary)',
    cursor: 'pointer',
  },
};
