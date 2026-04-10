import type { Priority, RepairStatus } from '../../types/repair';

export const STATUS_COLORS: Record<RepairStatus, string> = {
  new: 'var(--color-primary)',
  accepted: 'var(--color-secondary)',
  in_progress: 'var(--color-warning)',
  completed: 'var(--color-success)',
  cancelled: 'var(--color-error)',
};

export const STATUS_LABELS: Record<RepairStatus, string> = {
  new: 'Mới tạo',
  accepted: 'Đã tiếp nhận',
  in_progress: 'Đang xử lý',
  completed: 'Hoàn thành',
  cancelled: 'Đã hủy',
};

export const PRIORITY_COLORS: Record<Priority, string> = {
  critical: 'var(--color-error)',
  high: 'var(--color-warning)',
  medium: 'var(--color-primary)',
  low: 'var(--color-text-secondary)',
};

export const PRIORITY_LABELS: Record<Priority, string> = {
  critical: 'Khẩn cấp',
  high: 'Cao',
  medium: 'Trung bình',
  low: 'Thấp',
};

export const ALL_STATUSES: RepairStatus[] = ['new', 'accepted', 'in_progress', 'completed', 'cancelled'];

export const STATUS_SORT_ORDER: Record<RepairStatus, number> = {
  new: 0,
  in_progress: 1,
  accepted: 2,
  completed: 3,
  cancelled: 4,
};
