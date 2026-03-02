import { create } from 'zustand';
import type { RepairStatus } from '../types/repair';

export type NotificationType = 'success' | 'error' | 'info';

export interface Notification {
  id: string;
  message: string;
  type: NotificationType;
  createdAt: number;
}

interface NotificationStore {
  notifications: Notification[];
  showNotification: (message: string, type: NotificationType) => void;
  removeNotification: (id: string) => void;
  clearAll: () => void;
}

let notificationCounter = 0;

export const useNotificationStore = create<NotificationStore>((set) => ({
  notifications: [],

  showNotification: (message, type) => {
    const id = `notification-${++notificationCounter}-${Date.now()}`;
    const notification: Notification = {
      id,
      message,
      type,
      createdAt: Date.now(),
    };

    set((state) => ({
      notifications: [...state.notifications, notification],
    }));

    // Auto-dismiss after 3 seconds
    setTimeout(() => {
      set((state) => ({
        notifications: state.notifications.filter((n) => n.id !== id),
      }));
    }, 3000);
  },

  removeNotification: (id) => {
    set((state) => ({
      notifications: state.notifications.filter((n) => n.id !== id),
    }));
  },

  clearAll: () => {
    set({ notifications: [] });
  },
}));

/** Convenience function — callable from anywhere without hooks */
export function showNotification(message: string, type: NotificationType = 'info'): void {
  useNotificationStore.getState().showNotification(message, type);
}

/** Vietnamese status-change messages */
const statusChangeMessages: Record<string, string> = {
  'new→accepted': 'Yêu cầu đã được tiếp nhận',
  'accepted→in_progress': 'Đã bắt đầu xử lý yêu cầu',
  'in_progress→completed': 'Yêu cầu đã hoàn thành',
  'new→cancelled': 'Yêu cầu đã bị hủy',
};

/** Notify on repair-request status transition */
export function notifyStatusChange(fromStatus: RepairStatus, toStatus: RepairStatus): void {
  const key = `${fromStatus}→${toStatus}`;
  const message = statusChangeMessages[key];
  if (message) {
    const type: NotificationType = toStatus === 'cancelled' ? 'info' : 'success';
    showNotification(message, type);
  }
}
