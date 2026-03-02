import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import {
  useNotificationStore,
  showNotification,
  notifyStatusChange,
} from '../notificationService';

describe('notificationService', () => {
  beforeEach(() => {
    useNotificationStore.setState({ notifications: [] });
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('showNotification', () => {
    it('adds a notification to the store', () => {
      showNotification('Test message', 'info');
      const { notifications } = useNotificationStore.getState();
      expect(notifications).toHaveLength(1);
      expect(notifications[0].message).toBe('Test message');
      expect(notifications[0].type).toBe('info');
    });

    it('defaults to info type', () => {
      showNotification('Default type');
      const { notifications } = useNotificationStore.getState();
      expect(notifications[0].type).toBe('info');
    });

    it('auto-dismisses after 3 seconds', () => {
      showNotification('Will disappear', 'success');
      expect(useNotificationStore.getState().notifications).toHaveLength(1);

      vi.advanceTimersByTime(3000);
      expect(useNotificationStore.getState().notifications).toHaveLength(0);
    });

    it('supports multiple concurrent notifications', () => {
      showNotification('First', 'info');
      showNotification('Second', 'error');
      showNotification('Third', 'success');
      expect(useNotificationStore.getState().notifications).toHaveLength(3);
    });
  });

  describe('removeNotification', () => {
    it('removes a specific notification by id', () => {
      showNotification('Keep', 'info');
      showNotification('Remove', 'error');
      const { notifications } = useNotificationStore.getState();
      const removeId = notifications[1].id;

      useNotificationStore.getState().removeNotification(removeId);
      const updated = useNotificationStore.getState().notifications;
      expect(updated).toHaveLength(1);
      expect(updated[0].message).toBe('Keep');
    });
  });

  describe('clearAll', () => {
    it('removes all notifications', () => {
      showNotification('A', 'info');
      showNotification('B', 'error');
      useNotificationStore.getState().clearAll();
      expect(useNotificationStore.getState().notifications).toHaveLength(0);
    });
  });

  describe('notifyStatusChange', () => {
    it('shows success notification for new → accepted', () => {
      notifyStatusChange('new', 'accepted');
      const { notifications } = useNotificationStore.getState();
      expect(notifications).toHaveLength(1);
      expect(notifications[0].message).toBe('Yêu cầu đã được tiếp nhận');
      expect(notifications[0].type).toBe('success');
    });

    it('shows success notification for accepted → in_progress', () => {
      notifyStatusChange('accepted', 'in_progress');
      const { notifications } = useNotificationStore.getState();
      expect(notifications[0].message).toBe('Đã bắt đầu xử lý yêu cầu');
      expect(notifications[0].type).toBe('success');
    });

    it('shows success notification for in_progress → completed', () => {
      notifyStatusChange('in_progress', 'completed');
      const { notifications } = useNotificationStore.getState();
      expect(notifications[0].message).toBe('Yêu cầu đã hoàn thành');
      expect(notifications[0].type).toBe('success');
    });

    it('shows info notification for new → cancelled', () => {
      notifyStatusChange('new', 'cancelled');
      const { notifications } = useNotificationStore.getState();
      expect(notifications[0].message).toBe('Yêu cầu đã bị hủy');
      expect(notifications[0].type).toBe('info');
    });

    it('does not show notification for unmapped transitions', () => {
      notifyStatusChange('in_progress', 'in_progress');
      expect(useNotificationStore.getState().notifications).toHaveLength(0);
    });
  });
});
