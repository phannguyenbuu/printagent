import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useNotificationStore, type NotificationType } from '../../services/notificationService';

// Inline style approach using CSS variables directly
const typeStyles: Record<NotificationType, React.CSSProperties> = {
  success: {
    background: 'color-mix(in srgb, var(--color-success) 12%, var(--color-surface))',
    border: '1px solid var(--color-success)',
    color: 'var(--color-text)',
    boxShadow: '0 4px 16px rgba(0,0,0,0.12)',
  },
  error: {
    background: 'color-mix(in srgb, var(--color-error) 12%, var(--color-surface))',
    border: '1px solid var(--color-error)',
    color: 'var(--color-text)',
    boxShadow: '0 4px 16px rgba(0,0,0,0.12)',
  },
  info: {
    background: 'color-mix(in srgb, var(--color-primary) 12%, var(--color-surface))',
    border: '1px solid var(--color-primary)',
    color: 'var(--color-text)',
    boxShadow: '0 4px 16px rgba(0,0,0,0.12)',
  },
};

const ToastContainer: React.FC = () => {
  const { notifications, removeNotification } = useNotificationStore();

  return (
    <div
      style={{
        position: 'fixed',
        top: 16,
        left: '50%',
        transform: 'translateX(-50%)',
        zIndex: 9999,
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
        width: '90%',
        maxWidth: 400,
        pointerEvents: 'none',
      }}
    >
      <AnimatePresence>
        {notifications.map((n) => (
          <motion.div
            key={n.id}
            initial={{ opacity: 0, y: -20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -10, scale: 0.95 }}
            transition={{ duration: 0.25, ease: [0.4, 0, 0.2, 1] }}
            onClick={() => removeNotification(n.id)}
            style={{
              pointerEvents: 'auto',
              cursor: 'pointer',
              borderRadius: 10,
              padding: '12px 16px',
              fontSize: 14,
              fontWeight: 500,
              backdropFilter: 'blur(12px)',
              ...typeStyles[n.type],
            }}
          >
            {n.message}
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
};

export default ToastContainer;
