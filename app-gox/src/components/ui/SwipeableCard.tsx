import { motion, useMotionValue, useTransform, type PanInfo } from 'framer-motion';
import type { ReactNode } from 'react';

interface SwipeableCardProps {
  children: ReactNode;
  onSwipeLeft?: () => void;
  onSwipeRight?: () => void;
  className?: string;
}

const SWIPE_THRESHOLD = 80;

export function SwipeableCard({
  children,
  onSwipeLeft,
  onSwipeRight,
  className,
}: SwipeableCardProps) {
  const x = useMotionValue(0);
  const leftIndicatorOpacity = useTransform(x, [-SWIPE_THRESHOLD, 0], [1, 0]);
  const rightIndicatorOpacity = useTransform(x, [0, SWIPE_THRESHOLD], [0, 1]);

  const handleDragEnd = (_: unknown, info: PanInfo) => {
    const offset = info.offset.x;
    if (offset < -SWIPE_THRESHOLD && onSwipeLeft) {
      onSwipeLeft();
    } else if (offset > SWIPE_THRESHOLD && onSwipeRight) {
      onSwipeRight();
    }
  };

  return (
    <div style={{ position: 'relative', overflow: 'hidden', borderRadius: '12px' }}>
      <motion.div
        style={{
          position: 'absolute', inset: 0, display: 'flex', alignItems: 'center',
          justifyContent: 'flex-end', paddingRight: '16px',
          background: 'rgba(0, 212, 255, 0.15)', borderRadius: '12px',
          opacity: leftIndicatorOpacity, pointerEvents: 'none',
        }}
      >
        <span style={{ color: 'var(--color-primary)', fontWeight: 600, fontSize: '14px' }}>Xem chi tiết</span>
      </motion.div>
      <motion.div
        style={{
          position: 'absolute', inset: 0, display: 'flex', alignItems: 'center',
          justifyContent: 'flex-start', paddingLeft: '16px',
          background: 'rgba(0, 255, 136, 0.15)', borderRadius: '12px',
          opacity: rightIndicatorOpacity, pointerEvents: 'none',
        }}
      >
        <span style={{ color: 'var(--color-success)', fontWeight: 600, fontSize: '14px' }}>Cập nhật</span>
      </motion.div>
      <motion.div
        className={className}
        style={{
          x, background: 'var(--color-surface)', borderRadius: '12px',
          border: '1px solid var(--color-surface-light)', padding: '16px',
          cursor: 'grab', position: 'relative', zIndex: 1, touchAction: 'pan-y',
        }}
        drag="x" dragConstraints={{ left: 0, right: 0 }} dragElastic={0.5}
        onDragEnd={handleDragEnd} whileTap={{ cursor: 'grabbing' }}
      >
        {children}
      </motion.div>
    </div>
  );
}
