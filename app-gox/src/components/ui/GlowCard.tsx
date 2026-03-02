import { motion } from 'framer-motion';
import type { ReactNode } from 'react';

interface GlowCardProps {
  children: ReactNode;
  onClick?: () => void;
  className?: string;
}

export function GlowCard({ children, onClick, className }: GlowCardProps) {
  return (
    <motion.div
      className={className}
      onClick={onClick}
      style={{
        background: 'var(--color-surface)',
        borderRadius: '12px',
        border: '1px solid var(--color-surface-light)',
        padding: '16px',
        cursor: onClick ? 'pointer' : 'default',
        overflow: 'hidden',
      }}
      whileHover={{
        scale: 1.02,
        boxShadow: 'var(--glow-primary)',
        borderColor: 'var(--color-primary)',
      }}
      transition={{
        duration: 0.35,
        ease: [0.4, 0, 0.2, 1],
      }}
    >
      {children}
    </motion.div>
  );
}
