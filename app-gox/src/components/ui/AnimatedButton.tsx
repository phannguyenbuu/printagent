import { motion } from 'framer-motion';
import type { ReactNode } from 'react';

type ButtonVariant = 'primary' | 'secondary' | 'danger';

interface AnimatedButtonProps {
  children: ReactNode;
  onClick?: () => void;
  variant?: ButtonVariant;
  disabled?: boolean;
  className?: string;
}

const variantStyles: Record<ButtonVariant, { color: string; borderColor: string; glowColor: string }> = {
  primary: {
    color: 'var(--color-primary)',
    borderColor: 'var(--color-primary)',
    glowColor: 'var(--glow-primary)',
  },
  secondary: {
    color: 'var(--color-secondary)',
    borderColor: 'var(--color-secondary)',
    glowColor: 'var(--glow-secondary)',
  },
  danger: {
    color: 'var(--color-error)',
    borderColor: 'var(--color-error)',
    glowColor: '0 0 20px color-mix(in srgb, var(--color-error) 40%, transparent)',
  },
};

export function AnimatedButton({
  children,
  onClick,
  variant = 'primary',
  disabled = false,
  className,
}: AnimatedButtonProps) {
  const styles = variantStyles[variant];

  return (
    <motion.button
      className={className}
      onClick={onClick}
      disabled={disabled}
      style={{
        background: 'var(--color-surface)',
        color: styles.color,
        border: `1px solid ${styles.borderColor}`,
        borderRadius: '8px',
        padding: '12px 24px',
        fontSize: '1rem',
        fontWeight: 600,
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.5 : 1,
        width: '100%',
        position: 'relative',
        overflow: 'hidden',
      }}
      whileHover={
        disabled
          ? {}
          : {
              boxShadow: styles.glowColor,
              borderColor: styles.color,
            }
      }
      whileTap={
        disabled
          ? {}
          : {
              scale: 0.97,
              boxShadow: styles.glowColor,
            }
      }
      transition={{
        duration: 0.2,
        ease: [0.4, 0, 0.2, 1],
      }}
    >
      {children}
    </motion.button>
  );
}
