import { motion } from 'framer-motion';

type SpinnerSize = 'sm' | 'md' | 'lg';

interface LoadingSpinnerProps {
  size?: SpinnerSize;
}

const sizeMap: Record<SpinnerSize, number> = {
  sm: 32,
  md: 48,
  lg: 72,
};

const dotCount = 8;

export function LoadingSpinner({ size = 'md' }: LoadingSpinnerProps) {
  const dimension = sizeMap[size];
  const radius = dimension / 2 - 6;
  const dotSize = size === 'sm' ? 4 : size === 'md' ? 5 : 7;

  return (
    <div
      style={{
        width: dimension,
        height: dimension,
        position: 'relative',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      {Array.from({ length: dotCount }).map((_, i) => {
        const angle = (i / dotCount) * Math.PI * 2;
        const x = Math.cos(angle) * radius;
        const y = Math.sin(angle) * radius;

        return (
          <motion.div
            key={i}
            style={{
              position: 'absolute',
              width: dotSize,
              height: dotSize,
              borderRadius: '50%',
              background: 'var(--color-primary)',
              left: '50%',
              top: '50%',
              marginLeft: -dotSize / 2,
              marginTop: -dotSize / 2,
              x,
              y,
            }}
            animate={{
              opacity: [0.3, 1, 0.3],
              scale: [0.8, 1.3, 0.8],
              boxShadow: [
                '0 0 4px rgba(0, 212, 255, 0.2)',
                '0 0 12px rgba(0, 212, 255, 0.6)',
                '0 0 4px rgba(0, 212, 255, 0.2)',
              ],
            }}
            transition={{
              duration: 1.4,
              repeat: Infinity,
              delay: i * (1.4 / dotCount),
              ease: 'easeInOut',
            }}
          />
        );
      })}
    </div>
  );
}
