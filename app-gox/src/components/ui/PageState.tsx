import type { CSSProperties } from 'react';

import { LoadingSpinner } from './LoadingSpinner';

interface PageLoadingProps {
  message?: string;
}

interface EmptyStateProps {
  message: string;
  centered?: boolean;
}

export function PageLoading({ message }: PageLoadingProps) {
  return (
    <div style={styles.loadingContainer}>
      <LoadingSpinner size="lg" />
      {message && <span style={styles.loadingText}>{message}</span>}
    </div>
  );
}

export function EmptyState({ message, centered = false }: EmptyStateProps) {
  return (
    <p style={{ ...styles.emptyText, textAlign: centered ? 'center' : 'left' }}>
      {message}
    </p>
  );
}

const styles: Record<string, CSSProperties> = {
  loadingContainer: {
    minHeight: '100vh',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '14px',
  },
  loadingText: {
    fontSize: '0.85rem',
    color: 'var(--color-text-secondary)',
  },
  emptyText: {
    margin: 0,
    fontSize: '0.85rem',
    color: 'var(--color-text-secondary)',
    lineHeight: 1.5,
  },
};
