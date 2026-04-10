import type { CSSProperties } from 'react';

import type { RepairStatus } from '../../types/repair';
import { STATUS_COLORS, STATUS_LABELS } from './repairVisuals';

interface StatusStatCardProps {
  status: RepairStatus;
  value: number;
  compact?: boolean;
}

export function StatusStatCard({ status, value, compact = false }: StatusStatCardProps) {
  const color = STATUS_COLORS[status];
  return (
    <div
      style={{
        ...styles.card,
        padding: compact ? '10px 8px' : '12px 10px',
        borderColor: `${color}40`,
        background: `${color}0d`,
      }}
    >
      <span style={{ ...styles.value, color }}>{value}</span>
      <span style={styles.label}>{STATUS_LABELS[status]}</span>
    </div>
  );
}

const styles: Record<string, CSSProperties> = {
  card: {
    borderRadius: '12px',
    border: '1px solid transparent',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    gap: '4px',
    minWidth: 0,
  },
  value: {
    fontSize: '1.25rem',
    fontWeight: 800,
    lineHeight: 1,
  },
  label: {
    fontSize: '0.72rem',
    textAlign: 'center',
    color: 'var(--color-text-secondary)',
    lineHeight: 1.35,
  },
};
