import type { CSSProperties } from 'react';

import type { RepairStatus } from '../../types/repair';
import { STATUS_COLORS, STATUS_LABELS } from './repairVisuals';

interface StatusBadgeProps {
  status: RepairStatus;
  label?: string;
  style?: CSSProperties;
}

export function StatusBadge({ status, label, style }: StatusBadgeProps) {
  const color = STATUS_COLORS[status];
  return (
    <span
      style={{
        ...baseStyle,
        background: `${color}20`,
        color,
        borderColor: `${color}40`,
        ...style,
      }}
    >
      {label ?? STATUS_LABELS[status]}
    </span>
  );
}

const baseStyle: CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'center',
  gap: '4px',
  padding: '4px 10px',
  borderRadius: '999px',
  border: '1px solid transparent',
  fontSize: '0.72rem',
  fontWeight: 700,
  lineHeight: 1.2,
  whiteSpace: 'nowrap',
};
