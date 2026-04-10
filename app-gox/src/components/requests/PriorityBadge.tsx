import type { CSSProperties } from 'react';

import type { Priority } from '../../types/repair';
import { PRIORITY_COLORS, PRIORITY_LABELS } from './repairVisuals';

interface PriorityBadgeProps {
  priority: Priority;
  label?: string;
  style?: CSSProperties;
}

export function PriorityBadge({ priority, label, style }: PriorityBadgeProps) {
  const color = PRIORITY_COLORS[priority];
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
      {label ?? PRIORITY_LABELS[priority]}
    </span>
  );
}

const baseStyle: CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'center',
  padding: '4px 10px',
  borderRadius: '999px',
  border: '1px solid transparent',
  fontSize: '0.72rem',
  fontWeight: 700,
  lineHeight: 1.2,
  whiteSpace: 'nowrap',
};
