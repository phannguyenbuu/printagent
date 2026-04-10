import type { CSSProperties, ReactNode } from 'react';

import type { RepairRequest } from '../../types/repair';
import { GlowCard } from '../ui/GlowCard';
import { WorkspaceBadge } from '../ui/WorkspaceBadge';
import { PriorityBadge } from './PriorityBadge';
import { StatusBadge } from './StatusBadge';

interface RequestCardProps {
  request: RepairRequest;
  onClick?: () => void;
  showWorkspace?: boolean;
  showPriority?: boolean;
  status?: RepairRequest['status'];
  metaTrailing?: ReactNode;
  locationContent?: ReactNode;
  description?: string;
  descriptionMaxLength?: number;
  footer?: ReactNode;
  style?: CSSProperties;
}

export function RequestCard({
  request,
  onClick,
  showWorkspace = true,
  showPriority = true,
  status,
  metaTrailing,
  locationContent,
  description,
  descriptionMaxLength = 80,
  footer,
  style,
}: RequestCardProps) {
  const statusValue = status ?? request.status;
  const displayDescription = typeof description === 'string' ? description.trim() : '';
  const trimmedDescription = displayDescription
    ? (
        displayDescription.length > descriptionMaxLength
          ? `${displayDescription.slice(0, descriptionMaxLength)}...`
          : displayDescription
      )
    : '';

  return (
    <GlowCard onClick={onClick}>
      <div style={{ ...styles.container, ...style }}>
        <div style={styles.header}>
          <span style={styles.machineName}>{request.machineName}</span>
          <StatusBadge status={statusValue} />
        </div>

        {showWorkspace && <WorkspaceBadge workspaceId={request.workspaceId} />}

        {(showPriority || metaTrailing) && (
          <div style={styles.metaRow}>
            {showPriority && <PriorityBadge priority={request.priority} />}
            {metaTrailing}
          </div>
        )}

        {locationContent}

        {trimmedDescription && (
          <p style={styles.description}>{trimmedDescription}</p>
        )}

        {footer && <div style={styles.footer}>{footer}</div>}
      </div>
    </GlowCard>
  );
}

const styles: Record<string, CSSProperties> = {
  container: {
    display: 'flex',
    flexDirection: 'column',
    gap: '10px',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    gap: '10px',
  },
  machineName: {
    fontSize: '0.95rem',
    fontWeight: 700,
    color: 'var(--color-text)',
    lineHeight: 1.35,
    flex: 1,
    minWidth: 0,
  },
  metaRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: '10px',
    flexWrap: 'wrap',
  },
  description: {
    margin: 0,
    fontSize: '0.82rem',
    lineHeight: 1.5,
    color: 'var(--color-text-secondary)',
  },
  footer: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: '10px',
    flexWrap: 'wrap',
  },
};
