import { useWorkspaceStore } from '../../stores/workspaceStore';

interface WorkspaceBadgeProps {
  workspaceId: string;
}

const DEFAULT_COLOR = '#888888';

export function WorkspaceBadge({ workspaceId }: WorkspaceBadgeProps) {
  const workspaces = useWorkspaceStore((s) => s.workspaces);
  const ws = workspaces.find((w) => w.id === workspaceId);
  if (!ws) return null;

  const color = ws.color || DEFAULT_COLOR;

  return (
    <span
      style={{
        ...badgeStyle,
        color,
        background: `${color}14`,
        borderColor: `${color}30`,
        borderLeftColor: color,
      }}
    >
      {ws.logo || '🏢'} {ws.name}
    </span>
  );
}

const badgeStyle: React.CSSProperties = {
  fontSize: '0.72rem',
  fontWeight: 600,
  padding: '3px 8px',
  borderRadius: '6px',
  border: '1px solid',
  borderLeftWidth: '3px',
  whiteSpace: 'nowrap',
  display: 'inline-block',
  marginTop: '4px',
  marginBottom: '2px',
};
