import type { ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { useWorkspaceStore } from '../../stores/workspaceStore';
import { BottomNav } from './BottomNav';

interface AppLayoutProps {
  children: ReactNode;
}

export function AppLayout({ children }: AppLayoutProps) {
  const activeIds = useWorkspaceStore((s) => s.activeIds);
  const workspaces = useWorkspaceStore((s) => s.workspaces);
  const navigate = useNavigate();

  const activeList = workspaces.filter((ws) => activeIds.includes(ws.id));
  const hasWorkspaces = activeList.length > 0;

  return (
    <div
      style={{
        minHeight: '100vh',
        paddingBottom: 70,
        paddingTop: hasWorkspaces ? 34 : 0,
        position: 'relative',
      }}
    >
      {/* Workspace bar */}
      {hasWorkspaces && (
        <div style={wsBarStyles.bar}>
          <div style={wsBarStyles.names}>
            {activeList.map((ws, i) => (
              <span key={ws.id} style={{ ...wsBarStyles.name, color: ws.color || 'var(--color-text)' }}>
                {ws.logo || '🏢'} {ws.name}{i < activeList.length - 1 ? ' · ' : ''}
              </span>
            ))}
          </div>
          <button
            style={wsBarStyles.switchBtn}
            onClick={() => navigate('/workspace', { replace: true })}
          >
            {activeList.length > 1 ? `${activeList.length} WS` : 'Đổi'} ↗
          </button>
        </div>
      )}
      {children}
      <BottomNav />
    </div>
  );
}

const wsBarStyles: Record<string, React.CSSProperties> = {
  bar: {
    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    padding: '6px 16px', gap: '8px',
    background: 'color-mix(in srgb, var(--color-primary) 8%, var(--color-surface))',
    borderBottom: '1px solid var(--color-surface-light)',
    position: 'fixed', top: 0, left: 0, right: 0, zIndex: 90,
  },
  names: {
    display: 'flex', alignItems: 'center', gap: '0',
    flex: 1, minWidth: 0, overflow: 'hidden',
  },
  name: {
    fontSize: '0.75rem', fontWeight: 600, color: 'var(--color-text)',
    whiteSpace: 'nowrap',
  },
  switchBtn: {
    background: 'none', border: '1px solid var(--color-surface-light)',
    borderRadius: '6px', padding: '3px 10px',
    fontSize: '0.72rem', fontWeight: 600, color: 'var(--color-primary)',
    cursor: 'pointer', flexShrink: 0,
  },
};
