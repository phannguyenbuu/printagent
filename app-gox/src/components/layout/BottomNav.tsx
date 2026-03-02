import { motion } from 'framer-motion';
import { useLocation, useNavigate } from 'react-router-dom';

interface NavTab {
  label: string;
  icon: string;
  path: string;
}

const tabs: NavTab[] = [
  { label: 'Dashboard', icon: '📊', path: '/dashboard' },
  { label: 'Yêu cầu', icon: '📋', path: '/requests' },
  { label: 'Kỹ thuật', icon: '🖥️', path: '/agents' },
  { label: 'Địa điểm', icon: '📍', path: '/locations' },
  { label: 'Tài khoản', icon: '👤', path: '/account' },
];

export function BottomNav() {
  const location = useLocation();
  const navigate = useNavigate();

  const activeIndex = tabs.findIndex((tab) =>
    location.pathname.startsWith(tab.path)
  );

  return (
    <nav
      style={{
        position: 'fixed',
        bottom: 0,
        left: '50%',
        transform: 'translateX(-50%)',
        width: '100%',
        maxWidth: 428,
        background: 'var(--color-surface)',
        borderTop: '1px solid var(--color-surface-light)',
        display: 'flex',
        justifyContent: 'space-around',
        alignItems: 'center',
        height: 60,
        zIndex: 100,
      }}
    >
      {tabs.map((tab, index) => {
        const isActive = index === activeIndex;

        return (
          <button
            key={tab.path}
            onClick={() => navigate(tab.path)}
            style={{
              flex: 1,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 2,
              height: '100%',
              position: 'relative',
              background: 'none',
              border: 'none',
              padding: 0,
              cursor: 'pointer',
              color: isActive
                ? 'var(--color-primary)'
                : 'var(--color-text-secondary)',
              transition: 'color 200ms ease',
            }}
          >
            {isActive && (
              <motion.div
                layoutId="bottomNavIndicator"
                style={{
                  position: 'absolute',
                  top: 0,
                  left: '20%',
                  right: '20%',
                  height: 3,
                  borderRadius: '0 0 3px 3px',
                  background: 'var(--color-primary)',
                  boxShadow: 'var(--glow-primary)',
                }}
                transition={{ type: 'spring', stiffness: 400, damping: 30 }}
              />
            )}
            <span style={{ fontSize: 20, lineHeight: 1 }}>{tab.icon}</span>
            <span style={{ fontSize: 11, fontWeight: isActive ? 600 : 400 }}>
              {tab.label}
            </span>
          </button>
        );
      })}
    </nav>
  );
}
