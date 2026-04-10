import type { CSSProperties } from 'react';

import type { Location } from '../../types/location';

interface RequestLocationBlockProps {
  location?: Location | null;
  fallbackLabel?: string;
  showName?: boolean;
  showAddress?: boolean;
  showPhone?: boolean;
  namePrefix?: string;
  addressPrefix?: string;
  phonePrefix?: string;
  style?: CSSProperties;
}

export function RequestLocationBlock({
  location,
  fallbackLabel = '',
  showName = true,
  showAddress = true,
  showPhone = true,
  namePrefix = '📍 ',
  addressPrefix = '',
  phonePrefix = '📞 ',
  style,
}: RequestLocationBlockProps) {
  if (!location && !fallbackLabel) return null;
  if (!location) {
    return <span style={{ ...styles.detail, ...style }}>{fallbackLabel}</span>;
  }

  return (
    <div style={{ ...styles.container, ...style }}>
      {showName && (
        <span style={styles.name}>
          {namePrefix}
          {location.name}
        </span>
      )}
      {showAddress && location.address && (
        <span style={styles.detail}>
          {addressPrefix}
          {location.address}
        </span>
      )}
      {showPhone && location.phone && (
        <span style={styles.detail}>
          {phonePrefix}
          {location.phone}
        </span>
      )}
    </div>
  );
}

const styles: Record<string, CSSProperties> = {
  container: {
    display: 'flex',
    flexDirection: 'column',
    gap: '3px',
  },
  name: {
    fontSize: '0.8rem',
    color: 'var(--color-text)',
    fontWeight: 600,
  },
  detail: {
    fontSize: '0.78rem',
    color: 'var(--color-text-secondary)',
    lineHeight: 1.4,
  },
};
