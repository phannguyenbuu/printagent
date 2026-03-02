export const neuralinkTheme = {
  colors: {
    background: '#0a0a0f',
    surface: '#12121a',
    surfaceLight: '#1a1a2e',
    primary: '#00d4ff',
    secondary: '#7b2ff7',
    accent: '#00ff88',
    text: '#e0e0e0',
    textSecondary: '#8888aa',
    error: '#ff4466',
    warning: '#ffaa00',
    success: '#00ff88',
    glow: '0 0 20px rgba(0, 212, 255, 0.3)',
  },
  animation: {
    fast: '200ms',
    normal: '350ms',
    slow: '500ms',
    easing: 'cubic-bezier(0.4, 0, 0.2, 1)',
  },
} as const;

export const neuralinkLightTheme = {
  colors: {
    background: '#f5f7ff',
    surface: '#ffffff',
    surfaceLight: '#dde3f5',
    primary: '#0066bb',
    secondary: '#5c16b8',
    accent: '#007a3d',
    text: '#111827',
    textSecondary: '#4b5563',
    error: '#b91c1c',
    warning: '#b45309',
    success: '#15803d',
    glow: '0 2px 12px rgba(0, 102, 187, 0.18)',
  },
  animation: {
    fast: '200ms',
    normal: '350ms',
    slow: '500ms',
    easing: 'cubic-bezier(0.4, 0, 0.2, 1)',
  },
} as const;

export type Theme = 'dark' | 'light';
