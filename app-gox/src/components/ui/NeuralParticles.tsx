import { useEffect, useMemo, useState } from 'react';
import Particles, { initParticlesEngine } from '@tsparticles/react';
import { loadSlim } from '@tsparticles/slim';
import type { ISourceOptions } from '@tsparticles/engine';

export function NeuralParticles() {
  const [ready, setReady] = useState(false);

  useEffect(() => {
    initParticlesEngine(async (engine) => {
      await loadSlim(engine);
    }).then(() => setReady(true));
  }, []);

  const options: ISourceOptions = useMemo(
    () => ({
      fullScreen: false,
      background: { color: { value: 'transparent' } },
      fpsLimit: 60,
      particles: {
        color: { value: '#00d4ff' },
        links: {
          enable: true,
          color: '#00d4ff',
          opacity: 0.15,
          distance: 150,
          width: 1,
        },
        move: {
          enable: true,
          speed: 0.8,
          direction: 'none' as const,
          random: true,
          straight: false,
          outModes: { default: 'bounce' as const },
        },
        number: {
          value: 50,
          density: { enable: true },
        },
        opacity: {
          value: { min: 0.4, max: 0.7 },
        },
        size: {
          value: { min: 1, max: 3 },
        },
        shape: { type: 'circle' },
      },
      detectRetina: true,
    }),
    [],
  );

  if (!ready) return null;

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        zIndex: 0,
        pointerEvents: 'none',
      }}
    >
      <Particles id="neural-particles" options={options} />
    </div>
  );
}
