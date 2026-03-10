import { motion } from 'framer-motion';

const versions = [
  { version: '1.2.0 (Stable)', date: '2026-03-10', url: 'https://agentapi.quanlymay.com/static/releases/GoPrinxAgent.exe', size: '12.5 MB' },
  { version: '1.0.0', date: '2026-01-15', url: 'https://agentapi.quanlymay.com/static/releases/GoPrinxAgent.exe', size: '10.2 MB' },
];

export default function DownloadPage() {
  return (
    <div style={{ padding: '20px 16px', maxWidth: 600, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
      >
        <h2 style={{ marginBottom: 8, color: 'var(--color-primary)', fontSize: '1.4rem', fontWeight: 700 }}>📥 Tải về GoPrinxAgent</h2>
        <p style={{ color: 'var(--color-text-secondary)', marginBottom: 24, fontSize: '0.88rem', lineHeight: 1.5 }}>
          Tải về bộ cài đặt GoPrinxAgent để cài lên các máy tính (Agent) cần quản lý máy in và máy photocopy trong mạng LAN.
        </p>

        <div style={{ display: 'grid', gap: 12 }}>
          {versions.map((v) => (
            <div
              key={v.version}
              style={{
                padding: '16px',
                background: 'var(--color-surface)',
                border: '1px solid var(--color-surface-light)',
                borderRadius: '12px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                boxShadow: '0 4px 12px rgba(0,0,0,0.05)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1 }}>
                <div style={{ background: 'rgba(var(--rgb-primary, 59, 130, 246), 0.1)', padding: '6px', borderRadius: '10px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <img src="https://agentapi.quanlymay.com/static/releases/icon.ico" alt="Agent Icon" style={{ width: '32px', height: '32px', display: 'block' }} />
                </div>
                <div>
                  <div style={{ fontWeight: 700, fontSize: '1rem', color: 'var(--color-text)' }}>
                    Phiên bản {v.version}
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--color-text-secondary)', marginTop: 4 }}>
                    Phát hành: {v.date} · {v.size}
                  </div>
                </div>
              </div>
              <a
                href={v.url}
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  padding: '10px 18px',
                  background: 'var(--color-primary)',
                  color: 'white',
                  borderRadius: '10px',
                  textDecoration: 'none',
                  fontSize: '0.82rem',
                  fontWeight: 600,
                  boxShadow: 'var(--glow-primary)',
                  textAlign: 'center',
                  minWidth: '80px',
                }}
              >
                Tải về
              </a>
            </div>
          ))}
        </div>

        <div style={{ 
          marginTop: '32px',
          padding: '20px',
          background: 'rgba(var(--rgb-primary, 59, 130, 246), 0.05)',
          borderRadius: '16px',
          border: '1px solid rgba(var(--rgb-primary, 59, 130, 246), 0.15)',
        }}>
          <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--color-primary)', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            💡 Hướng dẫn cài đặt
          </h3>
          <ul style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)', paddingLeft: '20px', margin: 0, display: 'flex', flexDirection: 'column', gap: '10px', lineHeight: 1.5 }}>
            <li>Tải file <strong>.exe</strong> về máy tính hoặc VPS cần giám sát.</li>
            <li>Chạy file cài đặt với quyền <strong>Administrator</strong>.</li>
            <li>Nhập <strong>Agent ID</strong> được cung cấp để định danh máy.</li>
            <li>Máy tính sẽ tự động xuất hiện trong tab <strong>Kỹ thuật</strong> sau khi khởi chạy thành công.</li>
          </ul>
        </div>
      </motion.div>
    </div>
  );
}
