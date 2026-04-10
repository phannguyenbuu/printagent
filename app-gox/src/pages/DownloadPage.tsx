import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

const API_BASE = import.meta.env.VITE_API_URL || 'https://agentapi.quanlymay.com';

/* ══════════════════════════════════════════════
   AGENT DOWNLOAD SECTION
══════════════════════════════════════════════ */
const versions = [
  { version: '1.2.0 (Stable)', date: '2026-03-10', url: `${API_BASE}/static/releases/GoPrinxAgent.exe`, size: '12.5 MB' },
  { version: '1.0.0', date: '2026-01-15', url: `${API_BASE}/static/releases/GoPrinxAgent.exe`, size: '10.2 MB' },
];

function AgentDownloadSection() {
  return (
    <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
      <p style={{ color: 'var(--color-text-secondary)', marginBottom: 16, fontSize: '0.87rem', lineHeight: 1.55 }}>
        Tải về bộ cài đặt GoPrinxAgent để cài lên các máy tính cần quản lý máy in trong mạng LAN.
      </p>
      <div style={{ display: 'grid', gap: 10 }}>
        {versions.map((v) => (
          <div key={v.version} style={{
            padding: '14px', background: 'var(--color-surface)',
            border: '1px solid var(--color-surface-light)', borderRadius: '12px',
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            boxShadow: '0 2px 8px rgba(0,0,0,0.06)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1 }}>
              <div style={{ background: 'rgba(59,130,246,0.1)', padding: '6px', borderRadius: '10px' }}>
                <img src={`${API_BASE}/static/releases/icon.ico`} alt="Agent" style={{ width: 30, height: 30, display: 'block' }} />
              </div>
              <div>
                <div style={{ fontWeight: 700, fontSize: '0.95rem', color: 'var(--color-text)' }}>Phiên bản {v.version}</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)', marginTop: 3 }}>
                  Phát hành: {v.date} · {v.size}
                </div>
              </div>
            </div>
            <a href={v.url} target="_blank" rel="noopener noreferrer" style={{
              padding: '9px 16px', background: 'var(--color-primary)', color: 'white',
              borderRadius: '10px', textDecoration: 'none', fontSize: '0.82rem', fontWeight: 600,
              boxShadow: 'var(--glow-primary)', whiteSpace: 'nowrap',
            }}>
              Tải về
            </a>
          </div>
        ))}
      </div>
      <div style={{
        marginTop: 20, padding: 16,
        background: 'rgba(59,130,246,0.05)', borderRadius: 14,
        border: '1px solid rgba(59,130,246,0.15)',
      }}>
        <h3 style={{ fontSize: '0.88rem', fontWeight: 700, color: 'var(--color-primary)', marginBottom: 10 }}>
          💡 Hướng dẫn cài đặt
        </h3>
        <ul style={{ fontSize: '0.82rem', color: 'var(--color-text-secondary)', paddingLeft: 18, margin: 0, display: 'flex', flexDirection: 'column', gap: 8, lineHeight: 1.5 }}>
          <li>Tải file <strong>.exe</strong> về máy tính cần giám sát.</li>
          <li>Chạy với quyền <strong>Administrator</strong>.</li>
          <li>Nhập <strong>Agent ID</strong> được cung cấp.</li>
          <li>Máy sẽ xuất hiện trong tab <strong>Kỹ thuật</strong> sau khi chạy.</li>
        </ul>
      </div>
    </motion.div>
  );
}

/* ══════════════════════════════════════════════
   PRINTER DRIVERS SECTION (from DriversPage)
══════════════════════════════════════════════ */
type Brand = 'ricoh' | 'toshiba' | 'fujifilm';

interface RicohModel { id: number; model: string; support_url?: string; drivers: Record<string, string>; }
interface ToshibaDriver { name: string; description: string; filename: string; version: string; date: string; download_url: string; }
interface ToshibaModel { category: string; model: string; slug: string; product_url: string; drivers: ToshibaDriver[]; total_windows_drivers: number; }
interface FujifilmModel { category: string; family: string; model: string; pid: string; all_links: string[]; }
type AnyModel = RicohModel | ToshibaModel | FujifilmModel;

const BRAND_CFG: Record<Brand, { label: string; color: string; emoji: string; placeholder: string; filters: string[] }> = {
  ricoh: { label: 'Ricoh', color: '#003087', emoji: '🔵', placeholder: 'Tìm Ricoh (MP 3054, IM C3500)...', filters: ['Tất cả', 'IM', 'IM C', 'MP', 'MP C', 'Aficio', 'SP', 'M'] },
  toshiba: { label: 'Toshiba', color: '#e4002b', emoji: '🔴', placeholder: 'Tìm Toshiba (e-STUDIO1208)...', filters: ['Tất cả', 'B/W COPIER', 'COLOR COPIER'] },
  fujifilm: { label: 'Fujifilm', color: '#00a040', emoji: '🟢', placeholder: 'Tìm Fujifilm (Apeos 5330)...', filters: ['Tất cả', 'ApeosPort', 'Apeos', 'DocuCentre', 'DocuPrint', 'ApeosPrint'] },
};

function modelName(m: AnyModel) { return (m as RicohModel).model || '—'; }
function driverCount(brand: Brand, m: AnyModel) {
  if (brand === 'ricoh') return Object.keys((m as RicohModel).drivers || {}).length;
  if (brand === 'toshiba') return (m as ToshibaModel).total_windows_drivers;
  if (brand === 'fujifilm') return ((m as FujifilmModel).all_links || []).length;
  return 0;
}
function modelMeta(brand: Brand, m: AnyModel) {
  if (brand === 'fujifilm') return (m as FujifilmModel).family || '';
  if (brand === 'toshiba') return (m as ToshibaModel).category || '';
  return '';
}
function matchFilter(brand: Brand, m: AnyModel, f: string) {
  if (f === 'Tất cả' || !f) return true;
  const name = modelName(m);
  if (brand === 'ricoh') {
    if (f === 'M') return /^M[ C]/.test(name);
    if (f === 'SP') return /^SP[ C]/.test(name);
    if (f === 'Aficio') return /^Aficio/.test(name);
    return name.startsWith(f + ' ');
  }
  if (brand === 'toshiba') return (m as ToshibaModel).category === f;
  if (brand === 'fujifilm') return (m as FujifilmModel).family === f;
  return true;
}

/* ─── Detail Panel ─── */
function DriverPanel({ brand, model, onClose }: { brand: Brand; model: AnyModel; onClose: () => void }) {
  const cfg = BRAND_CFG[brand];
  const name = modelName(model);

  const body = () => {
    if (brand === 'ricoh') {
      const entries = Object.entries((model as RicohModel).drivers || {});
      if (!entries.length) return <NoDriver label="Ricoh" url={(model as RicohModel).support_url} />;
      return <>
        <SLabel>Windows Print Drivers</SLabel>
        {entries.map(([type, url]) => <DRow key={type} name={type} sub={url.split('/').pop()!} url={url} ext="EXE" />)}
        {(model as RicohModel).support_url && <GLink url={(model as RicohModel).support_url!} label="Xem trên Ricoh Support" />}
      </>;
    }
    if (brand === 'toshiba') {
      const m = model as ToshibaModel;
      if (!m.drivers?.length) return <NoDriver label="Toshiba" url={m.product_url} />;
      return <>
        <SLabel>Print Drivers</SLabel>
        {m.drivers.map((d, i) => <DRow key={i} name={d.description || d.name} sub={`${d.version ? 'v' + d.version + ' · ' : ''}${d.date || ''}`} url={d.download_url} ext={(d.filename.split('.').pop() || 'zip').toUpperCase()} />)}
        <GLink url={m.product_url} label="Xem trên trang Toshiba" />
      </>;
    }
    if (brand === 'fujifilm') {
      const m = model as FujifilmModel;
      const exes = m.all_links.filter(u => u.endsWith('.exe'));
      const other = m.all_links.filter(u => !u.endsWith('.exe'));
      return <>
        {m.pid && <div style={{ fontSize: 11, color: 'var(--color-text-secondary)', marginBottom: 10 }}>Mã: <b>{m.pid}</b> · {m.family}</div>}
        {exes.length > 0 && <>
          <SLabel>Windows Drivers</SLabel>
          {exes.map((url, i) => {
            const fn = url.split('/').pop()!;
            let label = fn;
            if (/easysetup/i.test(fn)) label = '🔧 Easy Setup';
            else if (/pcl6/i.test(fn)) label = 'PCL6 Driver';
            else if (/ps[^a-z]/i.test(fn)) label = 'PostScript Driver';
            return <DRow key={i} name={label} sub={fn} url={url} ext="EXE" />;
          })}
        </>}
        {other.length > 0 && <>
          <SLabel>Tài liệu khác</SLabel>
          {other.map((url, i) => { const fn = url.split('/').pop()!; return <DRow key={i} name={fn} sub="" url={url} ext={fn.split('.').pop()?.toUpperCase() || 'FILE'} />; })}
        </>}
        <GLink url="https://support-fb.fujifilm.com/" label="Fujifilm Support Site" />
      </>;
    }
  };

  return <>
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose}
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.35)', zIndex: 200 }} />
    <motion.div initial={{ x: '100%' }} animate={{ x: 0 }} exit={{ x: '100%' }}
      transition={{ type: 'spring', stiffness: 380, damping: 35 }}
      style={{
        position: 'fixed', right: 0, top: 0, bottom: 0, width: 340, maxWidth: '95vw',
        background: 'var(--color-surface)', borderLeft: '1px solid var(--color-surface-light)',
        boxShadow: '-8px 0 32px rgba(0,0,0,0.18)', zIndex: 201, overflowY: 'auto'
      }}>
      <div style={{
        display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between',
        padding: '16px 16px 12px', borderBottom: '1px solid var(--color-surface-light)',
        position: 'sticky', top: 0, background: 'var(--color-surface)', zIndex: 2
      }}>
        <div>
          <div style={{
            fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em',
            color: cfg.color, background: `${cfg.color}18`, display: 'inline-block',
            padding: '2px 8px', borderRadius: 4, marginBottom: 3
          }}>{cfg.label}</div>
          <div style={{ fontWeight: 700, fontSize: '0.98rem', color: 'var(--color-text)' }}>{name}</div>
        </div>
        <button onClick={onClose}
          style={{ background: 'none', border: 'none', fontSize: 18, cursor: 'pointer', color: 'var(--color-text-secondary)' }}>✕</button>
      </div>
      <div style={{ padding: '14px 16px 32px' }}>{body()}</div>
    </motion.div>
  </>;
}

function SLabel({ children }: { children: React.ReactNode }) {
  return <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--color-text-secondary)', margin: '16px 0 7px' }}>{children}</div>;
}
function DRow({ name, sub, url, ext }: { name: string; sub: string; url: string; ext: string }) {
  return <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--color-surface-light)', gap: 8 }}>
    <div style={{ minWidth: 0 }}>
      <div style={{ fontWeight: 500, fontSize: 13, color: 'var(--color-text)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{name}</div>
      {sub && <div style={{ fontSize: 11, color: 'var(--color-text-secondary)', marginTop: 2 }}>{sub}</div>}
    </div>
    <a href={url} target="_blank" rel="noopener noreferrer"
      style={{
        flexShrink: 0, padding: '4px 10px', background: 'var(--color-primary)', color: '#fff',
        borderRadius: 6, fontSize: 11, fontWeight: 600, textDecoration: 'none', whiteSpace: 'nowrap'
      }}>
      ↓ {ext}
    </a>
  </div>;
}
function GLink({ url, label }: { url: string; label: string }) {
  return <div style={{ marginTop: 16, textAlign: 'center' }}>
    <a href={url} target="_blank" rel="noopener noreferrer"
      style={{
        display: 'inline-block', padding: '6px 14px', border: '1.5px solid var(--color-primary)',
        color: 'var(--color-primary)', borderRadius: 7, fontSize: 12, fontWeight: 600, textDecoration: 'none'
      }}>
      {label} →
    </a>
  </div>;
}
function NoDriver({ label, url }: { label: string; url?: string }) {
  return <div style={{ textAlign: 'center', padding: '24px 8px', color: 'var(--color-text-secondary)' }}>
    <div style={{ fontSize: 28, marginBottom: 8 }}>📄</div>
    <p style={{ fontSize: 13, marginBottom: 12 }}>Không có driver tải trực tiếp.</p>
    {url && <GLink url={url} label={`Xem trên ${label} Support`} />}
  </div>;
}

function PrinterDriversSection() {
  const [brand, setBrand] = useState<Brand>('ricoh');
  const [catalogs, setCatalogs] = useState<Record<Brand, AnyModel[] | null>>({ ricoh: null, toshiba: null, fujifilm: null });
  const [loading, setLoading] = useState<Record<Brand, boolean>>({ ricoh: false, toshiba: false, fujifilm: false });
  const [errMsg, setErrMsg] = useState<Record<Brand, string | null>>({ ricoh: null, toshiba: null, fujifilm: null });
  const [search, setSearch] = useState('');
  const [filter, setFilter] = useState('Tất cả');
  const [selected, setSelected] = useState<{ brand: Brand; model: AnyModel } | null>(null);

  const load = useCallback(async (b: Brand) => {
    if (catalogs[b] !== null || loading[b]) return;
    setLoading(p => ({ ...p, [b]: true }));
    try {
      const res = await fetch(`${API_BASE}/api/drivers/${b}`);
      const json = await res.json();
      if (json.ok) setCatalogs(p => ({ ...p, [b]: json.data }));
      else setErrMsg(p => ({ ...p, [b]: json.error || 'Lỗi tải catalog' }));
    } catch { setErrMsg(p => ({ ...p, [b]: 'Lỗi kết nối server' })); }
    finally { setLoading(p => ({ ...p, [b]: false })); }
  }, [catalogs, loading]);

  useEffect(() => { load(brand); setSearch(''); setFilter('Tất cả'); }, [brand]); // eslint-disable-line

  const cfg = BRAND_CFG[brand];
  const data = catalogs[brand] || [];
  const q = search.toLowerCase();
  const list = data.filter(m => (!q || modelName(m).toLowerCase().includes(q)) && matchFilter(brand, m, filter));

  return (
    <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
      {/* Brand tabs */}
      <div style={{ display: 'flex', borderBottom: '2px solid var(--color-surface-light)', marginBottom: 12 }}>
        {(Object.keys(BRAND_CFG) as Brand[]).map(b => (
          <button key={b} onClick={() => setBrand(b)} style={{
            flex: 1, padding: '8px 4px', background: 'none', border: 'none',
            borderBottom: brand === b ? `3px solid ${BRAND_CFG[b].color}` : '3px solid transparent',
            fontWeight: 700, fontSize: 13, color: brand === b ? BRAND_CFG[b].color : 'var(--color-text-secondary)',
            cursor: 'pointer', marginBottom: -2, transition: 'all 0.15s',
          }}>
            {BRAND_CFG[b].emoji} {BRAND_CFG[b].label}
          </button>
        ))}
      </div>

      {/* Search */}
      <input type="text" placeholder={cfg.placeholder} value={search}
        onChange={e => setSearch(e.target.value)}
        style={{
          width: '100%', padding: '9px 12px', border: '1.5px solid var(--color-surface-light)',
          borderRadius: 9, fontSize: 13, background: 'var(--color-surface)', color: 'var(--color-text)',
          outline: 'none', boxSizing: 'border-box', marginBottom: 8
        }} />

      {/* Filter chips */}
      <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: 8 }}>
        {cfg.filters.map(f => (
          <button key={f} onClick={() => setFilter(f)} style={{
            padding: '3px 10px', borderRadius: 20, fontSize: 11, fontWeight: 600,
            border: `1.5px solid ${filter === f ? cfg.color : 'var(--color-surface-light)'}`,
            background: filter === f ? cfg.color : 'transparent',
            color: filter === f ? '#fff' : 'var(--color-text-secondary)', cursor: 'pointer',
          }}>{f}</button>
        ))}
      </div>

      <div style={{ fontSize: 11, color: 'var(--color-text-secondary)', marginBottom: 6 }}>
        {loading[brand] ? 'Đang tải...' : `${list.length} models`}
      </div>

      {/* List */}
      <div style={{ border: '1.5px solid var(--color-surface-light)', borderRadius: 11, overflow: 'hidden' }}>
        {loading[brand] && <div style={{ padding: 28, textAlign: 'center', color: 'var(--color-text-secondary)', fontSize: 13 }}>⏳ Đang tải {cfg.label}...</div>}
        {errMsg[brand] && <div style={{ padding: 20, textAlign: 'center', color: '#e55', fontSize: 13 }}>⚠️ {errMsg[brand]}</div>}
        {!loading[brand] && !errMsg[brand] && list.length === 0 && (
          <div style={{ padding: 28, textAlign: 'center', color: 'var(--color-text-secondary)', fontSize: 13 }}>Không tìm thấy</div>
        )}
        {!loading[brand] && list.map((m, i) => {
          const cnt = driverCount(brand, m);
          const meta = modelMeta(brand, m);
          return (
            <div key={i} onClick={() => setSelected({ brand, model: m })}
              style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '10px 13px', borderBottom: i < list.length - 1 ? '1px solid var(--color-surface-light)' : 'none',
                cursor: 'pointer', background: 'var(--color-surface)', gap: 8, transition: 'background 0.12s'
              }}
              onMouseEnter={e => (e.currentTarget.style.background = `color-mix(in srgb, ${cfg.color} 6%, var(--color-surface))`)}
              onMouseLeave={e => (e.currentTarget.style.background = 'var(--color-surface)')}>
              <div style={{ minWidth: 0 }}>
                <div style={{ fontWeight: 500, fontSize: 13, color: 'var(--color-text)' }}>{modelName(m)}</div>
                {meta && <div style={{ fontSize: 11, color: 'var(--color-text-secondary)', marginTop: 1 }}>{meta}</div>}
              </div>
              {cnt > 0
                ? <span style={{ flexShrink: 0, fontSize: 11, fontWeight: 600, color: cfg.color, background: `${cfg.color}18`, padding: '2px 9px', borderRadius: 20 }}>↓ {cnt} file{cnt > 1 ? 's' : ''}</span>
                : <span style={{ flexShrink: 0, fontSize: 11, color: 'var(--color-text-secondary)' }}>→ Web</span>}
            </div>
          );
        })}
      </div>

      <AnimatePresence>
        {selected && <DriverPanel brand={selected.brand} model={selected.model} onClose={() => setSelected(null)} />}
      </AnimatePresence>
    </motion.div>
  );
}

/* ══════════════════════════════════════════════
   MAIN PAGE — 2 sub-tabs
══════════════════════════════════════════════ */
type SubTab = 'agent' | 'drivers';

export default function DownloadPage() {
  const [sub, setSub] = useState<SubTab>('agent');

  return (
    <div style={{ padding: '16px 16px 0' }}>
      <h2 style={{ margin: '0 0 14px', fontSize: '1.2rem', fontWeight: 700, color: 'var(--color-text)' }}>
        📥 Tải về
      </h2>

      {/* Sub-tab bar */}
      <div style={{ display: 'flex', borderBottom: '2px solid var(--color-surface-light)', marginBottom: 18 }}>
        {([
          { key: 'agent', icon: '🖥️', label: 'GoPrinxAgent' },
          { key: 'drivers', icon: '🖨️', label: 'Driver máy in' },
        ] as { key: SubTab; icon: string; label: string }[]).map(t => (
          <button key={t.key} onClick={() => setSub(t.key)} style={{
            padding: '9px 18px', background: 'none', border: 'none',
            borderBottom: sub === t.key ? '3px solid var(--color-primary)' : '3px solid transparent',
            fontWeight: 700, fontSize: '0.9rem',
            color: sub === t.key ? 'var(--color-primary)' : 'var(--color-text-secondary)',
            cursor: 'pointer', marginBottom: -2, transition: 'all 0.15s', display: 'flex', alignItems: 'center', gap: 6,
          }}>
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      {sub === 'agent' && <AgentDownloadSection />}
      {sub === 'drivers' && <PrinterDriversSection />}
    </div>
  );
}
