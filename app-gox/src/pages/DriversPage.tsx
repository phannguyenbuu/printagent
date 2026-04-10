import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

const API_BASE = import.meta.env.VITE_API_URL || 'https://agentapi.quanlymay.com';

type Brand = 'ricoh' | 'toshiba' | 'fujifilm';

interface RicohModel {
    id: number;
    model: string;
    support_url?: string;
    drivers: Record<string, string>;
}

interface ToshibaDriver {
    name: string;
    description: string;
    filename: string;
    version: string;
    date: string;
    download_url: string;
}

interface ToshibaModel {
    category: string;
    model: string;
    slug: string;
    product_url: string;
    drivers: ToshibaDriver[];
    total_windows_drivers: number;
}

interface FujifilmModel {
    category: string;
    family: string;
    model: string;
    pid: string;
    all_links: string[];
}

type AnyModel = RicohModel | ToshibaModel | FujifilmModel;

const BRAND_CONFIG: Record<Brand, { label: string; color: string; emoji: string; searchPlaceholder: string; filters: string[] }> = {
    ricoh: {
        label: 'Ricoh',
        color: '#003087',
        emoji: '🔵',
        searchPlaceholder: 'Tìm model Ricoh (vd: MP 3054, IM C3500)...',
        filters: ['Tất cả', 'IM', 'IM C', 'MP', 'MP C', 'Aficio', 'SP', 'M'],
    },
    toshiba: {
        label: 'Toshiba',
        color: '#e4002b',
        emoji: '🔴',
        searchPlaceholder: 'Tìm model Toshiba (vd: e-STUDIO1208)...',
        filters: ['Tất cả', 'B/W COPIER', 'COLOR COPIER'],
    },
    fujifilm: {
        label: 'Fujifilm',
        color: '#00a040',
        emoji: '🟢',
        searchPlaceholder: 'Tìm model Fujifilm (vd: Apeos 5330)...',
        filters: ['Tất cả', 'ApeosPort', 'Apeos', 'DocuCentre', 'DocuPrint', 'ApeosPrint'],
    },
};

function getModelName(_brand: Brand, m: AnyModel): string {
    return (m as RicohModel).model || '—';
}

function getDriverCount(brand: Brand, m: AnyModel): number {
    if (brand === 'ricoh') return Object.keys((m as RicohModel).drivers || {}).length;
    if (brand === 'toshiba') return (m as ToshibaModel).total_windows_drivers;
    if (brand === 'fujifilm') return ((m as FujifilmModel).all_links || []).length;
    return 0;
}

function getModelMeta(brand: Brand, m: AnyModel): string {
    if (brand === 'fujifilm') return (m as FujifilmModel).family || '';
    if (brand === 'toshiba') return (m as ToshibaModel).category || '';
    return '';
}

function matchFilter(brand: Brand, m: AnyModel, filter: string): boolean {
    if (filter === 'Tất cả' || !filter) return true;
    const name = getModelName(brand, m);
    if (brand === 'ricoh') {
        if (filter === 'M') return /^M[ C]/.test(name);
        if (filter === 'SP') return /^SP[ C]/.test(name);
        if (filter === 'Aficio') return /^Aficio/.test(name);
        return name.startsWith(filter + ' ');
    }
    if (brand === 'toshiba') return (m as ToshibaModel).category === filter;
    if (brand === 'fujifilm') return (m as FujifilmModel).family === filter;
    return true;
}

/* ─── Detail Panel ─────────────────────────────────── */
function DriverPanel({ brand, model, onClose }: { brand: Brand; model: AnyModel; onClose: () => void }) {
    const name = getModelName(brand, model);

    const renderDrivers = () => {
        if (brand === 'ricoh') {
            const m = model as RicohModel;
            const entries = Object.entries(m.drivers || {});
            if (!entries.length)
                return (
                    <NoDriver label="Ricoh" url={m.support_url} />
                );
            return (
                <>
                    <SectionLabel>Windows Print Drivers</SectionLabel>
                    {entries.map(([type, url]) => (
                        <DlRow key={type} name={type} sub={url.split('/').pop() || ''} url={url} ext="EXE" />
                    ))}
                    {m.support_url && (
                        <GhostLink url={m.support_url} label="Xem tất cả trên Ricoh Support" />
                    )}
                </>
            );
        }

        if (brand === 'toshiba') {
            const m = model as ToshibaModel;
            if (!m.drivers?.length)
                return <NoDriver label="Toshiba" url={m.product_url} />;
            return (
                <>
                    <SectionLabel>Print Drivers</SectionLabel>
                    {m.drivers.map((d, i) => (
                        <DlRow
                            key={i}
                            name={d.description || d.name}
                            sub={`${d.version ? 'v' + d.version + ' · ' : ''}${d.date || ''}`}
                            url={d.download_url}
                            ext={(d.filename.split('.').pop() || 'zip').toUpperCase()}
                        />
                    ))}
                    <GhostLink url={m.product_url} label="Xem trên trang Toshiba" />
                </>
            );
        }

        if (brand === 'fujifilm') {
            const m = model as FujifilmModel;
            const links = m.all_links || [];
            if (!links.length)
                return <NoDriver label="Fujifilm" url="https://support-fb.fujifilm.com/" />;
            const exeLinks = links.filter((u) => u.toLowerCase().endsWith('.exe'));
            const otherLinks = links.filter((u) => !u.toLowerCase().endsWith('.exe'));
            return (
                <>
                    {m.pid && (
                        <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', marginBottom: 12 }}>
                            Mã: <b>{m.pid}</b> · {m.family}
                        </div>
                    )}
                    {exeLinks.length > 0 && (
                        <>
                            <SectionLabel>Windows Drivers & Installers</SectionLabel>
                            {exeLinks.map((url, i) => {
                                const fn = url.split('/').pop() || '';
                                let label = fn;
                                if (/easysetup/i.test(fn)) label = '🔧 Easy Setup (Full Installer)';
                                else if (/pcl6/i.test(fn)) label = 'PCL6 Driver';
                                else if (/ps[^a-z]/i.test(fn)) label = 'PostScript Driver';
                                else if (/mmds/i.test(fn)) label = 'MMDS Driver';
                                return <DlRow key={i} name={label} sub={fn} url={url} ext="EXE" />;
                            })}
                        </>
                    )}
                    {otherLinks.length > 0 && (
                        <>
                            <SectionLabel>Tài liệu khác</SectionLabel>
                            {otherLinks.map((url, i) => {
                                const fn = url.split('/').pop() || '';
                                return (
                                    <DlRow key={i} name={fn} sub="" url={url} ext={fn.split('.').pop()?.toUpperCase() || 'FILE'} />
                                );
                            })}
                        </>
                    )}
                    <GhostLink url="https://support-fb.fujifilm.com/" label="Fujifilm Support Site" />
                </>
            );
        }
    };

    return (
        <>
            {/* Overlay */}
            <motion.div
                initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                onClick={onClose}
                style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.35)', zIndex: 200 }}
            />
            {/* Panel */}
            <motion.div
                initial={{ x: '100%' }} animate={{ x: 0 }} exit={{ x: '100%' }}
                transition={{ type: 'spring', stiffness: 380, damping: 35 }}
                style={{
                    position: 'fixed', right: 0, top: 0, bottom: 0,
                    width: 340, maxWidth: '95vw',
                    background: 'var(--color-surface)',
                    borderLeft: '1px solid var(--color-surface-light)',
                    boxShadow: '-8px 0 32px rgba(0,0,0,0.18)',
                    zIndex: 201, overflowY: 'auto', display: 'flex', flexDirection: 'column',
                }}
            >
                {/* Header */}
                <div style={{
                    display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between',
                    padding: '18px 16px 14px',
                    borderBottom: '1px solid var(--color-surface-light)',
                    position: 'sticky', top: 0, background: 'var(--color-surface)', zIndex: 2,
                }}>
                    <div>
                        <div style={{
                            fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em',
                            color: BRAND_CONFIG[brand].color, background: `${BRAND_CONFIG[brand].color}18`,
                            display: 'inline-block', padding: '2px 8px', borderRadius: 4, marginBottom: 4,
                        }}>
                            {BRAND_CONFIG[brand].label}
                        </div>
                        <div style={{ fontWeight: 700, fontSize: '1rem', color: 'var(--color-text)' }}>{name}</div>
                    </div>
                    <button
                        onClick={onClose}
                        style={{ background: 'none', border: 'none', fontSize: 18, cursor: 'pointer', color: 'var(--color-text-secondary)', paddingTop: 2 }}
                    >✕</button>
                </div>
                {/* Body */}
                <div style={{ padding: '14px 16px 32px', flex: 1 }}>
                    {renderDrivers()}
                </div>
            </motion.div>
        </>
    );
}

/* ─── Small components ─── */
function SectionLabel({ children }: { children: React.ReactNode }) {
    return (
        <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--color-text-secondary)', margin: '18px 0 8px' }}>
            {children}
        </div>
    );
}

function DlRow({ name, sub, url, ext }: { name: string; sub: string; url: string; ext: string }) {
    return (
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '9px 0', borderBottom: '1px solid var(--color-surface-light)', gap: 8 }}>
            <div style={{ minWidth: 0 }}>
                <div style={{ fontWeight: 500, fontSize: 14, color: 'var(--color-text)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{name}</div>
                {sub && <div style={{ fontSize: 11, color: 'var(--color-text-secondary)', marginTop: 2 }}>{sub}</div>}
            </div>
            <a
                href={url} target="_blank" rel="noopener noreferrer"
                style={{
                    flexShrink: 0, padding: '5px 11px',
                    background: 'var(--color-primary)', color: '#fff',
                    borderRadius: 7, fontSize: 12, fontWeight: 600,
                    textDecoration: 'none', whiteSpace: 'nowrap',
                }}
            >
                ↓ {ext}
            </a>
        </div>
    );
}

function GhostLink({ url, label }: { url: string; label: string }) {
    return (
        <div style={{ marginTop: 18, textAlign: 'center' }}>
            <a
                href={url} target="_blank" rel="noopener noreferrer"
                style={{
                    display: 'inline-block', padding: '7px 16px',
                    border: '1.5px solid var(--color-primary)', color: 'var(--color-primary)',
                    borderRadius: 8, fontSize: 13, fontWeight: 600, textDecoration: 'none',
                }}
            >
                {label} →
            </a>
        </div>
    );
}

function NoDriver({ label, url }: { label: string; url?: string }) {
    return (
        <div style={{ textAlign: 'center', padding: '28px 8px', color: 'var(--color-text-secondary)' }}>
            <div style={{ fontSize: 32, marginBottom: 10 }}>📄</div>
            <p style={{ fontSize: 13, marginBottom: 14 }}>Không có driver tải trực tiếp cho model này.</p>
            {url && <GhostLink url={url} label={`Xem trên ${label} Support`} />}
        </div>
    );
}

/* ─── Main Page ─────────────────────────────────────── */
export default function DriversPage() {
    const [activeBrand, setActiveBrand] = useState<Brand>('ricoh');
    const [catalogs, setCatalogs] = useState<Record<Brand, AnyModel[] | null>>({ ricoh: null, toshiba: null, fujifilm: null });
    const [loading, setLoading] = useState<Record<Brand, boolean>>({ ricoh: false, toshiba: false, fujifilm: false });
    const [error, setError] = useState<Record<Brand, string | null>>({ ricoh: null, toshiba: null, fujifilm: null });
    const [search, setSearch] = useState('');
    const [activeFilter, setActiveFilter] = useState('Tất cả');
    const [selectedModel, setSelectedModel] = useState<{ brand: Brand; model: AnyModel } | null>(null);

    const loadCatalog = useCallback(async (brand: Brand) => {
        if (catalogs[brand] !== null || loading[brand]) return;
        setLoading((p) => ({ ...p, [brand]: true }));
        try {
            const res = await fetch(`${API_BASE}/api/drivers/${brand}`);
            const json = await res.json();
            if (json.ok) {
                setCatalogs((p) => ({ ...p, [brand]: json.data }));
            } else {
                setError((p) => ({ ...p, [brand]: json.error || 'Không tải được catalog' }));
            }
        } catch {
            setError((p) => ({ ...p, [brand]: 'Lỗi kết nối server' }));
        } finally {
            setLoading((p) => ({ ...p, [brand]: false }));
        }
    }, [catalogs, loading]);

    useEffect(() => {
        loadCatalog(activeBrand);
        setSearch('');
        setActiveFilter('Tất cả');
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [activeBrand]);

    const data = catalogs[activeBrand] || [];
    const q = search.toLowerCase();
    const filtered = data.filter((m) => {
        const nameMatch = !q || getModelName(activeBrand, m).toLowerCase().includes(q);
        return nameMatch && matchFilter(activeBrand, m, activeFilter);
    });

    const cfg = BRAND_CONFIG[activeBrand];

    return (
        <div style={{ paddingBottom: 80 }}>
            {/* Header */}
            <div style={{ padding: '16px 16px 0' }}>
                <h2 style={{ margin: '0 0 4px', fontSize: '1.25rem', fontWeight: 700, color: 'var(--color-text)' }}>
                    🖨️ Driver máy in
                </h2>
                <p style={{ margin: 0, fontSize: 13, color: 'var(--color-text-secondary)' }}>
                    Tìm và tải driver cho máy photocopy
                </p>
            </div>

            {/* Brand tabs */}
            <div style={{ display: 'flex', gap: 0, borderBottom: '2px solid var(--color-surface-light)', margin: '14px 0 0', padding: '0 16px' }}>
                {(Object.keys(BRAND_CONFIG) as Brand[]).map((brand) => (
                    <button
                        key={brand}
                        onClick={() => setActiveBrand(brand)}
                        style={{
                            padding: '9px 16px',
                            background: 'none', border: 'none',
                            borderBottom: activeBrand === brand ? `3px solid ${BRAND_CONFIG[brand].color}` : '3px solid transparent',
                            fontWeight: 700, fontSize: 14,
                            color: activeBrand === brand ? BRAND_CONFIG[brand].color : 'var(--color-text-secondary)',
                            cursor: 'pointer', marginBottom: -2, transition: 'all 0.15s',
                        }}
                    >
                        {BRAND_CONFIG[brand].emoji} {BRAND_CONFIG[brand].label}
                    </button>
                ))}
            </div>

            <div style={{ padding: '14px 16px 0' }}>
                {/* Search */}
                <input
                    type="text"
                    placeholder={cfg.searchPlaceholder}
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    style={{
                        width: '100%', padding: '10px 14px',
                        border: '1.5px solid var(--color-surface-light)',
                        borderRadius: 10, fontSize: 14, outline: 'none',
                        background: 'var(--color-surface)',
                        color: 'var(--color-text)',
                        boxSizing: 'border-box',
                    }}
                />

                {/* Filter chips */}
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', margin: '10px 0 6px' }}>
                    {cfg.filters.map((f) => (
                        <button
                            key={f}
                            onClick={() => setActiveFilter(f)}
                            style={{
                                padding: '4px 12px', borderRadius: 20, fontSize: 12, fontWeight: 600,
                                border: `1.5px solid ${activeFilter === f ? cfg.color : 'var(--color-surface-light)'}`,
                                background: activeFilter === f ? cfg.color : 'transparent',
                                color: activeFilter === f ? '#fff' : 'var(--color-text-secondary)',
                                cursor: 'pointer', transition: 'all 0.15s',
                            }}
                        >
                            {f}
                        </button>
                    ))}
                </div>

                {/* Count */}
                <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', marginBottom: 8 }}>
                    {loading[activeBrand] ? 'Đang tải...' : `${filtered.length} models`}
                </div>

                {/* List */}
                <div style={{ border: '1.5px solid var(--color-surface-light)', borderRadius: 12, overflow: 'hidden' }}>
                    {loading[activeBrand] && (
                        <div style={{ padding: 32, textAlign: 'center', color: 'var(--color-text-secondary)', fontSize: 14 }}>
                            ⏳ Đang tải catalog {cfg.label}...
                        </div>
                    )}
                    {error[activeBrand] && (
                        <div style={{ padding: 24, textAlign: 'center', color: '#e55', fontSize: 13 }}>
                            ⚠️ {error[activeBrand]}
                        </div>
                    )}
                    {!loading[activeBrand] && !error[activeBrand] && filtered.length === 0 && (
                        <div style={{ padding: 32, textAlign: 'center', color: 'var(--color-text-secondary)', fontSize: 14 }}>
                            Không tìm thấy model nào
                        </div>
                    )}
                    {!loading[activeBrand] && filtered.map((m, i) => {
                        const name = getModelName(activeBrand, m);
                        const count = getDriverCount(activeBrand, m);
                        const meta = getModelMeta(activeBrand, m);
                        return (
                            <motion.div
                                key={i}
                                initial={{ opacity: 0 }}
                                animate={{ opacity: 1 }}
                                transition={{ delay: Math.min(i * 0.02, 0.3) }}
                                onClick={() => setSelectedModel({ brand: activeBrand, model: m })}
                                style={{
                                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                                    padding: '11px 14px',
                                    borderBottom: i < filtered.length - 1 ? '1px solid var(--color-surface-light)' : 'none',
                                    cursor: 'pointer', transition: 'background 0.12s',
                                    background: 'var(--color-surface)',
                                    gap: 10,
                                }}
                                onMouseEnter={(e) => (e.currentTarget.style.background = 'color-mix(in srgb, var(--color-primary) 5%, var(--color-surface))')}
                                onMouseLeave={(e) => (e.currentTarget.style.background = 'var(--color-surface)')}
                            >
                                <div style={{ minWidth: 0 }}>
                                    <div style={{ fontWeight: 500, fontSize: 14, color: 'var(--color-text)' }}>{name}</div>
                                    {meta && <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', marginTop: 2 }}>{meta}</div>}
                                </div>
                                {count > 0 ? (
                                    <span style={{
                                        flexShrink: 0, fontSize: 12, fontWeight: 600,
                                        color: cfg.color, background: `${cfg.color}18`,
                                        padding: '3px 10px', borderRadius: 20,
                                    }}>
                                        ↓ {count} file{count > 1 ? 's' : ''}
                                    </span>
                                ) : (
                                    <span style={{ flexShrink: 0, fontSize: 12, color: 'var(--color-text-secondary)' }}>→ Web</span>
                                )}
                            </motion.div>
                        );
                    })}
                </div>
            </div>

            {/* Detail panel */}
            <AnimatePresence>
                {selectedModel && (
                    <DriverPanel
                        brand={selectedModel.brand}
                        model={selectedModel.model}
                        onClose={() => setSelectedModel(null)}
                    />
                )}
            </AnimatePresence>
        </div>
    );
}
