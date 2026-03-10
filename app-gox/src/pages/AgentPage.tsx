import { useState, useEffect, useCallback, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { GlowCard } from '../components/ui/GlowCard';
import { AnimatedButton } from '../components/ui/AnimatedButton';
import { AnimatedList } from '../components/ui/AnimatedList';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import {
  mockGetAgents,
  mockGetCopiers,
  mockInstallPrinterDriver,
  mockInstallScan,
  mockBulkInstallDriver,
  mockBulkInstallScan,
  mockSendNotification,
  mockConfigureCopier,
  mockUpdateAgent,
  mockDeleteAgent,
  mockDeleteCopier,
} from '../api/mockAgentApi';
import type { Agent, AgentActionResult, PrinterBrand, PrinterModel, Copier } from '../types/agent';
import { PRINTER_MODELS, PRINTER_BRANDS } from '../types/agent';

type ModalType = 'driver' | 'scan' | 'bulk_driver' | 'bulk_scan' | 'bulk_all' | 'notify' | 'settings' | 'connect_lan' | 'copier_scan' | 'copier_add' | 'copier_config' | 'copier_delete' | 'agent_edit' | 'agent_delete' | null;
type LanTab = 'agents' | 'copiers' | 'downloads';

const PORT_OPTIONS = [
  { label: '9100 (RAW)', value: 9100 },
  { label: 'Custom', value: 'custom' as const },
];

export function AgentPage() {
  const [lanTab, setLanTab] = useState<LanTab>('agents');
  const [agents, setAgents] = useState<Agent[]>([]);
  const [copiers, setCopiers] = useState<Copier[]>([]);
  const [expandedCopier, setExpandedCopier] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // Copier scan state
  const [scanProgress, setScanProgress] = useState<'idle' | 'scanning' | 'done'>('idle');
  const [scanFound, setScanFound] = useState<{ ip: string; mac: string }[]>([]);

  // MAC ID edit state for manual add form
  const [macEditing, setMacEditing] = useState(false);
  const [macLookupLoading, setMacLookupLoading] = useState(false);

  // Manual add copier form
  const [newCopierName, setNewCopierName] = useState('');
  const [newCopierBrand, setNewCopierBrand] = useState<PrinterBrand | ''>('');
  const [newCopierModel, setNewCopierModel] = useState('');
  const [newCopierIp, setNewCopierIp] = useState('');
  const [newCopierLocation, setNewCopierLocation] = useState('');
  const [newCopierMac, setNewCopierMac] = useState('');
  const [addCopierError, setAddCopierError] = useState('');
  const [actionLoading, setActionLoading] = useState(false);

  // Agent edit state
  const [editingAgent, setEditingAgent] = useState<Agent | null>(null);
  const [editAgentHostname, setEditAgentHostname] = useState('');
  const [editAgentIp, setEditAgentIp] = useState('');
  const [editAgentError, setEditAgentError] = useState('');

  // Copier config state
  const [configCopier, setConfigCopier] = useState<Copier | null>(null);
  const [configIp, setConfigIp] = useState('');
  const [configMac, setConfigMac] = useState('');
  const [configMacEditing, setConfigMacEditing] = useState(false);
  const [configMacLookupLoading, setConfigMacLookupLoading] = useState(false);
  const [configUser, setConfigUser] = useState('');
  const [configPass, setConfigPass] = useState('');
  const [configShowPass, setConfigShowPass] = useState(false);
  const [configError, setConfigError] = useState('');
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);
  const [modal, setModal] = useState<ModalType>(null);
  const [settingsTab, setSettingsTab] = useState<'config' | 'download'>('config');
  const [results, setResults] = useState<AgentActionResult[]>([]);

  // Driver fields
  const [selectedBrand, setSelectedBrand] = useState<PrinterBrand | ''>('');
  const [selectedModel, setSelectedModel] = useState<PrinterModel | null>(null);
  const [printerIp, setPrinterIp] = useState('');
  const [printerPort, setPrinterPort] = useState<9100 | 'custom'>(9100);
  const [customPort, setCustomPort] = useState('');

  // Scan fields — SMB and FTP are independent
  const [enableSmb, setEnableSmb] = useState(true);
  const [enableFtp, setEnableFtp] = useState(false);
  const [scanPriority, setScanPriority] = useState<'smb' | 'ftp'>('smb');
  const [scanAutoConfig, setScanAutoConfig] = useState(true);
  // Copier credentials — dùng để đăng nhập web UI máy photocopy khi cấu hình scan
  const [copierIp, setCopierIp] = useState('');
  const [copierUser, setCopierUser] = useState('admin');
  const [copierPass, setCopierPass] = useState('');
  // Drive picker for auto-create folder
  const [smbDrive, setSmbDrive] = useState('C');
  const [ftpDrive, setFtpDrive] = useState('C');
  // Available drives — mock: agent may have D, E; C always present
  const availableDrives = useMemo(() => {
    if (!selectedAgent) return ['C', 'D', 'E'];
    // Simulate: online agents with printerConfig tend to have extra drives
    return selectedAgent.driverInstalled ? ['C', 'D', 'E'] : ['C'];
  }, [selectedAgent]);

  // SMB config
  const [smbServer, setSmbServer] = useState('');
  const [smbPath, setSmbPath] = useState('');
  const [smbUser, setSmbUser] = useState('');
  const [smbPass, setSmbPass] = useState('');
  // FTP config
  const [ftpServer, setFtpServer] = useState('');
  const [ftpPath, setFtpPath] = useState('');
  const [ftpUser, setFtpUser] = useState('');
  const [ftpPass, setFtpPass] = useState('');

  // Notification
  const [notifyMessage, setNotifyMessage] = useState('');
  const [notifyTarget, setNotifyTarget] = useState<string>('all');

  const fetchAgents = useCallback(async () => {
    setLoading(true);
    const [agentData, copierData] = await Promise.all([mockGetAgents(), mockGetCopiers()]);
    setAgents(agentData);
    setCopiers(copierData);
    setLoading(false);
  }, []);

  useEffect(() => { fetchAgents(); }, [fetchAgents]);

  const onlineCount = agents.filter((a) => a.status === 'online').length;

  const modelsForBrand = useMemo(() => {
    if (!selectedBrand) return [];
    return PRINTER_MODELS.filter((m) => m.brand === selectedBrand);
  }, [selectedBrand]);

  const resetForm = () => {
    setSelectedBrand(''); setSelectedModel(null); setPrinterIp(''); setPrinterPort(9100); setCustomPort('');
    setEnableSmb(true); setEnableFtp(false); setScanPriority('smb'); setScanAutoConfig(true);
    setCopierUser('admin'); setCopierPass(''); setCopierIp('');
    setSmbDrive('C'); setFtpDrive('C');
    setSmbServer(''); setSmbPath(''); setSmbUser(''); setSmbPass('');
    setFtpServer(''); setFtpPath(''); setFtpUser(''); setFtpPass('');
    setNotifyMessage(''); setResults([]);
    // copier form
    setNewCopierName(''); setNewCopierBrand(''); setNewCopierModel('');
    setNewCopierIp(''); setNewCopierLocation(''); setNewCopierMac('');
    setAddCopierError(''); setScanProgress('idle'); setScanFound([]);
    setMacEditing(false); setMacLookupLoading(false);
    setConfigMac(''); setConfigUser(''); setConfigPass(''); setConfigError(''); setConfigMacEditing(false); setConfigShowPass(false); setConfigIp(''); setConfigMacLookupLoading(false);
  };

  const openModal = (type: ModalType, agent?: Agent) => {
    setSelectedAgent(agent ?? null);
    setModal(type);
    resetForm();
    setNotifyTarget(agent ? agent.id : 'all');
  };

  const closeModal = () => { setModal(null); setSelectedAgent(null); setConfigCopier(null); resetForm(); };

  const openCopierConfig = (copier: Copier) => {
    setConfigCopier(copier);
    setConfigIp(copier.ipAddress);
    setConfigMac(copier.macId);
    setConfigUser(copier.webUsername ?? '');
    setConfigPass(copier.webPassword ?? '');
    setConfigError('');
    setConfigMacEditing(false);
    setConfigMacLookupLoading(false);
    setConfigShowPass(false);
    setModal('copier_config');
  };

  const handleConfigIpChange = async (ip: string) => {
    setConfigIp(ip);
    if (!configMacEditing) {
      const trimmed = ip.trim();
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed)) {
        setConfigMacLookupLoading(true);
        await new Promise((r) => setTimeout(r, 400));
        setConfigMac(mockMacFromIp(trimmed));
        setConfigMacLookupLoading(false);
      } else {
        setConfigMac('');
      }
    }
  };

  const handleSaveCopierConfig = async () => {
    if (!configCopier) return;
    setConfigError('');
    if (!configMac.trim()) { setConfigError('Vui lòng nhập MAC ID'); return; }
    setActionLoading(true);
    const r = await mockConfigureCopier(configCopier.id, {
      macId: configMac,
      ipAddress: configIp.trim(),
      webUsername: configUser,
      webPassword: configPass,
    });
    setActionLoading(false);
    if (r.success) {
      await fetchAgents();
      closeModal();
    } else {
      setConfigError(r.message);
    }
  };

  const buildDriverConfig = () => ({
    brand: selectedModel?.brand ?? (selectedBrand as PrinterBrand),
    model: selectedModel?.model ?? '',
    driverName: selectedModel?.driverName ?? '',
    printerIp: printerIp.trim(),
    port: printerPort,
    customPort: printerPort === 'custom' ? Number(customPort) || undefined : undefined,
  });

  const buildScanConfig = () => ({
    enableSmb,
    enableFtp,
    priority: scanPriority,
    autoConfig: scanAutoConfig,
    copierUsername: copierUser.trim(),
    copierPassword: copierPass,
    copierIp: copierIp.trim(),
    smb: enableSmb ? { server: smbServer.trim(), path: smbPath.trim(), username: smbUser.trim(), password: smbPass.trim() } : undefined,
    ftp: enableFtp ? { server: ftpServer.trim(), path: ftpPath.trim(), username: ftpUser.trim(), password: ftpPass.trim() } : undefined,
  });

  const handleInstallDriver = useCallback(async () => {
    if (!selectedAgent || !selectedModel || !printerIp.trim()) return;
    setActionLoading(true);
    const r = await mockInstallPrinterDriver(selectedAgent.id, buildDriverConfig());
    setResults([r]);
    setActionLoading(false);
    await fetchAgents();
  }, [selectedAgent, selectedModel, printerIp, printerPort, customPort, fetchAgents]);

  const handleInstallScan = useCallback(async () => {
    if (!selectedAgent || (!enableSmb && !enableFtp)) return;
    setActionLoading(true);
    const r = await mockInstallScan(selectedAgent.id, buildScanConfig());
    setResults([r]);
    setActionLoading(false);
    await fetchAgents();
  }, [selectedAgent, enableSmb, enableFtp, scanPriority, scanAutoConfig, copierIp, copierUser, copierPass, smbServer, smbPath, smbUser, smbPass, ftpServer, ftpPath, ftpUser, ftpPass, fetchAgents]);

  const handleBulkDriver = useCallback(async () => {
    if (!selectedModel || !printerIp.trim()) return;
    setActionLoading(true);
    const r = await mockBulkInstallDriver(buildDriverConfig());
    setResults(r);
    setActionLoading(false);
    await fetchAgents();
  }, [selectedModel, printerIp, printerPort, customPort, fetchAgents]);

  const handleBulkScan = useCallback(async () => {
    if (!enableSmb && !enableFtp) return;
    setActionLoading(true);
    const r = await mockBulkInstallScan(buildScanConfig());
    setResults(r);
    setActionLoading(false);
    await fetchAgents();
  }, [enableSmb, enableFtp, scanPriority, scanAutoConfig, copierIp, copierUser, copierPass, smbServer, smbPath, smbUser, smbPass, ftpServer, ftpPath, ftpUser, ftpPass, fetchAgents]);

  const handleBulkAll = useCallback(async () => {
    if (!selectedModel || !printerIp.trim() || (!enableSmb && !enableFtp)) return;
    setActionLoading(true);
    const driverResults = await mockBulkInstallDriver(buildDriverConfig());
    const scanResults = await mockBulkInstallScan(buildScanConfig());
    setResults([{ success: true, message: '--- Driver ---' }, ...driverResults, { success: true, message: '--- Scan ---' }, ...scanResults]);
    setActionLoading(false);
    await fetchAgents();
  }, [selectedModel, printerIp, printerPort, customPort, enableSmb, enableFtp, scanPriority, scanAutoConfig, copierIp, copierUser, copierPass, smbServer, smbPath, smbUser, smbPass, ftpServer, ftpPath, ftpUser, ftpPass, fetchAgents]);

  const handleSendNotification = useCallback(async () => {
    if (!notifyMessage.trim()) return;
    setActionLoading(true);
    const r = await mockSendNotification(notifyTarget, notifyMessage.trim());
    setResults([r]);
    setActionLoading(false);
  }, [notifyTarget, notifyMessage]);

  const handleUpdateAgent = async () => {
    if (!editingAgent || !editAgentHostname.trim()) return;
    setActionLoading(true);
    const r = await mockUpdateAgent(editingAgent.id, {
      hostname: editAgentHostname.trim(),
      ipAddress: editAgentIp.trim(),
    });
    setActionLoading(false);
    if (r.success) {
      await fetchAgents();
      closeModal();
    } else {
      setEditAgentError(r.message);
    }
  };

  const handleDeleteAgent = async () => {
    if (!selectedAgent) return;
    setActionLoading(true);
    const r = await mockDeleteAgent(selectedAgent.id);
    setActionLoading(false);
    if (r.success) {
      await fetchAgents();
      closeModal();
    }
  };

  const handleDeleteCopier = async (copierId: string) => {
    if (!window.confirm('Bạn có chắc chắn muốn xóa máy photocopy này?')) return;
    setActionLoading(true);
    const r = await mockDeleteCopier(copierId);
    setActionLoading(false);
    if (r.success) {
      await fetchAgents();
    }
  };

  const openAgentEdit = (agent: Agent) => {
    setEditingAgent(agent);
    setEditAgentHostname(agent.hostname);
    setEditAgentIp(agent.ipAddress);
    setEditAgentError('');
    setModal('agent_edit');
  };

  const openAgentDelete = (agent: Agent) => {
    setSelectedAgent(agent);
    setModal('agent_delete');
  };

  const handleExecute = () => {
    if (modal === 'driver') handleInstallDriver();
    else if (modal === 'scan') handleInstallScan();
    else if (modal === 'bulk_driver') handleBulkDriver();
    else if (modal === 'bulk_scan') handleBulkScan();
    else if (modal === 'bulk_all' || modal === 'settings') handleBulkAll();
    else if (modal === 'notify') handleSendNotification();
  };

  const handleCopierScan = async () => {
    setScanProgress('scanning');
    setScanFound([]);
    await new Promise((r) => setTimeout(r, 1800));
    // Mock: simulate ARP table — each IP gets a deterministic MAC
    const mockIps = ['192.168.1.200', '192.168.1.201', '192.168.1.205', '192.168.1.210'];
    setScanFound(mockIps.map((ip) => ({ ip, mac: mockMacFromIp(ip) })));
    setScanProgress('done');
  };

  // Mock ARP lookup: derive a plausible MAC from last 2 octets of IP
  const mockMacFromIp = (ip: string): string => {
    const parts = ip.split('.');
    const seed = [0xAA, 0xBB, 0xCC,
      parseInt(parts[1] ?? '0') & 0xFF,
      parseInt(parts[2] ?? '0') & 0xFF,
      parseInt(parts[3] ?? '0') & 0xFF,
    ];
    return seed.map((b) => b.toString(16).padStart(2, '0').toUpperCase()).join(':');
  };

  // When IP field changes in manual form, auto-lookup MAC after short debounce
  const handleCopierIpChange = async (ip: string) => {
    setNewCopierIp(ip);
    if (!macEditing) {
      const trimmed = ip.trim();
      // Only lookup when IP looks complete (x.x.x.x)
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed)) {
        setMacLookupLoading(true);
        await new Promise((r) => setTimeout(r, 400));
        setNewCopierMac(mockMacFromIp(trimmed));
        setMacLookupLoading(false);
      } else {
        setNewCopierMac('');
      }
    }
  };

  // MAC input auto-format: insert ':' every 2 hex chars
  const handleMacInput = (raw: string) => {
    // Strip everything except hex chars
    const hex = raw.replace(/[^0-9a-fA-F]/g, '').toUpperCase().slice(0, 12);
    // Insert ':' every 2 chars
    const formatted = hex.match(/.{1,2}/g)?.join(':') ?? hex;
    setNewCopierMac(formatted);
  };

  const handleAddCopier = () => {
    setAddCopierError('');
    if (!newCopierName.trim()) { setAddCopierError('Vui lòng nhập tên máy'); return; }
    if (!newCopierBrand) { setAddCopierError('Vui lòng chọn dòng máy'); return; }
    if (!newCopierModel.trim()) { setAddCopierError('Vui lòng nhập mã/model máy'); return; }
    if (!newCopierIp.trim()) { setAddCopierError('Vui lòng nhập địa chỉ IP'); return; }
    if (!newCopierMac.trim()) { setAddCopierError('Vui lòng nhập MAC ID'); return; }
    const macId = newCopierMac.trim().toUpperCase();
    if (copiers.some((c) => c.macId === macId)) { setAddCopierError('MAC ID này đã tồn tại'); return; }
    const newCopier: Copier = {
      id: macId,
      macId,
      name: newCopierName.trim(),
      brand: newCopierBrand as PrinterBrand,
      model: newCopierModel.trim(),
      ipAddress: newCopierIp.trim(),
      status: 'offline',
      lastSeen: new Date().toISOString(),
      connectedPCs: [],
      location: newCopierLocation.trim() || undefined,
    };
    setCopiers((prev) => [...prev, newCopier]);
    closeModal();
  };

  const showDriverFields = modal === 'driver' || modal === 'bulk_driver' || modal === 'bulk_all' || modal === 'settings';
  const showScanFields = modal === 'scan' || modal === 'bulk_scan' || modal === 'bulk_all' || modal === 'settings';

  if (loading) {
    return <div style={styles.loadingContainer}><LoadingSpinner size="lg" /></div>;
  }

  return (
    <motion.div style={styles.container}
      initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: [0.4, 0, 0.2, 1] }}>

      <h1 style={styles.title}>🖥️ Kỹ thuật - Agent</h1>
      <p style={{ ...styles.subtitle, margin: 0 }}>{agents.length} máy tính · {onlineCount} online · {agents.length - onlineCount} offline</p>

      {/* Tab switcher */}
      <div style={styles.tabBar}>
        {([['agents', '🖥️ Máy tính'], ['copiers', '🖨️ Photocopy'], ['downloads', '📥 Tải Agent']] as [LanTab, string][]).map(([tab, label]) => (
          <button
            key={tab}
            style={{
              ...styles.tabBtn,
              background: lanTab === tab ? 'color-mix(in srgb, var(--color-primary) 10%, var(--color-surface))' : 'transparent',
              color: lanTab === tab ? 'var(--color-primary)' : 'var(--color-text-secondary)',
              borderBottom: lanTab === tab ? '2px solid var(--color-primary)' : '2px solid transparent',
            }}
            onClick={() => setLanTab(tab)}
          >
            {label}
            {tab === 'copiers' && (
              <span style={styles.tabBadge}>{copiers.length}</span>
            )}
          </button>
        ))}
      </div>

      <AnimatePresence mode="wait">
        {lanTab === 'agents' ? (
          <motion.div key="agents" initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 10 }} transition={{ duration: 0.2 }}
            style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <GlowCard>
              <h2 style={styles.sectionTitle}>Thao tác hàng loạt</h2>
              {/* Row 1: Driver + Scan riêng lẻ */}
              <div style={styles.bulkRow}>
                <button style={styles.bulkTile} onClick={() => openModal('bulk_driver')}>
                  <span style={styles.bulkTileIcon}>🖨️</span>
                  <span style={styles.bulkTileLabel}>Cài Driver</span>
                  <span style={styles.bulkTileSub}>Toàn bộ agent</span>
                </button>
                <button style={styles.bulkTile} onClick={() => openModal('bulk_scan')}>
                  <span style={styles.bulkTileIcon}>📠</span>
                  <span style={styles.bulkTileLabel}>Cài Scan</span>
                  <span style={styles.bulkTileSub}>Toàn bộ agent</span>
                </button>
              </div>
              {/* Row 2: Driver + Scan cùng lúc — nổi bật */}
              <button style={styles.bulkPrimary} onClick={() => openModal('bulk_all')}>
                <span>⚡</span>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: '1px' }}>
                  <span style={{ fontWeight: 700, fontSize: '0.88rem' }}>Driver + Scan toàn bộ</span>
                  <span style={{ fontSize: '0.72rem', opacity: 0.75 }}>Cài đặt cùng lúc cho tất cả agent</span>
                </div>
              </button>
              {/* Row 3: Thông báo + Thiết lập */}
              <div style={styles.bulkRow}>
                <button style={styles.bulkSecondary} onClick={() => openModal('notify')}>
                  📢 Thông báo
                </button>
                <button style={{ ...styles.bulkSecondary, color: 'var(--color-primary)', borderColor: 'var(--color-primary)' }}
                  onClick={() => openModal('settings')}>
                  ⚙️ Thiết lập chung
                </button>
              </div>
            </GlowCard>

            {/* Agent List */}
            <AnimatedList>
              {agents.map((agent) => (
                <GlowCard key={agent.id}>
                  <div style={styles.agentHeader}>
                    <div style={styles.agentInfo}>
                      <span style={styles.agentName}>{agent.hostname}</span>
                      <span style={{
                        ...styles.statusBadge,
                        background: agent.status === 'online' ? 'rgba(var(--rgb-success,0,255,136),0.12)' : 'rgba(var(--rgb-error,255,68,102),0.12)',
                        color: agent.status === 'online' ? 'var(--color-status-online)' : 'var(--color-status-offline)',
                        borderColor: agent.status === 'online' ? 'var(--color-status-online)' : 'var(--color-status-offline)',
                      }}>
                        {agent.status === 'online' ? '🟢 Online' : '🔴 Offline'}
                      </span>
                    </div>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <button style={{ ...styles.smallBtn, padding: '4px 6px' }} onClick={() => openAgentEdit(agent)} title="Chỉnh sửa">✏️</button>
                      <button style={{ ...styles.smallBtn, padding: '4px 6px', color: 'var(--color-error)' }} onClick={() => openAgentDelete(agent)} title="Xóa">🗑️</button>
                    </div>
                  </div>
                  <div style={styles.agentMeta}>
                    <span style={styles.metaText}>IP: {agent.ipAddress}</span>
                    <span style={styles.metaText}>OS: {agent.os}</span>
                  </div>

                  {/* Status chips */}
                  <div style={styles.statusRow}>
                    {[
                      { label: '🖨️ Driver', ok: agent.driverInstalled },
                      { label: 'SMB', ok: agent.scanSmbInstalled },
                      { label: 'FTP', ok: agent.scanFtpInstalled },
                      { label: 'Auto CFG', ok: agent.scanConfigured },
                    ].map(({ label, ok }) => (
                      <span key={label} style={{
                        ...styles.statusChip,
                        background: ok ? 'rgba(var(--rgb-success,0,255,136),0.12)' : 'var(--color-chip-bg)',
                        color: ok ? 'var(--color-success)' : 'var(--color-text-secondary)',
                        borderColor: ok ? 'var(--color-success)' : 'var(--color-chip-border)',
                      }}>
                        {label}: {ok ? '✓' : '✗'}
                      </span>
                    ))}
                  </div>

                  {/* Driver detail */}
                  {agent.printerConfig && (
                    <div style={styles.configDetail}>
                      <span style={styles.configLabel}>🖨️ {agent.printerConfig.brand} {agent.printerConfig.model}</span>
                      <span style={styles.configSub}>
                        IP: {agent.printerConfig.printerIp} · Port: {agent.printerConfig.port === 'custom' ? agent.printerConfig.customPort : agent.printerConfig.port}
                      </span>
                    </div>
                  )}

                  {/* Scan detail */}
                  {agent.scanConfig && (
                    <div style={styles.configDetail}>
                      <span style={styles.configLabel}>
                        📠 Scan {[agent.scanConfig.enableSmb && 'SMB', agent.scanConfig.enableFtp && 'FTP'].filter(Boolean).join('+')}
                        {agent.scanConfig.enableSmb && agent.scanConfig.enableFtp && ` · Ưu tiên: ${agent.scanConfig.priority.toUpperCase()}`}
                        {agent.scanConfig.autoConfig && ' · ⚡ Auto'}
                      </span>
                      {agent.scanConfig.smb && <span style={styles.configSub}>SMB: {agent.scanConfig.smb.server}{agent.scanConfig.smb.path} ({agent.scanConfig.smb.username})</span>}
                      {agent.scanConfig.ftp && <span style={styles.configSub}>FTP: {agent.scanConfig.ftp.server}{agent.scanConfig.ftp.path} ({agent.scanConfig.ftp.username})</span>}
                    </div>
                  )}

                  {/* Photocopy machines synced to this agent */}
                  {(() => {
                    const linked = copiers.filter((c) => c.connectedPCs.includes(agent.hostname));
                    if (linked.length === 0) return null;
                    return (
                      <div style={styles.configDetail}>
                        <span style={{ ...styles.configLabel, color: 'var(--color-secondary)' }}>🖨️ Máy photocopy đồng bộ ({linked.length})</span>
                        {linked.map((c) => (
                          <div key={c.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '4px' }}>
                            <span style={styles.configSub}>{c.name} · {c.ipAddress}</span>
                            <span style={{
                              fontSize: '0.65rem', fontWeight: 600, padding: '1px 6px', borderRadius: '6px',
                              background: c.isConfigured ? 'color-mix(in srgb, var(--color-success) 10%, var(--color-surface))' : 'var(--color-chip-bg)',
                              color: c.isConfigured ? 'var(--color-success)' : 'var(--color-text-secondary)',
                              border: `1px solid ${c.isConfigured ? 'var(--color-success)' : 'var(--color-chip-border)'}`,
                            }}>
                              {c.isConfigured ? '🔗 Đã kết nối' : '⚠️ Chưa cấu hình'}
                            </span>
                          </div>
                        ))}
                      </div>
                    );
                  })()}

                  {agent.status === 'online' && (
                    <div style={styles.agentActions}>
                      <button style={styles.smallBtn} onClick={() => openModal('driver', agent)}>🖨️ Driver</button>
                      <button style={styles.smallBtn} onClick={() => openModal('scan', agent)}>📠 Scan</button>
                      <button style={styles.smallBtn} onClick={() => openModal('notify', agent)}>📢 Thông báo</button>
                    </div>
                  )}
                </GlowCard>
              ))}
            </AnimatedList>
          </motion.div>
        ) : lanTab === 'copiers' ? (
          <motion.div key="copiers" initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -10 }} transition={{ duration: 0.2 }}
            style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={styles.copierSummaryText}>
                {copiers.length} máy · {copiers.filter(c => c.status === 'online').length} online · {copiers.filter(c => c.status === 'offline').length} offline
              </span>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button style={styles.smallBtn} onClick={() => openModal('copier_scan')}>🔍 Quét mạng</button>
                <button style={{ ...styles.smallBtn, borderColor: 'var(--color-primary)', color: 'var(--color-primary)' }}
                  onClick={() => openModal('copier_add')}>➕ Thêm thủ công</button>
              </div>
            </div>
            <AnimatedList>
              {copiers.map((copier) => {
                const isExpanded = expandedCopier === copier.id;
                const isOnline = copier.status === 'online';
                return (
                  <GlowCard key={copier.id}>
                    {/* Header row */}
                    <div style={styles.copierHeader}>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '2px', flex: 1, minWidth: 0 }}>
                        <span style={styles.copierName}>{copier.name}</span>
                        {copier.location && <span style={styles.copierLocation}>📍 {copier.location}</span>}
                      </div>
                      <span style={{
                        ...styles.statusBadge,
                        background: isOnline ? 'rgba(var(--rgb-success,0,255,136),0.12)' : 'rgba(var(--rgb-error,255,68,102),0.12)',
                        color: isOnline ? 'var(--color-status-online)' : 'var(--color-status-offline)',
                        borderColor: isOnline ? 'var(--color-status-online)' : 'var(--color-status-offline)',
                        flexShrink: 0,
                      }}>
                        {isOnline ? '🟢 Online' : '🔴 Offline'}
                      </span>
                    </div>

                    {/* Meta */}
                    <div style={styles.copierMeta}>
                      <span style={styles.metaText}>🖨️ {copier.brand} {copier.model}</span>
                      <span style={styles.metaText}>IP: {copier.ipAddress}</span>
                      <span style={styles.metaText}>MAC: {copier.macId}</span>
                      {copier.driverVersion && <span style={styles.metaText}>Driver: {copier.driverVersion}</span>}
                    </div>

                    {/* PC count chip */}
                    <div style={styles.statusRow}>
                      <span style={{
                        ...styles.statusChip,
                        background: copier.connectedPCs.length > 0 ? 'color-mix(in srgb, var(--color-primary) 10%, var(--color-surface))' : 'var(--color-chip-bg)',
                        color: copier.connectedPCs.length > 0 ? 'var(--color-primary)' : 'var(--color-text-secondary)',
                        borderColor: copier.connectedPCs.length > 0 ? 'var(--color-primary)' : 'var(--color-chip-border)',
                      }}>
                        🖥️ {copier.connectedPCs.length} PC đang dùng
                      </span>
                      {/* Connection status */}
                      <span style={{
                        ...styles.statusChip,
                        background: copier.isConfigured ? 'color-mix(in srgb, var(--color-success) 10%, var(--color-surface))' : 'var(--color-chip-bg)',
                        color: copier.isConfigured ? 'var(--color-success)' : 'var(--color-text-secondary)',
                        borderColor: copier.isConfigured ? 'var(--color-success)' : 'var(--color-chip-border)',
                      }}>
                        {copier.isConfigured ? '🔗 Đã kết nối' : '⚠️ Chưa cấu hình'}
                      </span>
                    </div>

                    {/* Config button */}
                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '8px' }}>
                      <button
                        style={{ ...styles.smallBtn, color: 'var(--color-error)' }}
                        onClick={() => handleDeleteCopier(copier.id)}
                      >
                        🗑️ Xóa
                      </button>
                      <button
                        style={{ ...styles.smallBtn, borderColor: 'var(--color-primary)', color: 'var(--color-primary)' }}
                        onClick={() => openCopierConfig(copier)}
                      >
                        ⚙️ Cấu hình
                      </button>
                    </div>

                    {/* Expand/collapse PC list */}
                    <button
                      style={styles.expandBtn}
                      onClick={() => setExpandedCopier(isExpanded ? null : copier.id)}
                    >
                      {isExpanded ? '▲ Ẩn danh sách PC' : '▼ Xem danh sách PC'}
                    </button>

                    <AnimatePresence>
                      {isExpanded && (
                        <motion.div
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: 'auto' }}
                          exit={{ opacity: 0, height: 0 }}
                          transition={{ duration: 0.2 }}
                          style={{ overflow: 'hidden' }}
                        >
                          <div style={styles.pcList}>
                            {copier.connectedPCs.length === 0 ? (
                              <span style={styles.emptyPcText}>Chưa có PC nào kết nối</span>
                            ) : (
                              copier.connectedPCs.map((pc) => {
                                const agent = agents.find((a) => a.hostname === pc);
                                return (
                                  <div key={pc} style={styles.pcRow}>
                                    <span style={styles.pcName}>🖥️ {pc}</span>
                                    {agent && (
                                      <span style={{
                                        ...styles.statusBadge,
                                        fontSize: '0.65rem',
                                        background: agent.status === 'online' ? 'rgba(var(--rgb-success,0,255,136),0.12)' : 'rgba(var(--rgb-error,255,68,102),0.12)',
                                        color: agent.status === 'online' ? 'var(--color-status-online)' : 'var(--color-status-offline)',
                                        borderColor: agent.status === 'online' ? 'var(--color-status-online)' : 'var(--color-status-offline)',
                                      }}>
                                        {agent.status === 'online' ? '🟢' : '🔴'} {agent.ipAddress}
                                      </span>
                                    )}
                                  </div>
                                );
                              })
                            )}
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </GlowCard>
                );
              })}
            </AnimatedList>
          </motion.div>
        ) : (
          <motion.div key="downloads" initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 1.05 }} transition={{ duration: 0.2 }}
            style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <GlowCard>
              <h2 style={styles.sectionTitle}>📥 Tải Agent cho VPS/Server</h2>
              <p style={styles.subtitle}>Sử dụng các phiên bản này để cài đặt PrintAgent lên máy chủ hoặc máy trạm đích.</p>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginTop: '16px' }}>
                <div style={styles.configDetail}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div>
                      <span style={styles.configLabel}>PrintAgent v1.2.0 (Ổn định)</span>
                      <span style={styles.configSub}>Phát hành: 10/03/2026 · 12.5 MB</span>
                    </div>
                    <a href="https://github.com/nguyenbuu/printagent/releases/download/v1.2.0/PrintAgent_Setup.exe"
                       style={{ ...styles.bulkSecondary, flex: 'none', background: 'var(--color-primary)', color: 'white', border: 'none', textDecoration: 'none', textAlign: 'center' }}>
                      Tải về .exe
                    </a>
                  </div>
                </div>

                <div style={styles.configDetail}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div>
                      <span style={styles.configLabel}>PrintAgent v1.3.0-beta (Thử nghiệm)</span>
                      <span style={styles.configSub}>Phát hành: 05/03/2026 · 14.1 MB</span>
                    </div>
                    <a href="#" style={{ ...styles.bulkSecondary, flex: 'none', textDecoration: 'none', textAlign: 'center' }}>
                      Tải về .exe
                    </a>
                  </div>
                </div>

                <div style={{ ...styles.scanBlock, background: 'rgba(var(--rgb-primary, 59, 130, 246), 0.05)', borderColor: 'rgba(var(--rgb-primary, 59, 130, 246), 0.2)' }}>
                  <span style={styles.scanBlockTitle}>💡 Hướng dẫn cài đặt</span>
                  <ul style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', paddingLeft: '20px', margin: '4px 0' }}>
                    <li>Tải file .exe về máy tính cần giám sát.</li>
                    <li>Chạy file cài đặt với quyền Administrator.</li>
                    <li>Nhập mã định danh (Agent ID) khi được yêu cầu.</li>
                    <li>Máy tính sẽ tự động xuất hiện trong danh sách "Máy tính" sau khi khởi chạy.</li>
                  </ul>
                </div>
              </div>
            </GlowCard>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Modal */}
      {modal && (
        <div style={styles.overlay} onClick={closeModal}>
          <motion.div style={styles.modal} onClick={(e) => e.stopPropagation()}
            initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }}>
            <h3 style={styles.modalTitle}>
              {modal === 'driver' && `🖨️ Cài driver - ${selectedAgent?.hostname}`}
              {modal === 'scan' && `📠 Cài scan - ${selectedAgent?.hostname}`}
              {modal === 'bulk_driver' && '🖨️ Cài driver toàn bộ agent'}
              {modal === 'bulk_scan' && '📠 Cài scan toàn bộ agent'}
              {modal === 'bulk_all' && '⚡ Cài driver + scan toàn bộ'}
              {modal === 'settings' && '⚙️ Thiết lập & Tải về'}
              {modal === 'notify' && '📢 Gửi thông báo'}
              {modal === 'copier_scan' && '🔍 Quét máy Photocopy trong mạng'}
              {modal === 'copier_add' && '➕ Thêm máy Photocopy thủ công'}
              {modal === 'copier_config' && `⚙️ Cấu hình - ${configCopier?.name}`}
              {modal === 'agent_edit' && `✏️ Chỉnh sửa Agent - ${editingAgent?.hostname}`}
              {modal === 'agent_delete' && `🗑️ Xóa Agent - ${selectedAgent?.hostname}`}
            </h3>

            {/* Inner Tabs for Settings Modal */}
            {modal === 'settings' && (
              <div style={{ display: 'flex', borderBottom: '1px solid var(--color-surface-light)', marginBottom: '12px' }}>
                <button
                  onClick={() => setSettingsTab('config')}
                  style={{
                    flex: 1, padding: '10px', background: 'none', border: 'none',
                    borderBottom: settingsTab === 'config' ? '2px solid var(--color-primary)' : '2px solid transparent',
                    color: settingsTab === 'config' ? 'var(--color-primary)' : 'var(--color-text-secondary)',
                    fontSize: '0.85rem', fontWeight: 600, cursor: 'pointer',
                  }}
                >
                  ⚙️ Cấu hình
                </button>
                <button
                  onClick={() => setSettingsTab('download')}
                  style={{
                    flex: 1, padding: '10px', background: 'none', border: 'none',
                    borderBottom: settingsTab === 'download' ? '2px solid var(--color-primary)' : '2px solid transparent',
                    color: settingsTab === 'download' ? 'var(--color-primary)' : 'var(--color-text-secondary)',
                    fontSize: '0.85rem', fontWeight: 600, cursor: 'pointer',
                  }}
                >
                  📥 Tải Agent
                </button>
              </div>
            )}

            {/* ── SETTINGS DOWNLOAD TAB ── */}
            {modal === 'settings' && settingsTab === 'download' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <p style={{ fontSize: '0.82rem', color: 'var(--color-text-secondary)', margin: 0 }}>
                  Tải bộ cài đặt PrintAgent để cài lên các máy tính khác trong mạng.
                </p>
                <div style={styles.configDetail}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={styles.configLabel}>PrintAgent v1.2.0 (Ổn định)</span>
                    <a href="https://github.com/nguyenbuu/printagent/releases/download/v1.2.0/PrintAgent_Setup.exe"
                       style={{ ...styles.smallBtn, background: 'var(--color-primary)', color: 'white', border: 'none', textDecoration: 'none' }}>
                      Tải .exe
                    </a>
                  </div>
                </div>
                <div style={{ padding: '10px', background: 'rgba(var(--rgb-primary, 59, 130, 246), 0.05)', borderRadius: '8px', fontSize: '0.78rem', color: 'var(--color-text-secondary)' }}>
                  💡 Sau khi tải về, hãy copy file vào VPS hoặc máy tính cần giám sát và chạy file cài đặt.
                </div>
              </div>
            )}

            {/* ── AGENT EDIT ── */}
            {modal === 'agent_edit' && editingAgent && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <div style={styles.formField}>
                  <label style={styles.label}>Hostname *</label>
                  <input type="text" value={editAgentHostname} onChange={(e) => setEditAgentHostname(e.target.value)}
                    placeholder="VD: DESKTOP-PC1" style={styles.input} />
                </div>
                <div style={styles.formField}>
                  <label style={styles.label}>IP Address</label>
                  <input type="text" value={editAgentIp} onChange={(e) => setEditAgentIp(e.target.value)}
                    placeholder="192.168.1.10" style={styles.input} />
                </div>
                {editAgentError && (
                  <div style={{ padding: '8px 12px', borderRadius: '8px', fontSize: '0.82rem', background: 'color-mix(in srgb, var(--color-error) 10%, var(--color-surface))', color: 'var(--color-error)', border: '1px solid var(--color-error)' }}>
                    {editAgentError}
                  </div>
                )}
                <div style={styles.modalActions}>
                  {actionLoading ? <LoadingSpinner size="sm" /> : (
                    <>
                      <AnimatedButton onClick={handleUpdateAgent}>Cập nhật</AnimatedButton>
                      <AnimatedButton onClick={closeModal} variant="secondary">Hủy</AnimatedButton>
                    </>
                  )}
                </div>
              </div>
            )}

            {/* ── AGENT DELETE ── */}
            {modal === 'agent_delete' && selectedAgent && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <p style={{ fontSize: '0.9rem', color: 'var(--color-text)', margin: 0 }}>
                  Bạn có chắc chắn muốn xóa agent <strong>{selectedAgent.hostname}</strong>?
                </p>
                <p style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', margin: 0 }}>
                  Hành động này sẽ gỡ bỏ agent khỏi hệ thống. Agent sẽ tự động xuất hiện lại nếu vẫn còn đang chạy trên máy tính đó.
                </p>
                <div style={styles.modalActions}>
                  {actionLoading ? <LoadingSpinner size="sm" /> : (
                    <>
                      <AnimatedButton onClick={handleDeleteAgent} variant="danger">
                        Xác nhận xóa
                      </AnimatedButton>
                      <AnimatedButton onClick={closeModal} variant="secondary">Hủy</AnimatedButton>
                    </>
                  )}
                </div>
              </div>
            )}

            {/* ── COPIER CONFIG ── */}
            {modal === 'copier_config' && configCopier && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <p style={{ fontSize: '0.82rem', color: 'var(--color-text-secondary)', margin: 0 }}>
                  Nhập địa chỉ IP để tra cứu MAC ID, sau đó cấu hình thông tin đăng nhập web UI.
                </p>

                {/* Connection status banner */}
                <div style={{
                  padding: '10px 14px', borderRadius: '8px', fontSize: '0.82rem', fontWeight: 600,
                  background: configCopier.isConfigured
                    ? 'color-mix(in srgb, var(--color-success) 10%, var(--color-surface))'
                    : 'color-mix(in srgb, var(--color-warning) 10%, var(--color-surface))',
                  color: configCopier.isConfigured ? 'var(--color-success)' : 'var(--color-warning)',
                  border: `1px solid ${configCopier.isConfigured ? 'var(--color-success)' : 'var(--color-warning)'}`,
                }}>
                  {configCopier.isConfigured ? '🔗 Đã kết nối máy' : '⚠️ Chưa cấu hình kết nối'}
                </div>

                {/* IP Address — primary input, triggers MAC lookup */}
                <div style={styles.formField}>
                  <label style={styles.label}>Địa chỉ IP *</label>
                  <input
                    type="text"
                    value={configIp}
                    onChange={(e) => handleConfigIpChange(e.target.value)}
                    placeholder="192.168.1.200"
                    style={styles.input}
                    autoFocus
                  />
                  <span style={{ fontSize: '0.7rem', color: 'var(--color-text-secondary)', marginTop: '2px' }}>
                    Nhập IP đầy đủ để tự động tra cứu MAC ID
                  </span>
                </div>

                {/* MAC ID — auto-filled from IP, editable */}
                <div style={styles.formField}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                    <label style={styles.label}>MAC ID *</label>
                    {configMacLookupLoading && (
                      <span style={{ fontSize: '0.72rem', color: 'var(--color-primary)' }}>⏳ Đang tra cứu...</span>
                    )}
                    {!configMacLookupLoading && configMac && !configMacEditing && (
                      <span style={{ fontSize: '0.72rem', color: 'var(--color-success)' }}>✓ Đã nhận diện</span>
                    )}
                    {!configMacEditing && configMac && (
                      <button type="button"
                        style={{ background: 'none', border: 'none', color: 'var(--color-primary)', fontSize: '0.72rem', cursor: 'pointer' }}
                        onClick={() => setConfigMacEditing(true)}>✏️ Sửa</button>
                    )}
                  </div>
                  {configMacEditing ? (
                    <div style={{ display: 'flex', gap: '6px' }}>
                      <input type="text" value={configMac}
                        onChange={(e) => {
                          const hex = e.target.value.replace(/[^0-9a-fA-F]/g, '').toUpperCase().slice(0, 12);
                          setConfigMac(hex.match(/.{1,2}/g)?.join(':') ?? hex);
                        }}
                        placeholder="AA:BB:CC:DD:EE:FF"
                        style={{ ...styles.input, fontFamily: 'monospace', letterSpacing: '0.05em', flex: 1 }}
                        maxLength={17} autoFocus />
                      <button type="button" onClick={() => setConfigMacEditing(false)}
                        style={{ ...styles.smallBtn, flexShrink: 0 }}>✓</button>
                    </div>
                  ) : (
                    <div style={{
                      ...styles.input,
                      fontFamily: 'monospace',
                      background: 'var(--color-inset-bg)',
                      color: configMac ? 'var(--color-text)' : 'var(--color-text-secondary)',
                      opacity: configMac ? 0.85 : 0.5,
                    }}>
                      {configMac || 'Nhập IP để tự động điền'}
                    </div>
                  )}
                </div>

                {/* Web UI credentials */}
                <div style={styles.scanBlock}>
                  <div style={styles.scanBlockTitle}>🔐 Tài khoản đăng nhập web UI</div>
                  <div style={styles.formField}>
                    <label style={styles.label}>Username</label>
                    <input type="text" value={configUser} onChange={(e) => setConfigUser(e.target.value)}
                      placeholder="admin" style={styles.input} autoComplete="off" />
                  </div>
                  <div style={styles.formField}>
                    <label style={styles.label}>Password</label>
                    <div style={{ display: 'flex', gap: '6px' }}>
                      <input
                        type={configShowPass ? 'text' : 'password'}
                        value={configPass}
                        onChange={(e) => setConfigPass(e.target.value)}
                        placeholder="(để trống nếu không có)"
                        style={{ ...styles.input, flex: 1 }}
                        autoComplete="new-password"
                      />
                      <button type="button"
                        style={{ ...styles.smallBtn, flexShrink: 0, fontSize: '0.8rem' }}
                        onClick={() => setConfigShowPass((v) => !v)}>
                        {configShowPass ? '🙈' : '👁️'}
                      </button>
                    </div>
                  </div>
                </div>

                {configError && (
                  <div style={{ padding: '8px 12px', borderRadius: '8px', fontSize: '0.82rem', background: 'color-mix(in srgb, var(--color-error) 10%, var(--color-surface))', color: 'var(--color-error)', border: '1px solid var(--color-error)' }}>
                    {configError}
                  </div>
                )}

                <div style={styles.modalActions}>
                  {actionLoading
                    ? <LoadingSpinner size="sm" />
                    : <>
                        <AnimatedButton onClick={handleSaveCopierConfig} disabled={!configIp.trim() || !configMac.trim()}>
                          💾 Lưu cấu hình
                        </AnimatedButton>
                        <AnimatedButton onClick={closeModal} variant="secondary">Hủy</AnimatedButton>
                      </>
                  }
                </div>
              </div>
            )}

            {/* ── COPIER SCAN ── */}
            {modal === 'copier_scan' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                <p style={{ fontSize: '0.82rem', color: 'var(--color-text-secondary)', margin: 0 }}>
                  Quét toàn bộ dải IP trong mạng LAN để tìm máy photocopy đang hoạt động.
                </p>
                {scanProgress === 'idle' && (
                  <AnimatedButton onClick={handleCopierScan}>🔍 Bắt đầu quét</AnimatedButton>
                )}
                {scanProgress === 'scanning' && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '12px', background: 'color-mix(in srgb, var(--color-primary) 8%, var(--color-surface))', borderRadius: '8px', border: '1px solid var(--color-primary)' }}>
                    <LoadingSpinner size="sm" />
                    <span style={{ fontSize: '0.85rem', color: 'var(--color-primary)' }}>Đang quét mạng...</span>
                  </div>
                )}
                {scanProgress === 'done' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    <p style={{ fontSize: '0.82rem', color: 'var(--color-text-secondary)', margin: 0 }}>
                      Tìm thấy {scanFound.length} thiết bị:
                    </p>
                    {scanFound.map(({ ip, mac }) => {
                      const exists = copiers.some((c) => c.ipAddress === ip);
                      return (
                        <div key={ip} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 12px', background: 'var(--color-inset-bg)', borderRadius: '8px', border: '1px solid var(--color-surface-light)' }}>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                            <span style={{ fontSize: '0.85rem', color: 'var(--color-text)' }}>🖨️ {ip}</span>
                            <span style={{ fontSize: '0.72rem', color: 'var(--color-text-secondary)', fontFamily: 'monospace' }}>MAC: {mac}</span>
                          </div>
                          {exists ? (
                            <span style={{ fontSize: '0.72rem', color: 'var(--color-text-secondary)' }}>Đã có</span>
                          ) : (
                            <button style={{ ...styles.smallBtn, fontSize: '0.72rem', padding: '4px 8px' }}
                              onClick={() => {
                                setNewCopierIp(ip);
                                setNewCopierMac(mac);
                                setModal('copier_add');
                                setScanProgress('idle');
                              }}>
                              + Thêm
                            </button>
                          )}
                        </div>
                      );
                    })}
                    <button style={{ ...styles.smallBtn, marginTop: '4px' }} onClick={() => setScanProgress('idle')}>🔄 Quét lại</button>
                  </div>
                )}
              </div>
            )}

            {/* ── COPIER ADD MANUAL ── */}
            {modal === 'copier_add' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <div style={styles.formField}>
                  <label style={styles.label}>Tên máy *</label>
                  <input type="text" value={newCopierName} onChange={(e) => setNewCopierName(e.target.value)}
                    placeholder="VD: Ricoh MP 7503 - Tầng 2" style={styles.input} />
                </div>
                <div style={styles.formField}>
                  <label style={styles.label}>Dòng máy *</label>
                  <div style={styles.brandRow}>
                    {PRINTER_BRANDS.map((brand) => (
                      <button key={brand} style={{
                        ...styles.brandBtn,
                        background: newCopierBrand === brand ? 'color-mix(in srgb, var(--color-primary) 12%, var(--color-surface))' : 'var(--color-bg)',
                        borderColor: newCopierBrand === brand ? 'var(--color-primary)' : 'var(--color-surface-light)',
                        color: newCopierBrand === brand ? 'var(--color-primary)' : 'var(--color-text)',
                      }} onClick={() => setNewCopierBrand(brand)}>
                        {brand}
                      </button>
                    ))}
                  </div>
                </div>
                <div style={styles.formField}>
                  <label style={styles.label}>Model *</label>
                  <input type="text" value={newCopierModel} onChange={(e) => setNewCopierModel(e.target.value)}
                    placeholder="VD: MP 7503" style={styles.input} />
                </div>
                <div style={styles.formField}>
                  <label style={styles.label}>Địa chỉ IP *</label>
                  <input type="text" value={newCopierIp} onChange={(e) => handleCopierIpChange(e.target.value)}
                    placeholder="192.168.1.200" style={styles.input} />
                </div>
                <div style={styles.formField}>
                  <label style={styles.label}>Vị trí</label>
                  <input type="text" value={newCopierLocation} onChange={(e) => setNewCopierLocation(e.target.value)}
                    placeholder="VD: Phòng kế toán - Tầng 2" style={styles.input} />
                </div>
                {/* MAC ID — disabled by default, click to edit */}
                <div style={styles.formField}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                    <label style={styles.label}>MAC ID *</label>
                    {macLookupLoading && <span style={{ fontSize: '0.72rem', color: 'var(--color-primary)' }}>⏳ Đang tra cứu...</span>}
                    {!macLookupLoading && !macEditing && newCopierMac && (
                      <span style={{ fontSize: '0.72rem', color: 'var(--color-success)' }}>✓ Tự động nhận diện</span>
                    )}
                  </div>
                  {!macEditing ? (
                    <button
                      type="button"
                      onClick={() => setMacEditing(true)}
                      style={{
                        ...styles.input,
                        textAlign: 'left',
                        cursor: 'pointer',
                        opacity: newCopierMac ? 0.65 : 0.45,
                        fontFamily: 'monospace',
                        color: newCopierMac ? 'var(--color-text)' : 'var(--color-text-secondary)',
                        background: 'var(--color-inset-bg)',
                        border: '1px dashed var(--color-surface-light)',
                        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                      }}
                    >
                      <span>{newCopierMac || 'AA:BB:CC:DD:EE:FF'}</span>
                      <span style={{ fontSize: '0.7rem', color: 'var(--color-primary)', fontFamily: 'inherit', opacity: 1 }}>✏️ Sửa</span>
                    </button>
                  ) : (
                    <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                      <input
                        type="text"
                        value={newCopierMac}
                        onChange={(e) => handleMacInput(e.target.value)}
                        placeholder="AA:BB:CC:DD:EE:FF"
                        style={{ ...styles.input, fontFamily: 'monospace', letterSpacing: '0.05em', flex: 1 }}
                        autoFocus
                        maxLength={17}
                      />
                      <button type="button" onClick={() => setMacEditing(false)}
                        style={{ ...styles.smallBtn, flexShrink: 0, padding: '10px 10px', fontSize: '0.75rem' }}>
                        ✓
                      </button>
                    </div>
                  )}
                  <span style={{ fontSize: '0.7rem', color: 'var(--color-text-secondary)', marginTop: '2px' }}>
                    Nhập IP để tự động tra cứu · Bấm để sửa thủ công
                  </span>
                </div>
                {addCopierError && (
                  <div style={{ padding: '8px 12px', borderRadius: '8px', fontSize: '0.82rem', background: 'color-mix(in srgb, var(--color-error) 10%, var(--color-surface))', color: 'var(--color-error)', border: '1px solid var(--color-error)' }}>
                    {addCopierError}
                  </div>
                )}
                <div style={styles.modalActions}>
                  <AnimatedButton onClick={handleAddCopier}>Thêm máy</AnimatedButton>
                  <AnimatedButton onClick={closeModal} variant="secondary">Hủy</AnimatedButton>
                </div>
              </div>
            )}

            {/* ── DRIVER FIELDS ── */}
            {showDriverFields && (
              <>
                {modal === 'settings' && <div style={styles.sectionLabel}>🖨️ Thiết lập Driver máy in</div>}

                {/* Brand */}
                <div style={styles.formField}>
                  <label style={styles.label}>Dòng máy *</label>
                  <div style={styles.brandRow}>
                    {PRINTER_BRANDS.map((brand) => (
                      <button key={brand} style={{
                        ...styles.brandBtn,
                        background: selectedBrand === brand ? 'color-mix(in srgb, var(--color-primary) 12%, var(--color-surface))' : 'var(--color-bg)',
                        borderColor: selectedBrand === brand ? 'var(--color-primary)' : 'var(--color-surface-light)',
                        color: selectedBrand === brand ? 'var(--color-primary)' : 'var(--color-text)',
                      }} onClick={() => { setSelectedBrand(brand); setSelectedModel(null); }}>
                        {brand}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Model */}
                {selectedBrand && (
                  <div style={styles.formField}>
                    <label style={styles.label}>Mã máy *</label>
                    <div style={styles.modelGrid}>
                      {modelsForBrand.map((m) => (
                        <button key={m.code} style={{
                          ...styles.modelBtn,
                          background: selectedModel?.code === m.code ? 'color-mix(in srgb, var(--color-primary) 12%, var(--color-surface))' : 'var(--color-bg)',
                          borderColor: selectedModel?.code === m.code ? 'var(--color-primary)' : 'var(--color-surface-light)',
                          color: selectedModel?.code === m.code ? 'var(--color-primary)' : 'var(--color-text)',
                        }} onClick={() => setSelectedModel(m)}>
                          <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>{m.code}</span>
                          <span style={{ fontSize: '0.6rem', color: 'var(--color-text-secondary)', textAlign: 'center' as const }}>{m.model}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {selectedModel && (
                  <div style={{ fontSize: '0.78rem', color: 'var(--color-primary)' }}>Driver: {selectedModel.driverName}</div>
                )}

                {/* IP + Port */}
                <div style={styles.formRow}>
                  <div style={{ ...styles.formField, flex: 2 }}>
                    <label style={styles.label}>IP máy in *</label>
                    <input type="text" value={printerIp} onChange={(e) => setPrinterIp(e.target.value)}
                      placeholder="192.168.1.200" style={styles.input} />
                  </div>
                  <div style={{ ...styles.formField, flex: 1 }}>
                    <label style={styles.label}>Port</label>
                    <select value={printerPort} onChange={(e) => setPrinterPort(e.target.value === 'custom' ? 'custom' : 9100)} style={styles.input}>
                      {PORT_OPTIONS.map((o) => <option key={String(o.value)} value={o.value}>{o.label}</option>)}
                    </select>
                  </div>
                </div>
                {printerPort === 'custom' && (
                  <div style={styles.formField}>
                    <label style={styles.label}>Số port *</label>
                    <input type="number" value={customPort} onChange={(e) => setCustomPort(e.target.value)}
                      placeholder="VD: 515" style={styles.input} min="1" max="65535" />
                  </div>
                )}
              </>
            )}

            {showDriverFields && showScanFields && <div style={styles.divider} />}

            {/* ── SCAN FIELDS ── */}
            {showScanFields && (
              <>
                {modal === 'settings' && <div style={styles.sectionLabel}>📠 Thiết lập Scan</div>}

                {/* Copier credentials */}
                <div style={styles.scanBlock}>
                  <div style={styles.scanBlockTitle}>🖨️ Tài khoản máy Photocopy</div>
                  <p style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)', margin: 0 }}>
                    Dùng để đăng nhập web UI máy photocopy và cấu hình scan destination.
                  </p>
                  <div style={styles.formField}>
                    <label style={styles.label}>IP máy Photocopy *</label>
                    <input type="text" value={copierIp} onChange={(e) => setCopierIp(e.target.value)}
                      placeholder="192.168.1.200" style={styles.input} />
                  </div>
                  <div style={styles.formRow}>
                    <div style={{ ...styles.formField, flex: 1 }}>
                      <label style={styles.label}>Username *</label>
                      <input type="text" value={copierUser} onChange={(e) => setCopierUser(e.target.value)}
                        placeholder="admin" style={styles.input} autoComplete="off" />
                    </div>
                    <div style={{ ...styles.formField, flex: 1 }}>
                      <label style={styles.label}>Password</label>
                      <input type="password" value={copierPass} onChange={(e) => setCopierPass(e.target.value)}
                        placeholder="(để trống nếu không có)" style={styles.input} autoComplete="new-password" />
                    </div>
                  </div>
                </div>

                {/* Enable SMB / FTP checkboxes */}
                <div style={styles.formField}>
                  <label style={styles.label}>Loại scan (có thể chọn cả hai)</label>
                  <div style={styles.checkRow}>
                    <label style={styles.checkLabel}>
                      <input type="checkbox" checked={enableSmb} onChange={(e) => setEnableSmb(e.target.checked)}
                        style={{ accentColor: 'var(--color-primary)', flexShrink: 0, width: 'auto' }} />
                      SMB
                    </label>
                    <label style={styles.checkLabel}>
                      <input type="checkbox" checked={enableFtp} onChange={(e) => setEnableFtp(e.target.checked)}
                        style={{ accentColor: 'var(--color-primary)', flexShrink: 0, width: 'auto' }} />
                      FTP
                    </label>
                  </div>
                </div>

                {/* Priority — only when both enabled */}
                {enableSmb && enableFtp && (
                  <div style={styles.formField}>
                    <label style={styles.label}>Ưu tiên</label>
                    <div style={styles.checkRow}>
                      {(['smb', 'ftp'] as const).map((t) => (
                        <label key={t} style={styles.checkLabel}>
                          <input type="radio" name="scanPriority" value={t} checked={scanPriority === t}
                            onChange={() => setScanPriority(t)}
                            style={{ accentColor: 'var(--color-primary)', flexShrink: 0, width: 'auto' }} />
                          {t.toUpperCase()}
                        </label>
                      ))}
                    </div>
                  </div>
                )}

                {/* Auto config checkbox */}
                <div style={styles.formField}>
                  <label style={styles.checkLabel}>
                    <input type="checkbox" checked={scanAutoConfig} onChange={(e) => setScanAutoConfig(e.target.checked)}
                      style={{ accentColor: 'var(--color-primary)', flexShrink: 0, width: 'auto' }} />
                    Tự động cấu hình scan (Auto)
                  </label>
                </div>

                {/* SMB config */}
                {enableSmb && (
                  <div style={styles.scanBlock}>
                    <div style={styles.scanBlockTitle}>SMB</div>
                    <div style={styles.formField}>
                      <label style={styles.label}>Server *</label>
                      <input type="text" value={smbServer} onChange={(e) => setSmbServer(e.target.value)}
                        placeholder="192.168.1.10" style={styles.input} />
                    </div>
                    <div style={styles.formField}>
                      <label style={styles.label}>Đường dẫn *</label>
                      <div style={styles.pathRow}>
                        <input type="text" value={smbPath} onChange={(e) => setSmbPath(e.target.value)}
                          placeholder="/scan/folder" style={{ ...styles.input, flex: 1 }} />
                        <select
                          value={smbDrive}
                          onChange={(e) => setSmbDrive(e.target.value)}
                          style={styles.driveSelect}
                          title="Chọn ổ đĩa"
                        >
                          {availableDrives.map((d) => <option key={d} value={d}>{d}:</option>)}
                        </select>
                        <button
                          style={styles.autoPathBtn}
                          onClick={() => setSmbPath(`${smbDrive}:\\ScanGox`)}
                          title={`Tạo thư mục ${smbDrive}:\\ScanGox`}
                          type="button"
                        >
                          📁 Tự động
                        </button>
                      </div>
                    </div>
                    <div style={styles.formRow}>
                      <div style={{ ...styles.formField, flex: 1 }}>
                        <label style={styles.label}>Username *</label>
                        <input type="text" value={smbUser} onChange={(e) => setSmbUser(e.target.value)}
                          placeholder="user" style={styles.input} />
                      </div>
                      <div style={{ ...styles.formField, flex: 1 }}>
                        <label style={styles.label}>Password *</label>
                        <input type="password" value={smbPass} onChange={(e) => setSmbPass(e.target.value)}
                          placeholder="pass" style={styles.input} />
                      </div>
                    </div>
                  </div>
                )}

                {/* FTP config */}
                {enableFtp && (
                  <div style={styles.scanBlock}>
                    <div style={styles.scanBlockTitle}>FTP</div>
                    <div style={styles.formField}>
                      <label style={styles.label}>Server *</label>
                      <input type="text" value={ftpServer} onChange={(e) => setFtpServer(e.target.value)}
                        placeholder="192.168.1.10" style={styles.input} />
                    </div>
                    <div style={styles.formField}>
                      <label style={styles.label}>Đường dẫn *</label>
                      <div style={styles.pathRow}>
                        <input type="text" value={ftpPath} onChange={(e) => setFtpPath(e.target.value)}
                          placeholder="/ftp/folder" style={{ ...styles.input, flex: 1 }} />
                        <select
                          value={ftpDrive}
                          onChange={(e) => setFtpDrive(e.target.value)}
                          style={styles.driveSelect}
                          title="Chọn ổ đĩa"
                        >
                          {availableDrives.map((d) => <option key={d} value={d}>{d}:</option>)}
                        </select>
                        <button
                          style={styles.autoPathBtn}
                          onClick={() => setFtpPath(`${ftpDrive}:\\ScanGox`)}
                          title={`Tạo thư mục ${ftpDrive}:\\ScanGox`}
                          type="button"
                        >
                          📁 Tự động
                        </button>
                      </div>
                    </div>
                    <div style={styles.formRow}>
                      <div style={{ ...styles.formField, flex: 1 }}>
                        <label style={styles.label}>Username *</label>
                        <input type="text" value={ftpUser} onChange={(e) => setFtpUser(e.target.value)}
                          placeholder="user" style={styles.input} />
                      </div>
                      <div style={{ ...styles.formField, flex: 1 }}>
                        <label style={styles.label}>Password *</label>
                        <input type="password" value={ftpPass} onChange={(e) => setFtpPass(e.target.value)}
                          placeholder="pass" style={styles.input} />
                      </div>
                    </div>
                  </div>
                )}
              </>
            )}

            {/* Notification */}
            {modal === 'notify' && (
              <>
                <div style={styles.formField}>
                  <label style={styles.label}>Gửi đến</label>
                  <select value={notifyTarget} onChange={(e) => setNotifyTarget(e.target.value)} style={styles.input}>
                    <option value="all">Tất cả agent</option>
                    {agents.filter((a) => a.status === 'online').map((a) => (
                      <option key={a.id} value={a.id}>{a.hostname}</option>
                    ))}
                  </select>
                </div>
                <div style={styles.formField}>
                  <label style={styles.label}>Nội dung thông báo</label>
                  <textarea value={notifyMessage} onChange={(e) => setNotifyMessage(e.target.value)}
                    placeholder="Nhập nội dung thông báo..." rows={3}
                    style={{ ...styles.input, resize: 'vertical' as const, fontFamily: 'inherit' }} />
                </div>
              </>
            )}

            {/* Results */}
            {results.length > 0 && (
              <div style={styles.resultBox}>
                {results.map((r, i) => (
                  <div key={i} style={{ fontSize: '0.8rem', color: r.success ? 'var(--color-success)' : 'var(--color-error)', marginBottom: '2px' }}>
                    {r.message}
                  </div>
                ))}
              </div>
            )}

            <div style={styles.modalActions}>
              {actionLoading ? <LoadingSpinner size="sm" /> : (
                modal !== 'copier_scan' && modal !== 'copier_add' && modal !== 'copier_config' ? (
                  <>
                    <AnimatedButton onClick={handleExecute}>{results.length > 0 ? 'Thực hiện lại' : 'Thực hiện'}</AnimatedButton>
                    <AnimatedButton onClick={closeModal} variant="secondary">Đóng</AnimatedButton>
                  </>
                ) : modal === 'copier_scan' ? (
                  <AnimatedButton onClick={closeModal} variant="secondary">Đóng</AnimatedButton>
                ) : null
              )}
            </div>
          </motion.div>
        </div>
      )}
    </motion.div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: { minHeight: '100vh', padding: '20px 16px', paddingBottom: '100px', display: 'flex', flexDirection: 'column', gap: '16px' },
  loadingContainer: { minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' },
  title: { fontSize: '1.5rem', fontWeight: 700, color: 'var(--color-primary)', margin: 0 },
  subtitle: { fontSize: '0.85rem', color: 'var(--color-text-secondary)', margin: 0 },
  sectionTitle: { fontSize: '1rem', fontWeight: 600, color: 'var(--color-text)', margin: '0 0 10px' },
  sectionLabel: { fontSize: '0.85rem', fontWeight: 600, color: 'var(--color-primary)', paddingBottom: '4px' },
  bulkActions: { display: 'flex', flexWrap: 'wrap' as const, gap: '8px' },
  bulkRow: { display: 'flex', gap: '8px', marginBottom: '8px' },
  bulkTile: {
    flex: 1, display: 'flex', flexDirection: 'column' as const, alignItems: 'center', gap: '4px',
    padding: '14px 8px', borderRadius: '10px', cursor: 'pointer',
    background: 'var(--color-inset-bg)', border: '1px solid var(--color-surface-light)',
    color: 'var(--color-text)', transition: 'border-color 150ms',
  },
  bulkTileIcon: { fontSize: '1.4rem', lineHeight: 1 },
  bulkTileLabel: { fontSize: '0.82rem', fontWeight: 700, color: 'var(--color-text)' },
  bulkTileSub: { fontSize: '0.68rem', color: 'var(--color-text-secondary)' },
  bulkPrimary: {
    width: '100%', display: 'flex', alignItems: 'center', gap: '12px',
    padding: '13px 16px', borderRadius: '10px', cursor: 'pointer', marginBottom: '8px',
    background: 'color-mix(in srgb, var(--color-primary) 10%, var(--color-surface))',
    border: '1px solid var(--color-primary)', color: 'var(--color-primary)',
    fontSize: '1.2rem',
  },
  bulkSecondary: {
    flex: 1, padding: '10px 8px', borderRadius: '8px', cursor: 'pointer',
    background: 'transparent', border: '1px solid var(--color-surface-light)',
    color: 'var(--color-text-secondary)', fontSize: '0.8rem', fontWeight: 600,
  },
  actionBtn: {
    background: 'var(--color-bg)', color: 'var(--color-text)',
    border: '1px solid var(--color-surface-light)', borderRadius: '8px',
    padding: '10px 14px', fontSize: '0.8rem', fontWeight: 500, cursor: 'pointer',
  },
  agentHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' },
  agentInfo: { display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' as const },
  agentName: { fontSize: '0.95rem', fontWeight: 600, color: 'var(--color-text)' },
  statusBadge: { fontSize: '0.7rem', fontWeight: 600, padding: '2px 8px', borderRadius: '6px', border: '1px solid' },
  agentMeta: { display: 'flex', flexDirection: 'column' as const, gap: '2px', marginBottom: '6px' },
  metaText: { fontSize: '0.8rem', color: 'var(--color-text-secondary)' },
  statusRow: { display: 'flex', flexWrap: 'wrap' as const, gap: '6px', marginBottom: '8px' },
  statusChip: { fontSize: '0.7rem', fontWeight: 600, padding: '3px 8px', borderRadius: '6px', border: '1px solid', whiteSpace: 'nowrap' as const },
  configDetail: {
    display: 'flex', flexDirection: 'column' as const, gap: '2px',
    padding: '6px 10px', marginBottom: '6px',
    background: 'var(--color-inset-bg)', borderRadius: '6px', border: '1px solid var(--color-surface-light)',
  },
  configLabel: { fontSize: '0.8rem', fontWeight: 600, color: 'var(--color-text)' },
  configSub: { fontSize: '0.75rem', color: 'var(--color-text-secondary)', paddingLeft: '4px' },
  agentActions: { display: 'flex', gap: '6px', flexWrap: 'wrap' as const },
  smallBtn: {
    background: 'transparent', color: 'var(--color-primary)',
    border: '1px solid var(--color-surface-light)', borderRadius: '6px',
    padding: '6px 10px', fontSize: '0.75rem', fontWeight: 500, cursor: 'pointer',
  },
  overlay: {
    position: 'fixed' as const, top: 0, left: 0, right: 0, bottom: 0,
    background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 200, padding: '16px',
  },
  modal: {
    background: 'var(--color-surface)', border: '1px solid var(--color-surface-light)',
    borderRadius: '12px', padding: '20px', width: '100%', maxWidth: 'min(500px, 90vw)',
    maxHeight: '88vh', overflowY: 'auto' as const,
    display: 'flex', flexDirection: 'column' as const, gap: '10px',
    boxShadow: '0 8px 32px rgba(0,0,0,0.18)',
  },
  modalTitle: { fontSize: '1rem', fontWeight: 600, color: 'var(--color-text)', margin: 0 },
  formField: { display: 'flex', flexDirection: 'column' as const, gap: '4px' },
  formRow: { display: 'flex', gap: '8px' },
  label: { fontSize: '0.8rem', color: 'var(--color-text-secondary)', fontWeight: 500 },
  input: {
    background: 'var(--color-bg)', color: 'var(--color-text)',
    border: '1px solid var(--color-surface-light)', borderRadius: '8px',
    padding: '10px 12px', fontSize: '0.9rem', width: '100%', boxSizing: 'border-box' as const,
  },
  brandRow: { display: 'flex', gap: '8px' },
  brandBtn: { flex: 1, padding: '10px 8px', borderRadius: '8px', border: '1px solid', fontSize: '0.85rem', fontWeight: 600, cursor: 'pointer' },
  modelGrid: { display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '6px' },
  modelBtn: { display: 'flex', flexDirection: 'column' as const, alignItems: 'center', gap: '2px', padding: '8px 4px', borderRadius: '8px', border: '1px solid', cursor: 'pointer' },
  // Checkbox/radio row — key fix: use flexbox with proper wrapping, no overflow
  checkRow: { display: 'flex', gap: '16px', flexWrap: 'wrap' as const },
  checkLabel: {
    display: 'flex', alignItems: 'center', gap: '6px',
    fontSize: '0.85rem', color: 'var(--color-text)', cursor: 'pointer',
    fontWeight: 500, minWidth: 0,
  },
  scanBlock: {
    border: '1px solid var(--color-surface-light)', borderRadius: '8px',
    padding: '10px 12px', display: 'flex', flexDirection: 'column' as const, gap: '8px',
  },
  scanBlockTitle: { fontSize: '0.8rem', fontWeight: 700, color: 'var(--color-primary)', marginBottom: '2px' },
  pathRow: { display: 'flex', gap: '6px', alignItems: 'center' },
  driveSelect: {
    background: 'var(--color-bg)', color: 'var(--color-text)',
    border: '1px solid var(--color-surface-light)', borderRadius: '8px',
    padding: '10px 8px', fontSize: '0.85rem', width: '52px', flexShrink: 0,
    boxSizing: 'border-box' as const,
  },
  autoPathBtn: {
    background: 'color-mix(in srgb, var(--color-primary) 10%, var(--color-surface))', color: 'var(--color-primary)',
    border: '1px solid var(--color-primary)', borderRadius: '8px',
    padding: '10px 10px', fontSize: '0.75rem', fontWeight: 600,
    cursor: 'pointer', whiteSpace: 'nowrap' as const, flexShrink: 0,
  },
  divider: { height: '1px', background: 'var(--color-surface-light)', margin: '2px 0' },
  resultBox: {
    background: 'var(--color-inset-bg)', borderRadius: '8px', padding: '10px 12px',
    border: '1px solid var(--color-surface-light)', maxHeight: '150px', overflowY: 'auto' as const,
  },
  modalActions: { display: 'flex', gap: '8px', marginTop: '4px' },
  connectHint: { fontSize: '0.82rem', color: 'var(--color-text-secondary)', margin: '0 0 4px' },
  backBtn: {
    background: 'none', border: 'none', color: 'var(--color-text-secondary)',
    fontSize: '0.85rem', cursor: 'pointer', padding: '0', fontWeight: 500,
  },
  // Tab bar
  tabBar: { display: 'flex', borderBottom: '1px solid var(--color-surface-light)', gap: '0' },
  tabBtn: {
    flex: 1, padding: '10px 8px', fontSize: '0.85rem', fontWeight: 600,
    cursor: 'pointer', border: 'none', borderRadius: '0',
    display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px',
    transition: 'color 200ms, background 200ms',
  },
  tabBadge: {
    fontSize: '0.65rem', fontWeight: 700, padding: '1px 6px', borderRadius: '8px',
    background: 'color-mix(in srgb, var(--color-primary) 15%, var(--color-surface))', color: 'var(--color-primary)',
  },
  // Copier section
  copierSummary: { padding: '4px 0' },
  copierSummaryText: { fontSize: '0.82rem', color: 'var(--color-text-secondary)' },
  copierHeader: { display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '8px', marginBottom: '6px' },
  copierName: { fontSize: '0.9rem', fontWeight: 600, color: 'var(--color-text)' },
  copierLocation: { fontSize: '0.75rem', color: 'var(--color-text-secondary)' },
  copierMeta: { display: 'flex', flexDirection: 'column' as const, gap: '2px', marginBottom: '8px' },
  expandBtn: {
    background: 'none', border: '1px solid var(--color-surface-light)', borderRadius: '6px',
    color: 'var(--color-primary)', fontSize: '0.75rem', fontWeight: 500,
    padding: '5px 10px', cursor: 'pointer', alignSelf: 'flex-start' as const, marginTop: '4px',
  },
  pcList: {
    display: 'flex', flexDirection: 'column' as const, gap: '6px',
    marginTop: '10px', padding: '10px 12px',
    background: 'var(--color-inset-bg)', borderRadius: '8px',
    border: '1px solid var(--color-surface-light)',
  },
  pcRow: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' },
  pcName: { fontSize: '0.82rem', fontWeight: 500, color: 'var(--color-text)' },
  emptyPcText: { fontSize: '0.8rem', color: 'var(--color-text-secondary)', textAlign: 'center' as const, padding: '4px 0' },
};
