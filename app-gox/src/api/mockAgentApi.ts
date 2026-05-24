import type { Agent, AgentActionResult, PrinterDriverConfig, ScanConfig, Copier } from '../types/agent';

const BASE_URL = import.meta.env.VITE_API_URL || 'https://agentapi.quanlymay.com';

async function fetchApi(path: string, options: RequestInit = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.error || `HTTP error! status: ${res.status}`);
  }
  return res.json();
}

export async function mockGetAgents(lanUid?: string): Promise<Agent[]> {
  const url = lanUid
    ? `/api/infor/list?lead=default&lan_uid=${encodeURIComponent(lanUid)}`
    : '/api/infor/list?lead=default';
  const data = await fetchApi(url);
  const uniqueAgents = new Map();
  
  (data.rows || []).forEach((r: any) => {
    if (!uniqueAgents.has(r.agent_uid)) {
      uniqueAgents.set(r.agent_uid, {
        id: r.agent_uid,
        hostname: r.printer_name || 'Agent',
        ipAddress: r.ip || '',
        os: 'Windows',
        status: r.is_latest ? 'online' : 'offline',
        lastSeen: r.updated_at,
        driverInstalled: true,
        scanSmbInstalled: false,
        scanFtpInstalled: false,
        scanConfigured: false,
      });
    }
  });
  
  return Array.from(uniqueAgents.values());
}

export async function mockInstallPrinterDriver(agentId: string, config: PrinterDriverConfig): Promise<AgentActionResult> {
  try {
    const res = await fetchApi(`/api/devices/${config.printerIp}/install-driver`, {
      method: 'POST',
      body: JSON.stringify({
        brand: config.brand,
        model: config.model,
        driver_name: config.driverName,
        driver_url: config.driverUrl || '',
      }),
    });
    return {
      success: res.ok !== false,
      message: res.message || `Lệnh cài driver đã được gửi thành công.`,
      agentId
    };
  } catch (err: any) {
    return {
      success: false,
      message: `Lỗi cài driver: ${err.message}`,
      agentId
    };
  }
}

export async function getDriversCatalog(brand: string): Promise<any[]> {
  try {
    const res = await fetchApi(`/api/drivers/${brand.toLowerCase()}`);
    if (res.ok && res.data) {
      return res.data;
    }
    return [];
  } catch (err) {
    console.error('Failed to fetch drivers catalog:', err);
    return [];
  }
}

export async function mockInstallScan(agentId: string, _config: ScanConfig): Promise<AgentActionResult> {
  return { success: true, message: `Lệnh cài scan đã được gửi đến agent ${agentId}`, agentId };
}

export async function mockBulkInstallDriver(_config: PrinterDriverConfig): Promise<AgentActionResult[]> {
  return [];
}

export async function mockBulkInstallScan(_config: ScanConfig): Promise<AgentActionResult[]> {
  return [];
}

export async function mockSendNotification(_agentId: string | 'all', _message: string): Promise<AgentActionResult> {
  return { success: true, message: `Đã gửi thông báo` };
}

export interface LanSiteInfo {
  lan_uid: string;
  lan_name: string;
  gateway_ip: string;
  active_agents: number;
  printers: Array<{
    id: number;
    printer_name: string;
    ip: string;
    mac_id: string;
    is_online: boolean;
    enabled: boolean;
  }>;
}

export async function getLanSites(): Promise<LanSiteInfo[]> {
  try {
    const res = await fetchApi('/api/lan-sites?lead=default');
    return res.rows || [];
  } catch (err) {
    console.error('Failed to fetch LAN sites:', err);
    return [];
  }
}

export async function mockGetCopiers(lanUid?: string): Promise<Copier[]> {
  // Use lan-sites API when filtering by LAN (includes printers per LAN)
  if (lanUid) {
    try {
      const res = await fetchApi(`/api/lan-sites?lead=default`);
      const lanRow = (res.rows || []).find((r: any) => r.lan_uid === lanUid);
      if (!lanRow) return [];
      return (lanRow.printers || []).map((p: any) => {
        const printerType = (p.printer_type || p.printer_name || '').toLowerCase();
        let brand: 'Ricoh' | 'Toshiba' | 'Xerox' = 'Ricoh';
        if (printerType.includes('toshiba')) brand = 'Toshiba';
        else if (printerType.includes('xerox') || printerType.includes('fujifilm')) brand = 'Xerox';
        const rawName: string = p.printer_name || '';
        const model = rawName.replace(/^(ricoh|toshiba|xerox|fujifilm)\s*/i, '').trim() || 'Unknown';
        return {
          id: String(p.id),
          name: rawName || 'Máy photocopy',
          brand,
          model,
          ipAddress: p.ip,
          macId: p.mac_id || '',
          status: p.is_online ? 'online' as const : 'offline' as const,
          lastSeen: '',
          connectedPCs: [],
          driverVersion: '',
          location: lanUid,
          isConfigured: p.enabled ?? true,
        };
      });
    } catch (err) {
      console.error('Failed to fetch copiers by LAN:', err);
      return [];
    }
  }

  // Fallback: load all from /api/infor/list (no LAN filter)
  const data = await fetchApi('/api/infor/list?lead=default');
  const uniqueCopiers = new Map<string, Copier>();
  (data.rows || []).forEach((r: any) => {
    const key = r.mac_id || r.ip;
    if (!key || uniqueCopiers.has(key)) return;

    const printerType = (r.printer_type || '').toLowerCase();
    let brand: 'Ricoh' | 'Toshiba' | 'Xerox' = 'Ricoh';
    if (printerType.includes('toshiba')) brand = 'Toshiba';
    else if (printerType.includes('xerox') || printerType.includes('fujifilm')) brand = 'Xerox';

    const rawName: string = r.printer_name || '';
    const model = rawName.replace(/^(ricoh|toshiba|xerox|fujifilm)\s*/i, '').trim() || 'Unknown';

    uniqueCopiers.set(key, {
      id: key,
      name: rawName || 'Máy photocopy',
      brand,
      model,
      ipAddress: r.ip,
      macId: r.mac_id || '',
      status: r.is_latest ? 'online' as const : 'offline' as const,
      lastSeen: r.updated_at,
      connectedPCs: [r.agent_uid].filter(Boolean),
      driverVersion: r.driver_version || '',
      location: r.lan_uid,
      isConfigured: true,
    });
  });
  return Array.from(uniqueCopiers.values());
}



export async function mockConfigureCopier(
  copierId: string,
  _config: { macId: string; ipAddress?: string; webUsername: string; webPassword: string }
): Promise<AgentActionResult> {
  return { success: true, message: `Đã cập nhật cấu hình máy ${copierId}` };
}

export async function mockDeleteCopier(copierId: string): Promise<AgentActionResult> {
  return { success: true, message: `Đã xóa máy photocopy ${copierId}` };
}

export async function mockUpdateAgent(agentId: string, _data: Partial<Agent>): Promise<AgentActionResult> {
  return { success: true, message: `Đã cập nhật thông tin agent ${agentId}` };
}

export async function mockDeleteAgent(agentId: string): Promise<AgentActionResult> {
  return { success: true, message: `Đã xóa agent ${agentId}` };
}
