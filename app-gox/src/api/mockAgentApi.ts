import type { Agent, AgentActionResult, PrinterDriverConfig, ScanConfig, Copier } from '../types/agent';

const BASE_URL = 'https://agentapi.quanlymay.com';

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

export async function mockGetAgents(): Promise<Agent[]> {
  const data = await fetchApi('/api/infor/list?lead=default');
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

export async function mockInstallPrinterDriver(agentId: string, _config: PrinterDriverConfig): Promise<AgentActionResult> {
  return { success: true, message: `Lệnh cài driver đã được gửi đến agent ${agentId}`, agentId };
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

export async function mockGetCopiers(): Promise<Copier[]> {
  const data = await fetchApi('/api/infor/list?lead=default');
  return (data.rows || []).map((r: any) => ({
    id: r.mac_id,
    name: r.printer_name || 'Ricoh Printer',
    model: 'MP 7503',
    ipAddress: r.ip,
    macId: r.mac_id,
    status: r.is_latest ? 'online' : 'offline',
    lastSeen: r.updated_at,
    connectedPCs: [r.agent_uid],
    driverVersion: 'v1.0',
    location: r.lan_uid,
    isConfigured: true,
  }));
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
