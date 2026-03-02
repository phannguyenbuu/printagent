import type { Agent, AgentActionResult, PrinterDriverConfig, ScanConfig, Copier } from '../types/agent';
import { mockAgents, mockCopiers } from './mockAgentData';

let agents: Agent[] = [...mockAgents];
let copiers: Copier[] = [...mockCopiers];

function delay(ms?: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms ?? 300 + Math.random() * 200));
}

export async function mockGetAgents(): Promise<Agent[]> {
  await delay();
  return [...agents];
}

export async function mockInstallPrinterDriver(agentId: string, config: PrinterDriverConfig): Promise<AgentActionResult> {
  await delay(800);
  const idx = agents.findIndex((a) => a.id === agentId);
  if (idx === -1) return { success: false, message: 'Không tìm thấy agent', agentId };
  if (agents[idx].status === 'offline') return { success: false, message: 'Agent đang offline', agentId };
  agents[idx] = { ...agents[idx], printerConfig: config, driverInstalled: true };
  const port = config.port === 'custom' ? config.customPort : config.port;
  return { success: true, message: `Đã cài driver "${config.brand} ${config.model}" (${config.printerIp}:${port}) cho ${agents[idx].hostname}`, agentId };
}

export async function mockInstallScan(agentId: string, config: ScanConfig): Promise<AgentActionResult> {
  await delay(800);
  const idx = agents.findIndex((a) => a.id === agentId);
  if (idx === -1) return { success: false, message: 'Không tìm thấy agent', agentId };
  if (agents[idx].status === 'offline') return { success: false, message: 'Agent đang offline', agentId };
  agents[idx] = {
    ...agents[idx],
    scanConfig: config,
    scanSmbInstalled: config.enableSmb ? true : agents[idx].scanSmbInstalled,
    scanFtpInstalled: config.enableFtp ? true : agents[idx].scanFtpInstalled,
    scanConfigured: config.autoConfig,
  };
  const types = [config.enableSmb && 'SMB', config.enableFtp && 'FTP'].filter(Boolean).join('+');
  return { success: true, message: `Đã cài scan ${types} cho ${agents[idx].hostname}`, agentId };
}

export async function mockBulkInstallDriver(config: PrinterDriverConfig): Promise<AgentActionResult[]> {
  await delay(1500);
  const results: AgentActionResult[] = [];
  for (let i = 0; i < agents.length; i++) {
    if (agents[i].status === 'online') {
      agents[i] = { ...agents[i], printerConfig: config, driverInstalled: true };
      results.push({ success: true, message: `✓ ${agents[i].hostname}`, agentId: agents[i].id });
    } else {
      results.push({ success: false, message: `✗ ${agents[i].hostname} (offline)`, agentId: agents[i].id });
    }
  }
  return results;
}

export async function mockBulkInstallScan(config: ScanConfig): Promise<AgentActionResult[]> {
  await delay(1500);
  const results: AgentActionResult[] = [];
  for (let i = 0; i < agents.length; i++) {
    if (agents[i].status === 'online') {
      agents[i] = {
        ...agents[i],
        scanConfig: config,
        scanSmbInstalled: config.enableSmb ? true : agents[i].scanSmbInstalled,
        scanFtpInstalled: config.enableFtp ? true : agents[i].scanFtpInstalled,
        scanConfigured: config.autoConfig,
      };
      results.push({ success: true, message: `✓ ${agents[i].hostname}`, agentId: agents[i].id });
    } else {
      results.push({ success: false, message: `✗ ${agents[i].hostname} (offline)`, agentId: agents[i].id });
    }
  }
  return results;
}

export async function mockSendNotification(agentId: string | 'all', _message: string): Promise<AgentActionResult> {
  await delay(600);
  if (agentId === 'all') {
    const onlineCount = agents.filter((a) => a.status === 'online').length;
    return { success: true, message: `Đã gửi thông báo đến ${onlineCount} agent online` };
  }
  const agent = agents.find((a) => a.id === agentId);
  if (!agent) return { success: false, message: 'Không tìm thấy agent' };
  if (agent.status === 'offline') return { success: false, message: `${agent.hostname} đang offline` };
  return { success: true, message: `Đã gửi thông báo đến ${agent.hostname}` };
}

export async function mockGetCopiers(): Promise<Copier[]> {
  await delay();
  return [...copiers];
}

export async function mockConfigureCopier(
  copierId: string,
  config: { macId: string; ipAddress?: string; webUsername: string; webPassword: string }
): Promise<AgentActionResult> {
  await delay(600);
  const idx = copiers.findIndex((c) => c.id === copierId);
  if (idx === -1) return { success: false, message: 'Không tìm thấy máy photocopy' };
  const newMac = config.macId.trim().toUpperCase();
  if (newMac && copiers.some((c, i) => c.macId === newMac && i !== idx)) {
    return { success: false, message: 'MAC ID này đã được dùng bởi máy khác' };
  }
  copiers[idx] = {
    ...copiers[idx],
    macId: newMac || copiers[idx].macId,
    id: newMac || copiers[idx].id,
    ipAddress: config.ipAddress?.trim() || copiers[idx].ipAddress,
    webUsername: config.webUsername.trim(),
    webPassword: config.webPassword,
    isConfigured: true,
  };
  return { success: true, message: `Đã cấu hình máy ${copiers[idx].name}` };
}
