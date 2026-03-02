export type PrinterBrand = 'Ricoh' | 'Toshiba' | 'Xerox';

export interface PrinterModel {
  brand: PrinterBrand;
  model: string;
  code: string;
  driverName: string;
}

export interface PrinterDriverConfig {
  brand: PrinterBrand;
  model: string;
  driverName: string;
  printerIp: string;
  port: number | 'custom';
  customPort?: number;
}

export interface ScanChannelConfig {
  server: string;
  path: string;
  username: string;
  password: string;
}

export interface ScanConfig {
  enableSmb: boolean;
  enableFtp: boolean;
  priority: 'smb' | 'ftp';
  smb?: ScanChannelConfig;
  ftp?: ScanChannelConfig;
  autoConfig: boolean;
}

export interface Agent {
  id: string;
  hostname: string;
  ipAddress: string;
  os: string;
  status: 'online' | 'offline';
  lastSeen: string;
  printerConfig?: PrinterDriverConfig;
  scanConfig?: ScanConfig;
  driverInstalled: boolean;
  scanSmbInstalled: boolean;
  scanFtpInstalled: boolean;
  scanConfigured: boolean;
}

export type AgentAction =
  | 'install_printer_driver'
  | 'install_scan'
  | 'setup_scan'
  | 'install_driver_all'
  | 'install_scan_all'
  | 'install_all'
  | 'send_notification'
  | 'general_settings';

export interface AgentActionResult {
  success: boolean;
  message: string;
  agentId?: string;
}

// Predefined printer models by brand
export const PRINTER_MODELS: PrinterModel[] = [
  // Ricoh
  { brand: 'Ricoh', model: 'MP 7503', code: '7503', driverName: 'Ricoh MP 7503 PCL6' },
  { brand: 'Ricoh', model: 'MP 7502', code: '7502', driverName: 'Ricoh MP 7502 PCL6' },
  { brand: 'Ricoh', model: 'MP 6054', code: '6054', driverName: 'Ricoh MP 6054 PCL6' },
  { brand: 'Ricoh', model: 'MP 5054', code: '5054', driverName: 'Ricoh MP 5054 PCL6' },
  { brand: 'Ricoh', model: 'MP 4054', code: '4054', driverName: 'Ricoh MP 4054 PCL6' },
  { brand: 'Ricoh', model: 'MP 3054', code: '3054', driverName: 'Ricoh MP 3054 PCL6' },
  { brand: 'Ricoh', model: 'MP 2014', code: '2014', driverName: 'Ricoh MP 2014 PCL6' },
  // Toshiba
  { brand: 'Toshiba', model: 'e-STUDIO 556', code: '556', driverName: 'Toshiba e-STUDIO 556 PS' },
  { brand: 'Toshiba', model: 'e-STUDIO 456', code: '456', driverName: 'Toshiba e-STUDIO 456 PS' },
  { brand: 'Toshiba', model: 'e-STUDIO 356', code: '356', driverName: 'Toshiba e-STUDIO 356 PS' },
  { brand: 'Toshiba', model: 'e-STUDIO 306', code: '306', driverName: 'Toshiba e-STUDIO 306 PS' },
  { brand: 'Toshiba', model: 'e-STUDIO 2508A', code: '2508A', driverName: 'Toshiba e-STUDIO 2508A PS' },
  // Xerox
  { brand: 'Xerox', model: 'WorkCentre 7855', code: '7855', driverName: 'Xerox WorkCentre 7855 PS' },
  { brand: 'Xerox', model: 'WorkCentre 7845', code: '7845', driverName: 'Xerox WorkCentre 7845 PS' },
  { brand: 'Xerox', model: 'WorkCentre 5855', code: '5855', driverName: 'Xerox WorkCentre 5855 PS' },
  { brand: 'Xerox', model: 'AltaLink C8055', code: 'C8055', driverName: 'Xerox AltaLink C8055 PS' },
  { brand: 'Xerox', model: 'VersaLink C7030', code: 'C7030', driverName: 'Xerox VersaLink C7030 PS' },
];

export const PRINTER_BRANDS: PrinterBrand[] = ['Ricoh', 'Toshiba', 'Xerox'];

// ── Photocopy machine (network copier) ──
export interface Copier {
  id: string;           // dùng macId làm ID phân biệt
  macId: string;        // MAC address, VD: "AA:BB:CC:DD:EE:FF"
  name: string;         // tên định danh, VD: "Ricoh MP 7503 - Tầng 2"
  brand: PrinterBrand;
  model: string;
  ipAddress: string;
  status: 'online' | 'offline';
  lastSeen: string;
  connectedPCs: string[]; // hostname của các PC đang dùng máy này
  driverVersion?: string;
  location?: string;    // vị trí vật lý, VD: "Phòng kế toán - Tầng 2"
  // Connection credentials (for web UI / SNMP access)
  webUsername?: string;
  webPassword?: string;
  isConfigured?: boolean; // true khi đã cấu hình xong user/pass
}
