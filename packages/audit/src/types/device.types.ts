/**
 * Tipos para gerenciamento de dispositivos no ZERO
 */

/**
 * Status de confiança de um dispositivo
 */
export type DeviceTrustLevel = 'untrusted' | 'trusted' | 'verified';

/**
 * Tipo de dispositivo
 */
export type DeviceType = 
  | 'desktop'
  | 'mobile'
  | 'tablet'
  | 'unknown';

/**
 * Sistema operacional do dispositivo
 */
export type DeviceOS =
  | 'windows'
  | 'macos'
  | 'linux'
  | 'ios'
  | 'android'
  | 'unknown';

/**
 * Navegador do dispositivo
 */
export type DeviceBrowser =
  | 'chrome'
  | 'firefox'
  | 'safari'
  | 'edge'
  | 'opera'
  | 'unknown';

/**
 * Informações detalhadas de um dispositivo
 */
export interface DeviceInfo {
  id: string;
  userId: string;
  name: string;
  type: DeviceType;
  os: DeviceOS;
  osVersion?: string;
  browser: DeviceBrowser;
  browserVersion?: string;
  trustLevel: DeviceTrustLevel;
  ipAddress: string;
  lastSeenAt: Date;
  createdAt: Date;
  updatedAt: Date;
  metadata?: {
    fingerprint?: string;
    location?: {
      country?: string;
      region?: string;
      city?: string;
    };
  };
}

/**
 * Dados para registro de novo dispositivo
 */
export interface RegisterDeviceData {
  userId: string;
  name?: string;
  userAgent: string;
  ipAddress: string;
  fingerprint?: string;
}

/**
 * Dados para atualização de dispositivo
 */
export interface UpdateDeviceData {
  name?: string;
  trustLevel?: DeviceTrustLevel;
  metadata?: Record<string, unknown>;
}

/**
 * Filtros para busca de dispositivos
 */
export interface DeviceFilters {
  userId?: string;
  trustLevel?: DeviceTrustLevel;
  type?: DeviceType;
  os?: DeviceOS;
  limit?: number;
  offset?: number;
}
