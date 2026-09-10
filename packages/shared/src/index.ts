/**
 * @zero/shared - Utilitários e tipos compartilhados
 * 
 * Este pacote contém tipos, constantes e utilitários usados em todo o projeto ZERO.
 * Nenhuma lógica sensível de segurança deve residir aqui.
 */

// ============================================================================
// TIPOS FUNDAMENTAIS
// ============================================================================

export type UUID = string;

export interface BaseEntity {
  id: UUID;
  createdAt: Date;
  updatedAt: Date;
}

// ============================================================================
// TIPOS DE USUÁRIO E AUTENTICAÇÃO
// ============================================================================

export interface User extends BaseEntity {
  email: string;
  emailVerified: boolean;
  passwordHash: string; // Argon2id hash - NUNCA logar ou expor
  recoveryCodeHash: string; // Hash do código de recuperação
  totpSecret?: string | null; // Criptografado
  webauthnEnabled: boolean;
  facialAuthEnabled: boolean;
  status: UserStatus;
  lastLoginAt?: Date | null;
  failedLoginAttempts: number;
  lockedUntil?: Date | null;
}

export type UserStatus = 'active' | 'pending_verification' | 'locked' | 'suspended';

export interface Session extends BaseEntity {
  userId: UUID;
  deviceId: UUID;
  refreshTokenHash: string; // Hash do refresh token
  expiresAt: Date;
  revokedAt?: Date | null;
  userAgent: string;
  ipAddress: string;
  lastActivityAt: Date;
  isTrusted: boolean;
}

export interface Device extends BaseEntity {
  userId: UUID;
  name: string;
  type: DeviceType;
  os: string;
  browser: string;
  fingerprint: string; // Hash do device fingerprint
  isTrusted: boolean;
  lastSeenAt: Date;
  createdAt: Date;
}

export type DeviceType = 'desktop' | 'mobile' | 'tablet' | 'unknown';

// ============================================================================
// TIPOS DE DOCUMENTOS
// ============================================================================

export interface Document extends BaseEntity {
  userId: UUID;
  folderId?: UUID | null;
  name: string;
  originalName: string;
  mimeType: string;
  size: number;
  hash: string; // SHA-256 do conteúdo
  encrypted: boolean;
  version: number;
  parentId?: UUID | null; // Para versionamento
  status: DocumentStatus;
  classification?: DocumentClassification | null;
  metadata: DocumentMetadata;
}

export type DocumentStatus = 'active' | 'deleted' | 'archived' | 'pending_scan';

export type DocumentClassification = 'public' | 'internal' | 'confidential' | 'secret';

export interface DocumentMetadata {
  uploadedBy: UUID;
  uploadedAt: Date;
  modifiedBy?: UUID;
  modifiedAt?: Date;
  description?: string;
  tags?: string[];
  customFields?: Record<string, string>;
}

export interface DocumentVersion extends BaseEntity {
  documentId: UUID;
  version: number;
  size: number;
  hash: string;
  changeReason?: string;
  changedBy: UUID;
}

// ============================================================================
// TIPOS DE PASTAS
// ============================================================================

export interface Folder extends BaseEntity {
  userId: UUID;
  parentId?: UUID | null;
  name: string;
  description?: string | null;
  color?: string | null;
  icon?: string | null;
  path: string; // Caminho materializado para buscas rápidas
}

// ============================================================================
// TIPOS DE AUDITORIA
// ============================================================================

export interface AuditLog extends BaseEntity {
  userId?: UUID | null;
  action: AuditAction;
  resourceType: ResourceType;
  resourceId?: UUID | null;
  details: AuditDetails;
  ipAddress?: string | null;
  userAgent?: string | null;
  sessionId?: UUID | null;
  success: boolean;
  errorMessage?: string | null;
}

export type AuditAction =
  | 'LOGIN_SUCCESS'
  | 'LOGIN_FAILURE'
  | 'LOGOUT'
  | 'PASSWORD_CHANGE'
  | 'MFA_ENABLE'
  | 'MFA_DISABLE'
  | 'WEBAUTHN_REGISTER'
  | 'WEBAUTHN_REMOVE'
  | 'FACIAL_AUTH_ENABLE'
  | 'FACIAL_AUTH_DISABLE'
  | 'SESSION_REVOKE'
  | 'DEVICE_TRUST'
  | 'DEVICE_UNTRUST'
  | 'DOCUMENT_UPLOAD'
  | 'DOCUMENT_DOWNLOAD'
  | 'DOCUMENT_VIEW'
  | 'DOCUMENT_UPDATE'
  | 'DOCUMENT_DELETE'
  | 'DOCUMENT_RESTORE'
  | 'FOLDER_CREATE'
  | 'FOLDER_UPDATE'
  | 'FOLDER_DELETE'
  | 'RECOVERY_CODE_GENERATE'
  | 'RECOVERY_CODE_USE'
  | 'ACCOUNT_LOCK'
  | 'ACCOUNT_UNLOCK'
  | 'EXPORT_REQUEST'
  | 'SETTINGS_CHANGE';

export type ResourceType =
  | 'user'
  | 'session'
  | 'device'
  | 'document'
  | 'folder'
  | 'system';

export interface AuditDetails {
  [key: string]: unknown;
  // NUNCA incluir: senhas, tokens completos, chaves, dados biométricos
  // Permitido: IDs (não sensíveis), timestamps, tipos de operação, status
}

// ============================================================================
// TIPOS DE RECUPERAÇÃO
// ============================================================================

export interface RecoveryCode extends BaseEntity {
  userId: UUID;
  codeHash: string; // Hash do código
  used: boolean;
  usedAt?: Date | null;
}

export interface BackupKey extends BaseEntity {
  userId: UUID;
  keyPurpose: KeyPurpose;
  encryptedKey: string; // Chave criptografada
  iv: string; // Initialization vector
  createdAt: Date;
}

export type KeyPurpose = 'data_encryption' | 'recovery' | 'backup';

// ============================================================================
// CONSTANTES E CONFIGURAÇÕES
// ============================================================================

export const SECURITY_CONSTANTS = {
  // Argon2id parameters
  ARGON2_MEMORY_SIZE: 65536, // 64 MB
  ARGON2_TIME_COST: 3,
  ARGON2_PARALLELISM: 4,
  
  // Session management
  ACCESS_TOKEN_EXPIRY: 15 * 60, // 15 minutes in seconds
  REFRESH_TOKEN_EXPIRY: 7 * 24 * 60 * 60, // 7 days
  TRUSTED_DEVICE_EXPIRY: 30 * 24 * 60 * 60, // 30 days
  
  // Rate limiting
  MAX_LOGIN_ATTEMPTS: 5,
  LOCKOUT_DURATION: 15 * 60, // 15 minutes
  MFA_MAX_ATTEMPTS: 3,
  BIOMETRIC_MAX_ATTEMPTS: 3,
  
  // Password requirements
  MIN_PASSWORD_LENGTH: 12,
  MAX_PASSWORD_LENGTH: 128,
  
  // File limits
  MAX_FILE_SIZE: 100 * 1024 * 1024, // 100 MB
  ALLOWED_MIME_TYPES: [
    'application/pdf',
    'image/jpeg',
    'image/png',
    'image/gif',
    'text/plain',
    'text/csv',
    'application/json',
    'application/zip',
    'application/x-zip-compressed',
  ],
  BLOCKED_EXTENSIONS: ['.exe', '.bat', '.cmd', '.sh', '.ps1', '.vbs', '.js', '.jar'],
  
  // TOTP
  TOTP_DIGITS: 6,
  TOTP_PERIOD: 30,
  TOTP_WINDOW: 1, // Allow 1 step before/after for clock skew
} as const;

export const PASSWORD_PATTERNS = {
  MIN_LENGTH: SECURITY_CONSTANTS.MIN_PASSWORD_LENGTH,
  MAX_LENGTH: SECURITY_CONSTANTS.MAX_PASSWORD_LENGTH,
  REQUIRE_UPPERCASE: true,
  REQUIRE_LOWERCASE: true,
  REQUIRE_NUMBER: true,
  REQUIRE_SPECIAL: true,
} as const;

// ============================================================================
// CLASSES DE ERRO
// ============================================================================

export class BaseError extends Error {
  public readonly code: string;
  public readonly details?: Record<string, unknown>;

  constructor(code: string, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'BaseError';
    this.code = code;
    if (details !== undefined) {
      this.details = details;
    }
    
    // Maintain proper stack trace in V8
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

export class ValidationError extends BaseError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('VALIDATION_ERROR', message, details);
    this.name = 'ValidationError';
  }
}

export class SecurityError extends BaseError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('SECURITY_ERROR', message, details);
    this.name = 'SecurityError';
  }
}

export class AuthError extends BaseError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('AUTH_ERROR', message, details);
    this.name = 'AuthError';
  }
}

export class NotFoundError extends BaseError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('NOT_FOUND', message, details);
    this.name = 'NotFoundError';
  }
}

export class PermissionError extends BaseError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('PERMISSION_DENIED', message, details);
    this.name = 'PermissionError';
  }
}

// ============================================================================
// UTILITÁRIOS
// ============================================================================

/**
 * Gera um UUID v4 seguro
 */
export function generateUUID(): UUID {
  if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) {
    return crypto.randomUUID();
  }
  // Fallback para ambientes sem crypto.randomUUID
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/**
 * Valida se uma string é um UUID válido
 */
export function isValidUUID(uuid: string): boolean {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

/**
 * Sanitiza um nome de arquivo para uso seguro
 */
export function sanitizeFilename(filename: string): string {
  // Remove caracteres perigosos e normaliza
  return filename
    .normalize('NFC')
    .replace(/[/\\?%*:|"<>]/g, '_')
    .replace(/\.\./g, '_')
    .trim()
    .slice(0, 255);
}

/**
 * Verifica se um MIME type é permitido
 */
export function isMimeTypeAllowed(mimeType: string): boolean {
  return SECURITY_CONSTANTS.ALLOWED_MIME_TYPES.includes(mimeType.toLowerCase() as any);
}

/**
 * Verifica se uma extensão é bloqueada
 */
export function isExtensionBlocked(extension: string): boolean {
  return SECURITY_CONSTANTS.BLOCKED_EXTENSIONS.includes(extension.toLowerCase() as any);
}

export default {
  generateUUID,
  isValidUUID,
  sanitizeFilename,
  isMimeTypeAllowed,
  isExtensionBlocked,
  SECURITY_CONSTANTS,
};
