/**
 * @zero/shared - Utilitários e tipos compartilhados
 *
 * Este pacote contém tipos, constantes e utilitários usados em todo o projeto ZERO.
 * Nenhuma lógica sensível de segurança deve residir aqui.
 */
export type UUID = string;
export interface BaseEntity {
    id: UUID;
    createdAt: Date;
    updatedAt: Date;
}
export interface User extends BaseEntity {
    email: string;
    emailVerified: boolean;
    passwordHash: string;
    recoveryCodeHash: string;
    totpSecret?: string | null;
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
    refreshTokenHash: string;
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
    fingerprint: string;
    isTrusted: boolean;
    lastSeenAt: Date;
    createdAt: Date;
}
export type DeviceType = 'desktop' | 'mobile' | 'tablet' | 'unknown';
export interface Document extends BaseEntity {
    userId: UUID;
    folderId?: UUID | null;
    name: string;
    originalName: string;
    mimeType: string;
    size: number;
    hash: string;
    encrypted: boolean;
    version: number;
    parentId?: UUID | null;
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
export interface Folder extends BaseEntity {
    userId: UUID;
    parentId?: UUID | null;
    name: string;
    description?: string | null;
    color?: string | null;
    icon?: string | null;
    path: string;
}
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
export type AuditAction = 'LOGIN_SUCCESS' | 'LOGIN_FAILURE' | 'LOGOUT' | 'PASSWORD_CHANGE' | 'MFA_ENABLE' | 'MFA_DISABLE' | 'WEBAUTHN_REGISTER' | 'WEBAUTHN_REMOVE' | 'FACIAL_AUTH_ENABLE' | 'FACIAL_AUTH_DISABLE' | 'SESSION_REVOKE' | 'DEVICE_TRUST' | 'DEVICE_UNTRUST' | 'DOCUMENT_UPLOAD' | 'DOCUMENT_DOWNLOAD' | 'DOCUMENT_VIEW' | 'DOCUMENT_UPDATE' | 'DOCUMENT_DELETE' | 'DOCUMENT_RESTORE' | 'FOLDER_CREATE' | 'FOLDER_UPDATE' | 'FOLDER_DELETE' | 'RECOVERY_CODE_GENERATE' | 'RECOVERY_CODE_USE' | 'ACCOUNT_LOCK' | 'ACCOUNT_UNLOCK' | 'EXPORT_REQUEST' | 'SETTINGS_CHANGE';
export type ResourceType = 'user' | 'session' | 'device' | 'document' | 'folder' | 'system';
export interface AuditDetails {
    [key: string]: unknown;
}
export interface RecoveryCode extends BaseEntity {
    userId: UUID;
    codeHash: string;
    used: boolean;
    usedAt?: Date | null;
}
export interface BackupKey extends BaseEntity {
    userId: UUID;
    keyPurpose: KeyPurpose;
    encryptedKey: string;
    iv: string;
    createdAt: Date;
}
export type KeyPurpose = 'data_encryption' | 'recovery' | 'backup';
export declare const SECURITY_CONSTANTS: {
    readonly ARGON2_MEMORY_SIZE: 65536;
    readonly ARGON2_TIME_COST: 3;
    readonly ARGON2_PARALLELISM: 4;
    readonly ACCESS_TOKEN_EXPIRY: number;
    readonly REFRESH_TOKEN_EXPIRY: number;
    readonly TRUSTED_DEVICE_EXPIRY: number;
    readonly MAX_LOGIN_ATTEMPTS: 5;
    readonly LOCKOUT_DURATION: number;
    readonly MFA_MAX_ATTEMPTS: 3;
    readonly BIOMETRIC_MAX_ATTEMPTS: 3;
    readonly MIN_PASSWORD_LENGTH: 12;
    readonly MAX_PASSWORD_LENGTH: 128;
    readonly MAX_FILE_SIZE: number;
    readonly ALLOWED_MIME_TYPES: readonly ["application/pdf", "image/jpeg", "image/png", "image/gif", "text/plain", "text/csv", "application/json", "application/zip", "application/x-zip-compressed"];
    readonly BLOCKED_EXTENSIONS: readonly [".exe", ".bat", ".cmd", ".sh", ".ps1", ".vbs", ".js", ".jar"];
    readonly TOTP_DIGITS: 6;
    readonly TOTP_PERIOD: 30;
    readonly TOTP_WINDOW: 1;
};
/**
 * Gera um UUID v4 seguro
 */
export declare function generateUUID(): UUID;
/**
 * Valida se uma string é um UUID válido
 */
export declare function isValidUUID(uuid: string): boolean;
/**
 * Sanitiza um nome de arquivo para uso seguro
 */
export declare function sanitizeFilename(filename: string): string;
/**
 * Verifica se um MIME type é permitido
 */
export declare function isMimeTypeAllowed(mimeType: string): boolean;
/**
 * Verifica se uma extensão é bloqueada
 */
export declare function isExtensionBlocked(extension: string): boolean;
declare const _default: {
    generateUUID: typeof generateUUID;
    isValidUUID: typeof isValidUUID;
    sanitizeFilename: typeof sanitizeFilename;
    isMimeTypeAllowed: typeof isMimeTypeAllowed;
    isExtensionBlocked: typeof isExtensionBlocked;
    SECURITY_CONSTANTS: {
        readonly ARGON2_MEMORY_SIZE: 65536;
        readonly ARGON2_TIME_COST: 3;
        readonly ARGON2_PARALLELISM: 4;
        readonly ACCESS_TOKEN_EXPIRY: number;
        readonly REFRESH_TOKEN_EXPIRY: number;
        readonly TRUSTED_DEVICE_EXPIRY: number;
        readonly MAX_LOGIN_ATTEMPTS: 5;
        readonly LOCKOUT_DURATION: number;
        readonly MFA_MAX_ATTEMPTS: 3;
        readonly BIOMETRIC_MAX_ATTEMPTS: 3;
        readonly MIN_PASSWORD_LENGTH: 12;
        readonly MAX_PASSWORD_LENGTH: 128;
        readonly MAX_FILE_SIZE: number;
        readonly ALLOWED_MIME_TYPES: readonly ["application/pdf", "image/jpeg", "image/png", "image/gif", "text/plain", "text/csv", "application/json", "application/zip", "application/x-zip-compressed"];
        readonly BLOCKED_EXTENSIONS: readonly [".exe", ".bat", ".cmd", ".sh", ".ps1", ".vbs", ".js", ".jar"];
        readonly TOTP_DIGITS: 6;
        readonly TOTP_PERIOD: 30;
        readonly TOTP_WINDOW: 1;
    };
};
export default _default;
//# sourceMappingURL=index.d.ts.map