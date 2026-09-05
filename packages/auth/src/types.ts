/**
 * Tipos e Interfaces para Autenticação
 */

import type { User, Session, Device } from '@zero/database';

// ============================================================================
// INPUTS DE AUTENTICAÇÃO
// ============================================================================

export interface RegisterInput {
  email: string;
  password: string;
  displayName?: string;
  recoveryEmail?: string;
}

export interface LoginInput {
  email: string;
  password: string;
  mfaCode?: string;
  deviceId?: string;
  rememberDevice?: boolean;
}

export interface MFAVerificationInput {
  userId: string;
  code: string;
  type: 'totp' | 'recovery';
}

export interface WebAuthnRegistrationInput {
  userId: string;
  credential: PublicKeyCredential;
  deviceName: string;
}

export interface WebAuthnLoginInput {
  credential: PublicKeyCredential;
  deviceName?: string;
}

export interface MFASetupResponse {
  success: boolean;
  totpSecret?: string;
  otpauthURI?: string;
  requiresVerification?: boolean;
  error?: AuthError;
}

export interface MFAVerifyResponse {
  success: boolean;
  session?: SessionData;
  recoveryCodes?: string[];
  error?: AuthError;
}

// ============================================================================
// RESPOSTAS DE AUTENTICAÇÃO
// ============================================================================


// ============================================================================
// REQUEST TYPES (para Express)
// ============================================================================

import type { Request } from 'express';

export interface AuthRequest extends Request {
  auth?: {
    userId: string;
    sessionId: string;
    deviceId: string;
    payload: JWTPayload;
  };
}
export interface AuthResponse {
  success: boolean;
  status?: 'pending_mfa' | 'completed' | 'locked' | 'failed';
  requiresMFA?: boolean;
  userId?: string;
  user?: {
    id: string;
    email: string;
    name: string | null;
  };
  tokens?: {
    accessToken: string;
    refreshToken: string;
    expiresAt: Date;
    refreshExpiresAt: Date;
  };
  session?: SessionData;
  mfaSessionId?: string;
  mfaType?: 'totp' | 'recovery';
  mfaSecret?: string;
  mfaQrCode?: string;
  recoveryCodes?: string[];
  lockedUntil?: Date;
  error?: AuthError;
}

export interface MFAResponse {
  success: boolean;
  session?: SessionData;
  secret?: string;
  backupCodes?: string[];
  qrCodeUrl?: string;
  error?: AuthError;
}

export interface AuthError {
  code: AuthErrorCode;
  message: string;
  details?: Record<string, unknown>;
}

export type AuthErrorCode =
  | 'INVALID_CREDENTIALS'
  | 'USER_NOT_FOUND'
  | 'USER_LOCKED'
  | 'MFA_REQUIRED'
  | 'MFA_INVALID_CODE'
  | 'MFA_ALREADY_ENABLED'
  | 'MFA_NOT_ENABLED'
  | 'SESSION_EXPIRED'
  | 'SESSION_INVALID'
  | 'DEVICE_NOT_TRUSTED'
  | 'RATE_LIMIT_EXCEEDED'
  | 'WEBAUTHN_NOT_SUPPORTED'
  | 'WEBAUTHN_REGISTRATION_FAILED'
  | 'WEBAUTHN_AUTHENTICATION_FAILED'
  | 'PASSWORD_WEAK'
  | 'EMAIL_INVALID'
  | 'EMAIL_ALREADY_EXISTS'
  | 'RECOVERY_CODE_INVALID'
  | 'INTERNAL_ERROR';

// ============================================================================
// DADOS DE SESSÃO
// ============================================================================

export interface SessionData {
  sessionId: string;
  userId: string;
  accessToken: string;
  refreshToken: string;
  expiresAt: Date;
  refreshExpiresAt: Date;
  device?: DeviceData;
  mfaVerified: boolean;
  createdAt: Date;
}

export interface DeviceData {
  deviceId: string;
  name: string;
  type: 'desktop' | 'mobile' | 'tablet' | 'unknown';
  os: string;
  browser: string;
  isTrusted: boolean;
  lastSeenAt: Date;
  ipAddress?: string;
  userAgent?: string;
}

// ============================================================================
// JWT PAYLOADS
// ============================================================================

export interface JWTPayload {
  sub: string; // userId
  sid: string; // sessionId
  typ: 'access';
  iat: number;
  exp: number;
  iss: string;
  aud: string;
  mfa: boolean;
}

export interface RefreshTokenPayload {
  sub: string; // userId
  sid: string; // sessionId
  typ: 'refresh';
  iat: number;
  exp: number;
  iss: string;
  aud: string;
  counter: number; // Para rotação de refresh tokens
}

// ============================================================================
// AUDITORIA DE AUTENTICAÇÃO
// ============================================================================

export interface AuthAuditEvent {
  action: AuthAuditAction;
  userId?: string;
  sessionId?: string;
  deviceId?: string;
  timestamp: Date;
  ipAddress: string;
  userAgent: string;
  success: boolean;
  failureReason?: string;
  metadata?: Record<string, unknown>;
}

export type AuthAuditAction =
  | 'REGISTER_REQUEST'
  | 'REGISTER_SUCCESS'
  | 'REGISTER_FAILURE'
  | 'LOGIN_REQUEST'
  | 'LOGIN_SUCCESS'
  | 'LOGIN_FAILURE_PASSWORD'
  | 'LOGIN_FAILURE_MFA'
  | 'LOGIN_FAILURE_LOCKED'
  | 'LOGOUT_REQUEST'
  | 'LOGOUT_SUCCESS'
  | 'TOKEN_REFRESH_SUCCESS'
  | 'TOKEN_REFRESH_FAILURE'
  | 'MFA_SETUP_INITIATED'
  | 'MFA_SETUP_COMPLETED'
  | 'MFA_VERIFICATION_SUCCESS'
  | 'MFA_VERIFICATION_FAILURE'
  | 'MFA_DISABLED'
  | 'WEBAUTHN_REGISTERED'
  | 'WEBAUTHN_AUTHENTICATED'
  | 'DEVICE_TRUSTED'
  | 'DEVICE_REVOKED'
  | 'SESSION_REVOKED'
  | 'PASSWORD_CHANGED'
  | 'RECOVERY_CODE_USED'
  | 'ACCOUNT_LOCKED'
  | 'ACCOUNT_UNLOCKED';

// ============================================================================
// CONFIGURAÇÃO E OPÇÕES
// ============================================================================

export interface AuthConfig {
  jwtSecret: string;
  jwtIssuer: string;
  jwtAudience: string;
  accessTokenExpiry: number; // segundos
  refreshTokenExpiry: number; // segundos
  maxLoginAttempts: number;
  lockoutDuration: number; // segundos
  requireMFA: boolean;
  allowWebAuthn: boolean;
  trustedDeviceExpiry: number; // dias
}

export interface TokenOptions {
  userId: string;
  sessionId: string;
  mfaVerified: boolean;
  counter?: number;
}
