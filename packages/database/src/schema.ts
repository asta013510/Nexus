/**
 * Schema do Banco de Dados - Drizzle ORM
 * 
 * PostgreSQL com Row-Level Security ready
 * 
 * SECURITY NOTES:
 * - Todos os IDs são UUIDs (não sequenciais)
 * - Password hashes NUNCA são expostos em selects normais
 * - Facial template é hash, NUNCA imagem bruta
 * - Recovery codes são hasheados
 * - Refresh tokens são hasheados
 * - Encryption keys são wrapped (envelope encryption)
 * - Soft delete para documentos (recuperação possível)
 * - Timestamps para auditoria
 */

import {
  pgTable,
  uuid,
  varchar,
  text,
  timestamp,
  boolean,
  integer,
  jsonb,
  index,
  uniqueIndex,
} from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';

// ============================================================================
// TABELA: USERS
// ============================================================================

export const users = pgTable('users', {
  id: uuid('id').primaryKey().notNull(),
  email: varchar('email', { length: 254 }).notNull(),
  passwordHash: text('password_hash').notNull(), // Argon2id hash
  passwordSalt: text('password_salt').notNull(), // Salt único por usuário
  
  displayName: varchar('display_name', { length: 100 }),
  recoveryEmail: varchar('recovery_email', { length: 254 }),
  
  status: varchar('status', { length: 20 }).notNull().default('pending_mfa'), // pending_mfa, active, locked, suspended
  
  mfaEnabled: boolean('mfa_enabled').notNull().default(false),
  mfaSecret: text('mfa_secret'), // TOTP secret (criptografado em produção)
  mfaBackupCodesHash: text('mfa_backup_codes_hash'), // Hash dos códigos de recuperação
  
  facialTemplateHash: text('facial_template_hash'), // Hash do template biométrico (NUNCA imagem)
  
  failedLoginAttempts: integer('failed_login_attempts').notNull().default(0),
  lockedUntil: timestamp('locked_until'),
  
  lastLoginAt: timestamp('last_login_at'),
  lastPasswordChangeAt: timestamp('last_password_change_at'),
  
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
  deletedAt: timestamp('deleted_at'), // Soft delete para conta
}, (table) => [
  uniqueIndex('users_email_unique').on(table.email),
  index('users_status_idx').on(table.status),
  index('users_created_at_idx').on(table.createdAt),
]);

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;

// ============================================================================
// TABELA: SESSIONS
// ============================================================================

export const sessions = pgTable('sessions', {
  id: uuid('id').primaryKey().notNull(),
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  
  refreshTokenHash: text('refresh_token_hash').notNull(), // Hash do refresh token
  refreshTokenCounter: integer('refresh_token_counter').notNull().default(0), // Para rotação
  
  expiresAt: timestamp('expires_at').notNull(),
  refreshExpiresAt: timestamp('refresh_expires_at').notNull(),
  
  revoked: boolean('revoked').notNull().default(false),
  revokedAt: timestamp('revoked_at'),
  revokeReason: varchar('revoke_reason', { length: 255 }),
  
  lastUsedAt: timestamp('last_used_at'),
  ipAddress: varchar('ip_address', { length: 45 }), // IPv6 max
  userAgent: text('user_agent'),
  
  createdAt: timestamp('created_at').notNull().defaultNow(),
}, (table) => [
  index('sessions_user_id_idx').on(table.userId),
  index('sessions_expires_at_idx').on(table.expiresAt),
  index('sessions_revoked_idx').on(table.revoked),
]);

export type Session = typeof sessions.$inferSelect;
export type NewSession = typeof sessions.$inferInsert;

// ============================================================================
// TABELA: DEVICES
// ============================================================================

export const devices = pgTable('devices', {
  id: uuid('id').primaryKey().notNull(),
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  
  name: varchar('name', { length: 255 }).notNull(),
  type: varchar('type', { length: 20 }).notNull(), // desktop, mobile, tablet, unknown
  
  os: varchar('os', { length: 100 }),
  browser: varchar('browser', { length: 100 }),
  
  isTrusted: boolean('is_trusted').notNull().default(false),
  trustedUntil: timestamp('trusted_until'),
  
  lastSeenAt: timestamp('last_seen_at'),
  ipAddress: varchar('ip_address', { length: 45 }),
  userAgent: text('user_agent'),
  
  createdAt: timestamp('created_at').notNull().defaultNow(),
}, (table) => [
  index('devices_user_id_idx').on(table.userId),
  index('devices_is_trusted_idx').on(table.isTrusted),
]);

export type Device = typeof devices.$inferSelect;
export type NewDevice = typeof devices.$inferInsert;

// ============================================================================
// TABELA: FOLDERS
// ============================================================================

export const folders = pgTable('folders', {
  id: uuid('id').primaryKey().notNull(),
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  parentId: uuid('parent_id').references((): any => folders.id, { onDelete: 'cascade' }),
  
  name: varchar('name', { length: 255 }).notNull(),
  description: text('description'),
  
  color: varchar('color', { length: 7 }), // Hex color #RRGGBB
  icon: varchar('icon', { length: 50 }),
  
  isSystem: boolean('is_system').notNull().default(false), // Pastas do sistema (ex: Trash)
  
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
  deletedAt: timestamp('deleted_at'),
}, (table) => [
  index('folders_user_id_idx').on(table.userId),
  index('folders_parent_id_idx').on(table.parentId),
  index('folders_deleted_at_idx').on(table.deletedAt),
]);

export type Folder = typeof folders.$inferSelect;
export type NewFolder = typeof folders.$inferInsert;

// ============================================================================
// TABELA: DOCUMENTS
// ============================================================================

export const documents = pgTable('documents', {
  id: uuid('id').primaryKey().notNull(),
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  folderId: uuid('folder_id').references(() => folders.id, { onDelete: 'set null' }),
  
  name: varchar('name', { length: 255 }).notNull(),
  description: text('description'),
  
  mimeType: varchar('mime_type', { length: 255 }).notNull(),
  size: integer('size').notNull(), // Bytes
  
  storageKey: text('storage_key').notNull(), // Chave no object storage
  storageBucket: varchar('storage_bucket', { length: 255 }).notNull().default('zero-documents'),
  
  contentHash: text('content_hash').notNull(), // SHA-256 do conteúdo
  encryptionKeyId: uuid('encryption_key_id').references(() => encryptionKeys.id),
  
  version: integer('version').notNull().default(1),
  currentVersionId: uuid('current_version_id').references(() => documentVersions.id),
  
  status: varchar('status', { length: 20 }).notNull().default('active'),
  classification: varchar('classification', { length: 50 }), // public, internal, confidential, secret
  
  tags: jsonb('tags').$type<string[]>(), // Array de tags
  
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
  deletedAt: timestamp('deleted_at'), // Soft delete
}, (table) => [
  index('documents_user_id_idx').on(table.userId),
  index('documents_folder_id_idx').on(table.folderId),
  index('documents_status_idx').on(table.status),
  index('documents_deleted_at_idx').on(table.deletedAt),
  index('documents_created_at_idx').on(table.createdAt),
]);

export type Document = typeof documents.$inferSelect;
export type NewDocument = typeof documents.$inferInsert;

// ============================================================================
// TABELA: DOCUMENT_VERSIONS
// ============================================================================

export const documentVersions = pgTable('document_versions', {
  id: uuid('id').primaryKey().notNull(),
  documentId: uuid('document_id').notNull().references(() => documents.id, { onDelete: 'cascade' }),
  userId: uuid('user_id').notNull().references(() => users.id),
  
  version: integer('version').notNull(),
  
  mimeType: varchar('mime_type', { length: 255 }).notNull(),
  size: integer('size').notNull(),
  
  storageKey: text('storage_key').notNull(),
  storageBucket: varchar('storage_bucket', { length: 255 }).notNull(),
  
  contentHash: text('content_hash').notNull(),
  encryptionKeyId: uuid('encryption_key_id').references(() => encryptionKeys.id),
  
  changeDescription: text('change_description'),
  
  createdAt: timestamp('created_at').notNull().defaultNow(),
}, (table) => [
  index('document_versions_document_id_idx').on(table.documentId),
  index('document_versions_user_id_idx').on(table.userId),
  uniqueIndex('document_versions_doc_version_unique').on(table.documentId, table.version),
]);

export type DocumentVersion = typeof documentVersions.$inferSelect;
export type NewDocumentVersion = typeof documentVersions.$inferInsert;

// ============================================================================
// TABELA: AUDIT_LOGS
// ============================================================================

export const auditLogs = pgTable('audit_logs', {
  id: uuid('id').primaryKey().notNull(),
  
  action: varchar('action', { length: 50 }).notNull(),
  resourceType: varchar('resource_type', { length: 50 }),
  resourceId: uuid('resource_id'),
  
  userId: uuid('user_id').references(() => users.id),
  sessionId: uuid('session_id').references(() => sessions.id),
  deviceId: uuid('device_id').references(() => devices.id),
  
  timestamp: timestamp('timestamp').notNull().defaultNow(),
  
  ipAddress: varchar('ip_address', { length: 45 }).notNull(),
  userAgent: text('user_agent').notNull(),
  
  success: boolean('success').notNull(),
  failureReason: varchar('failure_reason', { length: 255 }),
  
  metadata: jsonb('metadata'), // Dados adicionais estruturados
  
  // Nota: NUNCA armazenar dados sensíveis nos logs
  // Senhas, tokens, chaves, dados biométricos - PROIBIDO
}, (table) => [
  index('audit_logs_user_id_idx').on(table.userId),
  index('audit_logs_action_idx').on(table.action),
  index('audit_logs_timestamp_idx').on(table.timestamp),
  index('audit_logs_resource_idx').on(table.resourceType, table.resourceId),
]);

export type AuditLog = typeof auditLogs.$inferSelect;
export type NewAuditLog = typeof auditLogs.$inferInsert;

// ============================================================================
// TABELA: RECOVERY_CODES
// ============================================================================

export const recoveryCodes = pgTable('recovery_codes', {
  id: uuid('id').primaryKey().notNull(),
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  
  codeHash: text('code_hash').notNull(), // Hash do código de recuperação
  codePrefix: varchar('code_prefix', { length: 4 }).notNull(), // Primeiros chars para identificação
  
  used: boolean('used').notNull().default(false),
  usedAt: timestamp('used_at'),
  
  createdAt: timestamp('created_at').notNull().defaultNow(),
  expiresAt: timestamp('expires_at'), // Opcional
}, (table) => [
  index('recovery_codes_user_id_idx').on(table.userId),
  index('recovery_codes_used_idx').on(table.used),
]);

export type RecoveryCode = typeof recoveryCodes.$inferSelect;
export type NewRecoveryCode = typeof recoveryCodes.$inferInsert;

// ============================================================================
// TABELA: WEBAUTHN_CREDENTIALS
// ============================================================================

export const webauthnCredentials = pgTable('webauthn_credentials', {
  id: uuid('id').primaryKey().notNull(),
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  
  credentialId: text('credential_id').notNull(), // ID da credencial WebAuthn
  publicKey: text('public_key').notNull(), // Chave pública
  
  counter: integer('counter').notNull().default(0), // Contador de assinatura
  transports: jsonb('transports').$type<string[]>(), // Transportes suportados
  
  deviceName: varchar('device_name', { length: 255 }),
  deviceType: varchar('device_type', { length: 50 }),
  
  createdAt: timestamp('created_at').notNull().defaultNow(),
  lastUsedAt: timestamp('last_used_at'),
}, (table) => [
  index('webauthn_credentials_user_id_idx').on(table.userId),
  uniqueIndex('webauthn_credentials_credential_id_unique').on(table.credentialId),
]);

export type WebAuthnCredential = typeof webauthnCredentials.$inferSelect;
export type NewWebAuthnCredential = typeof webauthnCredentials.$inferInsert;

// ============================================================================
// TABELA: ENCRYPTION_KEYS
// ============================================================================

export const encryptionKeys = pgTable('encryption_keys', {
  id: uuid('id').primaryKey().notNull(),
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  
  keyType: varchar('key_type', { length: 50 }).notNull(), // master, document, backup
  
  // Envelope encryption:
  // - wrappedKey: chave encriptada com KEK (Key Encryption Key)
  // - keyCipherText: dados encriptados com esta chave
  wrappedKey: text('wrapped_key').notNull(),
  keyIv: text('key_iv').notNull(),
  keyTag: text('key_tag').notNull(),
  
  keyPurpose: varchar('key_purpose', { length: 100 }),
  keyVersion: integer('key_version').notNull().default(1),
  
  rotatedFromId: uuid('rotated_from_id').references(() => encryptionKeys.id),
  
  createdAt: timestamp('created_at').notNull().defaultNow(),
  expiresAt: timestamp('expires_at'),
  revokedAt: timestamp('revoked_at'),
}, (table) => [
  index('encryption_keys_user_id_idx').on(table.userId),
  index('encryption_keys_key_type_idx').on(table.keyType),
]);

export type EncryptionKey = typeof encryptionKeys.$inferSelect;
export type NewEncryptionKey = typeof encryptionKeys.$inferInsert;

// ============================================================================
// RELATIONS
// ============================================================================

export const userRelations = relations(users, ({ many }) => ({
  sessions: many(sessions),
  devices: many(devices),
  folders: many(folders),
  documents: many(documents),
  auditLogs: many(auditLogs),
  recoveryCodes: many(recoveryCodes),
  webauthnCredentials: many(webauthnCredentials),
  encryptionKeys: many(encryptionKeys),
  documentVersions: many(documentVersions),
}));

export const sessionRelations = relations(sessions, ({ one }) => ({
  user: one(users, {
    fields: [sessions.userId],
    references: [users.id],
  }),
}));

export const deviceRelations = relations(devices, ({ one }) => ({
  user: one(users, {
    fields: [devices.userId],
    references: [users.id],
  }),
}));

export const folderRelations = relations(folders, ({ one, many }) => ({
  user: one(users, {
    fields: [folders.userId],
    references: [users.id],
  }),
  parent: one(folders, {
    fields: [folders.parentId],
    references: [folders.id],
  }),
  children: many(folders, {
    relationName: 'folderHierarchy',
  }),
  documents: many(documents),
}));

export const documentRelations = relations(documents, ({ one, many }) => ({
  user: one(users, {
    fields: [documents.userId],
    references: [users.id],
  }),
  folder: one(folders, {
    fields: [documents.folderId],
    references: [folders.id],
  }),
  versions: many(documentVersions),
  encryptionKey: one(encryptionKeys, {
    fields: [documents.encryptionKeyId],
    references: [encryptionKeys.id],
  }),
}));

export const documentVersionRelations = relations(documentVersions, ({ one }) => ({
  document: one(documents, {
    fields: [documentVersions.documentId],
    references: [documents.id],
  }),
  user: one(users, {
    fields: [documentVersions.userId],
    references: [users.id],
  }),
  encryptionKey: one(encryptionKeys, {
    fields: [documentVersions.encryptionKeyId],
    references: [encryptionKeys.id],
  }),
}));

export const auditLogRelations = relations(auditLogs, ({ one }) => ({
  user: one(users, {
    fields: [auditLogs.userId],
    references: [users.id],
  }),
  session: one(sessions, {
    fields: [auditLogs.sessionId],
    references: [sessions.id],
  }),
  device: one(devices, {
    fields: [auditLogs.deviceId],
    references: [devices.id],
  }),
}));

export const recoveryCodeRelations = relations(recoveryCodes, ({ one }) => ({
  user: one(users, {
    fields: [recoveryCodes.userId],
    references: [users.id],
  }),
}));

export const webauthnCredentialRelations = relations(webauthnCredentials, ({ one }) => ({
  user: one(users, {
    fields: [webauthnCredentials.userId],
    references: [users.id],
  }),
}));

export const encryptionKeyRelations = relations(encryptionKeys, ({ one, many }) => ({
  user: one(users, {
    fields: [encryptionKeys.userId],
    references: [users.id],
  }),
  documents: many(documents),
  documentVersions: many(documentVersions),
}));

// Export schema agrupado
export const schema = {
  users,
  sessions,
  devices,
  folders,
  documents,
  documentVersions,
  auditLogs,
  recoveryCodes,
  webauthnCredentials,
  encryptionKeys,
};
