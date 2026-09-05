"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.schema = exports.encryptionKeyRelations = exports.webauthnCredentialRelations = exports.recoveryCodeRelations = exports.auditLogRelations = exports.documentVersionRelations = exports.documentRelations = exports.folderRelations = exports.deviceRelations = exports.sessionRelations = exports.userRelations = exports.encryptionKeys = exports.webauthnCredentials = exports.recoveryCodes = exports.auditLogs = exports.documentVersions = exports.documents = exports.folders = exports.devices = exports.sessions = exports.users = void 0;
const pg_core_1 = require("drizzle-orm/pg-core");
const drizzle_orm_1 = require("drizzle-orm");
// ============================================================================
// TABELA: USERS
// ============================================================================
exports.users = (0, pg_core_1.pgTable)('users', {
    id: (0, pg_core_1.uuid)('id').primaryKey().notNull(),
    email: (0, pg_core_1.varchar)('email', { length: 254 }).notNull(),
    passwordHash: (0, pg_core_1.text)('password_hash').notNull(), // Argon2id hash
    passwordSalt: (0, pg_core_1.text)('password_salt').notNull(), // Salt único por usuário
    displayName: (0, pg_core_1.varchar)('display_name', { length: 100 }),
    recoveryEmail: (0, pg_core_1.varchar)('recovery_email', { length: 254 }),
    status: (0, pg_core_1.varchar)('status', { length: 20 }).notNull().default('pending_mfa'), // pending_mfa, active, locked, suspended
    mfaEnabled: (0, pg_core_1.boolean)('mfa_enabled').notNull().default(false),
    mfaSecret: (0, pg_core_1.text)('mfa_secret'), // TOTP secret (criptografado em produção)
    mfaBackupCodesHash: (0, pg_core_1.text)('mfa_backup_codes_hash'), // Hash dos códigos de recuperação
    facialTemplateHash: (0, pg_core_1.text)('facial_template_hash'), // Hash do template biométrico (NUNCA imagem)
    failedLoginAttempts: (0, pg_core_1.integer)('failed_login_attempts').notNull().default(0),
    lockedUntil: (0, pg_core_1.timestamp)('locked_until'),
    lastLoginAt: (0, pg_core_1.timestamp)('last_login_at'),
    lastPasswordChangeAt: (0, pg_core_1.timestamp)('last_password_change_at'),
    createdAt: (0, pg_core_1.timestamp)('created_at').notNull().defaultNow(),
    updatedAt: (0, pg_core_1.timestamp)('updated_at').notNull().defaultNow(),
    deletedAt: (0, pg_core_1.timestamp)('deleted_at'), // Soft delete para conta
}, (table) => [
    (0, pg_core_1.uniqueIndex)('users_email_unique').on(table.email),
    (0, pg_core_1.index)('users_status_idx').on(table.status),
    (0, pg_core_1.index)('users_created_at_idx').on(table.createdAt),
]);
// ============================================================================
// TABELA: SESSIONS
// ============================================================================
exports.sessions = (0, pg_core_1.pgTable)('sessions', {
    id: (0, pg_core_1.uuid)('id').primaryKey().notNull(),
    userId: (0, pg_core_1.uuid)('user_id').notNull().references(() => exports.users.id, { onDelete: 'cascade' }),
    refreshTokenHash: (0, pg_core_1.text)('refresh_token_hash').notNull(), // Hash do refresh token
    refreshTokenCounter: (0, pg_core_1.integer)('refresh_token_counter').notNull().default(0), // Para rotação
    expiresAt: (0, pg_core_1.timestamp)('expires_at').notNull(),
    refreshExpiresAt: (0, pg_core_1.timestamp)('refresh_expires_at').notNull(),
    revoked: (0, pg_core_1.boolean)('revoked').notNull().default(false),
    revokedAt: (0, pg_core_1.timestamp)('revoked_at'),
    revokeReason: (0, pg_core_1.varchar)('revoke_reason', { length: 255 }),
    lastUsedAt: (0, pg_core_1.timestamp)('last_used_at'),
    ipAddress: (0, pg_core_1.varchar)('ip_address', { length: 45 }), // IPv6 max
    userAgent: (0, pg_core_1.text)('user_agent'),
    createdAt: (0, pg_core_1.timestamp)('created_at').notNull().defaultNow(),
}, (table) => [
    (0, pg_core_1.index)('sessions_user_id_idx').on(table.userId),
    (0, pg_core_1.index)('sessions_expires_at_idx').on(table.expiresAt),
    (0, pg_core_1.index)('sessions_revoked_idx').on(table.revoked),
]);
// ============================================================================
// TABELA: DEVICES
// ============================================================================
exports.devices = (0, pg_core_1.pgTable)('devices', {
    id: (0, pg_core_1.uuid)('id').primaryKey().notNull(),
    userId: (0, pg_core_1.uuid)('user_id').notNull().references(() => exports.users.id, { onDelete: 'cascade' }),
    name: (0, pg_core_1.varchar)('name', { length: 255 }).notNull(),
    type: (0, pg_core_1.varchar)('type', { length: 20 }).notNull(), // desktop, mobile, tablet, unknown
    os: (0, pg_core_1.varchar)('os', { length: 100 }),
    browser: (0, pg_core_1.varchar)('browser', { length: 100 }),
    isTrusted: (0, pg_core_1.boolean)('is_trusted').notNull().default(false),
    trustedUntil: (0, pg_core_1.timestamp)('trusted_until'),
    lastSeenAt: (0, pg_core_1.timestamp)('last_seen_at'),
    ipAddress: (0, pg_core_1.varchar)('ip_address', { length: 45 }),
    userAgent: (0, pg_core_1.text)('user_agent'),
    createdAt: (0, pg_core_1.timestamp)('created_at').notNull().defaultNow(),
}, (table) => [
    (0, pg_core_1.index)('devices_user_id_idx').on(table.userId),
    (0, pg_core_1.index)('devices_is_trusted_idx').on(table.isTrusted),
]);
// ============================================================================
// TABELA: FOLDERS
// ============================================================================
exports.folders = (0, pg_core_1.pgTable)('folders', {
    id: (0, pg_core_1.uuid)('id').primaryKey().notNull(),
    userId: (0, pg_core_1.uuid)('user_id').notNull().references(() => exports.users.id, { onDelete: 'cascade' }),
    parentId: (0, pg_core_1.uuid)('parent_id').references(() => exports.folders.id, { onDelete: 'cascade' }),
    name: (0, pg_core_1.varchar)('name', { length: 255 }).notNull(),
    description: (0, pg_core_1.text)('description'),
    color: (0, pg_core_1.varchar)('color', { length: 7 }), // Hex color #RRGGBB
    icon: (0, pg_core_1.varchar)('icon', { length: 50 }),
    isSystem: (0, pg_core_1.boolean)('is_system').notNull().default(false), // Pastas do sistema (ex: Trash)
    createdAt: (0, pg_core_1.timestamp)('created_at').notNull().defaultNow(),
    updatedAt: (0, pg_core_1.timestamp)('updated_at').notNull().defaultNow(),
    deletedAt: (0, pg_core_1.timestamp)('deleted_at'),
}, (table) => [
    (0, pg_core_1.index)('folders_user_id_idx').on(table.userId),
    (0, pg_core_1.index)('folders_parent_id_idx').on(table.parentId),
    (0, pg_core_1.index)('folders_deleted_at_idx').on(table.deletedAt),
]);
// ============================================================================
// TABELA: DOCUMENTS
// ============================================================================
exports.documents = (0, pg_core_1.pgTable)('documents', {
    id: (0, pg_core_1.uuid)('id').primaryKey().notNull(),
    userId: (0, pg_core_1.uuid)('user_id').notNull().references(() => exports.users.id, { onDelete: 'cascade' }),
    folderId: (0, pg_core_1.uuid)('folder_id').references(() => exports.folders.id, { onDelete: 'set null' }),
    name: (0, pg_core_1.varchar)('name', { length: 255 }).notNull(),
    description: (0, pg_core_1.text)('description'),
    mimeType: (0, pg_core_1.varchar)('mime_type', { length: 255 }).notNull(),
    size: (0, pg_core_1.integer)('size').notNull(), // Bytes
    storageKey: (0, pg_core_1.text)('storage_key').notNull(), // Chave no object storage
    storageBucket: (0, pg_core_1.varchar)('storage_bucket', { length: 255 }).notNull().default('zero-documents'),
    contentHash: (0, pg_core_1.text)('content_hash').notNull(), // SHA-256 do conteúdo
    encryptionKeyId: (0, pg_core_1.uuid)('encryption_key_id').references(() => exports.encryptionKeys.id),
    version: (0, pg_core_1.integer)('version').notNull().default(1),
    currentVersionId: (0, pg_core_1.uuid)('current_version_id').references(() => exports.documentVersions.id),
    status: (0, pg_core_1.varchar)('status', { length: 20 }).notNull().default('active'),
    classification: (0, pg_core_1.varchar)('classification', { length: 50 }), // public, internal, confidential, secret
    tags: (0, pg_core_1.jsonb)('tags').$type(), // Array de tags
    createdAt: (0, pg_core_1.timestamp)('created_at').notNull().defaultNow(),
    updatedAt: (0, pg_core_1.timestamp)('updated_at').notNull().defaultNow(),
    deletedAt: (0, pg_core_1.timestamp)('deleted_at'), // Soft delete
}, (table) => [
    (0, pg_core_1.index)('documents_user_id_idx').on(table.userId),
    (0, pg_core_1.index)('documents_folder_id_idx').on(table.folderId),
    (0, pg_core_1.index)('documents_status_idx').on(table.status),
    (0, pg_core_1.index)('documents_deleted_at_idx').on(table.deletedAt),
    (0, pg_core_1.index)('documents_created_at_idx').on(table.createdAt),
]);
// ============================================================================
// TABELA: DOCUMENT_VERSIONS
// ============================================================================
exports.documentVersions = (0, pg_core_1.pgTable)('document_versions', {
    id: (0, pg_core_1.uuid)('id').primaryKey().notNull(),
    documentId: (0, pg_core_1.uuid)('document_id').notNull().references(() => exports.documents.id, { onDelete: 'cascade' }),
    userId: (0, pg_core_1.uuid)('user_id').notNull().references(() => exports.users.id),
    version: (0, pg_core_1.integer)('version').notNull(),
    mimeType: (0, pg_core_1.varchar)('mime_type', { length: 255 }).notNull(),
    size: (0, pg_core_1.integer)('size').notNull(),
    storageKey: (0, pg_core_1.text)('storage_key').notNull(),
    storageBucket: (0, pg_core_1.varchar)('storage_bucket', { length: 255 }).notNull(),
    contentHash: (0, pg_core_1.text)('content_hash').notNull(),
    encryptionKeyId: (0, pg_core_1.uuid)('encryption_key_id').references(() => exports.encryptionKeys.id),
    changeDescription: (0, pg_core_1.text)('change_description'),
    createdAt: (0, pg_core_1.timestamp)('created_at').notNull().defaultNow(),
}, (table) => [
    (0, pg_core_1.index)('document_versions_document_id_idx').on(table.documentId),
    (0, pg_core_1.index)('document_versions_user_id_idx').on(table.userId),
    (0, pg_core_1.uniqueIndex)('document_versions_doc_version_unique').on(table.documentId, table.version),
]);
// ============================================================================
// TABELA: AUDIT_LOGS
// ============================================================================
exports.auditLogs = (0, pg_core_1.pgTable)('audit_logs', {
    id: (0, pg_core_1.uuid)('id').primaryKey().notNull(),
    action: (0, pg_core_1.varchar)('action', { length: 50 }).notNull(),
    resourceType: (0, pg_core_1.varchar)('resource_type', { length: 50 }),
    resourceId: (0, pg_core_1.uuid)('resource_id'),
    userId: (0, pg_core_1.uuid)('user_id').references(() => exports.users.id),
    sessionId: (0, pg_core_1.uuid)('session_id').references(() => exports.sessions.id),
    deviceId: (0, pg_core_1.uuid)('device_id').references(() => exports.devices.id),
    timestamp: (0, pg_core_1.timestamp)('timestamp').notNull().defaultNow(),
    ipAddress: (0, pg_core_1.varchar)('ip_address', { length: 45 }).notNull(),
    userAgent: (0, pg_core_1.text)('user_agent').notNull(),
    success: (0, pg_core_1.boolean)('success').notNull(),
    failureReason: (0, pg_core_1.varchar)('failure_reason', { length: 255 }),
    metadata: (0, pg_core_1.jsonb)('metadata'), // Dados adicionais estruturados
    // Nota: NUNCA armazenar dados sensíveis nos logs
    // Senhas, tokens, chaves, dados biométricos - PROIBIDO
}, (table) => [
    (0, pg_core_1.index)('audit_logs_user_id_idx').on(table.userId),
    (0, pg_core_1.index)('audit_logs_action_idx').on(table.action),
    (0, pg_core_1.index)('audit_logs_timestamp_idx').on(table.timestamp),
    (0, pg_core_1.index)('audit_logs_resource_idx').on(table.resourceType, table.resourceId),
]);
// ============================================================================
// TABELA: RECOVERY_CODES
// ============================================================================
exports.recoveryCodes = (0, pg_core_1.pgTable)('recovery_codes', {
    id: (0, pg_core_1.uuid)('id').primaryKey().notNull(),
    userId: (0, pg_core_1.uuid)('user_id').notNull().references(() => exports.users.id, { onDelete: 'cascade' }),
    codeHash: (0, pg_core_1.text)('code_hash').notNull(), // Hash do código de recuperação
    codePrefix: (0, pg_core_1.varchar)('code_prefix', { length: 4 }).notNull(), // Primeiros chars para identificação
    used: (0, pg_core_1.boolean)('used').notNull().default(false),
    usedAt: (0, pg_core_1.timestamp)('used_at'),
    createdAt: (0, pg_core_1.timestamp)('created_at').notNull().defaultNow(),
    expiresAt: (0, pg_core_1.timestamp)('expires_at'), // Opcional
}, (table) => [
    (0, pg_core_1.index)('recovery_codes_user_id_idx').on(table.userId),
    (0, pg_core_1.index)('recovery_codes_used_idx').on(table.used),
]);
// ============================================================================
// TABELA: WEBAUTHN_CREDENTIALS
// ============================================================================
exports.webauthnCredentials = (0, pg_core_1.pgTable)('webauthn_credentials', {
    id: (0, pg_core_1.uuid)('id').primaryKey().notNull(),
    userId: (0, pg_core_1.uuid)('user_id').notNull().references(() => exports.users.id, { onDelete: 'cascade' }),
    credentialId: (0, pg_core_1.text)('credential_id').notNull(), // ID da credencial WebAuthn
    publicKey: (0, pg_core_1.text)('public_key').notNull(), // Chave pública
    counter: (0, pg_core_1.integer)('counter').notNull().default(0), // Contador de assinatura
    transports: (0, pg_core_1.jsonb)('transports').$type(), // Transportes suportados
    deviceName: (0, pg_core_1.varchar)('device_name', { length: 255 }),
    deviceType: (0, pg_core_1.varchar)('device_type', { length: 50 }),
    createdAt: (0, pg_core_1.timestamp)('created_at').notNull().defaultNow(),
    lastUsedAt: (0, pg_core_1.timestamp)('last_used_at'),
}, (table) => [
    (0, pg_core_1.index)('webauthn_credentials_user_id_idx').on(table.userId),
    (0, pg_core_1.uniqueIndex)('webauthn_credentials_credential_id_unique').on(table.credentialId),
]);
// ============================================================================
// TABELA: ENCRYPTION_KEYS
// ============================================================================
exports.encryptionKeys = (0, pg_core_1.pgTable)('encryption_keys', {
    id: (0, pg_core_1.uuid)('id').primaryKey().notNull(),
    userId: (0, pg_core_1.uuid)('user_id').notNull().references(() => exports.users.id, { onDelete: 'cascade' }),
    keyType: (0, pg_core_1.varchar)('key_type', { length: 50 }).notNull(), // master, document, backup
    // Envelope encryption:
    // - wrappedKey: chave encriptada com KEK (Key Encryption Key)
    // - keyCipherText: dados encriptados com esta chave
    wrappedKey: (0, pg_core_1.text)('wrapped_key').notNull(),
    keyIv: (0, pg_core_1.text)('key_iv').notNull(),
    keyTag: (0, pg_core_1.text)('key_tag').notNull(),
    keyPurpose: (0, pg_core_1.varchar)('key_purpose', { length: 100 }),
    keyVersion: (0, pg_core_1.integer)('key_version').notNull().default(1),
    rotatedFromId: (0, pg_core_1.uuid)('rotated_from_id').references(() => exports.encryptionKeys.id),
    createdAt: (0, pg_core_1.timestamp)('created_at').notNull().defaultNow(),
    expiresAt: (0, pg_core_1.timestamp)('expires_at'),
    revokedAt: (0, pg_core_1.timestamp)('revoked_at'),
}, (table) => [
    (0, pg_core_1.index)('encryption_keys_user_id_idx').on(table.userId),
    (0, pg_core_1.index)('encryption_keys_key_type_idx').on(table.keyType),
]);
// ============================================================================
// RELATIONS
// ============================================================================
exports.userRelations = (0, drizzle_orm_1.relations)(exports.users, ({ many }) => ({
    sessions: many(exports.sessions),
    devices: many(exports.devices),
    folders: many(exports.folders),
    documents: many(exports.documents),
    auditLogs: many(exports.auditLogs),
    recoveryCodes: many(exports.recoveryCodes),
    webauthnCredentials: many(exports.webauthnCredentials),
    encryptionKeys: many(exports.encryptionKeys),
    documentVersions: many(exports.documentVersions),
}));
exports.sessionRelations = (0, drizzle_orm_1.relations)(exports.sessions, ({ one }) => ({
    user: one(exports.users, {
        fields: [exports.sessions.userId],
        references: [exports.users.id],
    }),
}));
exports.deviceRelations = (0, drizzle_orm_1.relations)(exports.devices, ({ one }) => ({
    user: one(exports.users, {
        fields: [exports.devices.userId],
        references: [exports.users.id],
    }),
}));
exports.folderRelations = (0, drizzle_orm_1.relations)(exports.folders, ({ one, many }) => ({
    user: one(exports.users, {
        fields: [exports.folders.userId],
        references: [exports.users.id],
    }),
    parent: one(exports.folders, {
        fields: [exports.folders.parentId],
        references: [exports.folders.id],
    }),
    children: many(exports.folders, {
        relationName: 'folderHierarchy',
    }),
    documents: many(exports.documents),
}));
exports.documentRelations = (0, drizzle_orm_1.relations)(exports.documents, ({ one, many }) => ({
    user: one(exports.users, {
        fields: [exports.documents.userId],
        references: [exports.users.id],
    }),
    folder: one(exports.folders, {
        fields: [exports.documents.folderId],
        references: [exports.folders.id],
    }),
    versions: many(exports.documentVersions),
    encryptionKey: one(exports.encryptionKeys, {
        fields: [exports.documents.encryptionKeyId],
        references: [exports.encryptionKeys.id],
    }),
}));
exports.documentVersionRelations = (0, drizzle_orm_1.relations)(exports.documentVersions, ({ one }) => ({
    document: one(exports.documents, {
        fields: [exports.documentVersions.documentId],
        references: [exports.documents.id],
    }),
    user: one(exports.users, {
        fields: [exports.documentVersions.userId],
        references: [exports.users.id],
    }),
    encryptionKey: one(exports.encryptionKeys, {
        fields: [exports.documentVersions.encryptionKeyId],
        references: [exports.encryptionKeys.id],
    }),
}));
exports.auditLogRelations = (0, drizzle_orm_1.relations)(exports.auditLogs, ({ one }) => ({
    user: one(exports.users, {
        fields: [exports.auditLogs.userId],
        references: [exports.users.id],
    }),
    session: one(exports.sessions, {
        fields: [exports.auditLogs.sessionId],
        references: [exports.sessions.id],
    }),
    device: one(exports.devices, {
        fields: [exports.auditLogs.deviceId],
        references: [exports.devices.id],
    }),
}));
exports.recoveryCodeRelations = (0, drizzle_orm_1.relations)(exports.recoveryCodes, ({ one }) => ({
    user: one(exports.users, {
        fields: [exports.recoveryCodes.userId],
        references: [exports.users.id],
    }),
}));
exports.webauthnCredentialRelations = (0, drizzle_orm_1.relations)(exports.webauthnCredentials, ({ one }) => ({
    user: one(exports.users, {
        fields: [exports.webauthnCredentials.userId],
        references: [exports.users.id],
    }),
}));
exports.encryptionKeyRelations = (0, drizzle_orm_1.relations)(exports.encryptionKeys, ({ one, many }) => ({
    user: one(exports.users, {
        fields: [exports.encryptionKeys.userId],
        references: [exports.users.id],
    }),
    documents: many(exports.documents),
    documentVersions: many(exports.documentVersions),
}));
// Export schema agrupado
exports.schema = {
    users: exports.users,
    sessions: exports.sessions,
    devices: exports.devices,
    folders: exports.folders,
    documents: exports.documents,
    documentVersions: exports.documentVersions,
    auditLogs: exports.auditLogs,
    recoveryCodes: exports.recoveryCodes,
    webauthnCredentials: exports.webauthnCredentials,
    encryptionKeys: exports.encryptionKeys,
};
//# sourceMappingURL=schema.js.map