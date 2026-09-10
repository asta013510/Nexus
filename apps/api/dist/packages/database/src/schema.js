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
import { pgTable, uuid, varchar, text, timestamp, boolean, integer, jsonb, index, uniqueIndex, } from 'drizzle-orm/pg-core';
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
}, (table) => ({
    emailUnique: uniqueIndex('users_email_unique').on(table.email),
    statusIdx: index('users_status_idx').on(table.status),
    createdAtIdx: index('users_created_at_idx').on(table.createdAt),
}));
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
}, (table) => ({
    userIdIdx: index('sessions_user_id_idx').on(table.userId),
    expiresAtIdx: index('sessions_expires_at_idx').on(table.expiresAt),
    revokedIdx: index('sessions_revoked_idx').on(table.revoked),
}));
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
}, (table) => ({
    userIdIdx: index('devices_user_id_idx').on(table.userId),
    isTrustedIdx: index('devices_is_trusted_idx').on(table.isTrusted),
}));
// ============================================================================
// TABELA: FOLDERS
// ============================================================================
export const folders = pgTable('folders', {
    id: uuid('id').primaryKey().notNull(),
    userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    parentId: uuid('parent_id').references(() => folders.id, { onDelete: 'cascade' }),
    name: varchar('name', { length: 255 }).notNull(),
    description: text('description'),
    color: varchar('color', { length: 7 }), // Hex color #RRGGBB
    icon: varchar('icon', { length: 50 }),
    isSystem: boolean('is_system').notNull().default(false), // Pastas do sistema (ex: Trash)
    createdAt: timestamp('created_at').notNull().defaultNow(),
    updatedAt: timestamp('updated_at').notNull().defaultNow(),
    deletedAt: timestamp('deleted_at'),
}, (table) => ({
    userIdIdx: index('folders_user_id_idx').on(table.userId),
    parentIdIdx: index('folders_parent_id_idx').on(table.parentId),
    deletedAtIdx: index('folders_deleted_at_idx').on(table.deletedAt),
}));
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
    encryptionKeyId: uuid('encryption_key_id'), // References encryptionKeys (definido depois)
    version: integer('version').notNull().default(1),
    currentVersionId: uuid('current_version_id'), // References documentVersions (definido depois)
    status: varchar('status', { length: 20 }).notNull().default('active'),
    classification: varchar('classification', { length: 50 }), // public, internal, confidential, secret
    tags: jsonb('tags').$type(), // Array de tags
    createdAt: timestamp('created_at').notNull().defaultNow(),
    updatedAt: timestamp('updated_at').notNull().defaultNow(),
    deletedAt: timestamp('deleted_at'), // Soft delete
}, (table) => ({
    userIdIdx: index('documents_user_id_idx').on(table.userId),
    folderIdIdx: index('documents_folder_id_idx').on(table.folderId),
    statusIdx: index('documents_status_idx').on(table.status),
    deletedAtIdx: index('documents_deleted_at_idx').on(table.deletedAt),
    createdAtIdx: index('documents_created_at_idx').on(table.createdAt),
}));
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
    encryptionKeyId: uuid('encryption_key_id'), // References encryptionKeys (definido depois)
    changeDescription: text('change_description'),
    createdAt: timestamp('created_at').notNull().defaultNow(),
}, (table) => ({
    documentIdIdx: index('document_versions_document_id_idx').on(table.documentId),
    userIdIdx: index('document_versions_user_id_idx').on(table.userId),
    docVersionUnique: uniqueIndex('document_versions_doc_version_unique').on(table.documentId, table.version),
}));
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
}, (table) => ({
    userIdIdx: index('audit_logs_user_id_idx').on(table.userId),
    actionIdx: index('audit_logs_action_idx').on(table.action),
    timestampIdx: index('audit_logs_timestamp_idx').on(table.timestamp),
    resourceIdx: index('audit_logs_resource_idx').on(table.resourceType, table.resourceId),
}));
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
}, (table) => ({
    userIdIdx: index('recovery_codes_user_id_idx').on(table.userId),
    usedIdx: index('recovery_codes_used_idx').on(table.used),
}));
// ============================================================================
// TABELA: WEBAUTHN_CREDENTIALS
// ============================================================================
export const webauthnCredentials = pgTable('webauthn_credentials', {
    id: uuid('id').primaryKey().notNull(),
    userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    credentialId: text('credential_id').notNull(), // ID da credencial WebAuthn
    publicKey: text('public_key').notNull(), // Chave pública
    counter: integer('counter').notNull().default(0), // Contador de assinatura
    transports: jsonb('transports').$type(), // Transportes suportados
    deviceName: varchar('device_name', { length: 255 }),
    deviceType: varchar('device_type', { length: 50 }),
    createdAt: timestamp('created_at').notNull().defaultNow(),
    lastUsedAt: timestamp('last_used_at'),
}, (table) => ({
    userIdIdx: index('webauthn_credentials_user_id_idx').on(table.userId),
    credentialIdUnique: uniqueIndex('webauthn_credentials_credential_id_unique').on(table.credentialId),
}));
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
    rotatedFromId: uuid('rotated_from_id'), // References encryptionKeys (self-reference, adicionar FK depois via migration)
    createdAt: timestamp('created_at').notNull().defaultNow(),
    expiresAt: timestamp('expires_at'),
    revokedAt: timestamp('revoked_at'),
}, (table) => ({
    userIdIdx: index('encryption_keys_user_id_idx').on(table.userId),
    keyTypeIdx: index('encryption_keys_key_type_idx').on(table.keyType),
}));
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic2NoZW1hLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vLi4vLi4vLi4vcGFja2FnZXMvZGF0YWJhc2Uvc3JjL3NjaGVtYS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7Ozs7Ozs7Ozs7Ozs7R0FjRztBQUVILE9BQU8sRUFDTCxPQUFPLEVBQ1AsSUFBSSxFQUNKLE9BQU8sRUFDUCxJQUFJLEVBQ0osU0FBUyxFQUNULE9BQU8sRUFDUCxPQUFPLEVBQ1AsS0FBSyxFQUNMLEtBQUssRUFDTCxXQUFXLEdBQ1osTUFBTSxxQkFBcUIsQ0FBQztBQUM3QixPQUFPLEVBQUUsU0FBUyxFQUFFLE1BQU0sYUFBYSxDQUFDO0FBRXhDLCtFQUErRTtBQUMvRSxnQkFBZ0I7QUFDaEIsK0VBQStFO0FBRS9FLE1BQU0sQ0FBQyxNQUFNLEtBQUssR0FBRyxPQUFPLENBQUMsT0FBTyxFQUFFO0lBQ3BDLEVBQUUsRUFBRSxJQUFJLENBQUMsSUFBSSxDQUFDLENBQUMsVUFBVSxFQUFFLENBQUMsT0FBTyxFQUFFO0lBQ3JDLEtBQUssRUFBRSxPQUFPLENBQUMsT0FBTyxFQUFFLEVBQUUsTUFBTSxFQUFFLEdBQUcsRUFBRSxDQUFDLENBQUMsT0FBTyxFQUFFO0lBQ2xELFlBQVksRUFBRSxJQUFJLENBQUMsZUFBZSxDQUFDLENBQUMsT0FBTyxFQUFFLEVBQUUsZ0JBQWdCO0lBQy9ELFlBQVksRUFBRSxJQUFJLENBQUMsZUFBZSxDQUFDLENBQUMsT0FBTyxFQUFFLEVBQUUseUJBQXlCO0lBRXhFLFdBQVcsRUFBRSxPQUFPLENBQUMsY0FBYyxFQUFFLEVBQUUsTUFBTSxFQUFFLEdBQUcsRUFBRSxDQUFDO0lBQ3JELGFBQWEsRUFBRSxPQUFPLENBQUMsZ0JBQWdCLEVBQUUsRUFBRSxNQUFNLEVBQUUsR0FBRyxFQUFFLENBQUM7SUFFekQsTUFBTSxFQUFFLE9BQU8sQ0FBQyxRQUFRLEVBQUUsRUFBRSxNQUFNLEVBQUUsRUFBRSxFQUFFLENBQUMsQ0FBQyxP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QUMsS0FBSyxFQUFFO1FBQ2YsTUFBTSxFQUFFLENBQUMsbUJBQW1CLENBQUMsTUFBTSxDQUFDO1FBQ3BDLFVBQVUsRUFBRSxDQUFDLEtBQUssQ0FBQyxFQUFFLENBQUM7S0FDdkIsQ0FBQztDQUNILENBQUMsQ0FBQyxDQUFDO0FBRUosTUFBTSxDQUFDLE1BQU0sc0JBQXNCLEdBQUcsU0FBUyxDQUFDLGNBQWMsRUFBRSxDQUFDLEVBQUUsR0FBRyxFQUFFLElBQUksRUFBRSxFQUFFLEVBQUUsQ0FBQyxDQUFDO0lBQ2xGLElBQUksRUFBRSxHQUFHLENBQUMsS0FBSyxFQUFFO1FBQ2YsTUFBTSxFQUFFLENBQUMsY0FBYyxDQUFDLE1BQU0sQ0FBQztRQUMvQixVQUFVLEVBQUUsQ0FBQyxLQUFLLENBQUMsRUFBRSxDQUFDO0tBQ3ZCLENBQUM7SUFDRixTQUFTLEVBQUUsSUFBSSxDQUFDLFNBQVMsQ0FBQztJQUMxQixnQkFBZ0IsRUFBRSxJQUFJLENBQUMsZ0JBQWdCLENBQUM7Q0FDekMsQ0FBQyxDQUFDLENBQUM7QUFFSix5QkFBeUI7QUFDekIsTUFBTSxDQUFDLE1BQU0sTUFBTSxHQUFHO0lBQ3BCLEtBQUs7SUFDTCxRQUFRO0lBQ1IsT0FBTztJQUNQLE9BQU87SUFDUCxTQUFTO0lBQ1QsZ0JBQWdCO0lBQ2hCLFNBQVM7SUFDVCxhQUFhO0lBQ2IsbUJBQW1CO0lBQ25CLGNBQWM7Q0FDZixDQUFDIiwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gKiBTY2hlbWEgZG8gQmFuY28gZGUgRGFkb3MgLSBEcml6emxlIE9STVxuICogXG4gKiBQb3N0Z3JlU1FMIGNvbSBSb3ctTGV2ZWwgU2VjdXJpdHkgcmVhZHlcbiAqIFxuICogU0VDVVJJVFkgTk9URVM6XG4gKiAtIFRvZG9zIG9zIElEcyBzw6NvIFVVSURzIChuw6NvIHNlcXVlbmNpYWlzKVxuICogLSBQYXNzd29yZCBoYXNoZXMgTlVOQ0Egc8OjbyBleHBvc3RvcyBlbSBzZWxlY3RzIG5vcm1haXNcbiAqIC0gRmFjaWFsIHRlbXBsYXRlIMOpIGhhc2gsIE5VTkNBIGltYWdlbSBicnV0YVxuICogLSBSZWNvdmVyeSBjb2RlcyBzw6NvIGhhc2hlYWRvc1xuICogLSBSZWZyZXNoIHRva2VucyBzw6NvIGhhc2hlYWRvc1xuICogLSBFbmNyeXB0aW9uIGtleXMgc8OjbyB3cmFwcGVkIChlbnZlbG9wZSBlbmNyeXB0aW9uKVxuICogLSBTb2Z0IGRlbGV0ZSBwYXJhIGRvY3VtZW50b3MgKHJlY3VwZXJhw6fDo28gcG9zc8OtdmVsKVxuICogLSBUaW1lc3RhbXBzIHBhcmEgYXVkaXRvcmlhXG4gKi9cblxuaW1wb3J0IHtcbiAgcGdUYWJsZSxcbiAgdXVpZCxcbiAgdmFyY2hhcixcbiAgdGV4dCxcbiAgdGltZXN0YW1wLFxuICBib29sZWFuLFxuICBpbnRlZ2VyLFxuICBqc29uYixcbiAgaW5kZXgsXG4gIHVuaXF1ZUluZGV4LFxufSBmcm9tICdkcml6emxlLW9ybS9wZy1jb3JlJztcbmltcG9ydCB7IHJlbGF0aW9ucyB9IGZyb20gJ2RyaXp6bGUtb3JtJztcblxuLy8gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxuLy8gVEFCRUxBOiBVU0VSU1xuLy8gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxuXG5leHBvcnQgY29uc3QgdXNlcnMgPSBwZ1RhYmxlKCd1c2VycycsIHtcbiAgaWQ6IHV1aWQoJ2lkJykucHJpbWFyeUtleSgpLm5vdE51bGwoKSxcbiAgZW1haWw6IHZhcmNoYXIoJ2VtYWlsJywgeyBsZW5ndGg6IDI1NCB9KS5ub3ROdWxsKCksXG4gIHBhc3N3b3JkSGFzaDogdGV4dCgncGFzc3dvcmRfaGFzaCcpLm5vdE51bGwoKSwgLy8gQXJnb24yaWQgaGFzaFxuICBwYXNzd29yZFNhbHQ6IHRleHQoJ3Bhc3N3b3JkX3NhbHQnKS5ub3ROdWxsKCksIC8vIFNhbHQgw7puaWNvIHBvciB1c3XDoXJpb1xuICBcbiAgZGlzcGxheU5hbWU6IHZhcmNoYXIoJ2Rpc3BsYXlfbmFtZScsIHsgbGVuZ3RoOiAxMDAgfSksXG4gIHJlY292ZXJ5RW1haWw6IHZhcmNoYXIoJ3JlY292ZXJ5X2VtYWlsJywgeyBsZW5ndGg6IDI1NCB9KSxcbiAgXG4gIHN0YXR1czogdmFyY2hhcignc3RhdHVzJywgeyBsZW5ndGg6IDIwIH0pLm5vdE51bGwoKS5kZWZhdWx0KCdwZW5kaW5nX21mYScpLCAvLyBwZW5kaW5nX21mYSwgYWN0aXZlLCBsb2NrZWQsIHN1c3BlbmRlZFxuICBcbiAgbWZhRW5hYmxlZDogYm9vbGVhbignbWZhX2VuYWJsZWQnKS5ub3ROdWxsKCkuZGVmYXVsdChmYWxzZSksXG4gIG1mYVNlY3JldDogdGV4dCgnbWZhX3NlY3JldCcpLCAvLyBUT1RQIHNlY3JldCAoY3JpcHRvZ3JhZmFkbyBlbSBwcm9kdcOnw6NvKVxuICBtZmFCYWNrdXBDb2Rlc0hhc2g6IHRleHQoJ21mYV9iYWNrdXBfY29kZXNfaGFzaCcpLCAvLyBIYXNoIGRvcyBjw7NkaWdvcyBkZSByZWN1cGVyYcOnw6NvXG4gIFxuICBmYWNpYWxUZW1wbGF0ZUhhc2g6IHRleHQoJ2ZhY2lhbF90ZW1wbGF0ZV9oYXNoJyksIC8vIEhhc2ggZG8gdGVtcGxhdGUgYmlvbcOpdHJpY28gKE5VTkNBIGltYWdlbSlcbiAgXG4gIGZhaWxlZExvZ2luQXR0ZW1wdHM6IGludGVnZXIoJ2ZhaWxlZF9sb2dpbl9hdHRlbXB0cycpLm5vdE51bGwoKS5kZWZhdWx0KDApLFxuICBsb2NrZWRVbnRpbDogdGltZXN0YW1wKCdsb2NrZWRfdW50aWwnKSxcbiAgXG4gIGxhc3RMb2dpbkF0OiB0aW1lc3RhbXAoJ2xhc3RfbG9naW5fYXQnKSxcbiAgbGFzdFBhc3N3b3JkQ2hhbmdlQXQ6IHRpbWVzdGFtcCgnbGFzdF9wYXNzd29yZF9jaGFuZ2VfYXQnKSxcbiAgXG4gIGNyZWF0ZWRBdDogdGltZXN0YW1wKCdjcmVhdGVkX2F0Jykubm90TnVsbCgpLmRlZmF1bHROb3coKSxcbiAgdXBkYXRlZEF0OiB0aW1lc3RhbXAoJ3VwZGF0ZWRfYXQnKS5ub3ROdWxsKCkuZGVmYXVsdE5vdygpLFxuICBkZWxldGVkQXQ6IHRpbWVzdGFtcCgnZGVsZXRlZF9hdCcpLCAvLyBTb2Z0IGRlbGV0ZSBwYXJhIGNvbnRhXG59LCAodGFibGUpID0+ICh7XG4gIGVtYWlsVW5pcXVlOiB1bmlxdWVJbmRleCgndXNlcnNfZW1haWxfdW5pcXVlJykub24odGFibGUuZW1haWwpLFxuICBzdGF0dXNJZHg6IGluZGV4KCd1c2Vyc19zdGF0dXNfaWR4Jykub24odGFibGUuc3RhdHVzKSxcbiAgY3JlYXRlZEF0SWR4OiBpbmRleCgndXNlcnNfY3JlYXRlZF9hdF9pZHgnKS5vbih0YWJsZS5jcmVhdGVkQXQpLFxufSkpO1xuXG5leHBvcnQgdHlwZSBVc2VyID0gdHlwZW9mIHVzZXJzLiRpbmZlclNlbGVjdDtcbmV4cG9ydCB0eXBlIE5ld1VzZXIgPSB0eXBlb2YgdXNlcnMuJGluZmVySW5zZXJ0O1xuXG4vLyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG4vLyBUQUJFTEE6IFNFU1NJT05TXG4vLyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG5cbmV4cG9ydCBjb25zdCBzZXNzaW9ucyA9IHBnVGFibGUoJ3Nlc3Npb25zJywge1xuICBpZDogdXVpZCgnaWQnKS5wcmltYXJ5S2V5KCkubm90TnVsbCgpLFxuICB1c2VySWQ6IHV1aWQoJ3VzZXJfaWQnKS5ub3ROdWxsKCkucmVmZXJlbmNlcygoKSA9PiB1c2Vycy5pZCwgeyBvbkRlbGV0ZTogJ2Nhc2NhZGUnIH0pLFxuICBcbiAgcmVmcmVzaFRva2VuSGFzaDogdGV4dCgncmVmcmVzaF90b2tlbl9oYXNoJykubm90TnVsbCgpLCAvLyBIYXNoIGRvIHJlZnJlc2ggdG9rZW5cbiAgcmVmcmVzaFRva2VuQ291bnRlcjogaW50ZWdlcigncmVmcmVzaF90b2tlbl9jb3VudGVyJykubm90TnVsbCgpLmRlZmF1bHQoMCksIC8vIFBhcmEgcm90YcOnw6NvXG4gIFxuICBleHBpcmVzQXQ6IHRpbWVzdGFtcCgnZXhwaXJlc19hdCcpLm5vdE51bGwoKSxcbiAgcmVmcmVzaEV4cGlyZXNBdDogdGltZXN0YW1wKCdyZWZyZXNoX2V4cGlyZXNfYXQnKS5ub3ROdWxsKCksXG4gIFxuICByZXZva2VkOiBib29sZWFuKCdyZXZva2VkJykubm90TnVsbCgpLmRlZmF1bHQoZmFsc2UpLFxuICByZXZva2VkQXQ6IHRpbWVzdGFtcCgncmV2b2tlZF9hdCcpLFxuICByZXZva2VSZWFzb246IHZhcmNoYXIoJ3Jldm9rZV9yZWFzb24nLCB7IGxlbmd0aDogMjU1IH0pLFxuICBcbiAgbGFzdFVzZWRBdDogdGltZXN0YW1wKCdsYXN0X3VzZWRfYXQnKSxcbiAgaXBBZGRyZXNzOiB2YXJjaGFyKCdpcF9hZGRyZXNzJywgeyBsZW5ndGg6IDQ1IH0pLCAvLyBJUHY2IG1heFxuICB1c2VyQWdlbnQ6IHRleHQoJ3VzZXJfYWdlbnQnKSxcbiAgXG4gIGNyZWF0ZWRBdDogdGltZXN0YW1wKCdjcmVhdGVkX2F0Jykubm90TnVsbCgpLmRlZmF1bHROb3coKSxcbn0sICh0YWJsZSkgPT4gKHtcbiAgdXNlcklkSWR4OiBpbmRleCgnc2Vzc2lvbnNfdXNlcl9pZF9pZHgnKS5vbih0YWJsZS51c2VySWQpLFxuICBleHBpcmVzQXRJZHg6IGluZGV4KCdzZXNzaW9uc19leHBpcmVzX2F0X2lkeCcpLm9uKHRhYmxlLmV4cGlyZXNBdCksXG4gIHJldm9rZWRJZHg6IGluZGV4KCdzZXNzaW9uc19yZXZva2VkX2lkeCcpLm9uKHRhYmxlLnJldm9rZWQpLFxufSkpO1xuXG5leHBvcnQgdHlwZSBTZXNzaW9uID0gdHlwZW9mIHNlc3Npb25zLiRpbmZlclNlbGVjdDtcbmV4cG9ydCB0eXBlIE5ld1Nlc3Npb24gPSB0eXBlb2Ygc2Vzc2lvbnMuJGluZmVySW5zZXJ0O1xuXG4vLyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG4vLyBUQUJFTEE6IERFVklDRVNcbi8vID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cblxuZXhwb3J0IGNvbnN0IGRldmljZXMgPSBwZ1RhYmxlKCdkZXZpY2VzJywge1xuICBpZDogdXVpZCgnaWQnKS5wcmltYXJ5S2V5KCkubm90TnVsbCgpLFxuICB1c2VySWQ6IHV1aWQoJ3VzZXJfaWQnKS5ub3ROdWxsKCkucmVmZXJlbmNlcygoKSA9PiB1c2Vycy5pZCwgeyBvbkRlbGV0ZTogJ2Nhc2NhZGUnIH0pLFxuICBcbiAgbmFtZTogdmFyY2hhcignbmFtZScsIHsgbGVuZ3RoOiAyNTUgfSkubm90TnVsbCgpLFxuICB0eXBlOiB2YXJjaGFyKCd0eXBlJywgeyBsZW5ndGg6IDIwIH0pLm5vdE51bGwoKSwgLy8gZGVza3RvcCwgbW9iaWxlLCB0YWJsZXQsIHVua25vd25cbiAgXG4gIG9zOiB2YXJjaGFyKCdvcycsIHsgbGVuZ3RoOiAxMDAgfSksXG4gIGJyb3dzZXI6IHZhcmNoYXIoJ2Jyb3dzZXInLCB7IGxlbmd0aDogMTAwIH0pLFxuICBcbiAgaXNUcnVzdGVkOiBib29sZWFuKCdpc190cnVzdGVkJykubm90TnVsbCgpLmRlZmF1bHQoZmFsc2UpLFxuICB0cnVzdGVkVW50aWw6IHRpbWVzdGFtcCgndHJ1c3RlZF91bnRpbCcpLFxuICBcbiAgbGFzdFNlZW5BdDogdGltZXN0YW1wKCdsYXN0X3NlZW5fYXQnKSxcbiAgaXBBZGRyZXNzOiB2YXJjaGFyKCdpcF9hZGRyZXNzJywgeyBsZW5ndGg6IDQ1IH0pLFxuICB1c2VyQWdlbnQ6IHRleHQoJ3VzZXJfYWdlbnQnKSxcbiAgXG4gIGNyZWF0ZWRBdDogdGltZXN0YW1wKCdjcmVhdGVkX2F0Jykubm90TnVsbCgpLmRlZmF1bHROb3coKSxcbn0sICh0YWJsZSkgPT4gKHtcbiAgdXNlcklkSWR4OiBpbmRleCgnZGV2aWNlc191c2VyX2lkX2lkeCcpLm9uKHRhYmxlLnVzZXJJZCksXG4gIGlzVHJ1c3RlZElkeDogaW5kZXgoJ2RldmljZXNfaXNfdHJ1c3RlZF9pZHgnKS5vbih0YWJsZS5pc1RydXN0ZWQpLFxufSkpO1xuXG5leHBvcnQgdHlwZSBEZXZpY2UgPSB0eXBlb2YgZGV2aWNlcy4kaW5mZXJTZWxlY3Q7XG5leHBvcnQgdHlwZSBOZXdEZXZpY2UgPSB0eXBlb2YgZGV2aWNlcy4kaW5mZXJJbnNlcnQ7XG5cbi8vID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cbi8vIFRBQkVMQTogRk9MREVSU1xuLy8gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxuXG5leHBvcnQgY29uc3QgZm9sZGVycyA9IHBnVGFibGUoJ2ZvbGRlcnMnLCB7XG4gIGlkOiB1dWlkKCdpZCcpLnByaW1hcnlLZXkoKS5ub3ROdWxsKCksXG4gIHVzZXJJZDogdXVpZCgndXNlcl9pZCcpLm5vdE51bGwoKS5yZWZlcmVuY2VzKCgpID0+IHVzZXJzLmlkLCB7IG9uRGVsZXRlOiAnY2FzY2FkZScgfSksXG4gIHBhcmVudElkOiB1dWlkKCdwYXJlbnRfaWQnKS5yZWZlcmVuY2VzKCgpOiBhbnkgPT4gZm9sZGVycy5pZCwgeyBvbkRlbGV0ZTogJ2Nhc2NhZGUnIH0pLFxuICBcbiAgbmFtZTogdmFyY2hhcignbmFtZScsIHsgbGVuZ3RoOiAyNTUgfSkubm90TnVsbCgpLFxuICBkZXNjcmlwdGlvbjogdGV4dCgnZGVzY3JpcHRpb24nKSxcbiAgXG4gIGNvbG9yOiB2YXJjaGFyKCdjb2xvcicsIHsgbGVuZ3RoOiA3IH0pLCAvLyBIZXggY29sb3IgI1JSR0dCQlxuICBpY29uOiB2YXJjaGFyKCdpY29uJywgeyBsZW5ndGg6IDUwIH0pLFxuICBcbiAgaXNTeXN0ZW06IGJvb2xlYW4oJ2lzX3N5c3RlbScpLm5vdE51bGwoKS5kZWZhdWx0KGZhbHNlKSwgLy8gUGFzdGFzIGRvIHNpc3RlbWEgKGV4OiBUcmFzaClcbiAgXG4gIGNyZWF0ZWRBdDogdGltZXN0YW1wKCdjcmVhdGVkX2F0Jykubm90TnVsbCgpLmRlZmF1bHROb3coKSxcbiAgdXBkYXRlZEF0OiB0aW1lc3RhbXAoJ3VwZGF0ZWRfYXQnKS5ub3ROdWxsKCkuZGVmYXVsdE5vdygpLFxuICBkZWxldGVkQXQ6IHRpbWVzdGFtcCgnZGVsZXRlZF9hdCcpLFxufSwgKHRhYmxlKSA9PiAoe1xuICB1c2VySWRJZHg6IGluZGV4KCdmb2xkZXJzX3VzZXJfaWRfaWR4Jykub24odGFibGUudXNlcklkKSxcbiAgcGFyZW50SWRJZHg6IGluZGV4KCdmb2xkZXJzX3BhcmVudF9pZF9pZHgnKS5vbih0YWJsZS5wYXJlbnRJZCksXG4gIGRlbGV0ZWRBdElkeDogaW5kZXgoJ2ZvbGRlcnNfZGVsZXRlZF9hdF9pZHgnKS5vbih0YWJsZS5kZWxldGVkQXQpLFxufSkpO1xuXG5leHBvcnQgdHlwZSBGb2xkZXIgPSB0eXBlb2YgZm9sZGVycy4kaW5mZXJTZWxlY3Q7XG5leHBvcnQgdHlwZSBOZXdGb2xkZXIgPSB0eXBlb2YgZm9sZGVycy4kaW5mZXJJbnNlcnQ7XG5cbi8vID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cbi8vIFRBQkVMQTogRE9DVU1FTlRTXG4vLyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG5cbmV4cG9ydCBjb25zdCBkb2N1bWVudHMgPSBwZ1RhYmxlKCdkb2N1bWVudHMnLCB7XG4gIGlkOiB1dWlkKCdpZCcpLnByaW1hcnlLZXkoKS5ub3ROdWxsKCksXG4gIHVzZXJJZDogdXVpZCgndXNlcl9pZCcpLm5vdE51bGwoKS5yZWZlcmVuY2VzKCgpID0+IHVzZXJzLmlkLCB7IG9uRGVsZXRlOiAnY2FzY2FkZScgfSksXG4gIGZvbGRlcklkOiB1dWlkKCdmb2xkZXJfaWQnKS5yZWZlcmVuY2VzKCgpID0+IGZvbGRlcnMuaWQsIHsgb25EZWxldGU6ICdzZXQgbnVsbCcgfSksXG4gIFxuICBuYW1lOiB2YXJjaGFyKCduYW1lJywgeyBsZW5ndGg6IDI1NSB9KS5ub3ROdWxsKCksXG4gIGRlc2NyaXB0aW9uOiB0ZXh0KCdkZXNjcmlwdGlvbicpLFxuICBcbiAgbWltZVR5cGU6IHZhcmNoYXIoJ21pbWVfdHlwZScsIHsgbGVuZ3RoOiAyNTUgfSkubm90TnVsbCgpLFxuICBzaXplOiBpbnRlZ2VyKCdzaXplJykubm90TnVsbCgpLCAvLyBCeXRlc1xuICBcbiAgc3RvcmFnZUtleTogdGV4dCgnc3RvcmFnZV9rZXknKS5ub3ROdWxsKCksIC8vIENoYXZlIG5vIG9iamVjdCBzdG9yYWdlXG4gIHN0b3JhZ2VCdWNrZXQ6IHZhcmNoYXIoJ3N0b3JhZ2VfYnVja2V0JywgeyBsZW5ndGg6IDI1NSB9KS5ub3ROdWxsKCkuZGVmYXVsdCgnemVyby1kb2N1bWVudHMnKSxcbiAgXG4gIGNvbnRlbnRIYXNoOiB0ZXh0KCdjb250ZW50X2hhc2gnKS5ub3ROdWxsKCksIC8vIFNIQS0yNTYgZG8gY29udGXDumRvXG4gIGVuY3J5cHRpb25LZXlJZDogdXVpZCgnZW5jcnlwdGlvbl9rZXlfaWQnKSwgLy8gUmVmZXJlbmNlcyBlbmNyeXB0aW9uS2V5cyAoZGVmaW5pZG8gZGVwb2lzKVxuICBcbiAgdmVyc2lvbjogaW50ZWdlcigndmVyc2lvbicpLm5vdE51bGwoKS5kZWZhdWx0KDEpLFxuICBjdXJyZW50VmVyc2lvbklkOiB1dWlkKCdjdXJyZW50X3ZlcnNpb25faWQnKSwgLy8gUmVmZXJlbmNlcyBkb2N1bWVudFZlcnNpb25zIChkZWZpbmlkbyBkZXBvaXMpXG4gIFxuICBzdGF0dXM6IHZhcmNoYXIoJ3N0YXR1cycsIHsgbGVuZ3RoOiAyMCB9KS5ub3ROdWxsKCkuZGVmYXVsdCgnYWN0aXZlJyksXG4gIGNsYXNzaWZpY2F0aW9uOiB2YXJjaGFyKCdjbGFzc2lmaWNhdGlvbicsIHsgbGVuZ3RoOiA1MCB9KSwgLy8gcHVibGljLCBpbnRlcm5hbCwgY29uZmlkZW50aWFsLCBzZWNyZXRcbiAgXG4gIHRhZ3M6IGpzb25iKCd0YWdzJykuJHR5cGU8c3RyaW5nW10+KCksIC8vIEFycmF5IGRlIHRhZ3NcbiAgXG4gIGNyZWF0ZWRBdDogdGltZXN0YW1wKCdjcmVhdGVkX2F0Jykubm90TnVsbCgpLmRlZmF1bHROb3coKSxcbiAgdXBkYXRlZEF0OiB0aW1lc3RhbXAoJ3VwZGF0ZWRfYXQnKS5ub3ROdWxsKCkuZGVmYXVsdE5vdygpLFxuICBkZWxldGVkQXQ6IHRpbWVzdGFtcCgnZGVsZXRlZF9hdCcpLCAvLyBTb2Z0IGRlbGV0ZVxufSwgKHRhYmxlKSA9PiAoe1xuICB1c2VySWRJZHg6IGluZGV4KCdkb2N1bWVudHNfdXNlcl9pZF9pZHgnKS5vbih0YWJsZS51c2VySWQpLFxuICBmb2xkZXJJZElkeDogaW5kZXgoJ2RvY3VtZW50c19mb2xkZXJfaWRfaWR4Jykub24odGFibGUuZm9sZGVySWQpLFxuICBzdGF0dXNJZHg6IGluZGV4KCdkb2N1bWVudHNfc3RhdHVzX2lkeCcpLm9uKHRhYmxlLnN0YXR1cyksXG4gIGRlbGV0ZWRBdElkeDogaW5kZXgoJ2RvY3VtZW50c19kZWxldGVkX2F0X2lkeCcpLm9uKHRhYmxlLmRlbGV0ZWRBdCksXG4gIGNyZWF0ZWRBdElkeDogaW5kZXgoJ2RvY3VtZW50c19jcmVhdGVkX2F0X2lkeCcpLm9uKHRhYmxlLmNyZWF0ZWRBdCksXG59KSk7XG5cbmV4cG9ydCB0eXBlIERvY3VtZW50ID0gdHlwZW9mIGRvY3VtZW50cy4kaW5mZXJTZWxlY3Q7XG5leHBvcnQgdHlwZSBOZXdEb2N1bWVudCA9IHR5cGVvZiBkb2N1bWVudHMuJGluZmVySW5zZXJ0O1xuXG4vLyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG4vLyBUQUJFTEE6IERPQ1VNRU5UX1ZFUlNJT05TXG4vLyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG5cbmV4cG9ydCBjb25zdCBkb2N1bWVudFZlcnNpb25zID0gcGdUYWJsZSgnZG9jdW1lbnRfdmVyc2lvbnMnLCB7XG4gIGlkOiB1dWlkKCdpZCcpLnByaW1hcnlLZXkoKS5ub3ROdWxsKCksXG4gIGRvY3VtZW50SWQ6IHV1aWQoJ2RvY3VtZW50X2lkJykubm90TnVsbCgpLnJlZmVyZW5jZXMoKCkgPT4gZG9jdW1lbnRzLmlkLCB7IG9uRGVsZXRlOiAnY2FzY2FkZScgfSksXG4gIHVzZXJJZDogdXVpZCgndXNlcl9pZCcpLm5vdE51bGwoKS5yZWZlcmVuY2VzKCgpID0+IHVzZXJzLmlkKSxcbiAgXG4gIHZlcnNpb246IGludGVnZXIoJ3ZlcnNpb24nKS5ub3ROdWxsKCksXG4gIFxuICBtaW1lVHlwZTogdmFyY2hhcignbWltZV90eXBlJywgeyBsZW5ndGg6IDI1NSB9KS5ub3ROdWxsKCksXG4gIHNpemU6IGludGVnZXIoJ3NpemUnKS5ub3ROdWxsKCksXG4gIFxuICBzdG9yYWdlS2V5OiB0ZXh0KCdzdG9yYWdlX2tleScpLm5vdE51bGwoKSxcbiAgc3RvcmFnZUJ1Y2tldDogdmFyY2hhcignc3RvcmFnZV9idWNrZXQnLCB7IGxlbmd0aDogMjU1IH0pLm5vdE51bGwoKSxcbiAgXG4gIGNvbnRlbnRIYXNoOiB0ZXh0KCdjb250ZW50X2hhc2gnKS5ub3ROdWxsKCksXG4gIGVuY3J5cHRpb25LZXlJZDogdXVpZCgnZW5jcnlwdGlvbl9rZXlfaWQnKSwgLy8gUmVmZXJlbmNlcyBlbmNyeXB0aW9uS2V5cyAoZGVmaW5pZG8gZGVwb2lzKVxuICBcbiAgY2hhbmdlRGVzY3JpcHRpb246IHRleHQoJ2NoYW5nZV9kZXNjcmlwdGlvbicpLFxuICBcbiAgY3JlYXRlZEF0OiB0aW1lc3RhbXAoJ2NyZWF0ZWRfYXQnKS5ub3ROdWxsKCkuZGVmYXVsdE5vdygpLFxufSwgKHRhYmxlKSA9PiAoe1xuICBkb2N1bWVudElkSWR4OiBpbmRleCgnZG9jdW1lbnRfdmVyc2lvbnNfZG9jdW1lbnRfaWRfaWR4Jykub24odGFibGUuZG9jdW1lbnRJZCksXG4gIHVzZXJJZElkeDogaW5kZXgoJ2RvY3VtZW50X3ZlcnNpb25zX3VzZXJfaWRfaWR4Jykub24odGFibGUudXNlcklkKSxcbiAgZG9jVmVyc2lvblVuaXF1ZTogdW5pcXVlSW5kZXgoJ2RvY3VtZW50X3ZlcnNpb25zX2RvY192ZXJzaW9uX3VuaXF1ZScpLm9uKHRhYmxlLmRvY3VtZW50SWQsIHRhYmxlLnZlcnNpb24pLFxufSkpO1xuXG5leHBvcnQgdHlwZSBEb2N1bWVudFZlcnNpb24gPSB0eXBlb2YgZG9jdW1lbnRWZXJzaW9ucy4kaW5mZXJTZWxlY3Q7XG5leHBvcnQgdHlwZSBOZXdEb2N1bWVudFZlcnNpb24gPSB0eXBlb2YgZG9jdW1lbnRWZXJzaW9ucy4kaW5mZXJJbnNlcnQ7XG5cbi8vID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cbi8vIFRBQkVMQTogQVVESVRfTE9HU1xuLy8gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxuXG5leHBvcnQgY29uc3QgYXVkaXRMb2dzID0gcGdUYWJsZSgnYXVkaXRfbG9ncycsIHtcbiAgaWQ6IHV1aWQoJ2lkJykucHJpbWFyeUtleSgpLm5vdE51bGwoKSxcbiAgXG4gIGFjdGlvbjogdmFyY2hhcignYWN0aW9uJywgeyBsZW5ndGg6IDUwIH0pLm5vdE51bGwoKSxcbiAgcmVzb3VyY2VUeXBlOiB2YXJjaGFyKCdyZXNvdXJjZV90eXBlJywgeyBsZW5ndGg6IDUwIH0pLFxuICByZXNvdXJjZUlkOiB1dWlkKCdyZXNvdXJjZV9pZCcpLFxuICBcbiAgdXNlcklkOiB1dWlkKCd1c2VyX2lkJykucmVmZXJlbmNlcygoKSA9PiB1c2Vycy5pZCksXG4gIHNlc3Npb25JZDogdXVpZCgnc2Vzc2lvbl9pZCcpLnJlZmVyZW5jZXMoKCkgPT4gc2Vzc2lvbnMuaWQpLFxuICBkZXZpY2VJZDogdXVpZCgnZGV2aWNlX2lkJykucmVmZXJlbmNlcygoKSA9PiBkZXZpY2VzLmlkKSxcbiAgXG4gIHRpbWVzdGFtcDogdGltZXN0YW1wKCd0aW1lc3RhbXAnKS5ub3ROdWxsKCkuZGVmYXVsdE5vdygpLFxuICBcbiAgaXBBZGRyZXNzOiB2YXJjaGFyKCdpcF9hZGRyZXNzJywgeyBsZW5ndGg6IDQ1IH0pLm5vdE51bGwoKSxcbiAgdXNlckFnZW50OiB0ZXh0KCd1c2VyX2FnZW50Jykubm90TnVsbCgpLFxuICBcbiAgc3VjY2VzczogYm9vbGVhbignc3VjY2VzcycpLm5vdE51bGwoKSxcbiAgZmFpbHVyZVJlYXNvbjogdmFyY2hhcignZmFpbHVyZV9yZWFzb24nLCB7IGxlbmd0aDogMjU1IH0pLFxuICBcbiAgbWV0YWRhdGE6IGpzb25iKCdtZXRhZGF0YScpLCAvLyBEYWRvcyBhZGljaW9uYWlzIGVzdHJ1dHVyYWRvc1xuICBcbiAgLy8gTm90YTogTlVOQ0EgYXJtYXplbmFyIGRhZG9zIHNlbnPDrXZlaXMgbm9zIGxvZ3NcbiAgLy8gU2VuaGFzLCB0b2tlbnMsIGNoYXZlcywgZGFkb3MgYmlvbcOpdHJpY29zIC0gUFJPSUJJRE9cbn0sICh0YWJsZSkgPT4gKHtcbiAgdXNlcklkSWR4OiBpbmRleCgnYXVkaXRfbG9nc191c2VyX2lkX2lkeCcpLm9uKHRhYmxlLnVzZXJJZCksXG4gIGFjdGlvbklkeDogaW5kZXgoJ2F1ZGl0X2xvZ3NfYWN0aW9uX2lkeCcpLm9uKHRhYmxlLmFjdGlvbiksXG4gIHRpbWVzdGFtcElkeDogaW5kZXgoJ2F1ZGl0X2xvZ3NfdGltZXN0YW1wX2lkeCcpLm9uKHRhYmxlLnRpbWVzdGFtcCksXG4gIHJlc291cmNlSWR4OiBpbmRleCgnYXVkaXRfbG9nc19yZXNvdXJjZV9pZHgnKS5vbih0YWJsZS5yZXNvdXJjZVR5cGUsIHRhYmxlLnJlc291cmNlSWQpLFxufSkpO1xuXG5leHBvcnQgdHlwZSBBdWRpdExvZyA9IHR5cGVvZiBhdWRpdExvZ3MuJGluZmVyU2VsZWN0O1xuZXhwb3J0IHR5cGUgTmV3QXVkaXRMb2cgPSB0eXBlb2YgYXVkaXRMb2dzLiRpbmZlckluc2VydDtcblxuLy8gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxuLy8gVEFCRUxBOiBSRUNPVkVSWV9DT0RFU1xuLy8gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxuXG5leHBvcnQgY29uc3QgcmVjb3ZlcnlDb2RlcyA9IHBnVGFibGUoJ3JlY292ZXJ5X2NvZGVzJywge1xuICBpZDogdXVpZCgnaWQnKS5wcmltYXJ5S2V5KCkubm90TnVsbCgpLFxuICB1c2VySWQ6IHV1aWQoJ3VzZXJfaWQnKS5ub3ROdWxsKCkucmVmZXJlbmNlcygoKSA9PiB1c2Vycy5pZCwgeyBvbkRlbGV0ZTogJ2Nhc2NhZGUnIH0pLFxuICBcbiAgY29kZUhhc2g6IHRleHQoJ2NvZGVfaGFzaCcpLm5vdE51bGwoKSwgLy8gSGFzaCBkbyBjw7NkaWdvIGRlIHJlY3VwZXJhw6fDo29cbiAgY29kZVByZWZpeDogdmFyY2hhcignY29kZV9wcmVmaXgnLCB7IGxlbmd0aDogNCB9KS5ub3ROdWxsKCksIC8vIFByaW1laXJvcyBjaGFycyBwYXJhIGlkZW50aWZpY2HDp8Ojb1xuICBcbiAgdXNlZDogYm9vbGVhbigndXNlZCcpLm5vdE51bGwoKS5kZWZhdWx0KGZhbHNlKSxcbiAgdXNlZEF0OiB0aW1lc3RhbXAoJ3VzZWRfYXQnKSxcbiAgXG4gIGNyZWF0ZWRBdDogdGltZXN0YW1wKCdjcmVhdGVkX2F0Jykubm90TnVsbCgpLmRlZmF1bHROb3coKSxcbiAgZXhwaXJlc0F0OiB0aW1lc3RhbXAoJ2V4cGlyZXNfYXQnKSwgLy8gT3BjaW9uYWxcbn0sICh0YWJsZSkgPT4gKHtcbiAgdXNlcklkSWR4OiBpbmRleCgncmVjb3ZlcnlfY29kZXNfdXNlcl9pZF9pZHgnKS5vbih0YWJsZS51c2VySWQpLFxuICB1c2VkSWR4OiBpbmRleCgncmVjb3ZlcnlfY29kZXNfdXNlZF9pZHgnKS5vbih0YWJsZS51c2VkKSxcbn0pKTtcblxuZXhwb3J0IHR5cGUgUmVjb3ZlcnlDb2RlID0gdHlwZW9mIHJlY292ZXJ5Q29kZXMuJGluZmVyU2VsZWN0O1xuZXhwb3J0IHR5cGUgTmV3UmVjb3ZlcnlDb2RlID0gdHlwZW9mIHJlY292ZXJ5Q29kZXMuJGluZmVySW5zZXJ0O1xuXG4vLyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG4vLyBUQUJFTEE6IFdFQkFVVEhOX0NSRURFTlRJQUxTXG4vLyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG5cbmV4cG9ydCBjb25zdCB3ZWJhdXRobkNyZWRlbnRpYWxzID0gcGdUYWJsZSgnd2ViYXV0aG5fY3JlZGVudGlhbHMnLCB7XG4gIGlkOiB1dWlkKCdpZCcpLnByaW1hcnlLZXkoKS5ub3ROdWxsKCksXG4gIHVzZXJJZDogdXVpZCgndXNlcl9pZCcpLm5vdE51bGwoKS5yZWZlcmVuY2VzKCgpID0+IHVzZXJzLmlkLCB7IG9uRGVsZXRlOiAnY2FzY2FkZScgfSksXG4gIFxuICBjcmVkZW50aWFsSWQ6IHRleHQoJ2NyZWRlbnRpYWxfaWQnKS5ub3ROdWxsKCksIC8vIElEIGRhIGNyZWRlbmNpYWwgV2ViQXV0aG5cbiAgcHVibGljS2V5OiB0ZXh0KCdwdWJsaWNfa2V5Jykubm90TnVsbCgpLCAvLyBDaGF2ZSBww7pibGljYVxuICBcbiAgY291bnRlcjogaW50ZWdlcignY291bnRlcicpLm5vdE51bGwoKS5kZWZhdWx0KDApLCAvLyBDb250YWRvciBkZSBhc3NpbmF0dXJhXG4gIHRyYW5zcG9ydHM6IGpzb25iKCd0cmFuc3BvcnRzJykuJHR5cGU8c3RyaW5nW10+KCksIC8vIFRyYW5zcG9ydGVzIHN1cG9ydGFkb3NcbiAgXG4gIGRldmljZU5hbWU6IHZhcmNoYXIoJ2RldmljZV9uYW1lJywgeyBsZW5ndGg6IDI1NSB9KSxcbiAgZGV2aWNlVHlwZTogdmFyY2hhcignZGV2aWNlX3R5cGUnLCB7IGxlbmd0aDogNTAgfSksXG4gIFxuICBjcmVhdGVkQXQ6IHRpbWVzdGFtcCgnY3JlYXRlZF9hdCcpLm5vdE51bGwoKS5kZWZhdWx0Tm93KCksXG4gIGxhc3RVc2VkQXQ6IHRpbWVzdGFtcCgnbGFzdF91c2VkX2F0JyksXG59LCAodGFibGUpID0+ICh7XG4gIHVzZXJJZElkeDogaW5kZXgoJ3dlYmF1dGhuX2NyZWRlbnRpYWxzX3VzZXJfaWRfaWR4Jykub24odGFibGUudXNlcklkKSxcbiAgY3JlZGVudGlhbElkVW5pcXVlOiB1bmlxdWVJbmRleCgnd2ViYXV0aG5fY3JlZGVudGlhbHNfY3JlZGVudGlhbF9pZF91bmlxdWUnKS5vbih0YWJsZS5jcmVkZW50aWFsSWQpLFxufSkpO1xuXG5leHBvcnQgdHlwZSBXZWJBdXRobkNyZWRlbnRpYWwgPSB0eXBlb2Ygd2ViYXV0aG5DcmVkZW50aWFscy4kaW5mZXJTZWxlY3Q7XG5leHBvcnQgdHlwZSBOZXdXZWJBdXRobkNyZWRlbnRpYWwgPSB0eXBlb2Ygd2ViYXV0aG5DcmVkZW50aWFscy4kaW5mZXJJbnNlcnQ7XG5cbi8vID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cbi8vIFRBQkVMQTogRU5DUllQVElPTl9LRVlTXG4vLyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG5cbmV4cG9ydCBjb25zdCBlbmNyeXB0aW9uS2V5cyA9IHBnVGFibGUoJ2VuY3J5cHRpb25fa2V5cycsIHtcbiAgaWQ6IHV1aWQoJ2lkJykucHJpbWFyeUtleSgpLm5vdE51bGwoKSxcbiAgdXNlcklkOiB1dWlkKCd1c2VyX2lkJykubm90TnVsbCgpLnJlZmVyZW5jZXMoKCkgPT4gdXNlcnMuaWQsIHsgb25EZWxldGU6ICdjYXNjYWRlJyB9KSxcbiAgXG4gIGtleVR5cGU6IHZhcmNoYXIoJ2tleV90eXBlJywgeyBsZW5ndGg6IDUwIH0pLm5vdE51bGwoKSwgLy8gbWFzdGVyLCBkb2N1bWVudCwgYmFja3VwXG4gIFxuICAvLyBFbnZlbG9wZSBlbmNyeXB0aW9uOlxuICAvLyAtIHdyYXBwZWRLZXk6IGNoYXZlIGVuY3JpcHRhZGEgY29tIEtFSyAoS2V5IEVuY3J5cHRpb24gS2V5KVxuICAvLyAtIGtleUNpcGhlclRleHQ6IGRhZG9zIGVuY3JpcHRhZG9zIGNvbSBlc3RhIGNoYXZlXG4gIHdyYXBwZWRLZXk6IHRleHQoJ3dyYXBwZWRfa2V5Jykubm90TnVsbCgpLFxuICBrZXlJdjogdGV4dCgna2V5X2l2Jykubm90TnVsbCgpLFxuICBrZXlUYWc6IHRleHQoJ2tleV90YWcnKS5ub3ROdWxsKCksXG4gIFxuICBrZXlQdXJwb3NlOiB2YXJjaGFyKCdrZXlfcHVycG9zZScsIHsgbGVuZ3RoOiAxMDAgfSksXG4gIGtleVZlcnNpb246IGludGVnZXIoJ2tleV92ZXJzaW9uJykubm90TnVsbCgpLmRlZmF1bHQoMSksXG4gIFxuICByb3RhdGVkRnJvbUlkOiB1dWlkKCdyb3RhdGVkX2Zyb21faWQnKSwgLy8gUmVmZXJlbmNlcyBlbmNyeXB0aW9uS2V5cyAoc2VsZi1yZWZlcmVuY2UsIGFkaWNpb25hciBGSyBkZXBvaXMgdmlhIG1pZ3JhdGlvbilcbiAgXG4gIGNyZWF0ZWRBdDogdGltZXN0YW1wKCdjcmVhdGVkX2F0Jykubm90TnVsbCgpLmRlZmF1bHROb3coKSxcbiAgZXhwaXJlc0F0OiB0aW1lc3RhbXAoJ2V4cGlyZXNfYXQnKSxcbiAgcmV2b2tlZEF0OiB0aW1lc3RhbXAoJ3Jldm9rZWRfYXQnKSxcbn0sICh0YWJsZSkgPT4gKHtcbiAgdXNlcklkSWR4OiBpbmRleCgnZW5jcnlwdGlvbl9rZXlzX3VzZXJfaWRfaWR4Jykub24odGFibGUudXNlcklkKSxcbiAga2V5VHlwZUlkeDogaW5kZXgoJ2VuY3J5cHRpb25fa2V5c19rZXlfdHlwZV9pZHgnKS5vbih0YWJsZS5rZXlUeXBlKSxcbn0pKTtcblxuZXhwb3J0IHR5cGUgRW5jcnlwdGlvbktleSA9IHR5cGVvZiBlbmNyeXB0aW9uS2V5cy4kaW5mZXJTZWxlY3Q7XG5leHBvcnQgdHlwZSBOZXdFbmNyeXB0aW9uS2V5ID0gdHlwZW9mIGVuY3J5cHRpb25LZXlzLiRpbmZlckluc2VydDtcblxuLy8gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxuLy8gUkVMQVRJT05TXG4vLyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG5cbmV4cG9ydCBjb25zdCB1c2VyUmVsYXRpb25zID0gcmVsYXRpb25zKHVzZXJzLCAoeyBtYW55IH0pID0+ICh7XG4gIHNlc3Npb25zOiBtYW55KHNlc3Npb25zKSxcbiAgZGV2aWNlczogbWFueShkZXZpY2VzKSxcbiAgZm9sZGVyczogbWFueShmb2xkZXJzKSxcbiAgZG9jdW1lbnRzOiBtYW55KGRvY3VtZW50cyksXG4gIGF1ZGl0TG9nczogbWFueShhdWRpdExvZ3MpLFxuICByZWNvdmVyeUNvZGVzOiBtYW55KHJlY292ZXJ5Q29kZXMpLFxuICB3ZWJhdXRobkNyZWRlbnRpYWxzOiBtYW55KHdlYmF1dGhuQ3JlZGVudGlhbHMpLFxuICBlbmNyeXB0aW9uS2V5czogbWFueShlbmNyeXB0aW9uS2V5cyksXG4gIGRvY3VtZW50VmVyc2lvbnM6IG1hbnkoZG9jdW1lbnRWZXJzaW9ucyksXG59KSk7XG5cbmV4cG9ydCBjb25zdCBzZXNzaW9uUmVsYXRpb25zID0gcmVsYXRpb25zKHNlc3Npb25zLCAoeyBvbmUgfSkgPT4gKHtcbiAgdXNlcjogb25lKHVzZXJzLCB7XG4gICAgZmllbGRzOiBbc2Vzc2lvbnMudXNlcklkXSxcbiAgICByZWZlcmVuY2VzOiBbdXNlcnMuaWRdLFxuICB9KSxcbn0pKTtcblxuZXhwb3J0IGNvbnN0IGRldmljZVJlbGF0aW9ucyA9IHJlbGF0aW9ucyhkZXZpY2VzLCAoeyBvbmUgfSkgPT4gKHtcbiAgdXNlcjogb25lKHVzZXJzLCB7XG4gICAgZmllbGRzOiBbZGV2aWNlcy51c2VySWRdLFxuICAgIHJlZmVyZW5jZXM6IFt1c2Vycy5pZF0sXG4gIH0pLFxufSkpO1xuXG5leHBvcnQgY29uc3QgZm9sZGVyUmVsYXRpb25zID0gcmVsYXRpb25zKGZvbGRlcnMsICh7IG9uZSwgbWFueSB9KSA9PiAoe1xuICB1c2VyOiBvbmUodXNlcnMsIHtcbiAgICBmaWVsZHM6IFtmb2xkZXJzLnVzZXJJZF0sXG4gICAgcmVmZXJlbmNlczogW3VzZXJzLmlkXSxcbiAgfSksXG4gIHBhcmVudDogb25lKGZvbGRlcnMsIHtcbiAgICBmaWVsZHM6IFtmb2xkZXJzLnBhcmVudElkXSxcbiAgICByZWZlcmVuY2VzOiBbZm9sZGVycy5pZF0sXG4gIH0pLFxuICBjaGlsZHJlbjogbWFueShmb2xkZXJzLCB7XG4gICAgcmVsYXRpb25OYW1lOiAnZm9sZGVySGllcmFyY2h5JyxcbiAgfSksXG4gIGRvY3VtZW50czogbWFueShkb2N1bWVudHMpLFxufSkpO1xuXG5leHBvcnQgY29uc3QgZG9jdW1lbnRSZWxhdGlvbnMgPSByZWxhdGlvbnMoZG9jdW1lbnRzLCAoeyBvbmUsIG1hbnkgfSkgPT4gKHtcbiAgdXNlcjogb25lKHVzZXJzLCB7XG4gICAgZmllbGRzOiBbZG9jdW1lbnRzLnVzZXJJZF0sXG4gICAgcmVmZXJlbmNlczogW3VzZXJzLmlkXSxcbiAgfSksXG4gIGZvbGRlcjogb25lKGZvbGRlcnMsIHtcbiAgICBmaWVsZHM6IFtkb2N1bWVudHMuZm9sZGVySWRdLFxuICAgIHJlZmVyZW5jZXM6IFtmb2xkZXJzLmlkXSxcbiAgfSksXG4gIHZlcnNpb25zOiBtYW55KGRvY3VtZW50VmVyc2lvbnMpLFxuICBlbmNyeXB0aW9uS2V5OiBvbmUoZW5jcnlwdGlvbktleXMsIHtcbiAgICBmaWVsZHM6IFtkb2N1bWVudHMuZW5jcnlwdGlvbktleUlkXSxcbiAgICByZWZlcmVuY2VzOiBbZW5jcnlwdGlvbktleXMuaWRdLFxuICB9KSxcbn0pKTtcblxuZXhwb3J0IGNvbnN0IGRvY3VtZW50VmVyc2lvblJlbGF0aW9ucyA9IHJlbGF0aW9ucyhkb2N1bWVudFZlcnNpb25zLCAoeyBvbmUgfSkgPT4gKHtcbiAgZG9jdW1lbnQ6IG9uZShkb2N1bWVudHMsIHtcbiAgICBmaWVsZHM6IFtkb2N1bWVudFZlcnNpb25zLmRvY3VtZW50SWRdLFxuICAgIHJlZmVyZW5jZXM6IFtkb2N1bWVudHMuaWRdLFxuICB9KSxcbiAgdXNlcjogb25lKHVzZXJzLCB7XG4gICAgZmllbGRzOiBbZG9jdW1lbnRWZXJzaW9ucy51c2VySWRdLFxuICAgIHJlZmVyZW5jZXM6IFt1c2Vycy5pZF0sXG4gIH0pLFxuICBlbmNyeXB0aW9uS2V5OiBvbmUoZW5jcnlwdGlvbktleXMsIHtcbiAgICBmaWVsZHM6IFtkb2N1bWVudFZlcnNpb25zLmVuY3J5cHRpb25LZXlJZF0sXG4gICAgcmVmZXJlbmNlczogW2VuY3J5cHRpb25LZXlzLmlkXSxcbiAgfSksXG59KSk7XG5cbmV4cG9ydCBjb25zdCBhdWRpdExvZ1JlbGF0aW9ucyA9IHJlbGF0aW9ucyhhdWRpdExvZ3MsICh7IG9uZSB9KSA9PiAoe1xuICB1c2VyOiBvbmUodXNlcnMsIHtcbiAgICBmaWVsZHM6IFthdWRpdExvZ3MudXNlcklkXSxcbiAgICByZWZlcmVuY2VzOiBbdXNlcnMuaWRdLFxuICB9KSxcbiAgc2Vzc2lvbjogb25lKHNlc3Npb25zLCB7XG4gICAgZmllbGRzOiBbYXVkaXRMb2dzLnNlc3Npb25JZF0sXG4gICAgcmVmZXJlbmNlczogW3Nlc3Npb25zLmlkXSxcbiAgfSksXG4gIGRldmljZTogb25lKGRldmljZXMsIHtcbiAgICBmaWVsZHM6IFthdWRpdExvZ3MuZGV2aWNlSWRdLFxuICAgIHJlZmVyZW5jZXM6IFtkZXZpY2VzLmlkXSxcbiAgfSksXG59KSk7XG5cbmV4cG9ydCBjb25zdCByZWNvdmVyeUNvZGVSZWxhdGlvbnMgPSByZWxhdGlvbnMocmVjb3ZlcnlDb2RlcywgKHsgb25lIH0pID0+ICh7XG4gIHVzZXI6IG9uZSh1c2Vycywge1xuICAgIGZpZWxkczogW3JlY292ZXJ5Q29kZXMudXNlcklkXSxcbiAgICByZWZlcmVuY2VzOiBbdXNlcnMuaWRdLFxuICB9KSxcbn0pKTtcblxuZXhwb3J0IGNvbnN0IHdlYmF1dGhuQ3JlZGVudGlhbFJlbGF0aW9ucyA9IHJlbGF0aW9ucyh3ZWJhdXRobkNyZWRlbnRpYWxzLCAoeyBvbmUgfSkgPT4gKHtcbiAgdXNlcjogb25lKHVzZXJzLCB7XG4gICAgZmllbGRzOiBbd2ViYXV0aG5DcmVkZW50aWFscy51c2VySWRdLFxuICAgIHJlZmVyZW5jZXM6IFt1c2Vycy5pZF0sXG4gIH0pLFxufSkpO1xuXG5leHBvcnQgY29uc3QgZW5jcnlwdGlvbktleVJlbGF0aW9ucyA9IHJlbGF0aW9ucyhlbmNyeXB0aW9uS2V5cywgKHsgb25lLCBtYW55IH0pID0+ICh7XG4gIHVzZXI6IG9uZSh1c2Vycywge1xuICAgIGZpZWxkczogW2VuY3J5cHRpb25LZXlzLnVzZXJJZF0sXG4gICAgcmVmZXJlbmNlczogW3VzZXJzLmlkXSxcbiAgfSksXG4gIGRvY3VtZW50czogbWFueShkb2N1bWVudHMpLFxuICBkb2N1bWVudFZlcnNpb25zOiBtYW55KGRvY3VtZW50VmVyc2lvbnMpLFxufSkpO1xuXG4vLyBFeHBvcnQgc2NoZW1hIGFncnVwYWRvXG5leHBvcnQgY29uc3Qgc2NoZW1hID0ge1xuICB1c2VycyxcbiAgc2Vzc2lvbnMsXG4gIGRldmljZXMsXG4gIGZvbGRlcnMsXG4gIGRvY3VtZW50cyxcbiAgZG9jdW1lbnRWZXJzaW9ucyxcbiAgYXVkaXRMb2dzLFxuICByZWNvdmVyeUNvZGVzLFxuICB3ZWJhdXRobkNyZWRlbnRpYWxzLFxuICBlbmNyeXB0aW9uS2V5cyxcbn07XG4iXX0=