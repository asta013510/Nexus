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
export declare const users: import("drizzle-orm/pg-core").PgTableWithColumns<{
    name: "users";
    schema: undefined;
    columns: {
        id: import("drizzle-orm/pg-core").PgColumn<{
            name: "id";
            tableName: "users";
            dataType: "string";
            columnType: "PgUUID";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        email: import("drizzle-orm/pg-core").PgColumn<{
            name: "email";
            tableName: "users";
            dataType: "string";
            columnType: "PgVarchar";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        passwordHash: import("drizzle-orm/pg-core").PgColumn<{
            name: "password_hash";
            tableName: "users";
            dataType: "string";
            columnType: "PgText";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        passwordSalt: import("drizzle-orm/pg-core").PgColumn<{
            name: "password_salt";
            tableName: "users";
            dataType: "string";
            columnType: "PgText";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        displayName: import("drizzle-orm/pg-core").PgColumn<{
            name: "display_name";
            tableName: "users";
            dataType: "string";
            columnType: "PgVarchar";
            data: string;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        recoveryEmail: import("drizzle-orm/pg-core").PgColumn<{
            name: "recovery_email";
            tableName: "users";
            dataType: "string";
            columnType: "PgVarchar";
            data: string;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        status: import("drizzle-orm/pg-core").PgColumn<{
            name: "status";
            tableName: "users";
            dataType: "string";
            columnType: "PgVarchar";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: true;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        mfaEnabled: import("drizzle-orm/pg-core").PgColumn<{
            name: "mfa_enabled";
            tableName: "users";
            dataType: "boolean";
            columnType: "PgBoolean";
            data: boolean;
            driverParam: boolean;
            notNull: true;
            hasDefault: true;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        mfaSecret: import("drizzle-orm/pg-core").PgColumn<{
            name: "mfa_secret";
            tableName: "users";
            dataType: "string";
            columnType: "PgText";
            data: string;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        mfaBackupCodesHash: import("drizzle-orm/pg-core").PgColumn<{
            name: "mfa_backup_codes_hash";
            tableName: "users";
            dataType: "string";
            columnType: "PgText";
            data: string;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        facialTemplateHash: import("drizzle-orm/pg-core").PgColumn<{
            name: "facial_template_hash";
            tableName: "users";
            dataType: "string";
            columnType: "PgText";
            data: string;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        failedLoginAttempts: import("drizzle-orm/pg-core").PgColumn<{
            name: "failed_login_attempts";
            tableName: "users";
            dataType: "number";
            columnType: "PgInteger";
            data: number;
            driverParam: string | number;
            notNull: true;
            hasDefault: true;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        lockedUntil: import("drizzle-orm/pg-core").PgColumn<{
            name: "locked_until";
            tableName: "users";
            dataType: "date";
            columnType: "PgTimestamp";
            data: Date;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        lastLoginAt: import("drizzle-orm/pg-core").PgColumn<{
            name: "last_login_at";
            tableName: "users";
            dataType: "date";
            columnType: "PgTimestamp";
            data: Date;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        lastPasswordChangeAt: import("drizzle-orm/pg-core").PgColumn<{
            name: "last_password_change_at";
            tableName: "users";
            dataType: "date";
            columnType: "PgTimestamp";
            data: Date;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        createdAt: import("drizzle-orm/pg-core").PgColumn<{
            name: "created_at";
            tableName: "users";
            dataType: "date";
            columnType: "PgTimestamp";
            data: Date;
            driverParam: string;
            notNull: true;
            hasDefault: true;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        updatedAt: import("drizzle-orm/pg-core").PgColumn<{
            name: "updated_at";
            tableName: "users";
            dataType: "date";
            columnType: "PgTimestamp";
            data: Date;
            driverParam: string;
            notNull: true;
            hasDefault: true;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        deletedAt: import("drizzle-orm/pg-core").PgColumn<{
            name: "deleted_at";
            tableName: "users";
            dataType: "date";
            columnType: "PgTimestamp";
            data: Date;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
    };
    dialect: "pg";
}>;
export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export declare const sessions: import("drizzle-orm/pg-core").PgTableWithColumns<{
    name: "sessions";
    schema: undefined;
    columns: {
        id: import("drizzle-orm/pg-core").PgColumn<{
            name: "id";
            tableName: "sessions";
            dataType: "string";
            columnType: "PgUUID";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        userId: import("drizzle-orm/pg-core").PgColumn<{
            name: "user_id";
            tableName: "sessions";
            dataType: "string";
            columnType: "PgUUID";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        refreshTokenHash: import("drizzle-orm/pg-core").PgColumn<{
            name: "refresh_token_hash";
            tableName: "sessions";
            dataType: "string";
            columnType: "PgText";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        refreshTokenCounter: import("drizzle-orm/pg-core").PgColumn<{
            name: "refresh_token_counter";
            tableName: "sessions";
            dataType: "number";
            columnType: "PgInteger";
            data: number;
            driverParam: string | number;
            notNull: true;
            hasDefault: true;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        expiresAt: import("drizzle-orm/pg-core").PgColumn<{
            name: "expires_at";
            tableName: "sessions";
            dataType: "date";
            columnType: "PgTimestamp";
            data: Date;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        refreshExpiresAt: import("drizzle-orm/pg-core").PgColumn<{
            name: "refresh_expires_at";
            tableName: "sessions";
            dataType: "date";
            columnType: "PgTimestamp";
            data: Date;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        revoked: import("drizzle-orm/pg-core").PgColumn<{
            name: "revoked";
            tableName: "sessions";
            dataType: "boolean";
            columnType: "PgBoolean";
            data: boolean;
            driverParam: boolean;
            notNull: true;
            hasDefault: true;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        revokedAt: import("drizzle-orm/pg-core").PgColumn<{
            name: "revoked_at";
            tableName: "sessions";
            dataType: "date";
            columnType: "PgTimestamp";
            data: Date;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        revokeReason: import("drizzle-orm/pg-core").PgColumn<{
            name: "revoke_reason";
            tableName: "sessions";
            dataType: "string";
            columnType: "PgVarchar";
            data: string;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        lastUsedAt: import("drizzle-orm/pg-core").PgColumn<{
            name: "last_used_at";
            tableName: "sessions";
            dataType: "date";
            columnType: "PgTimestamp";
            data: Date;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        ipAddress: import("drizzle-orm/pg-core").PgColumn<{
            name: "ip_address";
            tableName: "sessions";
            dataType: "string";
            columnType: "PgVarchar";
            data: string;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        userAgent: import("drizzle-orm/pg-core").PgColumn<{
            name: "user_agent";
            tableName: "sessions";
            dataType: "string";
            columnType: "PgText";
            data: string;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        createdAt: import("drizzle-orm/pg-core").PgColumn<{
            name: "created_at";
            tableName: "sessions";
            dataType: "date";
            columnType: "PgTimestamp";
            data: Date;
            driverParam: string;
            notNull: true;
            hasDefault: true;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
    };
    dialect: "pg";
}>;
export type Session = typeof sessions.$inferSelect;
export type NewSession = typeof sessions.$inferInsert;
export declare const devices: import("drizzle-orm/pg-core").PgTableWithColumns<{
    name: "devices";
    schema: undefined;
    columns: {
        id: import("drizzle-orm/pg-core").PgColumn<{
            name: "id";
            tableName: "devices";
            dataType: "string";
            columnType: "PgUUID";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        userId: import("drizzle-orm/pg-core").PgColumn<{
            name: "user_id";
            tableName: "devices";
            dataType: "string";
            columnType: "PgUUID";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        name: import("drizzle-orm/pg-core").PgColumn<{
            name: "name";
            tableName: "devices";
            dataType: "string";
            columnType: "PgVarchar";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        type: import("drizzle-orm/pg-core").PgColumn<{
            name: "type";
            tableName: "devices";
            dataType: "string";
            columnType: "PgVarchar";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        os: import("drizzle-orm/pg-core").PgColumn<{
            name: "os";
            tableName: "devices";
            dataType: "string";
            columnType: "PgVarchar";
            data: string;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        browser: import("drizzle-orm/pg-core").PgColumn<{
            name: "browser";
            tableName: "devices";
            dataType: "string";
            columnType: "PgVarchar";
            data: string;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        isTrusted: import("drizzle-orm/pg-core").PgColumn<{
            name: "is_trusted";
            tableName: "devices";
            dataType: "boolean";
            columnType: "PgBoolean";
            data: boolean;
            driverParam: boolean;
            notNull: true;
            hasDefault: true;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        trustedUntil: import("drizzle-orm/pg-core").PgColumn<{
            name: "trusted_until";
            tableName: "devices";
            dataType: "date";
            columnType: "PgTimestamp";
            data: Date;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        lastSeenAt: import("drizzle-orm/pg-core").PgColumn<{
            name: "last_seen_at";
            tableName: "devices";
            dataType: "date";
            columnType: "PgTimestamp";
            data: Date;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        ipAddress: import("drizzle-orm/pg-core").PgColumn<{
            name: "ip_address";
            tableName: "devices";
            dataType: "string";
            columnType: "PgVarchar";
            data: string;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        userAgent: import("drizzle-orm/pg-core").PgColumn<{
            name: "user_agent";
            tableName: "devices";
            dataType: "string";
            columnType: "PgText";
            data: string;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        createdAt: import("drizzle-orm/pg-core").PgColumn<{
            name: "created_at";
            tableName: "devices";
            dataType: "date";
            columnType: "PgTimestamp";
            data: Date;
            driverParam: string;
            notNull: true;
            hasDefault: true;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
    };
    dialect: "pg";
}>;
export type Device = typeof devices.$inferSelect;
export type NewDevice = typeof devices.$inferInsert;
export declare const folders: import("drizzle-orm/pg-core").PgTableWithColumns<{
    name: "folders";
    schema: undefined;
    columns: {
        id: import("drizzle-orm/pg-core").PgColumn<{
            name: "id";
            tableName: "folders";
            dataType: "string";
            columnType: "PgUUID";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        userId: import("drizzle-orm/pg-core").PgColumn<{
            name: "user_id";
            tableName: "folders";
            dataType: "string";
            columnType: "PgUUID";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        parentId: import("drizzle-orm/pg-core").PgColumn<{
            name: "parent_id";
            tableName: "folders";
            dataType: "string";
            columnType: "PgUUID";
            data: string;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        name: import("drizzle-orm/pg-core").PgColumn<{
            name: "name";
            tableName: "folders";
            dataType: "string";
            columnType: "PgVarchar";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        description: import("drizzle-orm/pg-core").PgColumn<{
            name: "description";
            tableName: "folders";
            dataType: "string";
            columnType: "PgText";
            data: string;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        color: import("drizzle-orm/pg-core").PgColumn<{
            name: "color";
            tableName: "folders";
            dataType: "string";
            columnType: "PgVarchar";
            data: string;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        icon: import("drizzle-orm/pg-core").PgColumn<{
            name: "icon";
            tableName: "folders";
            dataType: "string";
            columnType: "PgVarchar";
            data: string;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        isSystem: import("drizzle-orm/pg-core").PgColumn<{
            name: "is_system";
            tableName: "folders";
            dataType: "boolean";
            columnType: "PgBoolean";
            data: boolean;
            driverParam: boolean;
            notNull: true;
            hasDefault: true;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        createdAt: import("drizzle-orm/pg-core").PgColumn<{
            name: "created_at";
            tableName: "folders";
            dataType: "date";
            columnType: "PgTimestamp";
            data: Date;
            driverParam: string;
            notNull: true;
            hasDefault: true;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        updatedAt: import("drizzle-orm/pg-core").PgColumn<{
            name: "updated_at";
            tableName: "folders";
            dataType: "date";
            columnType: "PgTimestamp";
            data: Date;
            driverParam: string;
            notNull: true;
            hasDefault: true;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        deletedAt: import("drizzle-orm/pg-core").PgColumn<{
            name: "deleted_at";
            tableName: "folders";
            dataType: "date";
            columnType: "PgTimestamp";
            data: Date;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
    };
    dialect: "pg";
}>;
export type Folder = typeof folders.$inferSelect;
export type NewFolder = typeof folders.$inferInsert;
export declare const documents: any;
export type Document = typeof documents.$inferSelect;
export type NewDocument = typeof documents.$inferInsert;
export declare const documentVersions: any;
export type DocumentVersion = typeof documentVersions.$inferSelect;
export type NewDocumentVersion = typeof documentVersions.$inferInsert;
export declare const auditLogs: import("drizzle-orm/pg-core").PgTableWithColumns<{
    name: "audit_logs";
    schema: undefined;
    columns: {
        id: import("drizzle-orm/pg-core").PgColumn<{
            name: "id";
            tableName: "audit_logs";
            dataType: "string";
            columnType: "PgUUID";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        action: import("drizzle-orm/pg-core").PgColumn<{
            name: "action";
            tableName: "audit_logs";
            dataType: "string";
            columnType: "PgVarchar";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        resourceType: import("drizzle-orm/pg-core").PgColumn<{
            name: "resource_type";
            tableName: "audit_logs";
            dataType: "string";
            columnType: "PgVarchar";
            data: string;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        resourceId: import("drizzle-orm/pg-core").PgColumn<{
            name: "resource_id";
            tableName: "audit_logs";
            dataType: "string";
            columnType: "PgUUID";
            data: string;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        userId: import("drizzle-orm/pg-core").PgColumn<{
            name: "user_id";
            tableName: "audit_logs";
            dataType: "string";
            columnType: "PgUUID";
            data: string;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        sessionId: import("drizzle-orm/pg-core").PgColumn<{
            name: "session_id";
            tableName: "audit_logs";
            dataType: "string";
            columnType: "PgUUID";
            data: string;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        deviceId: import("drizzle-orm/pg-core").PgColumn<{
            name: "device_id";
            tableName: "audit_logs";
            dataType: "string";
            columnType: "PgUUID";
            data: string;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        timestamp: import("drizzle-orm/pg-core").PgColumn<{
            name: "timestamp";
            tableName: "audit_logs";
            dataType: "date";
            columnType: "PgTimestamp";
            data: Date;
            driverParam: string;
            notNull: true;
            hasDefault: true;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        ipAddress: import("drizzle-orm/pg-core").PgColumn<{
            name: "ip_address";
            tableName: "audit_logs";
            dataType: "string";
            columnType: "PgVarchar";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        userAgent: import("drizzle-orm/pg-core").PgColumn<{
            name: "user_agent";
            tableName: "audit_logs";
            dataType: "string";
            columnType: "PgText";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        success: import("drizzle-orm/pg-core").PgColumn<{
            name: "success";
            tableName: "audit_logs";
            dataType: "boolean";
            columnType: "PgBoolean";
            data: boolean;
            driverParam: boolean;
            notNull: true;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        failureReason: import("drizzle-orm/pg-core").PgColumn<{
            name: "failure_reason";
            tableName: "audit_logs";
            dataType: "string";
            columnType: "PgVarchar";
            data: string;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        metadata: import("drizzle-orm/pg-core").PgColumn<{
            name: "metadata";
            tableName: "audit_logs";
            dataType: "json";
            columnType: "PgJsonb";
            data: unknown;
            driverParam: unknown;
            notNull: false;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
    };
    dialect: "pg";
}>;
export type AuditLog = typeof auditLogs.$inferSelect;
export type NewAuditLog = typeof auditLogs.$inferInsert;
export declare const recoveryCodes: import("drizzle-orm/pg-core").PgTableWithColumns<{
    name: "recovery_codes";
    schema: undefined;
    columns: {
        id: import("drizzle-orm/pg-core").PgColumn<{
            name: "id";
            tableName: "recovery_codes";
            dataType: "string";
            columnType: "PgUUID";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        userId: import("drizzle-orm/pg-core").PgColumn<{
            name: "user_id";
            tableName: "recovery_codes";
            dataType: "string";
            columnType: "PgUUID";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        codeHash: import("drizzle-orm/pg-core").PgColumn<{
            name: "code_hash";
            tableName: "recovery_codes";
            dataType: "string";
            columnType: "PgText";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        codePrefix: import("drizzle-orm/pg-core").PgColumn<{
            name: "code_prefix";
            tableName: "recovery_codes";
            dataType: "string";
            columnType: "PgVarchar";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        used: import("drizzle-orm/pg-core").PgColumn<{
            name: "used";
            tableName: "recovery_codes";
            dataType: "boolean";
            columnType: "PgBoolean";
            data: boolean;
            driverParam: boolean;
            notNull: true;
            hasDefault: true;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        usedAt: import("drizzle-orm/pg-core").PgColumn<{
            name: "used_at";
            tableName: "recovery_codes";
            dataType: "date";
            columnType: "PgTimestamp";
            data: Date;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        createdAt: import("drizzle-orm/pg-core").PgColumn<{
            name: "created_at";
            tableName: "recovery_codes";
            dataType: "date";
            columnType: "PgTimestamp";
            data: Date;
            driverParam: string;
            notNull: true;
            hasDefault: true;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        expiresAt: import("drizzle-orm/pg-core").PgColumn<{
            name: "expires_at";
            tableName: "recovery_codes";
            dataType: "date";
            columnType: "PgTimestamp";
            data: Date;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
    };
    dialect: "pg";
}>;
export type RecoveryCode = typeof recoveryCodes.$inferSelect;
export type NewRecoveryCode = typeof recoveryCodes.$inferInsert;
export declare const webauthnCredentials: import("drizzle-orm/pg-core").PgTableWithColumns<{
    name: "webauthn_credentials";
    schema: undefined;
    columns: {
        id: import("drizzle-orm/pg-core").PgColumn<{
            name: "id";
            tableName: "webauthn_credentials";
            dataType: "string";
            columnType: "PgUUID";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        userId: import("drizzle-orm/pg-core").PgColumn<{
            name: "user_id";
            tableName: "webauthn_credentials";
            dataType: "string";
            columnType: "PgUUID";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        credentialId: import("drizzle-orm/pg-core").PgColumn<{
            name: "credential_id";
            tableName: "webauthn_credentials";
            dataType: "string";
            columnType: "PgText";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        publicKey: import("drizzle-orm/pg-core").PgColumn<{
            name: "public_key";
            tableName: "webauthn_credentials";
            dataType: "string";
            columnType: "PgText";
            data: string;
            driverParam: string;
            notNull: true;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        counter: import("drizzle-orm/pg-core").PgColumn<{
            name: "counter";
            tableName: "webauthn_credentials";
            dataType: "number";
            columnType: "PgInteger";
            data: number;
            driverParam: string | number;
            notNull: true;
            hasDefault: true;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        transports: import("drizzle-orm/pg-core").PgColumn<{
            name: "transports";
            tableName: "webauthn_credentials";
            dataType: "json";
            columnType: "PgJsonb";
            data: string[];
            driverParam: unknown;
            notNull: false;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        deviceName: import("drizzle-orm/pg-core").PgColumn<{
            name: "device_name";
            tableName: "webauthn_credentials";
            dataType: "string";
            columnType: "PgVarchar";
            data: string;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        deviceType: import("drizzle-orm/pg-core").PgColumn<{
            name: "device_type";
            tableName: "webauthn_credentials";
            dataType: "string";
            columnType: "PgVarchar";
            data: string;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: [string, ...string[]];
            baseColumn: never;
        }, {}, {}>;
        createdAt: import("drizzle-orm/pg-core").PgColumn<{
            name: "created_at";
            tableName: "webauthn_credentials";
            dataType: "date";
            columnType: "PgTimestamp";
            data: Date;
            driverParam: string;
            notNull: true;
            hasDefault: true;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
        lastUsedAt: import("drizzle-orm/pg-core").PgColumn<{
            name: "last_used_at";
            tableName: "webauthn_credentials";
            dataType: "date";
            columnType: "PgTimestamp";
            data: Date;
            driverParam: string;
            notNull: false;
            hasDefault: false;
            enumValues: undefined;
            baseColumn: never;
        }, {}, {}>;
    };
    dialect: "pg";
}>;
export type WebAuthnCredential = typeof webauthnCredentials.$inferSelect;
export type NewWebAuthnCredential = typeof webauthnCredentials.$inferInsert;
export declare const encryptionKeys: any;
export type EncryptionKey = typeof encryptionKeys.$inferSelect;
export type NewEncryptionKey = typeof encryptionKeys.$inferInsert;
export declare const userRelations: import("drizzle-orm").Relations<"users", {
    sessions: import("drizzle-orm").Many<"sessions">;
    devices: import("drizzle-orm").Many<"devices">;
    folders: import("drizzle-orm").Many<"folders">;
    documents: import("drizzle-orm").Many<any>;
    auditLogs: import("drizzle-orm").Many<"audit_logs">;
    recoveryCodes: import("drizzle-orm").Many<"recovery_codes">;
    webauthnCredentials: import("drizzle-orm").Many<"webauthn_credentials">;
    encryptionKeys: import("drizzle-orm").Many<any>;
    documentVersions: import("drizzle-orm").Many<any>;
}>;
export declare const sessionRelations: import("drizzle-orm").Relations<"sessions", {
    user: import("drizzle-orm").One<"users", true>;
}>;
export declare const deviceRelations: import("drizzle-orm").Relations<"devices", {
    user: import("drizzle-orm").One<"users", true>;
}>;
export declare const folderRelations: import("drizzle-orm").Relations<"folders", {
    user: import("drizzle-orm").One<"users", true>;
    parent: import("drizzle-orm").One<"folders", false>;
    children: import("drizzle-orm").Many<"folders">;
    documents: import("drizzle-orm").Many<any>;
}>;
export declare const documentRelations: import("drizzle-orm").Relations<string, {
    user: import("drizzle-orm").One<"users", false>;
    folder: import("drizzle-orm").One<"folders", false>;
    versions: import("drizzle-orm").Many<any>;
    encryptionKey: import("drizzle-orm").One<any, false>;
}>;
export declare const documentVersionRelations: import("drizzle-orm").Relations<string, {
    document: import("drizzle-orm").One<any, false>;
    user: import("drizzle-orm").One<"users", false>;
    encryptionKey: import("drizzle-orm").One<any, false>;
}>;
export declare const auditLogRelations: import("drizzle-orm").Relations<"audit_logs", {
    user: import("drizzle-orm").One<"users", false>;
    session: import("drizzle-orm").One<"sessions", false>;
    device: import("drizzle-orm").One<"devices", false>;
}>;
export declare const recoveryCodeRelations: import("drizzle-orm").Relations<"recovery_codes", {
    user: import("drizzle-orm").One<"users", true>;
}>;
export declare const webauthnCredentialRelations: import("drizzle-orm").Relations<"webauthn_credentials", {
    user: import("drizzle-orm").One<"users", true>;
}>;
export declare const encryptionKeyRelations: import("drizzle-orm").Relations<string, {
    user: import("drizzle-orm").One<"users", false>;
    documents: import("drizzle-orm").Many<any>;
    documentVersions: import("drizzle-orm").Many<any>;
}>;
export declare const schema: {
    users: import("drizzle-orm/pg-core").PgTableWithColumns<{
        name: "users";
        schema: undefined;
        columns: {
            id: import("drizzle-orm/pg-core").PgColumn<{
                name: "id";
                tableName: "users";
                dataType: "string";
                columnType: "PgUUID";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            email: import("drizzle-orm/pg-core").PgColumn<{
                name: "email";
                tableName: "users";
                dataType: "string";
                columnType: "PgVarchar";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            passwordHash: import("drizzle-orm/pg-core").PgColumn<{
                name: "password_hash";
                tableName: "users";
                dataType: "string";
                columnType: "PgText";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            passwordSalt: import("drizzle-orm/pg-core").PgColumn<{
                name: "password_salt";
                tableName: "users";
                dataType: "string";
                columnType: "PgText";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            displayName: import("drizzle-orm/pg-core").PgColumn<{
                name: "display_name";
                tableName: "users";
                dataType: "string";
                columnType: "PgVarchar";
                data: string;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            recoveryEmail: import("drizzle-orm/pg-core").PgColumn<{
                name: "recovery_email";
                tableName: "users";
                dataType: "string";
                columnType: "PgVarchar";
                data: string;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            status: import("drizzle-orm/pg-core").PgColumn<{
                name: "status";
                tableName: "users";
                dataType: "string";
                columnType: "PgVarchar";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: true;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            mfaEnabled: import("drizzle-orm/pg-core").PgColumn<{
                name: "mfa_enabled";
                tableName: "users";
                dataType: "boolean";
                columnType: "PgBoolean";
                data: boolean;
                driverParam: boolean;
                notNull: true;
                hasDefault: true;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            mfaSecret: import("drizzle-orm/pg-core").PgColumn<{
                name: "mfa_secret";
                tableName: "users";
                dataType: "string";
                columnType: "PgText";
                data: string;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            mfaBackupCodesHash: import("drizzle-orm/pg-core").PgColumn<{
                name: "mfa_backup_codes_hash";
                tableName: "users";
                dataType: "string";
                columnType: "PgText";
                data: string;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            facialTemplateHash: import("drizzle-orm/pg-core").PgColumn<{
                name: "facial_template_hash";
                tableName: "users";
                dataType: "string";
                columnType: "PgText";
                data: string;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            failedLoginAttempts: import("drizzle-orm/pg-core").PgColumn<{
                name: "failed_login_attempts";
                tableName: "users";
                dataType: "number";
                columnType: "PgInteger";
                data: number;
                driverParam: string | number;
                notNull: true;
                hasDefault: true;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            lockedUntil: import("drizzle-orm/pg-core").PgColumn<{
                name: "locked_until";
                tableName: "users";
                dataType: "date";
                columnType: "PgTimestamp";
                data: Date;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            lastLoginAt: import("drizzle-orm/pg-core").PgColumn<{
                name: "last_login_at";
                tableName: "users";
                dataType: "date";
                columnType: "PgTimestamp";
                data: Date;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            lastPasswordChangeAt: import("drizzle-orm/pg-core").PgColumn<{
                name: "last_password_change_at";
                tableName: "users";
                dataType: "date";
                columnType: "PgTimestamp";
                data: Date;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            createdAt: import("drizzle-orm/pg-core").PgColumn<{
                name: "created_at";
                tableName: "users";
                dataType: "date";
                columnType: "PgTimestamp";
                data: Date;
                driverParam: string;
                notNull: true;
                hasDefault: true;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            updatedAt: import("drizzle-orm/pg-core").PgColumn<{
                name: "updated_at";
                tableName: "users";
                dataType: "date";
                columnType: "PgTimestamp";
                data: Date;
                driverParam: string;
                notNull: true;
                hasDefault: true;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            deletedAt: import("drizzle-orm/pg-core").PgColumn<{
                name: "deleted_at";
                tableName: "users";
                dataType: "date";
                columnType: "PgTimestamp";
                data: Date;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
        };
        dialect: "pg";
    }>;
    sessions: import("drizzle-orm/pg-core").PgTableWithColumns<{
        name: "sessions";
        schema: undefined;
        columns: {
            id: import("drizzle-orm/pg-core").PgColumn<{
                name: "id";
                tableName: "sessions";
                dataType: "string";
                columnType: "PgUUID";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            userId: import("drizzle-orm/pg-core").PgColumn<{
                name: "user_id";
                tableName: "sessions";
                dataType: "string";
                columnType: "PgUUID";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            refreshTokenHash: import("drizzle-orm/pg-core").PgColumn<{
                name: "refresh_token_hash";
                tableName: "sessions";
                dataType: "string";
                columnType: "PgText";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            refreshTokenCounter: import("drizzle-orm/pg-core").PgColumn<{
                name: "refresh_token_counter";
                tableName: "sessions";
                dataType: "number";
                columnType: "PgInteger";
                data: number;
                driverParam: string | number;
                notNull: true;
                hasDefault: true;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            expiresAt: import("drizzle-orm/pg-core").PgColumn<{
                name: "expires_at";
                tableName: "sessions";
                dataType: "date";
                columnType: "PgTimestamp";
                data: Date;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            refreshExpiresAt: import("drizzle-orm/pg-core").PgColumn<{
                name: "refresh_expires_at";
                tableName: "sessions";
                dataType: "date";
                columnType: "PgTimestamp";
                data: Date;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            revoked: import("drizzle-orm/pg-core").PgColumn<{
                name: "revoked";
                tableName: "sessions";
                dataType: "boolean";
                columnType: "PgBoolean";
                data: boolean;
                driverParam: boolean;
                notNull: true;
                hasDefault: true;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            revokedAt: import("drizzle-orm/pg-core").PgColumn<{
                name: "revoked_at";
                tableName: "sessions";
                dataType: "date";
                columnType: "PgTimestamp";
                data: Date;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            revokeReason: import("drizzle-orm/pg-core").PgColumn<{
                name: "revoke_reason";
                tableName: "sessions";
                dataType: "string";
                columnType: "PgVarchar";
                data: string;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            lastUsedAt: import("drizzle-orm/pg-core").PgColumn<{
                name: "last_used_at";
                tableName: "sessions";
                dataType: "date";
                columnType: "PgTimestamp";
                data: Date;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            ipAddress: import("drizzle-orm/pg-core").PgColumn<{
                name: "ip_address";
                tableName: "sessions";
                dataType: "string";
                columnType: "PgVarchar";
                data: string;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            userAgent: import("drizzle-orm/pg-core").PgColumn<{
                name: "user_agent";
                tableName: "sessions";
                dataType: "string";
                columnType: "PgText";
                data: string;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            createdAt: import("drizzle-orm/pg-core").PgColumn<{
                name: "created_at";
                tableName: "sessions";
                dataType: "date";
                columnType: "PgTimestamp";
                data: Date;
                driverParam: string;
                notNull: true;
                hasDefault: true;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
        };
        dialect: "pg";
    }>;
    devices: import("drizzle-orm/pg-core").PgTableWithColumns<{
        name: "devices";
        schema: undefined;
        columns: {
            id: import("drizzle-orm/pg-core").PgColumn<{
                name: "id";
                tableName: "devices";
                dataType: "string";
                columnType: "PgUUID";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            userId: import("drizzle-orm/pg-core").PgColumn<{
                name: "user_id";
                tableName: "devices";
                dataType: "string";
                columnType: "PgUUID";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            name: import("drizzle-orm/pg-core").PgColumn<{
                name: "name";
                tableName: "devices";
                dataType: "string";
                columnType: "PgVarchar";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            type: import("drizzle-orm/pg-core").PgColumn<{
                name: "type";
                tableName: "devices";
                dataType: "string";
                columnType: "PgVarchar";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            os: import("drizzle-orm/pg-core").PgColumn<{
                name: "os";
                tableName: "devices";
                dataType: "string";
                columnType: "PgVarchar";
                data: string;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            browser: import("drizzle-orm/pg-core").PgColumn<{
                name: "browser";
                tableName: "devices";
                dataType: "string";
                columnType: "PgVarchar";
                data: string;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            isTrusted: import("drizzle-orm/pg-core").PgColumn<{
                name: "is_trusted";
                tableName: "devices";
                dataType: "boolean";
                columnType: "PgBoolean";
                data: boolean;
                driverParam: boolean;
                notNull: true;
                hasDefault: true;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            trustedUntil: import("drizzle-orm/pg-core").PgColumn<{
                name: "trusted_until";
                tableName: "devices";
                dataType: "date";
                columnType: "PgTimestamp";
                data: Date;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            lastSeenAt: import("drizzle-orm/pg-core").PgColumn<{
                name: "last_seen_at";
                tableName: "devices";
                dataType: "date";
                columnType: "PgTimestamp";
                data: Date;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            ipAddress: import("drizzle-orm/pg-core").PgColumn<{
                name: "ip_address";
                tableName: "devices";
                dataType: "string";
                columnType: "PgVarchar";
                data: string;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            userAgent: import("drizzle-orm/pg-core").PgColumn<{
                name: "user_agent";
                tableName: "devices";
                dataType: "string";
                columnType: "PgText";
                data: string;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            createdAt: import("drizzle-orm/pg-core").PgColumn<{
                name: "created_at";
                tableName: "devices";
                dataType: "date";
                columnType: "PgTimestamp";
                data: Date;
                driverParam: string;
                notNull: true;
                hasDefault: true;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
        };
        dialect: "pg";
    }>;
    folders: import("drizzle-orm/pg-core").PgTableWithColumns<{
        name: "folders";
        schema: undefined;
        columns: {
            id: import("drizzle-orm/pg-core").PgColumn<{
                name: "id";
                tableName: "folders";
                dataType: "string";
                columnType: "PgUUID";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            userId: import("drizzle-orm/pg-core").PgColumn<{
                name: "user_id";
                tableName: "folders";
                dataType: "string";
                columnType: "PgUUID";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            parentId: import("drizzle-orm/pg-core").PgColumn<{
                name: "parent_id";
                tableName: "folders";
                dataType: "string";
                columnType: "PgUUID";
                data: string;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            name: import("drizzle-orm/pg-core").PgColumn<{
                name: "name";
                tableName: "folders";
                dataType: "string";
                columnType: "PgVarchar";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            description: import("drizzle-orm/pg-core").PgColumn<{
                name: "description";
                tableName: "folders";
                dataType: "string";
                columnType: "PgText";
                data: string;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            color: import("drizzle-orm/pg-core").PgColumn<{
                name: "color";
                tableName: "folders";
                dataType: "string";
                columnType: "PgVarchar";
                data: string;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            icon: import("drizzle-orm/pg-core").PgColumn<{
                name: "icon";
                tableName: "folders";
                dataType: "string";
                columnType: "PgVarchar";
                data: string;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            isSystem: import("drizzle-orm/pg-core").PgColumn<{
                name: "is_system";
                tableName: "folders";
                dataType: "boolean";
                columnType: "PgBoolean";
                data: boolean;
                driverParam: boolean;
                notNull: true;
                hasDefault: true;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            createdAt: import("drizzle-orm/pg-core").PgColumn<{
                name: "created_at";
                tableName: "folders";
                dataType: "date";
                columnType: "PgTimestamp";
                data: Date;
                driverParam: string;
                notNull: true;
                hasDefault: true;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            updatedAt: import("drizzle-orm/pg-core").PgColumn<{
                name: "updated_at";
                tableName: "folders";
                dataType: "date";
                columnType: "PgTimestamp";
                data: Date;
                driverParam: string;
                notNull: true;
                hasDefault: true;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            deletedAt: import("drizzle-orm/pg-core").PgColumn<{
                name: "deleted_at";
                tableName: "folders";
                dataType: "date";
                columnType: "PgTimestamp";
                data: Date;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
        };
        dialect: "pg";
    }>;
    documents: any;
    documentVersions: any;
    auditLogs: import("drizzle-orm/pg-core").PgTableWithColumns<{
        name: "audit_logs";
        schema: undefined;
        columns: {
            id: import("drizzle-orm/pg-core").PgColumn<{
                name: "id";
                tableName: "audit_logs";
                dataType: "string";
                columnType: "PgUUID";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            action: import("drizzle-orm/pg-core").PgColumn<{
                name: "action";
                tableName: "audit_logs";
                dataType: "string";
                columnType: "PgVarchar";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            resourceType: import("drizzle-orm/pg-core").PgColumn<{
                name: "resource_type";
                tableName: "audit_logs";
                dataType: "string";
                columnType: "PgVarchar";
                data: string;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            resourceId: import("drizzle-orm/pg-core").PgColumn<{
                name: "resource_id";
                tableName: "audit_logs";
                dataType: "string";
                columnType: "PgUUID";
                data: string;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            userId: import("drizzle-orm/pg-core").PgColumn<{
                name: "user_id";
                tableName: "audit_logs";
                dataType: "string";
                columnType: "PgUUID";
                data: string;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            sessionId: import("drizzle-orm/pg-core").PgColumn<{
                name: "session_id";
                tableName: "audit_logs";
                dataType: "string";
                columnType: "PgUUID";
                data: string;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            deviceId: import("drizzle-orm/pg-core").PgColumn<{
                name: "device_id";
                tableName: "audit_logs";
                dataType: "string";
                columnType: "PgUUID";
                data: string;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            timestamp: import("drizzle-orm/pg-core").PgColumn<{
                name: "timestamp";
                tableName: "audit_logs";
                dataType: "date";
                columnType: "PgTimestamp";
                data: Date;
                driverParam: string;
                notNull: true;
                hasDefault: true;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            ipAddress: import("drizzle-orm/pg-core").PgColumn<{
                name: "ip_address";
                tableName: "audit_logs";
                dataType: "string";
                columnType: "PgVarchar";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            userAgent: import("drizzle-orm/pg-core").PgColumn<{
                name: "user_agent";
                tableName: "audit_logs";
                dataType: "string";
                columnType: "PgText";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            success: import("drizzle-orm/pg-core").PgColumn<{
                name: "success";
                tableName: "audit_logs";
                dataType: "boolean";
                columnType: "PgBoolean";
                data: boolean;
                driverParam: boolean;
                notNull: true;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            failureReason: import("drizzle-orm/pg-core").PgColumn<{
                name: "failure_reason";
                tableName: "audit_logs";
                dataType: "string";
                columnType: "PgVarchar";
                data: string;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            metadata: import("drizzle-orm/pg-core").PgColumn<{
                name: "metadata";
                tableName: "audit_logs";
                dataType: "json";
                columnType: "PgJsonb";
                data: unknown;
                driverParam: unknown;
                notNull: false;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
        };
        dialect: "pg";
    }>;
    recoveryCodes: import("drizzle-orm/pg-core").PgTableWithColumns<{
        name: "recovery_codes";
        schema: undefined;
        columns: {
            id: import("drizzle-orm/pg-core").PgColumn<{
                name: "id";
                tableName: "recovery_codes";
                dataType: "string";
                columnType: "PgUUID";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            userId: import("drizzle-orm/pg-core").PgColumn<{
                name: "user_id";
                tableName: "recovery_codes";
                dataType: "string";
                columnType: "PgUUID";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            codeHash: import("drizzle-orm/pg-core").PgColumn<{
                name: "code_hash";
                tableName: "recovery_codes";
                dataType: "string";
                columnType: "PgText";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            codePrefix: import("drizzle-orm/pg-core").PgColumn<{
                name: "code_prefix";
                tableName: "recovery_codes";
                dataType: "string";
                columnType: "PgVarchar";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            used: import("drizzle-orm/pg-core").PgColumn<{
                name: "used";
                tableName: "recovery_codes";
                dataType: "boolean";
                columnType: "PgBoolean";
                data: boolean;
                driverParam: boolean;
                notNull: true;
                hasDefault: true;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            usedAt: import("drizzle-orm/pg-core").PgColumn<{
                name: "used_at";
                tableName: "recovery_codes";
                dataType: "date";
                columnType: "PgTimestamp";
                data: Date;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            createdAt: import("drizzle-orm/pg-core").PgColumn<{
                name: "created_at";
                tableName: "recovery_codes";
                dataType: "date";
                columnType: "PgTimestamp";
                data: Date;
                driverParam: string;
                notNull: true;
                hasDefault: true;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            expiresAt: import("drizzle-orm/pg-core").PgColumn<{
                name: "expires_at";
                tableName: "recovery_codes";
                dataType: "date";
                columnType: "PgTimestamp";
                data: Date;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
        };
        dialect: "pg";
    }>;
    webauthnCredentials: import("drizzle-orm/pg-core").PgTableWithColumns<{
        name: "webauthn_credentials";
        schema: undefined;
        columns: {
            id: import("drizzle-orm/pg-core").PgColumn<{
                name: "id";
                tableName: "webauthn_credentials";
                dataType: "string";
                columnType: "PgUUID";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            userId: import("drizzle-orm/pg-core").PgColumn<{
                name: "user_id";
                tableName: "webauthn_credentials";
                dataType: "string";
                columnType: "PgUUID";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            credentialId: import("drizzle-orm/pg-core").PgColumn<{
                name: "credential_id";
                tableName: "webauthn_credentials";
                dataType: "string";
                columnType: "PgText";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            publicKey: import("drizzle-orm/pg-core").PgColumn<{
                name: "public_key";
                tableName: "webauthn_credentials";
                dataType: "string";
                columnType: "PgText";
                data: string;
                driverParam: string;
                notNull: true;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            counter: import("drizzle-orm/pg-core").PgColumn<{
                name: "counter";
                tableName: "webauthn_credentials";
                dataType: "number";
                columnType: "PgInteger";
                data: number;
                driverParam: string | number;
                notNull: true;
                hasDefault: true;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            transports: import("drizzle-orm/pg-core").PgColumn<{
                name: "transports";
                tableName: "webauthn_credentials";
                dataType: "json";
                columnType: "PgJsonb";
                data: string[];
                driverParam: unknown;
                notNull: false;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            deviceName: import("drizzle-orm/pg-core").PgColumn<{
                name: "device_name";
                tableName: "webauthn_credentials";
                dataType: "string";
                columnType: "PgVarchar";
                data: string;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            deviceType: import("drizzle-orm/pg-core").PgColumn<{
                name: "device_type";
                tableName: "webauthn_credentials";
                dataType: "string";
                columnType: "PgVarchar";
                data: string;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: [string, ...string[]];
                baseColumn: never;
            }, {}, {}>;
            createdAt: import("drizzle-orm/pg-core").PgColumn<{
                name: "created_at";
                tableName: "webauthn_credentials";
                dataType: "date";
                columnType: "PgTimestamp";
                data: Date;
                driverParam: string;
                notNull: true;
                hasDefault: true;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
            lastUsedAt: import("drizzle-orm/pg-core").PgColumn<{
                name: "last_used_at";
                tableName: "webauthn_credentials";
                dataType: "date";
                columnType: "PgTimestamp";
                data: Date;
                driverParam: string;
                notNull: false;
                hasDefault: false;
                enumValues: undefined;
                baseColumn: never;
            }, {}, {}>;
        };
        dialect: "pg";
    }>;
    encryptionKeys: any;
};
//# sourceMappingURL=schema.d.ts.map