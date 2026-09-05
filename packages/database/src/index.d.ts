/**
 * @zero/database - Módulo de Banco de Dados
 *
 * PostgreSQL + Drizzle ORM
 * Conexão segura com pool e Row-Level Security
 */
export { schema } from './schema';
export * from './schema';
export type { User, NewUser, Session, NewSession, Device, NewDevice, Folder, NewFolder, Document, NewDocument, DocumentVersion, NewDocumentVersion, AuditLog, NewAuditLog, RecoveryCode, NewRecoveryCode, WebAuthnCredential, NewWebAuthnCredential, EncryptionKey, NewEncryptionKey, } from './schema';
export declare function createDatabaseClient(connectionString: string): void;
//# sourceMappingURL=index.d.ts.map