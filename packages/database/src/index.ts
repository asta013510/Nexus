/**
 * @zero/database - Módulo de Banco de Dados
 * 
 * PostgreSQL + Drizzle ORM
 * Conexão segura com pool e Row-Level Security
 */

export { schema } from './schema';
export * from './schema';

// Re-export types
export type {
  User,
  NewUser,
  Session,
  NewSession,
  Device,
  NewDevice,
  Folder,
  NewFolder,
  Document,
  NewDocument,
  DocumentVersion,
  NewDocumentVersion,
  AuditLog,
  NewAuditLog,
  RecoveryCode,
  NewRecoveryCode,
  WebAuthnCredential,
  NewWebAuthnCredential,
  EncryptionKey,
  NewEncryptionKey,
} from './schema';

// Database connection helper (será implementado na API)
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function createDatabaseClient(_connectionString: string) {
  // Implementação será feita no pacote da API
  throw new Error('Database client deve ser inicializado pela API');
}
