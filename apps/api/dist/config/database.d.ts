/**
 * Configuração do Database - ZERO API
 *
 * PostgreSQL + Drizzle ORM com conexões seguras
 * SECURITY: Pool configurado com timeouts e SSL quando em produção
 */
import { PostgresJsDatabase } from 'drizzle-orm/postgres-js';
import { schema } from '@zero/database';
/**
 * Inicializa a conexão com o banco de dados
 * SECURITY: Configurações hardened para produção
 */
export declare function initDatabase(): PostgresJsDatabase<typeof schema>;
/**
 * Obtém a instância do database
 * SECURITY: Garante que database foi inicializado
 */
export declare function getDatabase(): PostgresJsDatabase<typeof schema>;
/**
 * Fecha a conexão com o banco (para shutdown graceful)
 */
export declare function closeDatabase(): Promise<void>;
/**
 * Executa health check no database
 */
export declare function checkDatabaseHealth(): Promise<boolean>;
export { schema };
//# sourceMappingURL=database.d.ts.map