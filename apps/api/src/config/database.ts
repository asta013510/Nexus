/**
 * Configuração do Database - ZERO API
 * 
 * PostgreSQL + Drizzle ORM com conexões seguras
 * SECURITY: Pool configurado com timeouts e SSL quando em produção
 */

import { drizzle, PostgresJsDatabase } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from '@zero/database/schema';
import { getConfig, isProduction } from './env.js';

let db: PostgresJsDatabase<typeof schema> | null = null;
let sqlClient: ReturnType<typeof postgres> | null = null;

/**
 * Inicializa a conexão com o banco de dados
 * SECURITY: Configurações hardened para produção
 */
export function initDatabase(): PostgresJsDatabase<typeof schema> {
  if (db) {
    return db;
  }

  const config = getConfig();

  // Configuração do cliente PostgreSQL
  sqlClient = postgres(config.DATABASE_URL, {
    // Pool settings
    max: 20,
    idle_timeout: 30,
    connect_timeout: 10,
    
    // Production hardening
    ssl: isProduction() ? { rejectUnauthorized: true } : false,
    
    // Prepared statements
    prepare: true,
    
    // Debug em desenvolvimento
    debug: process.env.NODE_ENV === 'development' 
      ? (connection, query, params, types) => {
          console.log('[DB Query]', connection, query, params);
        }
      : undefined,
  });

  // Criar instância do Drizzle ORM
  db = drizzle(sqlClient, { schema });

  console.log('✅ Database conectado');

  return db;
}

/**
 * Obtém a instância do database
 * SECURITY: Garante que database foi inicializado
 */
export function getDatabase(): PostgresJsDatabase<typeof schema> {
  if (!db) {
    throw new Error('Database não inicializado. Chame initDatabase() primeiro.');
  }
  return db;
}

/**
 * Fecha a conexão com o banco (para shutdown graceful)
 */
export async function closeDatabase(): Promise<void> {
  if (sqlClient) {
    await sqlClient.end();
    sqlClient = null;
    db = null;
    console.log('🔒 Database desconectado');
  }
}

/**
 * Executa health check no database
 */
export async function checkDatabaseHealth(): Promise<boolean> {
  try {
    const database = getDatabase();
    const result = await database.execute('SELECT 1');
    return result.length > 0;
  } catch (error) {
    console.error('❌ Database health check failed:', error);
    return false;
  }
}

export { schema };
