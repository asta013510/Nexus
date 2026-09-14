/**
 * Configuração da Aplicação - ZERO API
 * 
 * Carrega variáveis de ambiente com validação estrita
 * SECURITY: Validação de todos os inputs críticos na inicialização
 */

import { z } from 'zod';

// Schema de validação das variáveis de ambiente
const envSchema = z.object({
  // Geral
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.string().transform(Number).default('3000'),
  
  // Database
  DATABASE_URL: z.string().url(),
  
  // Redis
  REDIS_URL: z.string().url(),
  
  // MinIO / S3
  MINIO_ENDPOINT: z.string(),
  MINIO_ACCESS_KEY: z.string().min(1),
  MINIO_SECRET_KEY: z.string().min(1),
  MINIO_BUCKET: z.string().default('documents'),
  MINIO_USE_SSL: z.string().transform((v) => v === 'true').default('false'),
  
  // JWT
  JWT_SECRET: z.string().min(32),
  JWT_EXPIRES_IN: z.string().default('15m'),
  REFRESH_TOKEN_EXPIRES_IN: z.string().default('7d'),
  REFRESH_TOKEN_ROTATION_ENABLED: z.string().transform((v) => v === 'true').default('true'),
  
  // Criptografia
  ENCRYPTION_MASTER_KEY: z.string().length(64), // 32 bytes em hex
  
  // Segurança
  MAX_LOGIN_ATTEMPTS: z.string().transform(Number).default('5'),
  LOCKOUT_DURATION_MINUTES: z.string().transform(Number).default('15'),
  MFA_MAX_ATTEMPTS: z.string().transform(Number).default('3'),
  BIOMETRIC_MAX_ATTEMPTS: z.string().transform(Number).default('3'),
  RATE_LIMIT_WINDOW_MS: z.string().transform(Number).default('60000'),
  RATE_LIMIT_MAX_REQUESTS: z.string().transform(Number).default('100'),
  
  // CORS
  CORS_ORIGIN: z.string().url(),
  CORS_CREDENTIALS: z.string().transform((v) => v === 'true').default('true'),
  
  // Logging
  LOG_LEVEL: z.string().default('info'),
  AUDIT_LOG_ENABLED: z.string().transform((v) => v === 'true').default('true'),
  
  // WebAuthn
  WEBAUTHN_RP_NAME: z.string().default('ZERO Security Center'),
  WEBAUTHN_RP_ID: z.string(),
  WEBAUTHN_ORIGIN: z.string().url(),
});

export type EnvConfig = z.infer<typeof envSchema>;

let config: EnvConfig | null = null;

/**
 * Carrega e valida a configuração
 * SECURITY: Falha rápido se configuração inválida
 */
export function loadConfig(): EnvConfig {
  if (config) {
    return config;
  }

  const parsed = envSchema.safeParse(process.env);

  if (!parsed.success) {
    console.error('❌ CONFIGURAÇÃO INVÁLIDA:');
    console.error(parsed.error.format());
    console.error('\nVerifique seu arquivo .env');
    process.exit(1);
  }

  config = parsed.data;
  
  // Warn sobre configurações de desenvolvimento
  if (config.NODE_ENV === 'development') {
    console.warn('⚠️  RODANDO EM MODO DE DESENVOLVIMENTO');
  }

  // Validate encryption key format
  if (!/^[0-9a-f]{64}$/i.test(config.ENCRYPTION_MASTER_KEY)) {
    console.error('❌ ENCRYPTION_MASTER_KEY deve ser uma string hex de 64 caracteres (32 bytes)');
    process.exit(1);
  }

  return config;
}

/**
 * Obtém a configuração carregada
 * SECURITY: Garante que config foi inicializada
 */
export function getConfig(): EnvConfig {
  if (!config) {
    throw new Error('Configuração não inicializada. Chame loadConfig() primeiro.');
  }
  return config;
}

/**
 * Verifica se está em produção
 */
export function isProduction(): boolean {
  return getConfig().NODE_ENV === 'production';
}

/**
 * Verifica se está em desenvolvimento
 */
export function isDevelopment(): boolean {
  return getConfig().NODE_ENV === 'development';
}

/**
 * Verifica se está em teste
 */
export function isTest(): boolean {
  return getConfig().NODE_ENV === 'test';
}
