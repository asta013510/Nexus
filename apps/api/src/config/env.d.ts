/**
 * Configuração da Aplicação - ZERO API
 *
 * Carrega variáveis de ambiente com validação estrita
 * SECURITY: Validação de todos os inputs críticos na inicialização
 */
import { z } from 'zod';
declare const envSchema: z.ZodObject<{
    NODE_ENV: z.ZodDefault<z.ZodEnum<["development", "production", "test"]>>;
    PORT: z.ZodDefault<z.ZodEffects<z.ZodString, number, string>>;
    DATABASE_URL: z.ZodString;
    REDIS_URL: z.ZodString;
    MINIO_ENDPOINT: z.ZodString;
    MINIO_ACCESS_KEY: z.ZodString;
    MINIO_SECRET_KEY: z.ZodString;
    MINIO_BUCKET: z.ZodDefault<z.ZodString>;
    MINIO_USE_SSL: z.ZodDefault<z.ZodEffects<z.ZodString, boolean, string>>;
    JWT_SECRET: z.ZodString;
    JWT_EXPIRES_IN: z.ZodDefault<z.ZodString>;
    REFRESH_TOKEN_EXPIRES_IN: z.ZodDefault<z.ZodString>;
    REFRESH_TOKEN_ROTATION_ENABLED: z.ZodDefault<z.ZodEffects<z.ZodString, boolean, string>>;
    ENCRYPTION_MASTER_KEY: z.ZodString;
    MAX_LOGIN_ATTEMPTS: z.ZodDefault<z.ZodEffects<z.ZodString, number, string>>;
    LOCKOUT_DURATION_MINUTES: z.ZodDefault<z.ZodEffects<z.ZodString, number, string>>;
    MFA_MAX_ATTEMPTS: z.ZodDefault<z.ZodEffects<z.ZodString, number, string>>;
    BIOMETRIC_MAX_ATTEMPTS: z.ZodDefault<z.ZodEffects<z.ZodString, number, string>>;
    RATE_LIMIT_WINDOW_MS: z.ZodDefault<z.ZodEffects<z.ZodString, number, string>>;
    RATE_LIMIT_MAX_REQUESTS: z.ZodDefault<z.ZodEffects<z.ZodString, number, string>>;
    CORS_ORIGIN: z.ZodString;
    CORS_CREDENTIALS: z.ZodDefault<z.ZodEffects<z.ZodString, boolean, string>>;
    LOG_LEVEL: z.ZodDefault<z.ZodString>;
    AUDIT_LOG_ENABLED: z.ZodDefault<z.ZodEffects<z.ZodString, boolean, string>>;
    WEBAUTHN_RP_NAME: z.ZodDefault<z.ZodString>;
    WEBAUTHN_RP_ID: z.ZodString;
    WEBAUTHN_ORIGIN: z.ZodString;
}, "strip", z.ZodTypeAny, {
    JWT_SECRET: string;
    NODE_ENV: "development" | "production" | "test";
    PORT: number;
    DATABASE_URL: string;
    REDIS_URL: string;
    MINIO_ENDPOINT: string;
    MINIO_ACCESS_KEY: string;
    MINIO_SECRET_KEY: string;
    MINIO_BUCKET: string;
    MINIO_USE_SSL: boolean;
    JWT_EXPIRES_IN: string;
    REFRESH_TOKEN_EXPIRES_IN: string;
    REFRESH_TOKEN_ROTATION_ENABLED: boolean;
    ENCRYPTION_MASTER_KEY: string;
    MAX_LOGIN_ATTEMPTS: number;
    LOCKOUT_DURATION_MINUTES: number;
    MFA_MAX_ATTEMPTS: number;
    BIOMETRIC_MAX_ATTEMPTS: number;
    RATE_LIMIT_WINDOW_MS: number;
    RATE_LIMIT_MAX_REQUESTS: number;
    CORS_ORIGIN: string;
    CORS_CREDENTIALS: boolean;
    LOG_LEVEL: string;
    AUDIT_LOG_ENABLED: boolean;
    WEBAUTHN_RP_NAME: string;
    WEBAUTHN_RP_ID: string;
    WEBAUTHN_ORIGIN: string;
}, {
    JWT_SECRET: string;
    DATABASE_URL: string;
    REDIS_URL: string;
    MINIO_ENDPOINT: string;
    MINIO_ACCESS_KEY: string;
    MINIO_SECRET_KEY: string;
    ENCRYPTION_MASTER_KEY: string;
    CORS_ORIGIN: string;
    WEBAUTHN_RP_ID: string;
    WEBAUTHN_ORIGIN: string;
    NODE_ENV?: "development" | "production" | "test" | undefined;
    PORT?: string | undefined;
    MINIO_BUCKET?: string | undefined;
    MINIO_USE_SSL?: string | undefined;
    JWT_EXPIRES_IN?: string | undefined;
    REFRESH_TOKEN_EXPIRES_IN?: string | undefined;
    REFRESH_TOKEN_ROTATION_ENABLED?: string | undefined;
    MAX_LOGIN_ATTEMPTS?: string | undefined;
    LOCKOUT_DURATION_MINUTES?: string | undefined;
    MFA_MAX_ATTEMPTS?: string | undefined;
    BIOMETRIC_MAX_ATTEMPTS?: string | undefined;
    RATE_LIMIT_WINDOW_MS?: string | undefined;
    RATE_LIMIT_MAX_REQUESTS?: string | undefined;
    CORS_CREDENTIALS?: string | undefined;
    LOG_LEVEL?: string | undefined;
    AUDIT_LOG_ENABLED?: string | undefined;
    WEBAUTHN_RP_NAME?: string | undefined;
}>;
export type EnvConfig = z.infer<typeof envSchema>;
/**
 * Carrega e valida a configuração
 * SECURITY: Falha rápido se configuração inválida
 */
export declare function loadConfig(): EnvConfig;
/**
 * Obtém a configuração carregada
 * SECURITY: Garante que config foi inicializada
 */
export declare function getConfig(): EnvConfig;
/**
 * Verifica se está em produção
 */
export declare function isProduction(): boolean;
/**
 * Verifica se está em desenvolvimento
 */
export declare function isDevelopment(): boolean;
/**
 * Verifica se está em teste
 */
export declare function isTest(): boolean;
export {};
//# sourceMappingURL=env.d.ts.map