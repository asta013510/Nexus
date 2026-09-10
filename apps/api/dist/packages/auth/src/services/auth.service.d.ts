/**
 * Serviço de Autenticação Principal
 *
 * Responsabilidades:
 * - Registro de usuários
 * - Login com validação de credenciais
 * - Gerenciamento de tentativas e lockout
 * - Integração com MFA
 * - Auditoria de eventos
 */
import { type User as DBUser } from '@zero/database';
import type { RegisterInput, LoginInput, AuthResponse, AuthAuditEvent } from '../types';
export declare function setDatabaseClient(client: any): void;
/**
 * Registra novo usuário no sistema
 *
 * SECURITY NOTES:
 * - Email normalizado para lowercase
 * - Senha hash com Argon2id antes de armazenar
 * - Validação de força da senha
 * - Verificação de email duplicado
 * - Geração de recovery codes
 * - Auditoria do evento
 */
export declare const AuthService: {
    register(input: RegisterInput, ipAddress: string, userAgent: string): Promise<AuthResponse>;
    /**
     * Autentica usuário com email e senha
     *
     * SECURITY NOTES:
     * - Timing-safe comparison para senha
     * - Rate limiting por IP e usuário
     * - Lockout após múltiplas falhas
     * - Mensagens de erro genéricas (não revelar se email existe)
     * - Requer MFA se habilitado
     */
    login(input: LoginInput, ipAddress: string, userAgent: string): Promise<AuthResponse>;
    /**
     * Cria sessão após autenticação bem-sucedida
     */
    createSession(user: DBUser, input: LoginInput, ipAddress: string, userAgent: string): Promise<AuthResponse>;
    /**
     * Incrementa tentativas falhas e aplica lockout se necessário
     */
    incrementFailedAttempts(userId: string): Promise<void>;
    /**
     * Reset tentativas falhas após login bem-sucedido
     */
    resetFailedAttempts(userId: string): Promise<void>;
    /**
     * Detecta tipo de dispositivo a partir do user agent
     */
    detectDeviceType(userAgent: string): "desktop" | "mobile" | "tablet" | "unknown";
    /**
     * Parse user agent para extrair OS e browser
     * Implementação simplificada - usar biblioteca dedicada em produção
     */
    parseUserAgent(userAgent: string): {
        os: string;
        browser: string;
    };
    /**
     * Log de auditoria para eventos de autenticação
     */
    auditLog(event: Omit<AuthAuditEvent, "success"> & {
        success: boolean;
    }): Promise<void>;
};
//# sourceMappingURL=auth.service.d.ts.map