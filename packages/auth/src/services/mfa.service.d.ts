/**
 * Serviço de MFA (Multi-Factor Authentication)
 *
 * Responsabilidades:
 * - Setup de TOTP para usuários
 * - Verificação de códigos TOTP
 * - Gerenciamento de backup codes
 * - Auditoria de eventos MFA
 *
 * SECURITY NOTES:
 * - TOTP baseado em RFC 6238
 * - Backup codes hasheados antes de armazenar
 * - Rate limiting em verificações
 * - Janela de tempo limitada para códigos
 */
import type { MFASetupResponse, AuthAuditEvent } from '../types';
export declare function setDatabaseClient(client: any): void;
export declare const MFAService: {
    /**
     * Inicia setup de MFA para usuário
     * Retorna secret TOTP e QR code URI
     */
    initiateMFASetup(userId: string, emailAddress: string): Promise<MFASetupResponse>;
    /**
     * Verifica código TOTP durante setup
     * Se válido, habilita MFA permanentemente e gera recovery codes
     */
    verifyMFASetup(userId: string, totpCode: string, ipAddress: string, userAgent: string): Promise<{
        success: boolean;
        recoveryCodes?: string[];
        error?: any;
    }>;
    /**
     * Verifica código TOTP durante login
     */
    verifyTOTP(userId: string, totpCode: string): Promise<{
        success: boolean;
        error?: any;
    }>;
    /**
     * Usa recovery code para autenticar
     */
    useRecoveryCode(userId: string, recoveryCode: string, ipAddress: string, userAgent: string): Promise<{
        success: boolean;
        error?: any;
    }>;
    /**
     * Gera novos recovery codes (requer autenticação prévia)
     */
    regenerateRecoveryCodes(userId: string, ipAddress: string, userAgent: string): Promise<{
        success: boolean;
        recoveryCodes?: string[];
        error?: any;
    }>;
    /**
     * Desabilita MFA do usuário (operação de alto risco)
     */
    disableMFA(userId: string, password: string, ipAddress: string, userAgent: string): Promise<{
        success: boolean;
        error?: any;
    }>;
    auditLog(event: AuthAuditEvent): Promise<void>;
};
//# sourceMappingURL=mfa.service.d.ts.map