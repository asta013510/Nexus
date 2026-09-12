/**
 * Serviço WebAuthn/Passkeys (Placeholder)
 *
 * NOTA: Esta é uma implementação inicial/planning.
 * WebAuthn completo requer:
 * - Integração com @simplewebauthn/server
 * - Geração de challenges criptográficas
 * - Validação de attestation/assertion responses
 * - Armazenamento seguro de credential IDs e public keys
 *
 * SECURITY NOTES:
 * - Usar apenas como fator ADICIONAL, nunca único
 * - Requerer MFA TOTP como fallback
 * - Validar origem (origin) das requisições
 * - Prevenir ataques de replay com challenges únicas
 * - Rate limiting agressivo
 */
import type { AuthAuditEvent } from '../types';
export declare function setDatabaseClient(client: any): void;
export declare const WebAuthService: {
    /**
     * NOT PRODUCTION READY
     *
     * Inicia registro de nova credencial WebAuthn
     * Retorna options para navigator.credentials.create()
     */
    startRegistration(userId: string, deviceName: string): Promise<{
        success: boolean;
        challenge?: string;
        publicKeyOptions?: any;
        error?: any;
    }>;
    /**
     * NOT PRODUCTION READY
     *
     * Completa registro de credencial WebAuthn
     * Valida response do navegador e armazena credencial
     */
    completeRegistration(userId: string, credentialResponse: any, ipAddress: string, userAgent: string): Promise<{
        success: boolean;
        error?: any;
    }>;
    /**
     * NOT PRODUCTION READY
     *
     * Inicia autenticação com WebAuthn
     * Retorna options para navigator.credentials.get()
     */
    startAuthentication(): Promise<{
        success: boolean;
        challenge?: string;
        publicKeyOptions?: any;
        error?: any;
    }>;
    /**
     * NOT PRODUCTION READY
     *
     * Completa autenticação WebAuthn
     * Valida assertion response e cria sessão se válido
     */
    completeAuthentication(credentialResponse: any, ipAddress: string, userAgent: string): Promise<{
        success: boolean;
        session?: any;
        error?: any;
    }>;
    /**
     * Lista credenciais WebAuthn registradas pelo usuário
     */
    listCredentials(userId: string): Promise<{
        success: boolean;
        credentials?: any[];
        error?: any;
    }>;
    /**
     * Remove credencial WebAuthn
     */
    removeCredential(credentialId: string, userId: string, ipAddress: string, userAgent: string): Promise<{
        success: boolean;
        error?: any;
    }>;
    auditLog(event: AuthAuditEvent): Promise<void>;
};
//# sourceMappingURL=webauthn.service.d.ts.map