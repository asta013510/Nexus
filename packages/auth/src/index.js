"use strict";
/**
 * @zero/auth - Módulo de Autenticação e Gerenciamento de Sessão
 *
 * RESPONSABILIDADES:
 * - Registro de usuários com validação segura
 * - Login com verificação de senha (Argon2id)
 * - MFA TOTP obrigatório
 * - WebAuthn/Passkeys opcional
 * - Gerenciamento de sessões (JWT + refresh tokens)
 * - Rate limiting para tentativas de login
 * - Auditoria de eventos de autenticação
 *
 * PRINCÍPIOS DE SEGURANÇA:
 * - NUNCA armazenar senhas em texto puro
 * - NUNCA logar dados sensíveis
 * - SEMPRE validar no backend
 * - SEMPRE usar timing-safe comparison
 * - MFA obrigatório após registro
 * - Sessions com expiry curto (15min access, 7d refresh)
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.AUTH_CONSTANTS = exports.validateEmail = exports.validatePassword = exports.decodeJWT = exports.verifyJWT = exports.generateAuthTokens = exports.WebAuthService = exports.MFAService = exports.SessionService = exports.AuthService = void 0;
// Serviços de Autenticação
var auth_service_1 = require("./services/auth.service");
Object.defineProperty(exports, "AuthService", { enumerable: true, get: function () { return auth_service_1.AuthService; } });
var session_service_1 = require("./services/session.service");
Object.defineProperty(exports, "SessionService", { enumerable: true, get: function () { return session_service_1.SessionService; } });
var mfa_service_1 = require("./services/mfa.service");
Object.defineProperty(exports, "MFAService", { enumerable: true, get: function () { return mfa_service_1.MFAService; } });
var webauthn_service_1 = require("./services/webauthn.service");
Object.defineProperty(exports, "WebAuthService", { enumerable: true, get: function () { return webauthn_service_1.WebAuthService; } });
// Utils
var tokens_1 = require("./utils/tokens");
Object.defineProperty(exports, "generateAuthTokens", { enumerable: true, get: function () { return tokens_1.generateAuthTokens; } });
Object.defineProperty(exports, "verifyJWT", { enumerable: true, get: function () { return tokens_1.verifyJWT; } });
Object.defineProperty(exports, "decodeJWT", { enumerable: true, get: function () { return tokens_1.decodeJWT; } });
var validation_1 = require("./utils/validation");
Object.defineProperty(exports, "validatePassword", { enumerable: true, get: function () { return validation_1.validatePassword; } });
Object.defineProperty(exports, "validateEmail", { enumerable: true, get: function () { return validation_1.validateEmail; } });
// Constants
var constants_1 = require("./constants");
Object.defineProperty(exports, "AUTH_CONSTANTS", { enumerable: true, get: function () { return constants_1.AUTH_CONSTANTS; } });
//# sourceMappingURL=index.js.map