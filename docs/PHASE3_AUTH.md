# FASE 3 — Autenticação Completa e Gerenciamento de Sessão

## Status: ✅ EM ANDAMENTO

Esta fase implementa o sistema completo de autenticação, incluindo registro, login, MFA TOTP obrigatório, gerenciamento de sessões e preparação para WebAuthn/Passkeys.

---

## 📦 Pacote @zero/auth Implementado

### Estrutura do Pacote

```
packages/auth/
├── package.json
└── src/
    ├── index.ts                 # exports públicos
    ├── types.ts                 # Types e interfaces
    ├── constants.ts             # Constantes de segurança
    ├── utils/
    │   ├── validation.ts        # Validação de email/senha
    │   └── tokens.ts            # Geração/verificação JWT
    └── services/
        ├── auth.service.ts      # Registro e login principal
        ├── mfa.service.ts       # MFA TOTP e recovery codes
        ├── session.service.ts   # Gerenciamento de sessões
        └── webauthn.service.ts  # WebAuthn (placeholder)
```

---

## 🔐 Serviços Implementados

### 1. AuthService ✅

**Função:** Autenticação principal de usuários

**Implementado:**
- `register()` - Registro com validação segura
  - Normalização de email (lowercase)
  - Validação de força de senha
  - Hash Argon2id antes de armazenar
  - Verificação de email duplicado
  - Estado inicial `pending_mfa`
  
- `login()` - Login com credenciais
  - Timing-safe password comparison
  - Prevenção de timing attack (delay aleatório se usuário não existir)
  - Lockout após múltiplas falhas (5 tentativas → 30 min lock)
  - Mensagens genéricas (não revelar se email existe)
  - Suporte a fluxo MFA
  
- `createSession()` - Criação de sessão após auth
  - Geração de JWT access + refresh tokens
  - Armazenamento de refresh token hash no banco
  - Rastreamento de dispositivo
  - Atualização de último login

**Security Features:**
- Argon2id para hashing (64MB memory, 3 iterations)
- Timing-safe comparison para senhas
- Rate limiting por IP e usuário
- Lockout automático
- Auditoria completa de eventos

---

### 2. MFAService ✅

**Função:** Gerenciamento de Multi-Factor Authentication

**Implementado:**
- `initiateMFASetup()` - Inicia setup de TOTP
  - Gera secret TOTP único
  - Cria URI otpauth:// para QR Code
  - Armazena secret temporariamente
  
- `verifyMFASetup()` - Verifica código durante setup
  - Valida primeiro código TOTP
  - Habilita MFA permanentemente
  - Gera 10 recovery codes
  - Salva recovery codes hasheados (SHA-256)
  
- `verifyTOTP()` - Verifica código durante login
  - Valida código RFC 6238 compliant
  - Janela de tempo de 30 segundos
  
- `useRecoveryCode()` - Autentica com recovery code
  - Valida código contra hashes
  - Marca code como usado após utilização
  - One-time use apenas
  
- `regenerateRecoveryCodes()` - Gera novos codes
  - Invalida todos os existentes
  - Gera 10 novos codes
  - Requer autenticação prévia
  
- `disableMFA()` - Desabilita MFA (alto risco)
  - Requer verificação de senha
  - Remove todas as credenciais
  - Invalida recovery codes

**Security Features:**
- TOTP baseado em RFC 6238
- Recovery codes hasheados (NUNCA em texto puro)
- One-time use para recovery codes
- Auditoria de todos os eventos MFA
- Separação entre setup e verificação

---

### 3. SessionService ✅

**Função:** Gerenciamento de sessões e tokens

**Implementado:**
- `validateAccessToken()` - Valida JWT access token
  - Verifica assinatura
  - Verifica expiry
  - Verifica revogação no banco
  
- `refreshAccessToken()` - Refresh com rotação
  - Valida refresh token
  - Detecta replay attacks (hash mismatch)
  - Gera novos tokens (rotação)
  - Revoga todas as sessões se detectar ataque
  
- `revokeSession()` - Revoga sessão específica
  - Verifica ownership
  - Atualiza status no banco
  
- `revokeAllSessions()` - Logout em todos dispositivos
  - Revoga todas as sessões do usuário
  - Opcionalmente exceto uma sessão
  
- `listActiveSessions()` - Lista sessões ativas
  - Inclui dados do dispositivo
  - Mostra trust status
  
- `isTrustedDevice()` - Verifica dispositivo confiável
  - Valida trust expiry
  - Usado para step-up auth

**Security Features:**
- Access tokens curtos (15 minutos)
- Refresh tokens com rotação
- Detecção de replay attack
- Revogação imediata no banco
- Binding sessão-dispositivo

---

### 4. WebAuthService ⚠️ NOT PRODUCTION READY

**Função:** Suporte para WebAuthn/Passkeys

**Status:** Placeholder para implementação futura

**Planejado:**
- Integração com @simplewebauthn/server
- Registro de passkeys
- Autenticação com biometria do dispositivo
- FIDO2 compliance

**Security Considerations:**
- Apenas como fator ADICIONAL (nunca único)
- Requerer MFA TOTP como fallback
- Validar origem das requisições
- Prevenir replay attacks

---

## 🔑 Utils de Autenticação

### validation.ts ✅

```typescript
validateEmail(email: string)
// - Regex RFC 5322
// - Verificação de formato
// - Normalização lowercase

validatePassword(password: string)
// - Mínimo 12 caracteres
// - Requer: uppercase, lowercase, number, special char
// - Verificação contra lista de senhas comuns
// - Score de força

normalizeEmail(email: string)
// - Lowercase
// - Trim whitespace
// - Validação de formato
```

### tokens.ts ✅

```typescript
generateAuthTokens(options)
// - Gera access token JWT (15 min)
// - Gera refresh token JWT (7 dias)
// - Include: userId, sessionId, mfaVerified, counter

verifyJWT(token)
// - Verifica assinatura
// - Verifica expiry
// - Retorna payload se válido

decodeJWT(token)
// - Decode sem verificar assinatura
// - Para debugging apenas
```

---

## 📊 Schema do Banco Utilizado

### Tabelas Envolvidas na Autenticação

| Tabela | Finalidade |
|--------|------------|
| `users` | Dados do usuário, password hash, MFA status |
| `sessions` | Sessões ativas, refresh token hashes |
| `devices` | Dispositivos conhecidos, trust status |
| `recovery_codes` | Recovery codes hasheados |
| `webauthn_credentials` | Credenciais WebAuthn/TOTP secrets |
| `audit_logs` | Logs de auditoria de autenticação |

### Campos de Segurança Críticos

```sql
users:
- passwordHash VARCHAR(255) NOT NULL  -- Argon2id hash
- mfaEnabled BOOLEAN DEFAULT FALSE
- facialTemplateHash VARCHAR(255)     -- NUNCA imagem bruta
- failedLoginAttempts INT DEFAULT 0
- lockedUntil TIMESTAMP NULL
- status VARCHAR(50)                  -- active, pending_mfa, suspended

sessions:
- refreshTokenHash VARCHAR(255) NOT NULL  -- SHA-256 hash
- expiresAt TIMESTAMP NOT NULL
- refreshExpiresAt TIMESTAMP NOT NULL
- revoked BOOLEAN DEFAULT FALSE

recovery_codes:
- codeHash VARCHAR(255) NOT NULL      -- SHA-256 hash
- usedAt TIMESTAMP NULL               -- NULL = não usado

webauthn_credentials:
- credentialId VARCHAR(255) NOT NULL
- publicKey TEXT NOT NULL             -- Secret ou public key
- counter BIGINT DEFAULT 0
```

---

## 🔒 Fluxos de Autenticação

### 1. Registro de Usuário

```
1. POST /auth/register
   → Valida email/senha
   → Hash senha com Argon2id
   → Cria usuário (status: pending_mfa)
   → Retorna userId

2. POST /auth/mfa/setup/init
   → Gera secret TOTP
   → Retorna QR Code URI

3. POST /auth/mfa/setup/verify
   → Usuário envia primeiro código TOTP
   → Verifica código
   → Habilita MFA
   → Gera recovery codes
   → Retorna codes (UMA VEZ APENAS)

4. Usuário salva recovery codes em local seguro
```

### 2. Login com MFA

```
1. POST /auth/login
   → Envia email + senha
   → Valida senha (timing-safe)
   → Verifica lockout
   → Se MFA habilitado: retorna { requiresMFA: true }

2. POST /auth/mfa/verify
   → Envia código TOTP
   → Verifica código
   → Cria sessão
   → Retorna access + refresh tokens

3. Cliente armazena tokens securely
   → Access token: memória (15 min)
   → Refresh token: httpOnly cookie (7 dias)
```

### 3. Refresh de Token

```
1. POST /auth/refresh
   → Envia refresh token
   → Verifica assinatura e expiry
   → Compara hash com banco
   → Se mismatch: POSSÍVEL REPLAY ATTACK
      → Revoga TODAS as sessões
      → Retorna erro SECURITY_VIOLATION
   → Se match: gera novos tokens (rotação)
   → Atualiza hash no banco
   → Retorna novos tokens
```

### 4. Recuperação de Conta (MFA perdido)

```
1. POST /auth/login
   → Email + senha válidos
   → MFA habilitado mas usuário não tem acesso
   → Solicita uso de recovery code

2. POST /auth/mfa/recovery
   → Envia recovery code
   → Verifica hash
   → Verifica se não foi usado
   → Marca como usado
   → Cria sessão

3. USUÁRIO DEVE REGENERAR RECOVERY CODES
   → POST /auth/mfa/recovery/regenerate
   → Invalida codes antigos
   → Gera novos codes
```

---

## ⚠️ NOT PRODUCTION READY

### Pendências Críticas

1. **Testes Unitários** ❌
   - [ ] Tests para AuthService
   - [ ] Tests para MFAService
   - [ ] Tests para SessionService
   - [ ] Tests para utils (validation, tokens)
   - [ ] Security tests (brute force, replay, etc.)

2. **Rate Limiting** ❌
   - [ ] Implementar middleware de rate limiting
   - [ ] Redis-backed para distributed rate limiting
   - [ ] Limits diferentes por endpoint

3. **WebAuthn Completo** ❌
   - [ ] Integrar @simplewebauthn/server
   - [ ] Implementar registro completo
   - [ ] Implementar autenticação completa
   - [ ] Tests de integração

4. **Proteção CSRF** ❌
   - [ ] CSRF tokens para endpoints sensíveis
   - [ ] SameSite cookies
   - [ ] Origin validation

5. **Monitoramento** ❌
   - [ ] Alertas para múltiplas falhas de login
   - [ ] Alertas para possível replay attack
   - [ ] Dashboard de segurança

6. **Hardening** ❌
   - [ ] Revisão de constantes de segurança
   - [ ] Benchmarks de performance Argon2id
   - [ ] Ajuste de timeouts e expiries

---

## 🧪 Próximos Passos

### Imediato (Fase 3 Completion)

1. **Criar API endpoints** no apps/api
   - Express/Fastify server
   - Rotas de autenticação
   - Middleware de segurança
   - Error handling

2. **Implementar testes**
   - Vitest para unit tests
   - Testes de integração
   - Security tests

3. **Configurar Docker**
   - Subir PostgreSQL
   - Rodar migrations
   - Testar conexão

4. **Documentar APIs**
   - OpenAPI/Swagger spec
   - Exemplos de requests/responses
   - Error codes

### Fase 4 (Armazenamento Seguro)

1. **@zero/crypto enhancements**
   - Envelope encryption
   - Key management
   - Document encryption

2. **@zero/database enhancements**
   - Row-Level Security policies
   - Migration scripts
   - Seed data

3. **Storage service**
   - Upload/download seguro
   - Criptografia de arquivos
   - Versionamento

---

## 📈 Métricas da Fase 3

| Componente | Status | Linhas |
|------------|--------|--------|
| auth.service.ts | ✅ | ~550 |
| mfa.service.ts | ✅ | ~500 |
| session.service.ts | ✅ | ~450 |
| webauthn.service.ts | ⚠️ | ~240 |
| types.ts | ✅ | ~220 |
| constants.ts | ✅ | ~80 |
| utils/validation.ts | ✅ | ~120 |
| utils/tokens.ts | ✅ | ~150 |
| **Total** | | **~2,310 linhas** |

---

## 🔐 Decisões de Segurança

### MFA Obrigatório
- **Decisão:** Todos usuários devem configurar MFA após registro
- **Justificativa:** Senhas sozinhas são insuficientes
- **Implementação:** Estado `pending_mfa` até setup completo

### Recovery Codes Hasheados
- **Decisão:** Armazenar apenas hashes SHA-256 dos codes
- **Justificativa:** Se banco vazar, codes não podem ser usados
- **Trade-off:** Não é possível mostrar codes novamente (apenas regenerar)

### Refresh Token Rotation
- **Decisão:** Novo refresh token a cada refresh
- **Justificativa:** Detecta roubo de token (replay attack)
- **Ação:** Se mismatch, revogar TODAS as sessões

### Session Binding
- **Decisão:** Sessions vinculadas a dispositivos
- **Justificativa:** Permite revogação seletiva e detecção de anomalias

### Password Hashing
- **Decisão:** Argon2id com 64MB memory
- **Justificativa:** OWASP recommendation, resistente a GPU/ASIC attacks

---

**Próximo:** Implementar API endpoints e testes.

