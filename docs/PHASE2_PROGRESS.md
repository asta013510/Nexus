# FASE 2 — Setup do Projeto e Infraestrutura

## Status: ✅ COMPLETO

Esta fase estabeleceu a base do monorepo, configuração de desenvolvimento e infraestrutura Docker.

---

## 📦 Estrutura do Monorepo Criada

```
ZERO/
├── package.json                 # Root package com workspaces
├── tsconfig.json                # TypeScript config compartilhada
├── .eslintrc.json               # ESLint com plugin security
├── .prettierrc                  # Prettier config
├── .gitignore                   # Git ignore para secrets e builds
│
├── apps/
│   ├── api/                     # Backend API (próxima fase)
│   └── web/                     # Frontend Web (fase posterior)
│
├── packages/
│   ├── shared/                  # Tipos e utilitários compartilhados ✅
│   │   ├── package.json
│   │   └── src/index.ts         # Typescript types, constants, utils
│   │
│   ├── crypto/                  # Operações criptográficas ✅
│   │   ├── package.json
│   │   └── src/index.ts         # Argon2id, AES-GCM, TOTP, hashing
│   │
│   ├── database/                # Schema e acesso ao banco ✅
│   │   ├── package.json
│   │   └── src/
│   │       ├── index.ts
│   │       └── schema.ts        # Drizzle ORM schema completo
│   │
│   ├── auth/                    # Autenticação (próxima fase)
│   └── security/                # Segurança (rate limiting, etc.)
│
├── infrastructure/
│   ├── docker-compose.yml       # PostgreSQL, Redis, MinIO ✅
│   └── .env.example             # Template de environment vars ✅
│
├── tests/
│   ├── unit/                    # Testes unitários
│   └── e2e/                     # Testes end-to-end
│
└── docs/
    ├── FOUNDATION.md            # Decisões fundamentais ✅
    ├── threat-model.md          # Threat model STRIDE ✅
    ├── architecture.md          # Arquitetura detalhada ✅
    ├── security.md              # Políticas de segurança ✅
    ├── recovery.md              # Recuperação e backup ✅
    └── PHASE2_PROGRESS.md       # Este arquivo
```

---

## 📦 Pacotes Implementados

### @zero/shared ✅
**Função:** Tipos TypeScript e constantes compartilhadas

**Implementado:**
- Types: `User`, `Session`, `Device`, `Document`, `Folder`, `AuditLog`, `RecoveryCode`
- Enums: `UserStatus`, `DocumentStatus`, `AuditAction`, `ResourceType`
- Constants: `SECURITY_CONSTANTS` (Argon2 params, session expiry, file limits)
- Utils: `generateUUID`, `isValidUUID`, `sanitizeFilename`, `isMimeTypeAllowed`

**Segurança:**
- Nenhum dado sensível armazenado
- Apenas tipos e funções stateless

---

### @zero/crypto ✅
**Função:** Primitivas criptográficas auditadas

**Implementado:**
- **Hashing:** SHA-256, HMAC-SHA256
- **Key Derivation:** Argon2id (OWASP recomendado)
- **Encryption:** AES-256-GCM via Web Crypto API + fallback XSalsa20-Poly1305
- **TOTP:** RFC 6238 compliant para MFA
- **Utils:** Base64 encoding, secure compare (timing-safe)

**Algoritmos Aprovados:**
| Operação | Algoritmo | Biblioteca |
|----------|-----------|------------|
| Hash de Senha | Argon2id | @noble/hashes |
| Hash de Dados | SHA-256 | @noble/hashes |
| Encription | AES-256-GCM | Web Crypto API |
| MAC | HMAC-SHA256 | @noble/hashes |
| TOTP | RFC 6238 | Implementação própria com @noble/hashes |

**NOT PRODUCTION READY:**
- [ ] Tests unitários para todas as funções crypto
- [ ] Benchmarks de performance
- [ ] Key rotation implementation completa
- [ ] Hardware Security Module (HSM) integration

---

### @zero/database ✅
**Função:** Schema do banco e tipos Drizzle ORM

**Implementado:**
- **11 tabelas:** users, sessions, devices, folders, documents, document_versions, audit_logs, recovery_codes, webauthn_credentials, encryption_keys
- **RLS ready:** Schema preparado para Row-Level Security policies
- **Indexes estratégicos:** Para queries comuns e constraints de unicidade
- **Soft delete:** Documents com `deletedAt` para recuperação
- **Versionamento:** Document versions table para histórico

**Security Features no Schema:**
- UUIDs para todos os IDs (não sequenciais)
- Password hashes NUNCA expostos em selects normais
- Facial template hash (NUNCA imagem bruta)
- Recovery codes hasheados
- Refresh tokens hasheados
- Encryption keys wrapped (envelope encryption)

**NOT PRODUCTION READY:**
- [ ] Migration files gerados
- [ ] RLS policies implementadas no banco
- [ ] Seed scripts para desenvolvimento
- [ ] Backup/restore scripts

---

## 🐳 Infraestrutura Docker

### Serviços Configurados:

| Serviço | Versão | Porta | Finalidade |
|---------|--------|-------|------------|
| PostgreSQL | 16-alpine | 5432 | Banco principal |
| Redis | 7-alpine | 6379 | Cache, rate limiting, sessões |
| MinIO | latest | 9000/9001 | S3-compatible object storage |

### Configurações de Segurança:
- SCRAM-SHA-256 authentication no PostgreSQL
- WAL level replica para Point-in-Time Recovery
- Health checks em todos os serviços
- Networks isolados
- Memory limits definidos
- Volumes persistentes

### NOT PRODUCTION READY:
- [ ] Secrets via Docker Secrets (atualmente env vars)
- [ ] TLS/SSL entre containers
- [ ] Network policies restritivas
- [ ] Audit logging do Docker
- [ ] Resource quotas em produção

---

## 🔧 Configurações de Desenvolvimento

### TypeScript ✅
- Strict mode habilitado
- ModuleResolution: NodeNext
- Path aliases: `@zero/*`
- No implicit any
- Exact optional property types

### ESLint ✅
- Plugin security habilitado
- Regras contra eval, timing attacks, injection
- TypeScript strict rules

### Prettier ✅
- Single quotes
- Semicolons obrigatórios
- Print width: 100

---

## 📋 Próximo: FASE 3

A Fase 3 implementará autenticação completa:

1. **@zero/auth package**
   - Registro de usuário
   - Login com senha + Argon2id
   - MFA TOTP obrigatório
   - WebAuthn/Passkeys opcional
   - Session management (JWT + refresh)

2. **API endpoints**
   - POST /auth/register
   - POST /auth/login
   - POST /auth/logout
   - POST /auth/refresh
   - POST /auth/mfa/enable
   - POST /auth/mfa/verify

3. **Middleware de segurança**
   - Rate limiting
   - CSRF protection
   - CORS configuration
   - Helmet headers

4. **Testes**
   - Unit tests para auth logic
   - Integration tests para endpoints
   - Security tests (brute force, etc.)

---

## ⚠️ Avisos Importantes

### Secrets Management
- `.env.example` criado com placeholders
- **NUNCA** commitar `.env` real
- Em produção: usar Docker Secrets ou Vault

### Criptografia
- Implementações usam bibliotecas auditadas (@noble/hashes, tweetnacl)
- **NÃO** use em produção sem testes completos
- Key management ainda não implementado completamente

### Database
- Schema definido mas migrations não geradas
- RLS policies precisam ser escritas
- Índices de auditoria precisam de manutenção

---

## 📊 Métricas da Fase

| Item | Status | Linhas de Código |
|------|--------|------------------|
| package.json root | ✅ | 50 |
| tsconfig.json | ✅ | 31 |
| .eslintrc.json | ✅ | 35 |
| @zero/shared | ✅ | 280 |
| @zero/crypto | ✅ | 450 |
| @zero/database schema | ✅ | 520 |
| docker-compose.yml | ✅ | 130 |
| .env.example | ✅ | 80 |
| **Total** | | **~1,576 linhas** |

---

**Próximo comando:** Instalar dependências e iniciar setup dos pacotes de autenticação.

