# ZERO — Architecture Document

## 1. Visão Geral

Este documento descreve a arquitetura do sistema ZERO, uma central de segurança pessoal para armazenamento e gerenciamento de documentos críticos.

A arquitetura segue princípios de **Zero Trust**, **Defense in Depth**, **Secure by Design** e **Least Privilege**.

---

## 2. Stack Tecnológico

### 2.1. Análise de Alternativas

| Componente | Opção A | Opção B | Opção C | Escolha | Justificativa |
|------------|---------|---------|---------|---------|---------------|
| **Frontend** | React + Next.js | Vue + Nuxt | Svelte + SvelteKit | **Next.js + React** | Ecossistema maduro, SSR/SSG, ampla adoção, TypeScript nativo |
| **Backend** | Node.js + TypeScript | Go | Python + FastAPI | **Node.js + TypeScript** | Tipagem forte, ecossistema rico, mesma linguagem no fullstack, performance adequada |
| **Banco de Dados** | PostgreSQL | MySQL | CockroachDB | **PostgreSQL** | ACID, Row-Level Security, extensions (pgcrypto), maturidade |
| **Cache/Sessões** | Redis | Memcached | etcd | **Redis** | Persistência opcional, estruturas ricas, pub/sub para eventos |
| **Object Storage** | AWS S3 | MinIO | Cloudflare R2 | **S3-Compatible** | Padrão da indústria, criptografia server-side, versionamento |
| **Autenticação** | WebAuthn + JWT | OAuth2 puro | Session-based | **WebAuthn + JWT** | Passwordless opcional, MFA nativo, stateless quando possível |
| **Criptografia** | libsodium | Web Crypto API | OpenSSL | **libsodium + Web Crypto** | APIs seguras, algoritmos modernos, auditadas |
| **Containerização** | Docker | Podman | containerd | **Docker** | Maturidade, ecossistema, documentação |
| **Orquestração** | Kubernetes | Docker Swarm | Nomad | **Docker Compose (inicial)** | Simplicidade inicial, evolução para K8s quando necessário |

### 2.2. Stack Final

```
Frontend:
  - Next.js 14+ (App Router)
  - React 18+
  - TypeScript 5+
  - TailwindCSS (estilização)
  - Zod (validação de schemas)

Backend:
  - Node.js 20+ LTS
  - TypeScript 5+
  - Express/Fastify (framework HTTP)
  - Prisma ORM (type-safe database access)

Banco de Dados:
  - PostgreSQL 15+
  - pgcrypto extension
  - Row-Level Security

Cache:
  - Redis 7+

Storage:
  - S3-compatible (AWS S3 / MinIO)

Segurança:
  - libsodium (criptografia)
  - WebAuthn (autenticação biométrica/passkeys)
  - OTP (TOTP/HOTP para MFA)

Infraestrutura:
  - Docker + Docker Compose
  - Nginx (reverse proxy)
  - Let's Encrypt (TLS)
```

---

## 3. Arquitetura de Alto Nível

```
┌─────────────────────────────────────────────────────────────────────┐
│                           CLIENTE                                   │
│                                                                     │
│  ┌─────────────────┐           ┌─────────────────┐                 │
│  │   Browser       │           │   Dispositivo   │                 │
│  │   (Next.js)     │           │   Móvel (fut.)  │                 │
│  │                 │           │                 │                 │
│  │  - WebAuthn     │           │  - Biometria    │                 │
│  │  - Crypto       │           │  - Offline      │                 │
│  │  - Session Mgmt │           │  - Sync         │                 │
│  └────────┬────────┘           └────────┬────────┘                 │
│           │                              │                          │
└───────────┼──────────────────────────────┼──────────────────────────┘
            │                              │
            │         HTTPS (TLS 1.3)      │
            │                              │
            ▼                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      CAMADA DE BORDA                                │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Nginx / Reverse Proxy                     │   │
│  │                                                              │   │
│  │  - TLS Termination                                           │   │
│  │  - HSTS                                                      │   │
│  │  - Rate Limiting (camada 1)                                  │   │
│  │  - CORS                                                      │   │
│  │  - Security Headers (CSP, X-Frame-Options, etc.)             │   │
│  └────────────────────────────┬────────────────────────────────┘   │
│                               │                                    │
└───────────────────────────────┼────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    CAMADA DE APLICAÇÃO                              │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    API Gateway / Backend                     │   │
│  │                                                              │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │   │
│  │  │   Auth       │  │  Documents   │  │   Account    │      │   │
│  │  │   Module     │  │   Module     │  │   Module     │      │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘      │   │
│  │                                                              │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │   │
│  │  │   Audit      │  │  Security    │  │   Crypto     │      │   │
│  │  │   Module     │  │   Module     │  │   Module     │      │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘      │   │
│  │                                                              │   │
│  │  Middleware:                                                 │   │
│  │  - Authentication (JWT validation)                           │   │
│  │  - Authorization (RBAC, ownership)                           │   │
│  │  - Rate Limiting (camada 2)                                  │   │
│  │  - Input Validation                                          │   │
│  │  - Request Logging                                           │   │
│  └────────────────────────────┬────────────────────────────────┘   │
│                               │                                    │
└───────────────────────────────┼────────────────────────────────────┘
                                │
            ┌───────────────────┼───────────────────┐
            │                   │                   │
            ▼                   ▼                   ▼
┌───────────────────┐ ┌───────────────────┐ ┌───────────────────────┐
│   PostgreSQL      │ │      Redis        │ │   Object Storage      │
│                   │ │                   │ │   (S3-compatible)     │
│  - Users          │ │  - Sessions       │ │                       │
│  - Documents      │ │  - Rate Limits    │ │  - Encrypted Files    │
│  - Audit Logs     │ │  - Cache          │ │  - Versioning         │
│  - Devices        │ │  - Pub/Sub        │ │  - Lifecycle Rules    │
│  - MFA Seeds      │ │                   │ │                       │
│  - Biometric Data │ │                   │ │                       │
│  (encrypted)      │ │                   │ │                       │
└───────────────────┘ └───────────────────┘ └───────────────────────┘
```

---

## 4. Modelo de Autenticação

### 4.1. Fatores de Autenticação

O ZERO implementa autenticação multifator (MFA) com os seguintes fatores:

**Fator 1: Algo que você sabe**
- Senha mestra (mínimo 12 caracteres)
- Hash: Argon2id (memory: 64MB, iterations: 3, parallelism: 4)

**Fator 2: Algo que você tem**
- TOTP (Time-based One-Time Password)
- Passkeys/WebAuthn (FIDO2)
- Chaves de recuperação (backup codes)

**Fator 3: Algo que você é**
- Reconhecimento facial (com liveness detection)
- *Nota: Biometria é fator adicional, nunca único*

### 4.2. Fluxo de Autenticação

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Usuário    │     │   Frontend   │     │    Backend   │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │
       │  1. Email/Senha    │                    │
       │───────────────────>│                    │
       │                    │  2. Validar creds  │
       │                    │───────────────────>│
       │                    │                    │
       │                    │  3. Retornar MFA   │
       │                    │<───────────────────│
       │                    │    required flag   │
       │  4. Solicitar MFA  │                    │
       │<───────────────────│                    │
       │                    │                    │
       │  5. Código TOTP/   │                    │
       │     Biometria      │                    │
       │───────────────────>│                    │
       │                    │  6. Verificar MFA  │
       │                    │───────────────────>│
       │                    │                    │
       │                    │  7. Gerar tokens   │
       │                    │<───────────────────│
       │                    │    (access + refresh)
       │  8. Tokens + User  │                    │
       │<───────────────────│                    │
       │                    │                    │
```

### 4.3. Gerenciamento de Sessão

**Access Token:**
- Tipo: JWT (JSON Web Token)
- Duração: 15 minutos
- Claims: `sub`, `iat`, `exp`, `jti`, `deviceId`, `scope`
- Assinatura: RS256 ou EdDSA

**Refresh Token:**
- Tipo: Opaque token (UUID v4)
- Duração: 7 dias (configurável)
- Armazenamento: Banco de dados (revogável)
- Binding: Device fingerprint + IP range

**Session Management:**
- Sessões armazenadas em Redis (cache) + PostgreSQL (persistência)
- Revogação imediata via blacklist em Redis
- Rotação de refresh token a cada uso (refresh token rotation)
- Detecção de reuso de refresh token (comprometimento)

---

## 5. Modelo de Criptografia

### 5.1. Camadas de Criptografia

```
┌─────────────────────────────────────────────────────────────┐
│                    HIERARQUIA DE CHAVES                     │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Master Key (KMS/HSM)                    │   │
│  │              - AES-256-GCM                           │   │
│  │              - Armazenada em HSM/KMS                 │   │
│  │              - Nunca sai do cofre                    │   │
│  └────────────────────┬────────────────────────────────┘   │
│                       │                                     │
│                       ▼                                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │           User Master Key (UMK)                      │   │
│  │           - Derivada da senha + salt                 │   │
│  │           - Argon2id → KDF                           │   │
│  │           - Usada para envelope encryption           │   │
│  └────────────────────┬────────────────────────────────┘   │
│                       │                                     │
│         ┌─────────────┴─────────────┐                      │
│         │                           │                       │
│         ▼                           ▼                       │
│  ┌─────────────────┐       ┌─────────────────┐             │
│  │  Data Key (DK)  │       │  Recovery Key   │             │
│  │  - AES-256-GCM  │       │  - Backup       │             │
│  │  - Criptografa  │       │  - Armazenada   │             │
│  │    documentos   │       │    separadamente│             │
│  └─────────────────┘       └─────────────────┘             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 5.2. Criptografia em Repouso

**Banco de Dados:**
- TDE (Transparent Data Encryption): AES-256-GCM
- Column-level encryption para dados sensíveis:
  - Templates biométricos
  - Seeds MFA (TOTP)
  - Chaves de recuperação
- pgcrypto extension para operações criptográficas

**Object Storage:**
- Server-side encryption (SSE-S3 ou SSE-KMS)
- Client-side encryption para documentos críticos:
  - Cada arquivo criptografado com chave única (DEK)
  - DEK criptografada com UMK do usuário (KEK)
  - Envelope encryption pattern

**Backups:**
- Criptografados antes de sair do servidor
- Chaves de backup armazenadas separadamente
- Testes de restauração periódicos

### 5.3. Criptografia em Trânsito

- TLS 1.3 obrigatório
- HSTS habilitado (max-age=31536000, includeSubDomains, preload)
- Cipher suites seguros (TLS_AES_256_GCM_SHA384, etc.)
- Certificate pinning (futuro, clientes móveis)
- OCSP Stapling habilitado

### 5.4. Algoritmos Criptográficos

| Propósito | Algoritmo | Tamanho/Parâmetros |
|-----------|-----------|-------------------|
| Hash de senhas | Argon2id | memory=64MB, iterations=3, parallelism=4 |
| Hash geral | SHA-256 / BLAKE2b | 256 bits |
| Criptografia simétrica | AES-256-GCM | 256 bits |
| Assinatura digital | Ed25519 | 256 bits |
| Key Exchange | X25519 | 256 bits |
| KDF | HKDF-SHA256 | - |
| TOTP | HMAC-SHA256 | 32 bytes seed |

---

## 6. Modelo de Dados

### 6.1. Entidades Principais

```
┌─────────────────────────────────────────────────────────────┐
│                     SCHEMA DO BANCO                         │
└─────────────────────────────────────────────────────────────┘

users
├── id: UUID (PK)
├── email: VARCHAR(255) UNIQUE
├── password_hash: TEXT
├── password_salt: TEXT
├── recovery_key_hash: TEXT
├── created_at: TIMESTAMP
├── updated_at: TIMESTAMP
├── last_login_at: TIMESTAMP
├── failed_login_attempts: INTEGER
├── locked_until: TIMESTAMP
└── status: ENUM (active, suspended, deleted)

user_mfa
├── id: UUID (PK)
├── user_id: UUID (FK → users.id)
├── type: ENUM (totp, webauthn, biometric)
├── secret_encrypted: TEXT (TOTP seed)
├── public_key: TEXT (WebAuthn)
├── credential_id: TEXT (WebAuthn)
├── transports: TEXT[] (WebAuthn)
├── counter: BIGINT (WebAuthn)
├── enabled: BOOLEAN
├── created_at: TIMESTAMP
└── last_used_at: TIMESTAMP

devices
├── id: UUID (PK)
├── user_id: UUID (FK → users.id)
├── name: VARCHAR(255)
├── device_fingerprint: TEXT
├── user_agent: TEXT
├── ip_address: INET
├── location_approx: TEXT
├── is_trusted: BOOLEAN
├── created_at: TIMESTAMP
├── last_active_at: TIMESTAMP
└── revoked_at: TIMESTAMP

sessions
├── id: UUID (PK)
├── user_id: UUID (FK → users.id)
├── device_id: UUID (FK → devices.id)
├── refresh_token_hash: TEXT
├── access_token_jti: TEXT
├── ip_address: INET
├── user_agent: TEXT
├── created_at: TIMESTAMP
├── expires_at: TIMESTAMP
├── revoked_at: TIMESTAMP
└── revoked_reason: TEXT

documents
├── id: UUID (PK)
├── user_id: UUID (FK → users.id)
├── parent_folder_id: UUID (FK → folders.id, nullable)
├── name: VARCHAR(255)
├── description: TEXT
├── mime_type: VARCHAR(255)
├── file_size: BIGINT
├── file_hash: TEXT (SHA-256)
├── storage_key: TEXT (S3 object key)
├── encryption_key_wrapped: TEXT (DEK encrypted with UMK)
├── version: INTEGER
├── status: ENUM (active, deleted, archived)
├── classification: ENUM (normal, sensitive, critical)
├── created_at: TIMESTAMP
├── updated_at: TIMESTAMP
├── deleted_at: TIMESTAMP (soft delete)
└── deleted_by: UUID (FK → users.id)

folders
├── id: UUID (PK)
├── user_id: UUID (FK → users.id)
├── parent_folder_id: UUID (FK → folders.id, nullable)
├── name: VARCHAR(255)
├── path: TEXT (materialized path)
├── created_at: TIMESTAMP
└── updated_at: TIMESTAMP

document_versions
├── id: UUID (PK)
├── document_id: UUID (FK → documents.id)
├── version: INTEGER
├── file_hash: TEXT
├── storage_key: TEXT
├── encryption_key_wrapped: TEXT
├── file_size: BIGINT
├── created_at: TIMESTAMP
└── created_by: UUID (FK → users.id)

audit_logs
├── id: UUID (PK)
├── user_id: UUID (FK → users.id, nullable)
├── action: VARCHAR(100)
├── resource_type: VARCHAR(100)
├── resource_id: UUID
├── old_value: JSONB (nullable)
├── new_value: JSONB (nullable)
├── ip_address: INET
├── user_agent: TEXT
├── device_id: UUID (FK → devices.id, nullable)
├── session_id: UUID (FK → sessions.id, nullable)
├── status: ENUM (success, failure)
├── failure_reason: TEXT
├── created_at: TIMESTAMP
└── metadata: JSONB

biometric_templates
├── id: UUID (PK)
├── user_id: UUID (FK → users.id)
├── template_data_encrypted: TEXT (template irreversível)
├── liveness_threshold: FLOAT
├── confidence_threshold: FLOAT
├── created_at: TIMESTAMP
├── updated_at: TIMESTAMP
└── last_used_at: TIMESTAMP

recovery_codes
├── id: UUID (PK)
├── user_id: UUID (FK → users.id)
├── code_hash: TEXT
├── used_at: TIMESTAMP (nullable)
├── created_at: TIMESTAMP
└── expires_at: TIMESTAMP
```

### 6.2. Row-Level Security (RLS)

PostgreSQL Row-Level Security será usado para isolamento lógico:

```sql
-- Exemplo de política RLS
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

CREATE POLICY user_isolation_policy ON documents
    FOR ALL
    USING (user_id = current_setting('app.current_user_id')::UUID);
```

---

## 7. Arquitetura de Armazenamento de Arquivos

### 7.1. Fluxo de Upload

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Cliente    │     │    Backend   │     │   Storage    │
└──────┬───────┘     └──────┬───────┘     └──────┬───────┘
       │                    │                    │
       │  1. Solicitar upload │                   │
       │────────────────────>│                    │
       │                    │                    │
       │                    │  2. Gerar presigned URL
       │                    │───────────────────>│
       │                    │                    │
       │  3. Presigned URL  │                    │
       │<────────────────────│                    │
       │                    │                    │
       │  4. Upload direto  │                    │
       │────────────────────────────────────────>│
       │     (HTTPS + crypto)                    │
       │                    │                    │
       │  5. Confirmar upload │                   │
       │────────────────────>│                    │
       │                    │  6. Validar hash   │
       │                    │  7. Metadados no DB│
       │                    │                    │
       │  8. Confirmação    │                    │
       │<────────────────────│                    │
       │                    │                    │
```

### 7.2. Estrutura de Storage

```
bucket-zero-documents/
├── {user-id}/
│   ├── {document-id}/
│   │   ├── v1/{uuid}.enc
│   │   ├── v2/{uuid}.enc
│   │   └── metadata.json.enc
│   └── {folder-id}/
│       └── ...
├── quarantine/
│   └── {suspicious-file-id}
└── temp/
    └── {upload-session-id}/
```

### 7.3. Proteção de Arquivos

1. **Validação de Tipo:**
   - Verificação de MIME type real (magic bytes)
   - Validação de extensão
   - Bloqueio de tipos perigosos (.exe, .bat, .scr, etc.)

2. **Limites:**
   - Tamanho máximo: 100MB (configurável)
   - Quota por usuário: 10GB (padrão)

3. **Quarentena:**
   - Arquivos novos em área isolada
   - Scan futuro com antivírus
   - Liberação após validação

4. **Versionamento:**
   - Cada upload cria nova versão
   - Versões anteriores preservadas
   - Limite de versões: 50 por documento

---

## 8. Sistema de Auditoria

### 8.1. Eventos Auditados

| Categoria | Eventos |
|-----------|---------|
| **Autenticação** | login_success, login_failure, logout, mfa_enabled, mfa_disabled, password_changed |
| **Sessão** | session_created, session_revoked, device_trusted, device_revoked |
| **Documentos** | document_uploaded, document_downloaded, document_viewed, document_updated, document_deleted, document_restored |
| **Biometria** | biometric_enrolled, biometric_verified, biometric_failed, biometric_removed |
| **Recuperação** | recovery_code_generated, recovery_code_used, account_recovery_initiated |
| **Admin** | user_suspended, user_deleted, config_changed |

### 8.2. Estrutura de Log

```json
{
  "id": "uuid",
  "timestamp": "2024-01-15T10:30:00Z",
  "user_id": "uuid",
  "action": "document_uploaded",
  "resource_type": "document",
  "resource_id": "uuid",
  "status": "success",
  "context": {
    "ip_address": "192.168.1.1",
    "user_agent": "Mozilla/5.0...",
    "device_id": "uuid",
    "location": "São Paulo, BR",
    "file_size": 1024000,
    "mime_type": "application/pdf"
  },
  "metadata": {}
}
```

### 8.3. Proteção de Logs

- Append-only (imutáveis)
- Envio para sistema externo (SIEM)
- Alertas para padrões suspeitos
- Retenção: 2 anos (configurável)
- Não logar dados sensíveis (senhas, tokens, conteúdo de arquivos)

---

## 9. Estratégia de Recuperação

### 9.1. Cenários de Recuperação

| Cenário | Mecanismo | Nível de Confiança |
|---------|-----------|-------------------|
| Esqueceu senha | Recovery codes + email verification | ALTO |
| Perdeu dispositivo MFA | Recovery codes + step-up auth | ALTO |
| Perdeu recovery codes | Processo manual com verificação de identidade | MÉDIO |
| Comprometimento de conta | Revogação total de sessões + reset completo | ALTO |
| Perda de dados | Backup criptografado + recovery key | ALTO |

### 9.2. Recovery Codes

- 10 códigos de uso único
- Cada código: 12 caracteres alfanuméricos
- Hash: bcrypt (custo 12)
- Armazenamento: banco de dados (cripitografado)
- Uso requer confirmação por email

### 9.3. Backup Strategy

```
┌─────────────────────────────────────────────────────────────┐
│                    ESTRATÉGIA DE BACKUP                     │
│                                                             │
│  Frequência:                                                │
│  - Banco de dados: hourly (WAL archiving)                  │
│  - Object storage: continuous versioning                   │
│  - Configurações: daily                                     │
│                                                             │
│  Retenção:                                                  │
│  - Hourly: 24 horas                                        │
│  - Daily: 30 dias                                          │
│  - Weekly: 12 semanas                                      │
│  - Monthly: 12 meses                                       │
│                                                             │
│  Localização:                                               │
│  - Primary: mesmo região (restauração rápida)              │
│  - Secondary: região diferente (disaster recovery)         │
│  - Offline: fitas/cofre (proteção contra ransomware)       │
│                                                             │
│  Testes:                                                    │
│  - Restauração automática semanal                          │
│  - Drill trimestral de disaster recovery                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 10. Segurança em Camadas

### 10.1. Defense in Depth

```
┌─────────────────────────────────────────────────────────────┐
│                    CAMADAS DE DEFESA                        │
│                                                             │
│  1. PERÍMETRO                                               │
│     - Firewall de borda                                     │
│     - WAF (Web Application Firewall)                        │
│     - DDoS protection                                       │
│     - TLS termination                                       │
│                                                             │
│  2. REDE                                                    │
│     - Network segmentation                                  │
│     - Private subnets                                       │
│     - Security groups                                       │
│     - VPC flow logs                                         │
│                                                             │
│  3. APLICAÇÃO                                               │
│     - Authentication (MFA obrigatório)                      │
│     - Authorization (RBAC + ownership)                      │
│     - Input validation                                      │
│     - Rate limiting                                         │
│     - CSRF protection                                       │
│     - CSP headers                                           │
│                                                             │
│  4. DADOS                                                   │
│     - Criptografia em repouso                               │
│     - Criptografia em trânsito                              │
│     - Row-level security                                    │
│     - Masking de dados sensíveis                            │
│                                                             │
│  5. MONITORAMENTO                                           │
│     - Audit logging                                         │
│     - Anomaly detection                                     │
│     - Alerting                                              │
│     - SIEM integration                                      │
│                                                             │
│  6. RESPOSTA                                                │
│     - Incident response plan                                │
│     - Session revocation                                    │
│     - Account lockdown                                      │
│     - Forensics capability                                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 10.2. Zero Trust Principles

- **Never trust, always verify:** Toda requisição autenticada e autorizada
- **Least privilege:** Acesso mínimo necessário
- **Micro-segmentation:** Isolamento de componentes
- **Assume breach:** Detecção e resposta rápidas
- **Continuous validation:** Sessões e dispositivos monitorados

---

## 11. Estrutura de Pastas do Projeto

```
ZERO/
├── apps/
│   ├── web/                    # Frontend Next.js
│   │   ├── src/
│   │   │   ├── app/           # App Router pages
│   │   │   ├── components/    # React components
│   │   │   ├── hooks/         # Custom hooks
│   │   │   ├── lib/           # Utilities
│   │   │   └── styles/        # CSS/Tailwind
│   │   ├── public/
│   │   └── package.json
│   │
│   └── api/                   # Backend Node.js
│       ├── src/
│       │   ├── modules/
│       │   │   ├── auth/      # Autenticação
│       │   │   ├── documents/ # Gerenciamento de documentos
│       │   │   ├── users/     # Gestão de usuários
│       │   │   ├── audit/     # Auditoria
│       │   │   └── security/  # Segurança
│       │   ├── shared/        # Código compartilhado
│       │   ├── config/        # Configurações
│       │   └── index.ts       # Entry point
│       ├── tests/
│       └── package.json
│
├── packages/
│   ├── auth/                  # Módulo de autenticação
│   ├── crypto/                # Criptografia
│   ├── security/              # Segurança (rate limit, validation)
│   ├── database/              # Schema, migrations, client
│   └── shared/                # Tipos, utils compartilhados
│
├── infrastructure/
│   ├── docker/
│   │   ├── Dockerfile.api
│   │   ├── Dockerfile.web
│   │   └── docker-compose.yml
│   ├── k8s/                   # Kubernetes manifests (futuro)
│   └── terraform/             # IaC (futuro)
│
├── tests/
│   ├── e2e/                   # Testes end-to-end
│   ├── integration/           # Testes de integração
│   └── security/              # Testes de segurança
│
├── docs/
│   ├── architecture.md        # Este documento
│   ├── threat-model.md        # Threat model
│   ├── security.md            # Políticas de segurança
│   ├── recovery.md            # Estratégia de recuperação
│   └── deployment.md          # Guia de deploy
│
├── scripts/
│   ├── setup.sh
│   ├── migrate.sh
│   └── backup.sh
│
├── .github/
│   └── workflows/
│       ├── ci.yml
│       ├── security-scan.yml
│       └── deploy.yml
│
├── .env.example
├── .gitignore
├── README.md
└── package.json               # Root package (monorepo)
```

---

## 12. Roadmap de Implementação

### Fase 1: Fundação (Semanas 1-4)
- [x] Threat model
- [x] Architecture document
- [ ] Setup do projeto (monorepo, TypeScript, ESLint)
- [ ] Configuração do banco de dados
- [ ] Schema inicial do banco
- [ ] Infraestrutura básica (Docker, PostgreSQL, Redis)

### Fase 2: Autenticação (Semanas 5-8)
- [ ] Registro de usuário
- [ ] Login com senha
- [ ] MFA (TOTP)
- [ ] Gerenciamento de sessão
- [ ] Gerenciamento de dispositivos
- [ ] Recovery codes

### Fase 3: Documentos (Semanas 9-12)
- [ ] Upload de arquivos
- [ ] Download de arquivos
- [ ] Criptografia de arquivos
- [ ] Organização em pastas
- [ ] Versionamento
- [ ] Pesquisa

### Fase 4: Segurança Avançada (Semanas 13-16)
- [ ] WebAuthn/Passkeys
- [ ] Biometria facial (liveness detection)
- [ ] Step-up authentication
- [ ] Auditoria completa
- [ ] Alertas de segurança

### Fase 5: Hardening (Semanas 17-20)
- [ ] Backups automatizados
- [ ] Disaster recovery testing
- [ ] Penetration testing
- [ ] Security audit
- [ ] Performance optimization

### Fase 6: Produção (Semanas 21-24)
- [ ] CI/CD pipeline
- [ ] Monitoring e alerting
- [ ] Documentation final
- [ ] Launch preparation

---

## 13. Referências

- OWASP Application Security Verification Standard (ASVS)
- NIST Cybersecurity Framework
- Zero Trust Architecture (NIST SP 800-207)
- FIDO2/WebAuthn Specification
- libsodium Documentation
- PostgreSQL Security Best Practices
- AWS S3 Security Best Practices

---

*Documento criado: $(date)*
*Versão: 1.0*
*Status: EM REVISÃO*
