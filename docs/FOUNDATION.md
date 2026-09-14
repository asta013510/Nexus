# ZERO — Foundation Document

## 1. Propósito e Visão

O **ZERO** é uma central de segurança pessoal para armazenamento, gerenciamento e proteção de documentos e informações pessoais críticas.

**Não é** um gerenciador de arquivos comum. É uma plataforma de segurança com arquitetura defensiva em camadas, projetada para resistir a comprometimento parcial do sistema.

### 1.1. Princípios Fundamentais

Prioridades (nesta ordem):
1. **Segurança** — Nunca sacrificada por conveniência
2. **Privacidade** — Minimização de dados coletados
3. **Integridade dos Dados** — Verificação criptográfica
4. **Recuperação Segura** — Resiliência a perda de acesso
5. **Confiabilidade** — Operação consistente e previsível
6. **Usabilidade** — Segurança não deve impedir uso legítimo
7. **Desempenho** — Otimizado dentro dos limites de segurança

### 1.2. Premissas de Ameaça

O sistema é projetado assumindo que:
- O dispositivo do usuário pode ser roubado
- Sessões podem ser comprometidas
- Ataques de brute force ocorrerão
- Bancos de dados podem ser copiados
- Backups podem vazar
- Partes da infraestrutura podem ser comprometidas
- Usuários cometerão erros
- Arquivos maliciosos serão enviados
- APIs serão abusadas

---

## 2. Decisões Arquiteturais Fundamentais

### 2.1. Stack Tecnológico

| Componente | Decisão | Justificativa |
|------------|---------|---------------|
| **Frontend** | Next.js 14+ + React + TypeScript | Ecossistema maduro, SSR, type safety, ampla adoção |
| **Backend** | Node.js 20+ LTS + TypeScript | Mesma linguagem fullstack, ecossistema rico, performance adequada |
| **Banco de Dados** | PostgreSQL 15+ | ACID, Row-Level Security, pgcrypto, maturidade |
| **Cache** | Redis 7+ | Sessions, rate limiting, pub/sub |
| **Storage** | S3-compatible | Padrão indústria, encryption, versionamento |
| **Criptografia** | libsodium + Web Crypto API | Algoritmos modernos, APIs seguras, auditadas |
| **Autenticação** | WebAuthn + JWT + TOTP | Passwordless, MFA nativo, padrão FIDO2 |

**Alternativas rejeitadas:**
- Go no backend: curva de aprendizado, ecossistema menor para este caso
- Python: GIL, performance inferior para I/O bound
- MySQL: menos recursos de segurança que PostgreSQL
- Session-based auth: escalabilidade limitada, stateful

### 2.2. Modelo de Autenticação

**Decisão:** Autenticação multifator obrigatória com hierarquia de fatores.

```
Fator Primário (obrigatório):
├── Senha mestra (Argon2id)
└── OU Passkey/WebAuthn

Fator Secundário (obrigatório para operações sensíveis):
├── TOTP (Google Authenticator, Authy)
├── WebAuthn/Passkey
└── Recovery codes (backup)

Fator Terciário (opcional, adicional):
└── Biometria facial com liveness detection
```

**Regras críticas:**
1. Biometria **NUNCA** é fator único
2. MFA é obrigatório para operações sensíveis
3. Recovery codes são gerados no registro
4. Sessões expiram e são revogáveis
5. Step-up auth para operações de alto risco

### 2.3. Modelo de Criptografia

**Decisão:** Criptografia em múltiplas camadas com envelope encryption.

```
Hierarquia de Chaves:
┌─────────────────────────────────────┐
│   Master Key (KMS/HSM)              │ ← Nunca sai do cofre
│   - AES-256-GCM                     │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│   User Master Key (UMK)             │ ← Derivada da senha
│   - Argon2id → KDF                  │
│   - Envelope encryption             │
└──────────────┬──────────────────────┘
               │
       ┌───────┴───────┐
       ▼               ▼
┌─────────────┐ ┌─────────────┐
│ Data Key    │ │ Recovery    │
│ (documentos)│ │ Key         │
│ AES-256-GCM │ │ (backup)    │
└─────────────┘ └─────────────┘
```

**Algoritmos:**
- Hash senhas: Argon2id (memory=64MB, iterations=3, parallelism=4)
- Criptografia: AES-256-GCM
- Assinatura: Ed25519
- Key Exchange: X25519
- Hash geral: SHA-256 ou BLAKE2b

**Regras críticas:**
1. Nunca implementar algoritmos criptográficos próprios
2. Chaves nunca armazenadas em texto puro
3. Separação entre dados e chaves
4. Rotação de chaves planejada
5. Destruição segura de chaves obsoletas

### 2.4. Arquitetura de Armazenamento

**Decisão:** Upload direto para S3 com presigned URLs + criptografia client-side opcional.

**Fluxo:**
1. Cliente solicita upload → Backend valida permissão
2. Backend gera presigned URL (S3)
3. Cliente faz upload direto para S3 (HTTPS)
4. Cliente confirma upload → Backend valida hash e salva metadados

**Proteções:**
- Validação de MIME type (magic bytes)
- Limites de tamanho (100MB padrão)
- Quarentena para novos arquivos
- Versionamento habilitado
- Server-side encryption (SSE-S3)
- Client-side encryption para documentos críticos

### 2.5. Isolamento de Dados

**Decisão:** Row-Level Security (RLS) no PostgreSQL + validação de ownership no backend.

**Defesas em camadas:**
1. **Banco:** RLS garante que usuário só acessa suas rows
2. **Backend:** Validação de ownership em cada operação
3. **API:** UUIDs imprevisíveis para recursos
4. **Código:** Testes automatizados de isolamento

**Regra crítica:** Nunca confiar em IDs vindos do cliente sem validar ownership.

### 2.6. Gerenciamento de Sessão

**Decisão:** JWT short-lived + Refresh tokens rotativos revogáveis.

```
Access Token (JWT):
├── Duração: 15 minutos
├── Claims: sub, iat, exp, jti, deviceId, scope
├── Assinatura: RS256/EdDSA
└── Armazenamento: memory (cliente)

Refresh Token:
├── Duração: 7 dias
├── Tipo: Opaque (UUID v4)
├── Armazenamento: banco de dados (revogável)
├── Binding: device fingerprint + IP range
└── Rotação: novo token a cada uso
```

**Proteções:**
- Revogação imediata via blacklist Redis
- Detecção de reuso (comprometimento)
- Device fingerprinting
- Limite de sessões ativas por usuário

### 2.7. Reconhecimento Facial

**Decisão:** Biometria como fator adicional com liveness detection.

**Arquitetura:**
1. **Captura:** Webcam/câmera do dispositivo
2. **Pré-processamento:** Normalização, detecção de face
3. **Liveness Detection:**
   - Movimentos aleatórios (piscar, virar)
   - Análise de textura (pele vs. tela)
   - Profundidade 3D (quando disponível)
   - Detecção de reflexo
4. **Extração de Template:** Rede neural → vetor de características
5. **Comparação:** Cosine similarity com template armazenado
6. **Armazenamento:** Template irreversível, criptografado

**Regras críticas:**
- **NUNCA** armazenar imagens brutas
- Templates irreversíveis quando possível
- Limite de 5 tentativas consecutivas
- Biometria sempre acompanhada de outro fator
- Fallback seguro (senha + MFA)

**Risco residual:** MÉDIO — Ataques sofisticados podem bypass liveness básica.

### 2.8. Auditoria e Logging

**Decisão:** Audit log estruturado, append-only, externo ao sistema principal.

**Eventos auditados:**
- Todos os eventos de autenticação
- Operações em documentos (CRUD)
- Mudanças de configuração de segurança
- Operações administrativas
- Falhas e exceções de segurança

**Proteções:**
- Append-only (imutável)
- Envio para SIEM externo
- Alertas para padrões suspeitos
- Não logar dados sensíveis
- Retenção: 2 anos

### 2.9. Estratégia de Recuperação

**Decisão:** Múltiplos mecanismos com níveis de confiança diferentes.

| Cenário | Mecanismo | Confiança |
|---------|-----------|-----------|
| Esqueceu senha | Recovery codes + email | ALTA |
| Perdeu MFA | Recovery codes + step-up | ALTA |
| Perdeu recovery codes | Processo manual + identidade | MÉDIA |
| Comprometimento | Revogação total + reset | ALTA |
| Perda de dados | Backup + recovery key | ALTA |

**Recovery Codes:**
- 10 códigos de uso único
- 12 caracteres alfanuméricos
- Hash: bcrypt (custo 12)
- Uso requer confirmação por email

**Backup:**
- Banco: hourly (WAL archiving)
- Storage: versionamento contínuo
- Criptografado, chaves separadas
- Testes de restauração semanais

---

## 3. Threat Model Summary

### 3.1. Ativos Críticos

1. Documentos do usuário (CRÍTICO)
2. Templates biométricos (CRÍTICO)
3. Credenciais de autenticação (CRÍTICO)
4. Chaves de criptografia (CRÍTICO)
5. Tokens de sessão (ALTO)
6. Logs de auditoria (ALTO)

### 3.2. Principais Ameaças (STRIDE)

| Categoria | Ameaça Principal | Mitigação |
|-----------|------------------|-----------|
| **Spoofing** | Falsificação de identidade | MFA obrigatório, WebAuthn |
| **Tampering** | Manipulação de dados | Hash integridade, RLS, audit logs |
| **Repudiation** | Negação de ações | Audit logs completos, contexto |
| **Information Disclosure** | Vazamento de dados | Criptografia em repouso/trânsito |
| **Denial of Service** | Brute force, DDoS | Rate limiting, lockout, CDN |
| **Elevation of Privilege** | Acesso cruzado | Validação ownership, RLS |

### 3.3. Riscos Resíduos Aceitos

1. **Sessão roubada (janela de 15min):** Token curto limita dano
2. **Bypass liveness sofisticado:** Biometria é fator adicional
3. **DDoS prolongado:** CDN mitiga, não elimina
4. **Upload malicioso desconhecido:** Validação reduz superfície
5. **Comprometimento de dependência:** Audit e lock versions

---

## 4. Modelo de Dados

### 4.1. Entidades Principais

**users** — Conta do usuário
- id, email, password_hash, password_salt
- recovery_key_hash, status
- created_at, updated_at, last_login_at
- failed_login_attempts, locked_until

**user_mfa** — Fatores MFA
- user_id, type (totp/webauthn/biometric)
- secret_encrypted, public_key, credential_id
- enabled, last_used_at

**devices** — Dispositivos conhecidos
- user_id, name, device_fingerprint
- user_agent, ip_address, is_trusted
- created_at, last_active_at, revoked_at

**sessions** — Sessões ativas
- user_id, device_id, refresh_token_hash
- access_token_jti, expires_at, revoked_at

**documents** — Documentos
- user_id, parent_folder_id, name
- mime_type, file_size, file_hash
- storage_key, encryption_key_wrapped
- version, status, classification
- created_at, updated_at, deleted_at

**folders** — Pastas
- user_id, parent_folder_id, name, path

**document_versions** — Histórico de versões
- document_id, version, file_hash
- storage_key, created_at, created_by

**audit_logs** — Logs de auditoria
- user_id, action, resource_type, resource_id
- old_value, new_value, ip_address
- device_id, session_id, status, metadata

**biometric_templates** — Templates faciais
- user_id, template_data_encrypted
- liveness_threshold, confidence_threshold

**recovery_codes** — Códigos de recuperação
- user_id, code_hash, used_at, expires_at

### 4.2. Row-Level Security

```sql
-- Habilitar RLS em todas as tabelas sensíveis
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE folders ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Política de isolamento
CREATE POLICY user_isolation ON documents
    FOR ALL
    USING (user_id = current_setting('app.current_user_id')::UUID);
```

---

## 5. Segurança em Camadas

### 5.1. Defense in Depth

```
Camada 1: PERÍMETRO
├── Firewall de borda
├── WAF (Web Application Firewall)
├── DDoS protection
└── TLS termination

Camada 2: REDE
├── Network segmentation
├── Private subnets
├── Security groups
└── VPC flow logs

Camada 3: APLICAÇÃO
├── Authentication (MFA)
├── Authorization (RBAC + ownership)
├── Input validation
├── Rate limiting
├── CSRF protection
└── CSP headers

Camada 4: DADOS
├── Criptografia em repouso
├── Criptografia em trânsito
├── Row-level security
└── Masking de dados sensíveis

Camada 5: MONITORAMENTO
├── Audit logging
├── Anomaly detection
├── Alerting
└── SIEM integration

Camada 6: RESPOSTA
├── Incident response plan
├── Session revocation
├── Account lockdown
└── Forensics capability
```

### 5.2. Zero Trust Principles

1. **Never trust, always verify** — Toda requisição autenticada e autorizada
2. **Least privilege** — Acesso mínimo necessário
3. **Micro-segmentation** — Isolamento de componentes
4. **Assume breach** — Detecção e resposta rápidas
5. **Continuous validation** — Sessões e dispositivos monitorados

---

## 6. Estrutura do Projeto

```
ZERO/
├── apps/
│   ├── web/                    # Frontend Next.js
│   └── api/                    # Backend Node.js
├── packages/
│   ├── auth/                   # Autenticação
│   ├── crypto/                 # Criptografia
│   ├── security/               # Segurança
│   ├── database/               # Schema, migrations
│   └── shared/                 # Utils compartilhados
├── infrastructure/
│   ├── docker/
│   ├── k8s/                    # Futuro
│   └── terraform/              # Futuro
├── tests/
│   ├── e2e/
│   ├── integration/
│   └── security/
├── docs/
│   ├── FOUNDATION.md           # Este documento
│   ├── threat-model.md
│   ├── architecture.md
│   ├── security.md
│   ├── recovery.md
│   └── deployment.md
├── scripts/
├── .github/workflows/
├── .env.example
├── .gitignore
├── README.md
└── package.json
```

---

## 7. Roadmap

### Fase 1: Fundação (Semanas 1-4)
- [x] Threat model
- [x] Architecture document
- [x] Foundation document
- [ ] Setup monorepo + TypeScript
- [ ] Schema do banco
- [ ] Infra Docker básica

### Fase 2: Autenticação (Semanas 5-8)
- [ ] Registro/login
- [ ] MFA (TOTP)
- [ ] Sessions + devices
- [ ] Recovery codes

### Fase 3: Documentos (Semanas 9-12)
- [ ] Upload/download
- [ ] Criptografia
- [ ] Pastas + versionamento
- [ ] Pesquisa

### Fase 4: Segurança Avançada (Semanas 13-16)
- [ ] WebAuthn/Passkeys
- [ ] Biometria facial
- [ ] Step-up auth
- [ ] Auditoria completa

### Fase 5: Hardening (Semanas 17-20)
- [ ] Backups
- [ ] Disaster recovery
- [ ] Penetration testing
- [ ] Security audit

### Fase 6: Produção (Semanas 21-24)
- [ ] CI/CD
- [ ] Monitoring
- [ ] Documentation final
- [ ] Launch

---

## 8. Riscos Críticos Identificados

| Risco | Impacto | Probabilidade | Mitigação | Status |
|-------|---------|---------------|-----------|--------|
| Vazamento de banco | CRÍTICO | MÉDIA | Criptografia, separação chaves | Planejado |
| Bypass biometria | CRÍTICO | MÉDIA | Liveness, MFA, limite tentativas | Em projeto |
| Roubo de sessão | ALTO | ALTA | Tokens curtos, revogação | Planejado |
| IDOR/acesso cruzado | CRÍTICO | MÉDIA | RLS, validação ownership | Prioritário |
| Injeção SQL | CRÍTICO | MÉDIA | Prepared statements, ORM | Prioritário |
| Upload malicioso | ALTO | MÉDIA | Validação, quarentena | Planejado |
| Perda de chaves | CRÍTICO | BAIXA | Backup chaves, recovery | Planejado |

---

## 9. Critérios de Qualidade

**NÃO ACEITAREMOS:**
- [ ] Código de demonstração mascarado de produção
- [ ] Senhas hardcoded
- [ ] Secrets no Git
- [ ] Criptografia inventada
- [ ] Validação apenas no frontend
- [ ] Autenticação falsa
- [ ] Reconhecimento facial ingênuo
- [ ] Endpoints sem autorização
- [ ] Logs contendo secrets
- [ ] Dependências abandonadas
- [ ] TODOs críticos escondidos

**MARCAR COMO "NOT PRODUCTION READY" QUANDO:**
- Implementação incompleta
- Segurança insuficiente
- Testes ausentes
- Documentação pendente

---

## 10. Próximos Passos Imediatos

1. **Setup do ambiente de desenvolvimento**
   - Inicializar monorepo com Turborepo/Nx
   - Configurar TypeScript, ESLint, Prettier
   - Setup Docker Compose (PostgreSQL, Redis, MinIO)

2. **Implementar schema do banco**
   - Prisma schema com todas as entidades
   - Migrations iniciais
   - Row-Level Security policies

3. **Configurar infraestrutura básica**
   - Dockerfiles para API e Web
   - Docker Compose para desenvolvimento
   - Scripts de setup

4. **Iniciar módulo de autenticação**
   - Registro de usuário
   - Login com senha (Argon2id)
   - Geração de recovery codes

---

## 11. Referências

- OWASP ASVS 4.0
- OWASP Top 10 2021
- NIST Cybersecurity Framework
- Zero Trust Architecture (NIST SP 800-207)
- FIDO2/WebAuthn Specification
- libsodium Documentation
- PostgreSQL Security Best Practices

---

*Documento criado: 2024*
*Versão: 1.0*
*Status: APROVADO*

**Este documento é a fonte da verdade para todas as decisões arquiteturais do ZERO.**

Qualquer desvio deve ser justificado, documentado e revisado.
