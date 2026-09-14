# ZERO — Políticas e Padrões de Segurança

## 1. Visão Geral

Este documento define as políticas e padrões de segurança que devem ser seguidos em todo o projeto ZERO.

**Status:** OBRIGATÓRIO para todo desenvolvimento.

---

## 2. Padrões de Codificação Segura

### 2.1. Validação de Input

**Regra:** Todo input deve ser validado no backend, independentemente de validação no frontend.

```typescript
// ✅ CORRETO
import { z } from 'zod';

const CreateUserSchema = z.object({
  email: z.string().email(),
  password: z.string().min(12).max(128),
  name: z.string().min(1).max(100),
});

// No handler da API
const result = CreateUserSchema.safeParse(req.body);
if (!result.success) {
  return res.status(400).json({ error: 'Invalid input' });
}
```

```typescript
// ❌ ERRADO
// Confiar apenas na validação do frontend
// Validar apenas no cliente
// Usar typeof sem validação de schema
```

### 2.2. Proteção contra SQL Injection

**Regra:** Usar sempre prepared statements ou ORM com parameterization.

```typescript
// ✅ CORRETO - Prisma ORM (parameterized queries)
const user = await prisma.user.findUnique({
  where: { email: userInputEmail },
});

// ✅ CORRETO - Query parameterizada
await db.query('SELECT * FROM users WHERE id = $1', [userId]);
```

```typescript
// ❌ ERRADO - Concatenação de string
await db.query(`SELECT * FROM users WHERE id = ${userId}`);
```

### 2.3. Proteção contra XSS

**Regra:** Escapar todo output HTML e usar Content Security Policy.

```typescript
// ✅ CORRETO - Next.js escapa por padrão
<div>{userInput}</div>

// ✅ CORRETO - CSP header
res.setHeader('Content-Security-Policy', "default-src 'self'");
```

```typescript
// ❌ ERRADO
<div dangerouslySetInnerHTML={{ __html: userInput }} />
```

### 2.4. Proteção contra CSRF

**Regra:** Tokens CSRF obrigatórios em todas as mutations.

```typescript
// ✅ CORRETO
// - CSRF token em cookie HttpOnly
// - Validação no middleware
// - SameSite=Strict em cookies
```

---

## 3. Padrões de Autenticação

### 3.1. Senhas

**Requisitos mínimos:**
- Comprimento: 12 caracteres (mínimo absoluto)
- Complexidade: Não exigir regras complexas (comprimento é mais eficaz)
- Hash: Argon2id
  - Memory: 64 MB
  - Iterations: 3
  - Parallelism: 4
  - Salt: 16 bytes (aleatório por usuário)

```typescript
import { hash, verify } from '@node-rs/argon2';

const options = {
  memoryCost: 65536, // 64 MB
  timeCost: 3,
  parallelism: 4,
};

const hash = await password.hash(options);
const valid = await verify(hash, password);
```

### 3.2. MFA (Multi-Factor Authentication)

**Requisitos:**
- TOTP obrigatório para todas as contas
- Período: 30 segundos
- Algoritmo: SHA-256
- Digits: 6
- Janela: ±1 período (tolerância de sincronização)

```typescript
import { generateSecret, generateToken, verifyToken } from 'otpauth';

const secret = generateSecret({ issuer: 'ZERO', label: email });
const token = generateToken({ secret });
const valid = verifyToken({ secret, token, window: 1 });
```

### 3.3. WebAuthn/Passkeys

**Requisitos:**
- Seguir FIDO2 specification
- Attestation: none ou direct (quando necessário)
- User verification: required para operações sensíveis
- Resident keys: encouraged

### 3.4. Recovery Codes

**Requisitos:**
- 10 códigos por conjunto
- 12 caracteres alfanuméricos cada
- Uso único
- Hash: bcrypt (custo 12)
- Armazenamento: banco de dados (criptografado)

---

## 4. Padrões de Criptografia

### 4.1. Algoritmos Aprovados

| Propósito | Algoritmo | Parâmetros |
|-----------|-----------|------------|
| Hash de senhas | Argon2id | memory=64MB, time=3, parallelism=4 |
| Hash geral | SHA-256, BLAKE2b | 256 bits |
| Criptografia simétrica | AES-256-GCM | 256 bits |
| Assinatura digital | Ed25519 | 256 bits |
| Key Exchange | X25519 | 256 bits |
| KDF | HKDF-SHA256 | - |
| TOTP | HMAC-SHA256 | 32 bytes seed |

### 4.2. Algoritmos Proibidos

| Algoritmo | Motivo |
|-----------|--------|
| MD5 | Colisões conhecidas |
| SHA-1 | Colisões práticas |
| DES, 3DES | Chave muito curta |
| RC4 | Vieses conhecidos |
| ECB mode | Padrões vazados |
| RSA < 2048 bits | Chave insuficiente |

### 4.3. Gerenciamento de Chaves

**Regras:**
1. Nunca armazenar chaves em texto puro
2. Separar chaves dos dados criptografados
3. Usar KMS/HSM para master keys
4. Rotação de chaves planejada
5. Destruição segura de chaves obsoletas

```typescript
// ✅ CORRETO - Envelope encryption
const dataKey = crypto.randomBytes(32); // DEK
const encryptedData = aes256GcmEncrypt(data, dataKey);
const wrappedKey = kmsEncrypt(dataKey, masterKey); // KEK
```

---

## 5. Padrões de Sessão

### 5.1. Access Tokens (JWT)

**Configuração:**
- Duração: 15 minutos
- Assinatura: RS256 ou EdDSA
- Claims obrigatórias: `sub`, `iat`, `exp`, `jti`, `deviceId`
- Armazenamento: memory (cliente)

### 5.2. Refresh Tokens

**Configuração:**
- Tipo: Opaque (UUID v4)
- Duração: 7 dias
- Armazenamento: banco de dados
- Rotação: novo token a cada uso
- Detecção de reuso: revogar toda a cadeia

### 5.3. Cookies

**Flags obrigatórias:**
- `Secure`: true (HTTPS apenas)
- `HttpOnly`: true (sem acesso JavaScript)
- `SameSite`: Strict
- `Path`: /
- `Domain`: específico (não wildcard)

---

## 6. Padrões de Logging e Auditoria

### 6.1. Dados que NUNCA devem ser logados

- Senhas (mesmo hashes)
- Tokens de sessão completos
- Seeds de TOTP
- Templates biométricos
- Chaves de criptografia
- Conteúdo de documentos
- Recovery codes
- PII desnecessária

### 6.2. Estrutura de Log de Auditoria

```json
{
  "id": "uuid-v4",
  "timestamp": "ISO-8601",
  "user_id": "uuid",
  "action": "document.uploaded",
  "resource_type": "document",
  "resource_id": "uuid",
  "status": "success",
  "context": {
    "ip_address": "192.168.1.1",
    "user_agent": "Mozilla/5.0...",
    "device_id": "uuid",
    "location": "São Paulo, BR"
  },
  "metadata": {
    "file_size": 1024000,
    "mime_type": "application/pdf"
  }
}
```

### 6.3. Níveis de Log

| Nível | Uso |
|-------|-----|
| ERROR | Erros que requerem atenção imediata |
| WARN | Situações anômalas não críticas |
| INFO | Eventos normais do sistema |
| DEBUG | Informações de debug (não produção) |
| AUDIT | Eventos de segurança (obrigatório) |

---

## 7. Padrões de Upload de Arquivos

### 7.1. Validação

**Requisitos:**
1. Verificar MIME type real (magic bytes)
2. Validar extensão
3. Limitar tamanho (100MB padrão)
4. Bloquear tipos perigosos

**Tipos bloqueados por padrão:**
- Executáveis: `.exe`, `.bat`, `.scr`, `.cmd`, `.ps1`
- Scripts: `.js`, `.vbs`, `.wsf` (quando upload direto)
- Outros: `.msi`, `.dll`, `.sys`

### 7.2. Armazenamento

**Requisitos:**
1. Names aleatórios (UUID)
2. Sem confiar no nome original
3. Server-side encryption obrigatória
4. Quarentena para novos arquivos

---

## 8. Padrões de API

### 8.1. Headers de Segurança

```http
# Obrigatórios em todas as respostas
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

### 8.2. Rate Limiting

**Limites padrão:**
- Login: 5 tentativas por 15 minutos
- MFA: 5 tentativas por 15 minutos
- Upload: 100 por hora
- API geral: 1000 por hora por usuário

### 8.3. Tratamento de Erros

**Regra:** Mensagens genéricas para usuários, detalhes apenas em logs.

```typescript
// ✅ CORRETO
return res.status(401).json({ 
  error: 'Invalid credentials' 
});

// ❌ ERRADO
return res.status(401).json({ 
  error: 'Password hash mismatch for user john@example.com',
  stack: '...'
});
```

---

## 9. Checklist de Segurança por Feature

### Nova Funcionalidade

- [ ] Threat model da feature
- [ ] Validação de input em todos os endpoints
- [ ] Autorização verificada (ownership, RBAC)
- [ ] Audit logging implementado
- [ ] Rate limiting aplicado
- [ ] Dados sensíveis protegidos
- [ ] Logs não contêm informações sensíveis
- [ ] Testes de segurança escritos

### Novo Endpoint

- [ ] Autenticação obrigatória
- [ ] Autorização implementada
- [ ] Input validation com schema
- [ ] Output encoding
- [ ] Error handling seguro
- [ ] Rate limiting
- [ ] CORS configurado
- [ ] Audit log

### Mudança no Banco de Dados

- [ ] Migration revisada
- [ ] RLS policies atualizadas
- [ ] Índices de performance
- [ ] Backup testado
- [ ] Rollback planejado

---

## 10. Revisão de Código

### Checklist de Security Review

- [ ] Validação de input em todos os pontos de entrada
- [ ] Autorização em todos os endpoints
- [ ] Sem secrets hardcoded
- [ ] Sem dados sensíveis em logs
- [ ] Criptografia usando bibliotecas aprovadas
- [ ] Tratamento de erros não vaza informações
- [ ] Rate limiting implementado
- [ ] Audit logging presente

---

## 11. Dependências

### Gestão de Dependências

**Requisitos:**
1. Lock versions (package-lock.json, pnpm-lock.yaml)
2. Audit regular (`npm audit`, `pnpm audit`)
3. Renovate/Dependabot habilitado
4. Analisar histórico do mantenedor
5. Preferir dependências ativas e bem mantidas

**Ferramentas:**
- `npm audit` / `pnpm audit`
- Snyk
- GitHub Dependabot
- OSS Index

---

## 12. Resposta a Incidentes

### Classificação de Severidade

| Severidade | Exemplo | Tempo de Resposta |
|------------|---------|-------------------|
| P0 - Crítico | Vazamento de dados, comprometimento total | Imediato (< 1h) |
| P1 - Alto | Auth bypass, privilege escalation | < 4 horas |
| P2 - Médio | XSS refletido, IDOR limitado | < 24 horas |
| P3 - Baixo | Information disclosure menor | < 1 semana |

### Processo de Resposta

1. **Detecção** — Monitoramento, alertas, reports
2. **Triagem** — Classificar severidade
3. **Contenção** — Isolar impacto
4. **Erradicação** — Remover causa raiz
5. **Recuperação** — Restaurar operação normal
6. **Lições Aprendidas** — Documentar e melhorar

---

## 13. Conformidade e Standards

Este projeto segue:

- [x] OWASP ASVS Level 2
- [x] OWASP Top 10 2021
- [x] Zero Trust Architecture (NIST SP 800-207)
- [ ] SOC 2 Type II (futuro)
- [ ] GDPR/LGPD (quando aplicável)

---

## 14. Referências

- OWASP Application Security Verification Standard (ASVS)
- OWASP Cheat Sheet Series
- CWE/SANS Top 25
- NIST Cybersecurity Framework
- Cloud Security Alliance (CSA)

---

*Documento criado: 2024*
*Versão: 1.0*
*Status: OBRIGATÓRIO*

**Violações deste documento devem ser tratadas como bugs de segurança.**
