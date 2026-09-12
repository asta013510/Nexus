# ZERO — Central de Segurança Pessoal

## Visão Geral

O **ZERO** é uma central de segurança pessoal para armazenamento, gerenciamento e proteção de documentos e informações pessoais críticas.

**Não é** um gerenciador de arquivos comum. É uma plataforma de segurança com arquitetura defensiva em camadas, projetada para resistir a comprometimento parcial do sistema.

---

## ⚠️ Status do Projeto

**FASE 1: FUNDAÇÃO** — Em andamento

- [x] Threat Model documentado
- [x] Architecture Document criado
- [x] Foundation Document definido
- [ ] Setup do monorepo
- [ ] Schema do banco de dados
- [ ] Infraestrutura Docker básica

**NOT PRODUCTION READY** — Este projeto está em desenvolvimento ativo. Nenhuma versão atual deve ser usada em produção.

---

## Princípios Fundamentais

Prioridades (nesta ordem):

1. **Segurança** — Nunca sacrificada por conveniência
2. **Privacidade** — Minimização de dados coletados
3. **Integridade dos Dados** — Verificação criptográfica
4. **Recuperação Segura** — Resiliência a perda de acesso
5. **Confiabilidade** — Operação consistente e previsível
6. **Usabilidade** — Segurança não deve impedir uso legítimo
7. **Desempenho** — Otimizado dentro dos limites de segurança

---

## Funcionalidades Planejadas

### Autenticação & Autorização
- [ ] Registro de usuário com validação de email
- [ ] Login com senha mestra (Argon2id)
- [ ] MFA obrigatório (TOTP, WebAuthn)
- [ ] Reconhecimento facial com liveness detection
- [ ] Gerenciamento de sessões e dispositivos
- [ ] Recovery codes para recuperação de conta
- [ ] Step-up authentication para operações críticas

### Documentos & Armazenamento
- [ ] Upload seguro de arquivos
- [ ] Download com verificação de integridade
- [ ] Criptografia em repouso (AES-256-GCM)
- [ ] Organização por pastas/categorias
- [ ] Versionamento de documentos
- [ ] Histórico de alterações
- [ ] Pesquisa em metadados
- [ ] Exclusão segura com lixeira

### Segurança & Auditoria
- [ ] Audit log de todas as operações sensíveis
- [ ] Detecção de comportamento anômalo
- [ ] Alertas de segurança
- [ ] Gerenciamento de dispositivos confiáveis
- [ ] Revogação de sessões
- [ ] Proteção contra brute force
- [ ] Rate limiting

### Recuperação & Backup
- [ ] Backup automatizado criptografado
- [ ] Recuperação de desastres
- [ ] Restauração point-in-time
- [ ] Testes periódicos de restauração

---

## Stack Tecnológico

| Componente | Tecnologia |
|------------|-----------|
| Frontend | Next.js 14+ + React + TypeScript |
| Backend | Node.js 20+ LTS + TypeScript |
| Banco de Dados | PostgreSQL 15+ |
| Cache | Redis 7+ |
| Storage | S3-compatible (MinIO/AWS S3) |
| Criptografia | libsodium + Web Crypto API |
| Autenticação | WebAuthn + JWT + TOTP |
| Containerização | Docker + Docker Compose |

---

## Estrutura do Projeto

```
ZERO/
├── apps/
│   ├── web/              # Frontend Next.js
│   └── api/              # Backend Node.js
├── packages/
│   ├── auth/             # Autenticação
│   ├── crypto/           # Criptografia
│   ├── security/         # Segurança
│   ├── database/         # Schema, migrations
│   └── shared/           # Utils compartilhados
├── infrastructure/
│   ├── docker/
│   └── scripts/
├── tests/
│   ├── e2e/
│   ├── integration/
│   └── security/
├── docs/
│   ├── FOUNDATION.md     # Documento fundamental
│   ├── threat-model.md   # Threat model
│   ├── architecture.md   # Arquitetura
│   ├── security.md       # Políticas de segurança
│   ├── recovery.md       # Estratégia de recuperação
│   └── deployment.md     # Guia de deploy
└── scripts/
```

---

## Documentação

| Documento | Descrição |
|-----------|-----------|
| [FOUNDATION.md](./docs/FOUNDATION.md) | Decisões arquiteturais fundamentais |
| [threat-model.md](./docs/threat-model.md) | Modelo de ameaças completo |
| [architecture.md](./docs/architecture.md) | Arquitetura detalhada do sistema |
| [security.md](./docs/security.md) | Políticas e padrões de segurança |
| [recovery.md](./docs/recovery.md) | Estratégia de recuperação e backup |
| [deployment.md](./docs/deployment.md) | Guia de implantação |

---

## Roadmap

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

## Requisitos de Desenvolvimento

- Node.js 20+ LTS
- npm ou pnpm
- Docker + Docker Compose
- PostgreSQL 15+
- Redis 7+

---

## Segurança

Este projeto segue princípios de:

- **Zero Trust** — Nunca confiar, sempre verificar
- **Defense in Depth** — Múltiplas camadas de segurança
- **Least Privilege** — Acesso mínimo necessário
- **Secure by Design** — Segurança desde a concepção

Para reportar vulnerabilidades de segurança, consulte [SECURITY.md](./SECURITY.md).

---

## Licença

[/LICENSE](./LICENSE)

---

## Aviso Legal

**ESTE SOFTWARE É FORNECIDO "COMO ESTÁ" SEM GARANTIAS DE QUALQUER TIPO.**

O ZERO é uma ferramenta de segurança em desenvolvimento. Use por sua própria conta e risco. Não armazene informações críticas até que o projeto atinja status de produção e passe por auditoria de segurança independente.

Consulte os documentos de arquitetura e threat model para entender as limitações e riscos residuais.

---

*Projeto ZERO — Central de Segurança Pessoal*
*Versão: 0.1.0-alpha*
*Status: EM DESENVOLVIMENTO*
