# ZERO — Estratégia de Recuperação e Backup

## 1. Visão Geral

Este documento descreve a estratégia de recuperação de desastres e backup do sistema ZERO.

**Objetivo:** Garantir que o sistema possa ser recuperado em cenários de:
- Perda de dados
- Comprometimento de conta
- Desastres naturais
- Falhas de infraestrutura
- Ransomware

---

## 2. Cenários de Recuperação de Conta

### 2.1. Esqueceu a Senha

**Mecanismo:** Recovery Codes + Email Verification

**Fluxo:**
1. Usuário solicita recuperação
2. Sistema envia email com link seguro (token único, expira em 1h)
3. Usuário clica no link
4. Sistema solicita recovery code (um dos 10 códigos)
5. Após validação, usuário define nova senha
6. Todas as sessões são revogadas
7. Audit log registrado

**Segurança:**
- Link de recuperação: token aleatório (256 bits), expira em 1h
- Recovery code: uso único, hash bcrypt
- Rate limit: 3 tentativas por hora
- Notificação por email em todas as etapas

### 2.2. Perdeu Acesso ao MFA

**Mecanismo:** Recovery Codes

**Fluxo:**
1. Usuário tenta login sem acesso ao TOTP
2. Seleciona "usar recovery code"
3. Insere um dos 10 códigos
4. Acesso concedido
5. Código usado é invalidado
6. Sistema incentiva geração de novos códigos

**Segurança:**
- Códigos de uso único
- Hash bcrypt (custo 12) no banco
- Alerta se múltiplos códigos usados em curto período

### 2.3. Perdeu Todos os Recovery Codes

**Mecanismo:** Processo Manual com Verificação de Identidade

**Fluxo:**
1. Usuário contacta suporte
2. Processo de verificação iniciado:
   - Confirmação de email
   - Confirmação de identidade (documentos quando aplicável)
   - Perguntas de segurança (se configuradas)
   - Período de espera (7 dias para segurança)
3. Após verificação:
   - Reset completo da conta
   - Novos recovery codes gerados
   - Todas as sessões revogadas
   - Audit log detalhado

**Segurança:**
- Período de espera previne ataques rápidos
- Múltiplas formas de verificação
- Audit trail completo
- Aprovação múltipla requerida

### 2.4. Comprometimento de Conta

**Mecanismo:** Emergency Lockdown

**Fluxo:**
1. Detecção (usuário ou sistema):
   - Atividade anômala
   - Login de localização incomum
   - Múltiplas falhas de MFA
2. Lockdown automático ou manual:
   - Todas as sessões revogadas
   - MFA resetado
   - Notificação imediata ao usuário
3. Recuperação:
   - Usuário verifica identidade
   - Nova senha definida
   - Novo MFA configurado
   - Recovery codes regenerados

---

## 3. Estratégia de Backup

### 3.1. Princípios

1. **Regra 3-2-1:**
   - 3 cópias dos dados
   - 2 tipos de mídia diferentes
   - 1 cópia off-site

2. **Criptografia:**
   - Todos os backups criptografados
   - Chaves separadas dos dados
   - Rotação de chaves anual

3. **Testes:**
   - Restauração testada semanalmente
   - Drill de disaster recovery trimestral

### 3.2. Frequência de Backup

| Componente | Tipo | Frequência | Retenção |
|------------|------|------------|----------|
| PostgreSQL | Full | Diário | 30 dias |
| PostgreSQL | WAL | Contínuo | 7 dias |
| PostgreSQL | Weekly | Semanal | 12 semanas |
| PostgreSQL | Monthly | Mensal | 12 meses |
| Object Storage | Versioning | Contínuo | 90 dias |
| Configurações | Full | Diário | 30 dias |
| Logs de Auditoria | Full | Diário | 2 anos |

### 3.3. Tipos de Backup

#### Backup Completo (Full)
- Dump completo do banco
- Executado diariamente às 03:00 UTC
- Comprimido e criptografado antes de sair do servidor
- Upload para S3 (região diferente)

#### Backup Incremental (WAL Archiving)
- Write-Ahead Logs arquivados continuamente
- Permite point-in-time recovery
- Retenção: 7 dias

#### Snapshot de Storage
- Versionamento habilitado no S3
- Lifecycle rules para retenção
- Replicação cross-region

### 3.4. Estrutura de Backup

```
s3://zero-backups-{region}/
├── database/
│   ├── daily/
│   │   ├── 2024-01-15-full.enc
│   │   ├── 2024-01-16-full.enc
│   │   └── ...
│   ├── weekly/
│   │   ├── 2024-W02-full.enc
│   │   ├── 2024-W03-full.enc
│   │   └── ...
│   ├── monthly/
│   │   ├── 2024-01-full.enc
│   │   ├── 2023-12-full.enc
│   │   └── ...
│   └── wal/
│       ├── 2024-01-15/
│       │   ├── 000000010000000000000001.enc
│       │   └── ...
│       └── ...
│
├── storage/
│   └── (versioning habilitado)
│
├── configs/
│   ├── 2024-01-15-configs.enc
│   ├── 2024-01-16-configs.enc
│   └── ...
│
└── manifests/
    ├── 2024-01-15-manifest.json
    ├── 2024-01-16-manifest.json
    └── ...
```

### 3.5. Criptografia de Backups

**Algoritmo:** AES-256-GCM

**Hierarquia de Chaves:**
```
Master Backup Key (KMS)
    └── Backup Encryption Key (BEK)
        └── Criptografa cada backup
```

**Armazenamento de Chaves:**
- Master Key: AWS KMS / HashiCorp Vault
- BEK: Rotacionada mensalmente
- Chaves antigas: Mantidas para restauração

---

## 4. Point-in-Time Recovery (PITR)

### 4.1. Capacidades

O sistema suporta restauração para qualquer ponto no tempo dentro da janela de retenção de WAL (7 dias).

**Casos de uso:**
- Corrupção de dados detectada tardiamente
- Exclusão acidental em massa
- Bug que corrompeu dados

### 4.2. Processo de PITR

1. Identificar timestamp alvo (antes do incidente)
2. Restaurar último backup full anterior
3. Aplicar WAL logs até timestamp desejado
4. Validar integridade dos dados
5. Substituir banco atual ou criar instância paralela

---

## 5. Disaster Recovery

### 5.1. Objetivos

| Métrica | Target |
|---------|--------|
| RPO (Recovery Point Objective) | < 1 hora |
| RTO (Recovery Time Objective) | < 4 horas |
| MAO (Maximum Acceptable Outage) | 24 horas |

### 5.2. Cenários de Disaster

#### Perda de Região AWS

**Resposta:**
1. Ativar infraestrutura em região secundária
2. Restaurar último backup da região secundária
3. Reconfigurar DNS (Route53)
4. Notificar usuários sobre indisponibilidade

**Tempo estimado:** 2-4 horas

#### Corrupção de Dados em Massa

**Resposta:**
1. Identificar causa raiz
2. Determinar ponto de corrupção
3. Executar PITR para ponto anterior
4. Validar integridade
5. Reativar sistema

**Tempo estimado:** 1-2 horas

#### Ataque de Ransomware

**Resposta:**
1. Isolar sistemas afetados
2. Acionar backups offline/immutable
3. Reconstruir infraestrutura do zero
4. Restaurar dados dos backups
5. Investigação forense

**Tempo estimado:** 4-24 horas

### 5.3. Infraestrutura de DR

**Região Primária:** us-east-1 (N. Virginia)
**Região Secundária:** us-west-2 (Oregon)

**Replicação:**
- Backups S3: Cross-region replication habilitado
- Banco de dados: Backup diário copiado para região secundária
- Configurações: Versionadas no Git + backup diário

---

## 6. Testes de Restauração

### 6.1. Teste Semanal Automatizado

**Escopo:** Restauração de backup mais recente

**Processo automatizado:**
1. Script baixa último backup full
2. Cria instância temporária de PostgreSQL
3. Restaura backup
4. Valida integridade (checksums, constraints)
5. Roda queries de validação
6. Destrói instância temporária
7. Reporta resultado

**Critérios de sucesso:**
- Restauração completa em < 30 minutos
- Todas as constraints válidas
- Contagem de rows conforme esperado
- Checksums de documentos críticos válidos

### 6.2. Drill Trimestral de Disaster Recovery

**Escopo:** Simulação de perda total de região

**Processo:**
1. Acionar playbook de DR
2. Provisionar infra em região secundária
3. Restaurar backups mais recentes
4. Validar funcionalidade completa
5. Documentar lições aprendidas
6. Atualizar playbooks

**Participantes:**
- Engineering
- Security
- Operations
- Management

---

## 7. Proteção contra Ransomware

### 7.1. Defesas

1. **Backups Imutáveis:**
   - S3 Object Lock (WORM - Write Once Read Many)
   - Retenção: 90 dias
   - Nem root pode deletar

2. **Separação de Credenciais:**
   - Credenciais de backup em cofre separado
   - MFA obrigatório para acesso
   - Audit log de todos os acessos

3. **Backups Offline:**
   - Cópia mensal em glacier deep archive
   - Air-gapped (sem acesso de rede direto)
   - Recuperação requer processo manual

### 7.2. Detecção

- Monitoramento de padrões de acesso anômalos
- Alertas para exclusão em massa
- Detecção de encryption de arquivos

---

## 8. Recuperação de Documentos Individuais

### 8.1. Lixeira

**Funcionamento:**
- Documentos excluídos vão para lixeira
- Permanecem por 30 dias
- Usuário pode restaurar
- Após 30 dias: exclusão permanente

### 8.2. Versões Anteriores

**Funcionamento:**
- Cada upload cria nova versão
- Últimas 50 versões preservadas
- Usuário pode baixar/restaurar qualquer versão
- Versões antigas: criptografia mantida

---

## 9. Responsabilidades

| Função | Responsabilidades |
|--------|-----------------|
| **Engineering** | Implementar backups, testes, automação |
| **Operations** | Monitorar backups, executar restores, drills |
| **Security** | Auditar processos, validar criptografia |
| **Management** | Aprovar recursos, revisar relatórios |

---

## 10. Playbooks de Emergência

### 10.1. Playbook: Perda de Dados

```
1. DETECTAR
   - Alerta de monitoramento
   - Report de usuário
   
2. CLASSIFICAR
   - Escopo: parcial ou total?
   - Causa: bug, ataque, erro humano?
   
3. CONTER
   - Parar processos afetados
   - Isolar sistemas comprometidos
   
4. RESTAURAR
   - Identificar backup apropriado
   - Executar restore
   - Validar integridade
   
5. COMUNICAR
   - Notificar stakeholders
   - Atualizar status page
   
6. INVESTIGAR
   - Root cause analysis
   - Documentar lições aprendidas
   
7. PREVENIR
   - Implementar correções
   - Atualizar monitoramento
```

### 10.2. Playbook: Comprometimento de Conta

```
1. DETECTAR
   - Login anômalo
   - Múltiplas falhas de MFA
   - Report de usuário
   
2. BLOQUEAR
   - Revogar todas as sessões
   - Forçar logout global
   - Bloquear login temporariamente
   
3. NOTIFICAR
   - Email ao usuário
   - Alerta na dashboard
   
4. RECUPERAR
   - Verificar identidade
   - Resetar credenciais
   - Gerar novos recovery codes
   
5. AUDITAR
   - Revisar logs de atividade
   - Identificar ações do atacante
   - Reverter mudanças maliciosas
```

---

## 11. Ferramentas

| Ferramenta | Uso |
|------------|-----|
| pg_dump / pg_restore | Backup/restore PostgreSQL |
| WAL-G | WAL archiving |
| AWS S3 | Armazenamento de backups |
| AWS KMS | Gerenciamento de chaves |
| Terraform | Infraestrutura como código |
| GitHub Actions | Automação de testes |

---

## 12. Métricas e Monitoring

### 12.1. Métricas de Backup

- **Backup Success Rate:** > 99.9%
- **Backup Duration:** < 2 horas (full)
- **Restore Duration:** < 30 minutos (teste)
- **Backup Size:** Trend analysis

### 12.2. Alertas

| Condição | Severidade | Ação |
|----------|------------|------|
| Backup falhou | P1 | Notificar on-call |
| Backup atrasado > 2h | P2 | Investigar |
| Restore teste falhou | P1 | Investigar imediatamente |
| Espaço backup > 80% | P3 | Planejar expansão |

---

## 13. Referências

- NIST SP 800-34 (Contingency Planning Guide)
- AWS Backup Best Practices
- PostgreSQL Backup and Recovery
- S3 Object Lock Documentation

---

*Documento criado: 2024*
*Versão: 1.0*
*Status: EM REVISÃO*

**Este documento deve ser testado e validado trimestralmente.**
