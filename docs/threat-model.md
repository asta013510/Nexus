# ZERO — Threat Model

## 1. Visão Geral

Este documento apresenta o modelo de ameaças (Threat Model) para o sistema ZERO, uma central de segurança pessoal para armazenamento e gerenciamento de documentos e informações críticas.

O modelo segue metodologias reconhecidas (STRIDE, OWASP ASVS, Zero Trust) e identifica ativos, superfícies de ataque, limites de confiança, ameaças, capacidades do atacante, impacto, probabilidade e mitigações.

---

## 2. Ativos Críticos

### 2.1. Dados Sensíveis
| Ativo | Descrição | Classificação |
|-------|-----------|---------------|
| Documentos do usuário | Arquivos armazenados (PDFs, imagens, etc.) | CRÍTICO |
| Templates biométricos faciais | Representações matemáticas de características faciais | CRÍTICO |
| Credenciais de autenticação | Hashes de senha, chaves de recuperação, seeds MFA | CRÍTICO |
| Chaves de criptografia | Chaves mestras, chaves derivadas, envelopes | CRÍTICO |
| Tokens de sessão | JWTs, refresh tokens, session IDs | ALTO |
| Logs de auditoria | Histórico de eventos de segurança | ALTO |
| Metadados de documentos | Nomes, tamanhos, hashes, timestamps | MÉDIO |
| Informações de dispositivos | User agents, IPs, fingerprints | MÉDIO |

### 2.2. Infraestrutura
| Ativo | Descrição | Classificação |
|-------|-----------|---------------|
| Banco de dados | PostgreSQL com dados estruturados | CRÍTICO |
| Object Storage | S3-compatible para arquivos criptografados | CRÍTICO |
| Servidores de aplicação | API e frontend | ALTO |
| Sistema de cache | Redis para sessões e rate limiting | ALTO |
| Chaves de infraestrutura | Secrets de banco, storage, serviços externos | CRÍTICO |

---

## 3. Trust Boundaries (Limites de Confiança)

```
┌─────────────────────────────────────────────────────────────────┐
│                    ZONA NÃO CONFIÁVEL                           │
│                                                                 │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐       │
│  │   Browser   │     │  Dispositivo│     │    Rede     │       │
│  │   (Cliente) │     │   Móvel     │     │  Pública    │       │
│  └──────┬──────┘     └──────┬──────┘     └──────┬──────┘       │
│         │                   │                   │               │
│         └───────────────────┼───────────────────┘               │
│                             │                                   │
│                     [TRUST BOUNDARY]                            │
│                             │                                   │
├─────────────────────────────┼───────────────────────────────────┤
│                    ZONA SEMI-CONFIÁVEL                          │
│                             │                                   │
│                     ┌───────▼───────┐                           │
│                     │  API Gateway  │                           │
│                     │  / Load Bal.  │                           │
│                     └───────┬───────┘                           │
│                             │                                   │
│                     [TRUST BOUNDARY]                            │
│                             │                                   │
├─────────────────────────────┼───────────────────────────────────┤
│                    ZONA CONFIÁVEL                               │
│                             │                                   │
│            ┌────────────────┼────────────────┐                  │
│            │                │                │                  │
│     ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐          │
│     │  Backend    │  │   Banco     │  │   Storage   │          │
│     │  API        │  │  de Dados   │  │  de Arquivos│          │
│     └──────┬──────┘  └──────┬──────┘  └──────┬──────┘          │
│            │                │                │                  │
│     ┌──────▼──────┐  ┌──────▼──────┐  ┌──────▼──────┐          │
│     │   Cache     │  │   KMS       │  │    Logs     │          │
│     │   (Redis)   │  │  (Chaves)   │  │  Auditoria  │          │
│     └─────────────┘  └─────────────┘  └─────────────┘          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Limites identificados:**

1. **Cliente ↔ Backend**: O cliente nunca é confiável. Toda validação deve ocorrer no backend.
2. **Backend ↔ Banco de Dados**: Query parameterization obrigatória. Credentials isolados.
3. **Backend ↔ Storage**: Acesso via IAM/credentials restritos. Criptografia em repouso.
4. **Serviços Internos**: Autenticação mútua entre serviços quando aplicável.
5. **Humano ↔ Sistema**: Admins não devem ter acesso direto a dados descriptografados.

---

## 4. Análise STRIDE

### 4.1. Spoofing (Falsificação de Identidade)

| ID | Ameaça | Impacto | Probabilidade | Mitigação |
|----|--------|---------|---------------|-----------|
| SP-01 | Atacante falsifica credenciais de login | CRÍTICO | ALTA | - Hash de senhas com Argon2id<br>- Rate limiting agressivo<br>- MFA obrigatório<br>- Detecção de anomalias |
| SP-02 | Atacante usa foto/vídeo para burlar biometria facial | CRÍTICO | MÉDIA | - Liveness detection<br>- Detecção de profundidade<br>- Análise de textura/micro-movimentos<br>- Limitação de tentativas<br>- Biometria como fator adicional, não único |
| SP-03 | Session hijacking via roubo de token | ALTO | ALTA | - Tokens de curta duração<br>- Refresh tokens revogáveis<br>- Binding de sessão a fingerprint do dispositivo<br>- HTTPS obrigatório com HSTS<br>- Cookie flags: Secure, HttpOnly, SameSite=Strict |
| SP-04 | Atacante se passa por serviço interno (SSRF) | ALTO | MÉDIA | - Validação estrita de URLs outbound<br>- Network segmentation<br>- Egress filtering<br>- Service mesh com mTLS |
| SP-05 | Credential stuffing com credenciais vazadas | ALTO | ALTA | - Verificação contra listas de senhas vazadas<br>- Rate limiting por IP e usuário<br>- MFA obrigatório<br>- Monitoramento de padrões de login |

### 4.2. Tampering (Violação de Integridade)

| ID | Ameaça | Impacto | Probabilidade | Mitigação |
|----|--------|---------|---------------|-----------|
| TM-01 | Manipulação de dados no banco | CRÍTICO | BAIXA | - Constraints de integridade<br>- Audit logs imutáveis<br>- Hash de integridade em documentos<br>- Backup versionado e testado |
| TM-02 | Modificação de arquivos em storage | CRÍTICO | BAIXA | - Imutabilidade do storage quando possível<br>- Hash criptográfico verificado no download<br>- Versionamento de documentos<br>- WORM (Write Once Read Many) para logs |
| TM-03 | Alteração de logs de auditoria | ALTO | MÉDIA | - Logs enviados para sistema externo<br>- Assinatura digital de logs críticos<br>- Append-only logging<br>- Alertas para exclusão/modificação de logs |
| TM-04 | Manipulação de parâmetros na API (IDOR) | ALTO | ALTA | - Autorização em todos os endpoints<br>- Validação de ownership<br>- UUIDs imprevisíveis<br>- Nunca confiar em IDs do cliente |
| TM-05 | CSRF - execução de ações não autorizadas | ALTO | MÉDIA | - CSRF tokens em todas as mutations<br>- SameSite cookies<br>- Validação de Origin/Referer headers |

### 4.3. Repudiation (Repúdio de Ações)

| ID | Ameaça | Impacto | Probabilidade | Mitigação |
|----|--------|---------|---------------|-----------|
| RP-01 | Usuário nega ter realizado ação crítica | ALTO | MÉDIA | - Audit logs completos<br>- Timestamp preciso<br>- Contexto da operação (IP, device, location)<br>- Confirmação explícita para operações críticas |
| RP-02 | Admin nega ação administrativa | ALTO | BAIXA | - Logs administrativos separados<br>- Aprovação múltipla para ações sensíveis<br>- Assinatura de logs críticos |
| RP-03 | Sistema não consegue provar origem de dado | MÉDIO | BAIXA | - Hash de integridade em documentos<br>- Cadeia de custódia registrada<br>- Metadados de proveniência |

### 4.4. Information Disclosure (Vazamento de Informação)

| ID | Ameaça | Impacto | Probabilidade | Mitigação |
|----|--------|---------|---------------|-----------|
| ID-01 | Vazamento de banco de dados | CRÍTICO | MÉDIA | - Criptografia em repouso (AES-256-GCM)<br>- Separação de chaves e dados<br>- TDE (Transparent Data Encryption)<br>- Column-level encryption para dados sensíveis |
| ID-02 | Vazamento de backups | CRÍTICO | MÉDIA | - Backups criptografados<br>- Chaves de backup separadas<br>- Armazenamento offline/air-gapped<br>- Testes de restauração periódicos |
| ID-03 | Exposição de templates biométricos | CRÍTICO | BAIXA | - Não armazenar imagens brutas<br>- Templates irreversíveis quando possível<br>- Armazenamento em enclave seguro/HSM<br>- Criptografia adicional para dados biométricos |
| ID-04 | Logs contendo dados sensíveis | ALTO | MÉDIA | - Sanitização de logs<br>- Não logar passwords, tokens, dados biométricos<br>- Log masking para PII<br>- Revisão automatizada de logs |
| ID-05 | Side-channel attacks (timing, cache) | MÉDIO | BAIXA | - Constant-time comparisons para secrets<br>- Rate limiting uniforme<br>- Isolamento de processos críticos |
| ID-06 | Erros revelando informações internas | MÉDIO | ALTA | - Error messages genéricas para usuários<br>- Logging detalhado apenas no backend<br>- Não expor stack traces<br>- Custom error pages |

### 4.5. Denial of Service (Negação de Serviço)

| ID | Ameaça | Impacto | Probabilidade | Mitigação |
|----|--------|---------|---------------|-----------|
| DS-01 | DDoS na camada de rede | ALTO | ALTA | - CDN/WAF na borda<br>- Rate limiting distribuído<br>- Auto-scaling quando aplicável<br>- Circuit breakers |
| DS-02 | Exhaustion de recursos (CPU, memória) | ALTO | MÉDIA | - Limites de upload (tamanho, taxa)<br>- Timeouts em todas as operações<br>- Resource quotas por usuário<br>- Queue management para operações pesadas |
| DS-03 | Brute force em autenticação | ALTO | ALTA | - Rate limiting progressivo<br>- Account lockout temporário<br>- CAPTCHA após falhas<br>- Delay exponencial entre tentativas |
| DS-04 | Amplification attacks | MÉDIO | MÉDIA | - Limites de response size<br>- Validação de input sizes<br>- Proteção contra GraphQL batching abuse |
| DS-05 | Resource exhaustion via uploads | ALTO | MÉDIA | - Limites rígidos de tamanho de arquivo<br>- Validação de tipo antes de processar<br>- Quotas de armazenamento por usuário<br>- Cleanup de arquivos órfãos |

### 4.6. Elevation of Privilege (Elevação de Privilégio)

| ID | Ameaça | Impacto | Probabilidade | Mitigação |
|----|--------|---------|---------------|-----------|
| EP-01 | Usuário acessa dados de outro usuário | CRÍTICO | MÉDIA | - Isolamento lógico rigoroso (tenant isolation)<br>- Validação de ownership em cada query<br>- Row-level security no banco<br>- Testes automatizados de isolamento |
| EP-02 | Escalação para admin | CRÍTICO | BAIXA | - RBAC estrito<br>- Separação de duties<br>- Admin actions requerem step-up auth<br>- Audit logs para todas as ações privilegiadas |
| EP-03 | Injeção de SQL/NoSQL | CRÍTICO | MÉDIA | - Prepared statements obrigatórios<br>- ORM com parameterization<br>- Input validation rigoroso<br>- Least privilege em database users |
| EP-04 | Injeção de comandos OS | CRÍTICO | BAIXA | - Nunca concatenar input em shell commands<br>- Sandboxing de processamento de arquivos<br>- Containers com privilégios mínimos<br>- AppArmor/SELinux profiles |
| EP-05 | Path traversal em arquivos | CRÍTICO | MÉDIA | - Sanitização de paths<br>- Uso de IDs opacos ao invés de paths<br>- Confinamento em diretórios específicos<br>- Validação de extensão e MIME type |

---

## 5. Cenários de Ataque Específicos

### 5.1. Ataque ao Sistema Biométrico Facial

**Cenário:** Atacante tenta usar foto, vídeo ou máscara para autenticar-se como vítima.

**Capacidades do Atacante:**
- Acesso a fotos públicas da vítima (redes sociais)
- Capacidade de criar vídeos deepfake
- Acesso a impressora 3D para máscaras
- Equipamento de gravação de alta qualidade

**Impacto:** Acesso total à conta se biometria for fator único.

**Mitigações Implementadas:**
1. **Liveness Detection Ativa:** Solicitação de movimentos aleatórios (piscar, virar cabeça)
2. **Análise de Textura:** Detecção de padrões de tela vs. pele real
3. **Profundidade 3D:** Uso de câmera depth quando disponível
4. **Detecção de Reflexo:** Análise de padrões de luz em telas
5. **Limite de Tentativas:** Máximo 5 tentativas consecutivas
6. **Biometria como Fator Adicional:** Nunca fator único de autenticação
7. **Fallback Seguro:** Senha + MFA como alternativa
8. **Template Irreversível:** Armazenar apenas hash do template, não imagem

**Risco Residual:** MÉDIO - Ataques sofisticados podem bypass liveness detection básica.

### 5.2. Comprometimento do Banco de Dados

**Cenário:** Atacante obtém cópia completa do banco de dados via SQL injection ou backup vazado.

**Capacidades do Atacante:**
- Exploração de vulnerabilidade SQLi
- Acesso físico ao servidor de backup
- Insider threat com acesso ao DB

**Impacto:** Exposição de todos os metadados, hashes de senha, templates biométricos.

**Mitigações Implementadas:**
1. **Criptografia em Repouso:** AES-256-GCM para todo o banco
2. **Separação de Chaves:** Chaves de criptografia em KMS separado
3. **Hash de Senhas:** Argon2id com salt único por usuário
4. **Column Encryption:** Dados biométricos com criptografia adicional
5. **Query Parameterization:** ORM com prepared statements
6. **Least Privilege:** Database user com permissões mínimas
7. **Audit Logging:** Todas as queries sensíveis logadas

**Risco Residual:** BAIXO - Dados criptografados são inúteis sem chaves.

### 5.3. Roubo de Sessão

**Cenário:** Atacante intercepta token de sessão via XSS, MITM ou malware no dispositivo.

**Capacidades do Atacante:**
- Exploração de XSS no frontend
- MITM em rede não segura
- Malware no dispositivo do usuário

**Impacto:** Acesso à conta enquanto sessão estiver válida.

**Mitigações Implementadas:**
1. **Tokens de Curta Duração:** Access tokens expiram em 15 minutos
2. **Refresh Tokens Revogáveis:** Armazenados no backend, verificáveis
3. **Device Fingerprinting:** Binding de sessão a características do dispositivo
4. **HTTPS Obrigatório:** HSTS habilitado
5. **Cookie Security:** Secure, HttpOnly, SameSite=Strict
6. **Detecção de Anomalia:** Alertas para mudança de IP/location
7. **Revogação Imediata:** Logout em todos os dispositivos disponível

**Risco Residual:** MÉDIO - Sessão roubada é válida até expiração/detecção.

### 5.4. Ataque de Força Bruta

**Cenário:** Atacante tenta adivinhar senha via tentativa repetida.

**Capacidades do Atacante:**
- Botnet para distribuição de requisições
- Lista de senhas comuns/vazadas
- Múltiplos IPs para bypass de rate limit

**Impacto:** Acesso à conta se senha for fraca.

**Mitigações Implementadas:**
1. **Rate Limiting Progressivo:** Delays exponenciais entre tentativas
2. **Account Lockout Temporário:** Bloqueio após 10 falhas consecutivas
3. **CAPTCHA:** Após 5 falhas
4. **Verificação de Senhas Vazadas:** Checagem contra HaveIBeenPwned
5. **Política de Senha Forte:** Mínimo 12 caracteres, complexidade
6. **MFA Obrigatório:** Mesmo com senha correta, requer segundo fator
7. **Monitoramento:** Alertas para padrões de brute force

**Risco Residual:** BAIXO - MFA torna brute force ineficaz.

### 5.5. Upload de Arquivo Malicioso

**Cenário:** Usuário (ou atacante) faz upload de arquivo executável disfarçado.

**Capacidades do Atacante:**
- Criação de arquivos poliglota
- Exploração de vulnerabilidades em visualizadores
- Social engineering para download/execução

**Impacto:** Comprometimento do servidor ou de outros usuários.

**Mitigações Implementadas:**
1. **Validação de MIME Type:** Verificação real do conteúdo, não extensão
2. **Limites de Tamanho:** Máximo definido por tipo de arquivo
3. **Quarentena:** Arquivos novos em área isolada
4. **Sanitização:** Remoção de metadados potencialmente perigosos
5. **Content-Disposition:** Forçar download ao invés de execução inline
6. **CSP Headers:** Prevenir execução de scripts em visualizadores
7. **Antivírus/Sandbox:** Integração futura para scanning

**Risco Residual:** MÉDIO - Novos vetores de ataque podem surgir.

---

## 6. Matriz de Riscos

| Risco | Impacto | Probabilidade | Risco Inicial | Mitigações | Risco Residual |
|-------|---------|---------------|---------------|------------|----------------|
| Vazamento de banco de dados | CRÍTICO | MÉDIA | CRÍTICO | Criptografia, separação de chaves | BAIXO |
| Roubo de sessão | ALTO | ALTA | CRÍTICO | Tokens curtos, revogação, fingerprinting | MÉDIO |
| Bypass de biometria facial | CRÍTICO | MÉDIA | CRÍTICO | Liveness, MFA, limite de tentativas | MÉDIO |
| Brute force de senha | ALTO | ALTA | CRÍTICO | Rate limiting, MFA, lockout | BAIXO |
| IDOR / acesso cruzado | CRÍTICO | MÉDIA | CRÍTICO | Validação de ownership, RLS | BAIXO |
| Injeção SQL | CRÍTICO | MÉDIA | CRÍTICO | Prepared statements, ORM | BAIXO |
| XSS refletido/armazenado | ALTO | MÉDIA | ALTO | CSP, escaping, sanitização | MÉDIO |
| CSRF | ALTO | MÉDIA | ALTO | CSRF tokens, SameSite cookies | BAIXO |
| DDoS | ALTO | ALTA | ALTO | CDN, rate limiting, auto-scaling | MÉDIO |
| Upload malicioso | ALTO | MÉDIA | ALTO | Validação, quarentena, CSP | MÉDIO |
| Vazamento de backup | CRÍTICO | BAIXA | CRÍTICO | Backup criptografado, chaves separadas | BAIXO |
| Insider threat | CRÍTICO | BAIXA | ALTO | Least privilege, audit logs, segregation | MÉDIO |
| Perda de chaves de criptografia | CRÍTICO | BAIXA | CRÍTICO | Backup de chaves, HSM, recovery | BAIXO |
| Comprometimento de dependência | ALTO | MÉDIA | ALTO | Lock versions, audit dependencies, SCA | MÉDIO |

---

## 7. Requisitos de Segurança (OWASP ASVS)

### Nível 2 (Recomendado para aplicação padrão)

**V1 - Arquitetura e Design**
- [x] Documentação de requisitos de segurança
- [x] Threat model documentado
- [ ] Segregação de componentes críticos
- [ ] Princípio de menor privilégio aplicado

**V2 - Autenticação**
- [ ] Senhas com mínimo 12 caracteres
- [ ] Armazenamento de senhas com Argon2id/bcrypt/scrypt
- [ ] MFA disponível e incentivado
- [ ] Proteção contra brute force
- [ ] Gerenciamento seguro de sessões

**V3 - Gestão de Sessão**
- [ ] IDs de sessão seguros e únicos
- [ ] Expiração de sessão configurada
- [ ] Renovação de ID de sessão após login
- [ ] Invalidação de sessão no logout

**V4 - Controle de Acesso**
- [ ] Princípio de negação por padrão
- [ ] Validação de autorização em cada requisição
- [ ] Isolamento de tenants/usuários
- [ ] Proteção contra IDOR

**V5 - Validação de Input**
- [ ] Validação de tipo, comprimento, formato
- [ ] Sanitização de output
- [ ] Proteção contra injection (SQL, OS, LDAP)
- [ ] Validação de uploads de arquivos

**V6 - Criptografia**
- [ ] TLS 1.2+ em trânsito
- [ ] AES-256-GCM em repouso
- [ ] Gerenciamento seguro de chaves
- [ ] Hashing seguro para senhas

**V7 - Logs e Monitoramento**
- [ ] Logs de eventos de segurança
- [ ] Proteção contra manipulação de logs
- [ ] Alertas para atividades suspeitas
- [ ] Não logar dados sensíveis

**V8 - Tratamento de Erros**
- [ ] Mensagens de erro genéricas
- [ ] Sem exposição de stack traces
- [ ] Logging detalhado no backend

**V9 - Proteção de Dados**
- [ ] Minimização de dados coletados
- [ ] Criptografia de dados sensíveis
- [ ] Retenção adequada de dados
- [ ] Destruição segura de dados

**V10 - Comunicação**
- [ ] Validação de certificados TLS
- [ ] HSTS habilitado
- [ ] Cookies seguros

**V11 - Business Logic**
- [ ] Validação de fluxo de negócio
- [ ] Prevenção de abuso de funcionalidades
- [ ] Rate limiting apropriado

**V12 - Files and Resources**
- [ ] Validação de tipos de arquivo
- [ ] Execução de arquivos desabilitada
- [ ] Scan de malware em uploads

**V13 - Mobile (futuro)**
- [ ] Armazenamento seguro no dispositivo
- [ ] Jailail/root detection
- [ ] Certificate pinning

**V14 - Configuração**
- [ ] Configurações seguras por padrão
- [ ] Remoção de defaults inseguros
- [ ] Hardening de servidores

---

## 8. Capacidades do Atacante (Assunções)

O sistema é projetado assumindo que o atacante pode:

1. **Rede:**
   - Interceptar tráfego não criptografado
   - Realizar MITM em redes comprometidas
   - Executar ataques DDoS
   - Spoofear IPs (limitado)

2. **Cliente:**
   - Comprometer dispositivos de usuários
   - Instalar malware/keyloggers
   - Acessar browsers via XSS
   - Roubar tokens de sessão

3. **Aplicação:**
   - Explorar vulnerabilidades conhecidas
   - Tentar SQL injection, XSS, CSRF
   - Realizar enumeração de usuários
   - Testar credenciais vazadas

4. **Infraestrutura:**
   - Acessar backups físicos
   - Comprometer servidores via vulnerabilidades
   - Explorar configurações incorretas
   - Realizar insider attacks

5. **Dados:**
   - Obter cópias de bancos de dados
   - Acessar storage de arquivos
   - Interceptar comunicações internas

**O sistema NÃO assume proteção contra:**
- Ataques de estado-nação com recursos ilimitados
- Comprometimento físico completo do datacenter
- Tortura/coerção de administradores
- Vulnerabilidades zero-day em bibliotecas fundamentais

---

## 9. Riscos Resíduos Aceitos

Após mitigação, os seguintes riscos residuais são considerados aceitáveis:

| Risco | Nível Residual | Justificativa |
|-------|----------------|---------------|
| Sessão roubada (janela de 15min) | MÉDIO | Token de curta duração limita dano; detecção de anomalia pode reduzir janela |
| Bypass de liveness detection sofisticado | MÉDIO | Biometria é fator adicional; MFA previne acesso total |
| DDoS prolongado | MÉDIO | CDN e infra estruturada mitigam, mas não eliminam completamente |
| Upload de arquivo malicioso desconhecido | MÉDIO | Validação reduz superfície; sandbox futuro adicionará camada |
| Comprometimento de dependência transitiva | MÉDIO | Audit e lock de versões reduzem risco; impossível eliminar completamente |

---

## 10. Próximos Passos

1. **Revisão do Threat Model:** Atualizar trimestralmente ou após mudanças arquiteturais significativas
2. **Validação de Controles:** Testar cada mitigação implementada
3. **Penetration Testing:** Contratar teste de penetração externo antes de produção
4. **Bug Bounty:** Considerar programa de recompensas após lançamento
5. **Monitoramento Contínuo:** Implementar SIEM para detecção de ameaças
6. **Treinamento:** Desenvolvedores devem entender ameaças identificadas

---

## 11. Referências

- OWASP Application Security Verification Standard (ASVS) 4.0
- OWASP Top 10 2021
- STRIDE Threat Model (Microsoft)
- NIST Cybersecurity Framework
- Zero Trust Architecture (NIST SP 800-207)
- CWE/SANS Top 25 Most Dangerous Software Errors

---

*Documento criado: $(date)*
*Versão: 1.0*
*Status: EM REVISÃO*
