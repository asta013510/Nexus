-- ZERO Database Initialization Script
-- PostgreSQL 16+ com Row-Level Security e hardening

-- ===========================================================================
-- EXTENSÕES NECESSÁRIAS
-- ===========================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- ===========================================================================
-- SCHEMA PRINCIPAL
-- ===========================================================================

-- O schema será criado via Drizzle ORM na migração
-- Este script configura segurança e políticas

-- ===========================================================================
-- CONFIGURAÇÕES DE SEGURANÇA GLOBAIS
-- ===========================================================================

-- Prevenir criação de databases por usuários normais
ALTER DATABASE zero SET default_transaction_read_only = off;

-- Log todas as conexões
ALTER DATABASE zero SET log_connections = on;
ALTER DATABASE zero SET log_disconnections = on;

-- Log queries lentas (>1s)
ALTER DATABASE zero SET log_min_duration_statement = 1000;

-- ===========================================================================
-- ROW-LEVEL SECURITY (RLS) - Políticas base
-- ===========================================================================

-- Nota: As tabelas serão criadas pelo Drizzle ORM
-- Estas políticas são aplicadas após a criação das tabelas

-- Exemplo de política para users (apenas o próprio usuário pode ver seus dados)
-- ALTER TABLE users ENABLE ROW LEVEL SECURITY;
-- CREATE POLICY users_isolation ON users
--   FOR ALL
--   USING (id = current_setting('app.current_user_id')::uuid);

-- Exemplo de política para documents (apenas owner pode acessar)
-- ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
-- CREATE POLICY documents_owner_isolation ON documents
--   FOR ALL
--   USING (user_id = current_setting('app.current_user_id')::uuid);

-- ===========================================================================
-- ÍNDICES DE PERFORMANCE E SEGURANÇA
-- ===========================================================================

-- Índices já definidos no schema do Drizzle ORM
-- Adicionar índices adicionais se necessário para auditoria

-- Índice composto para audit logs (buscas frequentes)
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_logs_user_timestamp_idx 
--   ON audit_logs(user_id, timestamp DESC);

-- ===========================================================================
-- FUNÇÕES UTILITÁRIAS
-- ===========================================================================

-- Função para gerar UUID v4 seguro
CREATE OR REPLACE FUNCTION generate_secure_uuid()
RETURNS UUID AS $$
BEGIN
  RETURN uuid_generate_v4();
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Função para atualizar timestamp automaticamente
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Função para soft delete
CREATE OR REPLACE FUNCTION soft_delete()
RETURNS TRIGGER AS $$
BEGIN
  NEW.deleted_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ===========================================================================
-- TRIGGERS
-- ===========================================================================

-- Os triggers serão adicionados via migrations do Drizzle ORM

-- ===========================================================================
-- AUDITORIA - Trigger function para capturar mudanças
-- ===========================================================================

CREATE OR REPLACE FUNCTION audit_trigger_function()
RETURNS TRIGGER AS $$
DECLARE
  action VARCHAR(50);
  old_data JSONB;
  new_data JSONB;
BEGIN
  -- Determinar ação
  IF (TG_OP = 'DELETE') THEN
    action := TG_OP || '_OLD';
    old_data := to_jsonb(OLD);
    new_data := NULL;
  ELSIF (TG_OP = 'UPDATE') THEN
    action := TG_OP || '_CHANGED';
    old_data := to_jsonb(OLD);
    new_data := to_jsonb(NEW);
  ELSIF (TG_OP = 'INSERT') THEN
    action := TG_OP;
    old_data := NULL;
    new_data := to_jsonb(NEW);
  END IF;

  -- Inserir log de auditoria (tabela será criada pelo Drizzle)
  -- INSERT INTO audit_logs (action, resource_type, resource_id, old_data, new_data, changed_at)
  -- VALUES (action, TG_TABLE_NAME, COALESCE(NEW.id, OLD.id), old_data, new_data, NOW());

  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ===========================================================================
-- PREVENÇÃO DE OPERAÇÕES PERIGOSAS
-- ===========================================================================

-- Prevenir DROP de tabelas sem permissão especial
-- CREATE EVENT TRIGGER prevent_table_drop
--   ON ddl_command_end
--   WHEN TAG IN ('DROP TABLE')
--   EXECUTE FUNCTION prevent_drop_operation();

-- ===========================================================================
-- MONITORAMENTO
-- ===========================================================================

-- View para monitorar conexões ativas
CREATE OR REPLACE VIEW active_connections AS
SELECT
  pid,
  usename,
  application_name,
  client_addr,
  client_port,
  backend_start,
  state,
  wait_event_type,
  wait_event,
  query
FROM pg_stat_activity
WHERE datname = current_database()
  AND state != 'idle';

-- View para monitorar locks
CREATE OR REPLACE VIEW database_locks AS
SELECT
  locktype,
  database,
  relation::regclass,
  page,
  tuple,
  virtualxid,
  transactionid,
  classid::regclass,
  objid,
  objsubid,
  virtualtransaction,
  pid,
  mode,
  granted
FROM pg_locks
WHERE database = (SELECT oid FROM pg_database WHERE datname = current_database());

-- ===========================================================================
-- CLEANUP AUTOMÁTICO (manutenção)
-- ===========================================================================

-- Configurar autovacuum agressivo para tabelas de alta rotatividade
-- ALTER TABLE sessions SET (autovacuum_vacuum_scale_factor = 0.1);
-- ALTER TABLE sessions SET (autovacuum_analyze_scale_factor = 0.05);

-- ===========================================================================
-- COMENTÁRIOS DE SEGURANÇA
-- ===========================================================================

COMMENT ON DATABASE zero IS 'ZERO - Central de Segurança Pessoal. Dados sensíveis. Acesso restrito.';

-- ===========================================================================
-- NOTA IMPORTANTE
-- ===========================================================================
-- 
-- Este script é executado APENAS na inicialização do banco.
-- 
-- Para migrations subsequentes, usar Drizzle Kit:
--   npm run db:migrate
--
-- Para produção:
--   - Habilitar SSL obrigatório
--   - Configurar autenticação scram-sha-256
--   - Restringir acesso por IP
--   - Habilitar audit logging completo
--   - Configurar backups point-in-time
--
-- ===========================================================================
