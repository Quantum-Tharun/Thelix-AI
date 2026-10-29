-- ==============================================================================
-- Thelix AI Migration 003: Durable Outbox Scan Tasks Schema
-- Target: Supabase / PostgreSQL (Production & Staging)
-- Description: Adds lease, retry, and payload columns to scan_tasks to support
--              out-of-process durable background scan worker claiming via
--              SELECT ... FOR UPDATE SKIP LOCKED.
-- ==============================================================================

BEGIN;

-- 1. Add durable outbox worker columns to public.scan_tasks
ALTER TABLE public.scan_tasks
    ADD COLUMN IF NOT EXISTS lease_owner VARCHAR(64),
    ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS max_attempts INTEGER NOT NULL DEFAULT 3,
    ADD COLUMN IF NOT EXISTS payload_json JSONB NOT NULL DEFAULT '{}'::jsonb;

-- 2. Indexes for efficient atomic worker claiming and lease expiration lookups
CREATE INDEX IF NOT EXISTS idx_scan_tasks_claim 
    ON public.scan_tasks(status, lease_expires_at);

CREATE INDEX IF NOT EXISTS idx_scan_tasks_lease_owner 
    ON public.scan_tasks(lease_owner);

COMMIT;

-- ------------------------------------------------------------------------------
-- ROLLBACK INSTRUCTIONS:
-- ------------------------------------------------------------------------------
-- BEGIN;
-- DROP INDEX IF EXISTS public.idx_scan_tasks_claim;
-- DROP INDEX IF EXISTS public.idx_scan_tasks_lease_owner;
-- ALTER TABLE public.scan_tasks
--     DROP COLUMN IF EXISTS lease_owner,
--     DROP COLUMN IF EXISTS lease_expires_at,
--     DROP COLUMN IF EXISTS attempt_count,
--     DROP COLUMN IF EXISTS max_attempts,
--     DROP COLUMN IF EXISTS payload_json;
-- COMMIT;
