-- ==============================================================================
-- Thelix AI Migration 002: User Daily Quotas and Quota Refund Records
-- Target: Supabase / PostgreSQL (Production & Staging)
-- Applies: Safe idempotent DDL for pilot quota reservation and refund idempotency
-- Rollback instructions provided at bottom of file.
-- ==============================================================================

BEGIN;

-- ------------------------------------------------------------------------------
-- 1. USER DAILY QUOTAS TABLE
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.user_daily_quotas (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    date_key VARCHAR(10) NOT NULL, -- YYYY-MM-DD in UTC
    scan_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- ------------------------------------------------------------------------------
-- 2. QUOTA REFUND RECORDS TABLE
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.quota_refund_records (
    id VARCHAR(36) PRIMARY KEY,
    scan_id VARCHAR(36) NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    date_key VARCHAR(10) NOT NULL, -- YYYY-MM-DD in UTC
    refunded_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- Deduplicate refund records, retaining the earliest refund record
WITH refund_survivors AS (
    SELECT 
        scan_id, 
        MIN(id) AS survivor_id
    FROM public.quota_refund_records
    GROUP BY scan_id
    HAVING COUNT(*) > 1
)
DELETE FROM public.quota_refund_records r
USING refund_survivors rs
WHERE r.scan_id = rs.scan_id 
  AND r.id != rs.survivor_id;

CREATE UNIQUE INDEX IF NOT EXISTS ix_quota_refund_records_scan_id ON public.quota_refund_records(scan_id);
CREATE INDEX IF NOT EXISTS idx_quota_refund_records_user_date ON public.quota_refund_records(user_id, date_key);

-- ------------------------------------------------------------------------------
-- 3. RECONCILE AND DEDUPLICATE USER DAILY QUOTAS
-- Cross-references persisted scans, distinct refunds, and quota rows to
-- guarantee accounting correctness without phantom scan inflation.
-- ------------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables 
        WHERE table_schema = 'public' AND table_name = 'scans'
    ) THEN
        -- When scans table is present, cross-reference actual persisted scans and distinct refunds
        WITH reconciled_counts AS (
            SELECT 
                q.user_id,
                q.date_key,
                MAX(q.id) AS survivor_id,
                LEAST(
                    SUM(q.scan_count),
                    GREATEST(
                        MAX(q.scan_count),
                        COALESCE((
                            SELECT COUNT(*) 
                            FROM public.scans s 
                            WHERE s.user_id::text = q.user_id 
                              AND to_char(s.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD') = q.date_key
                        ), 0) - COALESCE((
                            SELECT COUNT(DISTINCT r.scan_id) 
                            FROM public.quota_refund_records r 
                            WHERE r.user_id = q.user_id 
                              AND r.date_key = q.date_key
                        ), 0)
                    )
                ) AS reconciled_count
            FROM public.user_daily_quotas q
            GROUP BY q.user_id, q.date_key
            HAVING COUNT(*) > 1
        )
        UPDATE public.user_daily_quotas u
        SET scan_count = rc.reconciled_count,
            updated_at = timezone('utc'::text, now())
        FROM reconciled_counts rc
        WHERE u.id = rc.survivor_id;
    ELSE
        -- Fallback when scans table is not present: consolidate using highest recorded count
        WITH quota_aggregates AS (
            SELECT user_id, date_key, MAX(scan_count) AS max_scan_count, MAX(id) AS survivor_id
            FROM public.user_daily_quotas
            GROUP BY user_id, date_key
            HAVING COUNT(*) > 1
        )
        UPDATE public.user_daily_quotas u
        SET scan_count = qa.max_scan_count,
            updated_at = timezone('utc'::text, now())
        FROM quota_aggregates qa
        WHERE u.id = qa.survivor_id;
    END IF;
END $$;

-- Delete non-survivor duplicate rows
WITH quota_aggregates AS (
    SELECT 
        user_id, 
        date_key, 
        MAX(id) AS survivor_id
    FROM public.user_daily_quotas
    GROUP BY user_id, date_key
    HAVING COUNT(*) > 1
)
DELETE FROM public.user_daily_quotas u
USING quota_aggregates qa
WHERE u.user_id = qa.user_id 
  AND u.date_key = qa.date_key 
  AND u.id != qa.survivor_id;

CREATE UNIQUE INDEX IF NOT EXISTS ix_user_daily_quota_unique ON public.user_daily_quotas(user_id, date_key);
CREATE INDEX IF NOT EXISTS idx_user_daily_quotas_user_id ON public.user_daily_quotas(user_id);
CREATE INDEX IF NOT EXISTS idx_user_daily_quotas_date_key ON public.user_daily_quotas(date_key);

-- ------------------------------------------------------------------------------
-- 3. ROW LEVEL SECURITY (RLS) POLICIES
-- ------------------------------------------------------------------------------
ALTER TABLE public.user_daily_quotas ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.quota_refund_records ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'user_daily_quotas' AND policyname = 'Users can read own daily quota'
    ) THEN
        CREATE POLICY "Users can read own daily quota"
            ON public.user_daily_quotas FOR SELECT
            USING (auth.uid()::text = user_id);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'user_daily_quotas' AND policyname = 'Service role has full access to daily quotas'
    ) THEN
        CREATE POLICY "Service role has full access to daily quotas"
            ON public.user_daily_quotas FOR ALL
            TO service_role
            USING (true)
            WITH CHECK (true);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'quota_refund_records' AND policyname = 'Service role has full access to quota refund records'
    ) THEN
        CREATE POLICY "Service role has full access to quota refund records"
            ON public.quota_refund_records FOR ALL
            TO service_role
            USING (true)
            WITH CHECK (true);
    END IF;
END $$;

COMMIT;

-- ==============================================================================
-- ROLLBACK PROCEDURE (Run only if reverting this migration):
-- BEGIN;
-- DROP POLICY IF EXISTS "Users can read own daily quota" ON public.user_daily_quotas;
-- DROP POLICY IF EXISTS "Service role has full access to daily quotas" ON public.user_daily_quotas;
-- DROP POLICY IF EXISTS "Service role has full access to quota refund records" ON public.quota_refund_records;
-- DROP TABLE IF EXISTS public.quota_refund_records CASCADE;
-- DROP TABLE IF EXISTS public.user_daily_quotas CASCADE;
-- COMMIT;
-- ==============================================================================
