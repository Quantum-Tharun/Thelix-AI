-- ==============================================================================
-- Thelix AI - Supabase PostgreSQL Schema & Row Level Security (RLS)
-- Version: 1.0.0
-- Description: Core schema for scans, tasks, evidence, findings, assessments,
--              feedback, artifacts, and audit events linked to Supabase Auth.
-- ==============================================================================

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ------------------------------------------------------------------------------
-- 1. SCANS TABLE
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    input_type VARCHAR(50) NOT NULL, -- 'url', 'screenshot', 'qr', 'document'
    raw_target TEXT NOT NULL,
    normalized_target TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'QUEUED', -- QUEUED, VALIDATING, EXTRACTING, ANALYZING, AGGREGATING, COMPLETED, PARTIAL, REJECTED, FAILED
    policy_version VARCHAR(20) NOT NULL DEFAULT '1.0.0',
    engine_versions JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_scans_user_id ON public.scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON public.scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON public.scans(created_at DESC);

-- ------------------------------------------------------------------------------
-- 2. SCAN TASKS TABLE (Observability & Per-Engine Latencies)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.scan_tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    engine_name VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'PENDING',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    error_code VARCHAR(50),
    error_message TEXT,
    lease_owner VARCHAR(64),
    lease_expires_at TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    payload_json JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_scan_tasks_scan_id ON public.scan_tasks(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_tasks_claim ON public.scan_tasks(status, lease_expires_at);

-- ------------------------------------------------------------------------------
-- 3. EVIDENCE TABLE (Normalized Atomic Observations)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    indicator_type VARCHAR(100) NOT NULL,
    indicator_value_or_reference TEXT NOT NULL,
    source_engine VARCHAR(100) NOT NULL,
    source_version VARCHAR(20) NOT NULL,
    reliability DOUBLE PRECISION NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    correlation_group VARCHAR(100),
    observation_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

CREATE INDEX IF NOT EXISTS idx_evidence_scan_id ON public.evidence(scan_id);
CREATE INDEX IF NOT EXISTS idx_evidence_indicator ON public.evidence(indicator_type);

-- ------------------------------------------------------------------------------
-- 4. FINDINGS TABLE (Consolidated Security Findings)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    finding_code VARCHAR(100) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL, -- critical, high, medium, low, info
    confidence DOUBLE PRECISION NOT NULL,
    source_engine VARCHAR(100) NOT NULL,
    source_version VARCHAR(20) NOT NULL,
    correlation_group VARCHAR(100),
    evidence_refs_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON public.findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_code ON public.findings(finding_code);

-- ------------------------------------------------------------------------------
-- 5. RISK ASSESSMENTS TABLE (Final Verdict & Narrative Explanation)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.risk_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL UNIQUE REFERENCES public.scans(id) ON DELETE CASCADE,
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    trust_score INTEGER NOT NULL CHECK (trust_score >= 0 AND trust_score <= 100),
    risk_level VARCHAR(20) NOT NULL, -- low, medium, high, critical
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    coverage_ratio DOUBLE PRECISION NOT NULL CHECK (coverage_ratio >= 0.0 AND coverage_ratio <= 1.0),
    recommended_action VARCHAR(20) NOT NULL, -- allow, warn, block, inconclusive
    summary TEXT NOT NULL,
    explanation TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

CREATE INDEX IF NOT EXISTS idx_risk_assessments_scan_id ON public.risk_assessments(scan_id);

-- ------------------------------------------------------------------------------
-- 6. SCAN FEEDBACK TABLE (User Accuracy Ratings)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.scan_feedback (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    rating VARCHAR(50) NOT NULL, -- helpful, false_positive, false_negative, inaccurate
    comments TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

CREATE INDEX IF NOT EXISTS idx_scan_feedback_scan_id ON public.scan_feedback(scan_id);

-- ------------------------------------------------------------------------------
-- 7. AUDIT EVENTS TABLE (Immutable Audit Trail)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES public.scans(id) ON DELETE CASCADE,
    user_id UUID,
    event_type VARCHAR(100) NOT NULL,
    details_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

CREATE INDEX IF NOT EXISTS idx_audit_events_scan_id ON public.audit_events(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON public.audit_events(created_at DESC);

-- ------------------------------------------------------------------------------
-- 8. ARTIFACTS TABLE (Metadata for Uploaded Screenshots/Files)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    artifact_type VARCHAR(50) NOT NULL,
    storage_path TEXT NOT NULL,
    file_hash VARCHAR(64),
    mime_type VARCHAR(100) NOT NULL,
    file_size_bytes INTEGER NOT NULL,
    retention_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

CREATE INDEX IF NOT EXISTS idx_artifacts_scan_id ON public.artifacts(scan_id);

-- ------------------------------------------------------------------------------
-- 9. USER DAILY QUOTAS TABLE (Pilot Rate Limiting & Scan Quotas)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.user_daily_quotas (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    date_key VARCHAR(10) NOT NULL, -- YYYY-MM-DD in UTC
    scan_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_user_daily_quota_unique ON public.user_daily_quotas(user_id, date_key);
CREATE INDEX IF NOT EXISTS idx_user_daily_quotas_user_id ON public.user_daily_quotas(user_id);
CREATE INDEX IF NOT EXISTS idx_user_daily_quotas_date_key ON public.user_daily_quotas(date_key);

-- ------------------------------------------------------------------------------
-- 10. QUOTA REFUND RECORDS TABLE (Idempotent Scan Quota Refunds)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.quota_refund_records (
    id VARCHAR(36) PRIMARY KEY,
    scan_id VARCHAR(36) NOT NULL UNIQUE,
    user_id VARCHAR(64) NOT NULL,
    date_key VARCHAR(10) NOT NULL, -- YYYY-MM-DD in UTC
    refunded_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_quota_refund_records_scan_id ON public.quota_refund_records(scan_id);
CREATE INDEX IF NOT EXISTS idx_quota_refund_records_user_date ON public.quota_refund_records(user_id, date_key);

-- ==============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- ==============================================================================

-- Enable RLS on all tables
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.risk_assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_feedback ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_daily_quotas ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.quota_refund_records ENABLE ROW LEVEL SECURITY;

-- ------------------------------------------------------------------------------
-- Scans Policies
-- ------------------------------------------------------------------------------
CREATE POLICY "Users can only select their own scans"
    ON public.scans FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can only insert their own scans"
    ON public.scans FOR INSERT
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can only update their own scans"
    ON public.scans FOR UPDATE
    USING (auth.uid() = user_id);

CREATE POLICY "Users can only delete their own scans"
    ON public.scans FOR DELETE
    USING (auth.uid() = user_id);

CREATE POLICY "Service role has full access to scans"
    ON public.scans FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- ------------------------------------------------------------------------------
-- Risk Assessments Policies (Users read assessment if they own the parent scan)
-- ------------------------------------------------------------------------------
CREATE POLICY "Users can read assessment for their scans"
    ON public.risk_assessments FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM public.scans
        WHERE public.scans.id = public.risk_assessments.scan_id
        AND public.scans.user_id = auth.uid()
    ));

CREATE POLICY "Service role has full access to risk assessments"
    ON public.risk_assessments FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- ------------------------------------------------------------------------------
-- Findings Policies
-- ------------------------------------------------------------------------------
CREATE POLICY "Users can read findings for their scans"
    ON public.findings FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM public.scans
        WHERE public.scans.id = public.findings.scan_id
        AND public.scans.user_id = auth.uid()
    ));

CREATE POLICY "Service role has full access to findings"
    ON public.findings FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- ------------------------------------------------------------------------------
-- Evidence Policies
-- ------------------------------------------------------------------------------
CREATE POLICY "Users can read evidence for their scans"
    ON public.evidence FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM public.scans
        WHERE public.scans.id = public.evidence.scan_id
        AND public.scans.user_id = auth.uid()
    ));

CREATE POLICY "Service role has full access to evidence"
    ON public.evidence FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- ------------------------------------------------------------------------------
-- Scan Tasks Policies
-- ------------------------------------------------------------------------------
CREATE POLICY "Users can read tasks for their scans"
    ON public.scan_tasks FOR SELECT
    USING (EXISTS (
        SELECT 1 FROM public.scans
        WHERE public.scans.id = public.scan_tasks.scan_id
        AND public.scans.user_id = auth.uid()
    ));

CREATE POLICY "Service role has full access to scan tasks"
    ON public.scan_tasks FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- ------------------------------------------------------------------------------
-- Feedback Policies
-- ------------------------------------------------------------------------------
CREATE POLICY "Users can manage feedback for their scans"
    ON public.scan_feedback FOR ALL
    USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Service role has full access to feedback"
    ON public.scan_feedback FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- ------------------------------------------------------------------------------
-- Audit Events Policies
-- ------------------------------------------------------------------------------
CREATE POLICY "Users can view audit events for their scans"
    ON public.audit_events FOR SELECT
    USING (auth.uid() = user_id OR EXISTS (
        SELECT 1 FROM public.scans
        WHERE public.scans.id = public.audit_events.scan_id
        AND public.scans.user_id = auth.uid()
    ));

CREATE POLICY "Service role has full access to audit events"
    ON public.audit_events FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- ------------------------------------------------------------------------------
-- Daily Quotas & Refund Records Policies
-- ------------------------------------------------------------------------------
CREATE POLICY "Users can read own daily quota"
    ON public.user_daily_quotas FOR SELECT
    USING (auth.uid()::text = user_id);

CREATE POLICY "Service role has full access to daily quotas"
    ON public.user_daily_quotas FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

CREATE POLICY "Service role has full access to quota refund records"
    ON public.quota_refund_records FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);
