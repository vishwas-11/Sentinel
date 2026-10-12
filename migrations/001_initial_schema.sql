-- =============================================================================
-- Sentinel PostgreSQL Schema for Supabase
-- Migration: 001_initial_schema.sql
-- =============================================================================
--
-- Tables:
-- 1. scans: High-level scan execution summaries and aggregated scoring metrics.
-- 2. attack_results: Granular per-attack evaluation records, verdicts, and mutation lineage.
-- 3. baselines: Named, immutable baseline snapshots for regression comparisons.
--
-- Security & Multi-tenancy:
-- - Includes optional tenant_id columns for future Row Level Security (RLS).
-- - Tables can be queried via Supabase PostgREST REST API (/rest/v1/).
-- =============================================================================

-- Enable pgcrypto for UUID generation if needed
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- -----------------------------------------------------------------------------
-- 1. Table: scans
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    target_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'completed', -- 'running', 'completed', 'failed'
    total_attacks INTEGER NOT NULL,
    evaluated_attacks INTEGER NOT NULL,
    pass_count INTEGER NOT NULL,
    fail_count INTEGER NOT NULL,
    error_count INTEGER NOT NULL,
    skipped_count INTEGER NOT NULL,
    evaluation_coverage DOUBLE PRECISION NOT NULL,
    attack_success_rate DOUBLE PRECISION,
    weighted_penalty INTEGER NOT NULL,
    max_possible_penalty INTEGER NOT NULL,
    security_score DOUBLE PRECISION,
    category_scores JSONB NOT NULL DEFAULT '{}'::jsonb,
    critical_findings JSONB NOT NULL DEFAULT '[]'::jsonb,
    mutation_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    report_schema_version TEXT NOT NULL DEFAULT '1.0.0',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    tenant_id TEXT DEFAULT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_tenant_id ON scans (tenant_id) WHERE tenant_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans (status);

-- -----------------------------------------------------------------------------
-- 2. Table: attack_results
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS attack_results (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    attack_id TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    verdict TEXT NOT NULL,
    weight INTEGER NOT NULL,
    penalty INTEGER NOT NULL,
    included BOOLEAN NOT NULL,
    exclusion_reason TEXT,
    reason TEXT NOT NULL,
    evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
    parent_attack_id TEXT,
    mutation_metadata JSONB DEFAULT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    tenant_id TEXT DEFAULT NULL
);

CREATE INDEX IF NOT EXISTS idx_attack_results_scan_id ON attack_results (scan_id);
CREATE INDEX IF NOT EXISTS idx_attack_results_attack_id ON attack_results (attack_id);
CREATE INDEX IF NOT EXISTS idx_attack_results_verdict ON attack_results (verdict);
CREATE INDEX IF NOT EXISTS idx_attack_results_category ON attack_results (category);
CREATE INDEX IF NOT EXISTS idx_attack_results_parent_attack_id ON attack_results (parent_attack_id) WHERE parent_attack_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_attack_results_tenant_id ON attack_results (tenant_id) WHERE tenant_id IS NOT NULL;

-- -----------------------------------------------------------------------------
-- 3. Table: baselines
-- -----------------------------------------------------------------------------
-- Immutability Principle:
-- A baseline points to an originating scan_id (FOREIGN KEY), but also stores an
-- immutable JSON snapshot of the ScoringReport at the time of baseline creation.
-- This ensures that historical regression gates remain strictly reproducible even
-- if historical records are modified or archived.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS baselines (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    report_snapshot JSONB NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    tenant_id TEXT DEFAULT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_baselines_name ON baselines (name);
CREATE INDEX IF NOT EXISTS idx_baselines_scan_id ON baselines (scan_id);
CREATE INDEX IF NOT EXISTS idx_baselines_created_at ON baselines (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_baselines_tenant_id ON baselines (tenant_id) WHERE tenant_id IS NOT NULL;

-- -----------------------------------------------------------------------------
-- 4. Row Level Security (RLS) Policies (Prepared for Multi-tenancy)
-- -----------------------------------------------------------------------------
-- In Supabase, RLS is enabled per table. When auth is integrated, queries using
-- the Supabase anon or authenticated keys will only see rows where tenant_id
-- matches the current JWT claim: auth.jwt() ->> 'tenant_id'.
-- Service-role keys bypass RLS for administrative operations.
-- -----------------------------------------------------------------------------

ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE attack_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE baselines ENABLE ROW LEVEL SECURITY;

-- Default permissive policy for service_role / development:
-- (Allows full access when tenant_id is NULL or when operating via backend service_role key)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'scans' AND policyname = 'service_role_all_scans'
    ) THEN
        CREATE POLICY service_role_all_scans ON scans FOR ALL USING (true) WITH CHECK (true);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'attack_results' AND policyname = 'service_role_all_results'
    ) THEN
        CREATE POLICY service_role_all_results ON attack_results FOR ALL USING (true) WITH CHECK (true);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE tablename = 'baselines' AND policyname = 'service_role_all_baselines'
    ) THEN
        CREATE POLICY service_role_all_baselines ON baselines FOR ALL USING (true) WITH CHECK (true);
    END IF;
END
$$;
