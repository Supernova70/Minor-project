# Intership-project-V2 Remaining Implementation Guide

## 1. Executive Summary

Intership-project-V2 has a solid baseline for:
- FastAPI app structure
- Email ingestion and persistence
- ML text classification
- Scan and verdict persistence

The core phishing pipeline is not complete yet. URL analysis and attachment analysis are still placeholders in scan orchestration, Alembic migrations are not yet created, and test coverage is minimal.

This guide describes what remains to build, how to build it, and the acceptance criteria for each area.

## 2. Current Status Snapshot

### Implemented
- App factory, routing, and health endpoint
- SQLAlchemy models for emails, attachments, scans, verdicts
- IMAP fetch and email parsing service
- ML text analyzer engine wired into scan flow
- Docker and PostgreSQL compose setup

### Partially Implemented
- Scan pipeline orchestration (currently ML-only)
- Alembic setup (environment exists, migration scripts absent)

### Missing
- URL analyzer engine
- Attachment analyzer engine
- VirusTotal integration client
- Persistent URL and attachment result models
- API-level auth, rate limiting, and caching strategy
- Production-grade tests and CI checks

## 3. Highest-Priority Gaps (P0)

## 3.1 Implement URL Analysis in Pipeline

### Why
Scan currently writes url_score = 0.0 and marks URL analysis as not implemented.

### Files to add
- app/engines/url_analyzer.py
- app/integrations/virustotal.py

### Files to modify
- app/services/scan_service.py
- app/config.py
- pyproject.toml (if additional libs are required)

### Implementation steps
1. Build URL extraction logic from email body_html and body_text.
2. Normalize and deduplicate URLs before scanning.
3. Implement VirusTotal client with:
- API key rotation
- timeout and retry policy
- consistent parsed response schema
4. Add URL risk scoring formula that maps VT results to 0-100.
5. Wire result into ScanService final score aggregation.
6. Store URL breakdown in verdict.breakdown.url.

### Acceptance criteria
- Scan output includes non-zero url_score when malicious/suspicious URLs exist.
- URL extraction works for plain text and HTML emails.
- VirusTotal failures do not crash full scan; they degrade gracefully.

## 3.2 Implement Attachment Analysis in Pipeline

### Why
Attachment analysis score is hardcoded 0.0 and marked not implemented.

### Files to add
- app/engines/attachment_analyzer.py

### Files to modify
- app/services/scan_service.py
- pyproject.toml (install optional analysis dependencies)

### Implementation steps
1. Enumerate email attachments from DB (Attachment records).
2. For each attachment, run static checks:
- extension and MIME mismatch
- macro/document heuristics for Office files
- PE metadata checks for executables
- PDF suspicious object checks
3. Optional: hash-based VT lookup for attachment SHA256.
4. Compute per-attachment risk and aggregate to attachment_score (0-100).
5. Persist detailed breakdown in verdict.breakdown.attachment.

### Acceptance criteria
- Scan output includes attachment_score based on actual files.
- Unsupported file types are handled safely without failure.
- Analyzer results are deterministic for same input.

## 3.3 Add Real Alembic Migration Scripts

### Why
Alembic environment exists but alembic/versions has no migration files.

### Files to modify/create
- alembic/versions/<timestamp>_initial_schema.py
- app/main.py

### Implementation steps
1. Generate initial revision from metadata.
2. Verify all tables and indexes are present in upgrade().
3. Add proper downgrade() logic.
4. Remove create_all usage from startup in production path.
5. Document migration workflow in README.

### Acceptance criteria
- Fresh DB can be created using alembic upgrade head only.
- Schema changes are reproducible via migration history.

## 4. Security and Correctness Gaps (P0/P1)

## 4.1 Secrets Hygiene

### Risk
A real credential appears to be present in local environment configuration. Treat this as leaked.

### Actions
1. Rotate affected email credentials and API keys immediately.
2. Ensure .env remains git-ignored.
3. Keep only placeholders in .env.example.
4. Add startup validation that blocks boot when placeholder secrets are used in production.

## 4.2 Attachment File Path Safety

### Risk
Attachment filenames are used directly when writing to disk.

### Implementation
1. Sanitize filename (remove path separators and control chars).
2. Enforce safe basename policy.
3. Add collision handling (uuid prefix or hash-based naming).
4. Keep original filename in DB metadata.

## 4.3 Message Identity and Deduplication

### Risk
message_id currently uses IMAP sequence id, which is mailbox-session dependent.

### Implementation
1. Parse RFC Message-ID header.
2. Store both remote UID and header message-id when available.
3. Deduplicate using normalized Message-ID first; fallback to hash(sender+subject+date).

## 5. Data Model Enhancements (P1)

To make URL and attachment analysis queryable and auditable, add dedicated result tables.

### New models
- UrlResult
- AttachmentResult

### Suggested fields
- UrlResult: id, scan_id, original_url, normalized_url, vt_malicious, vt_suspicious, vt_harmless, risk_score, raw_payload, created_at
- AttachmentResult: id, scan_id, attachment_id, file_type, risk_score, verdict, static_findings, vt_findings, created_at

### Acceptance criteria
- UI/API can retrieve detailed per-item findings without parsing generic JSON.
- Historical trend queries are possible (e.g., top suspicious domains).

## 6. API Enhancements (P1)

## 6.1 Add Async Scan Job Mode

Current scan endpoint performs work inline, which can time out for real workloads.

### Implementation
1. Add optional async mode in POST /scans/{email_id}.
2. Return 202 Accepted with scan status pending/running.
3. Use a background worker (Celery/RQ/FastAPI background task for first stage).
4. Keep GET /scans/{id} for polling.

## 6.2 Add Filtering and Search

### Endpoints to improve
- GET /emails: filter by sender, date range, has_attachments
- GET /scans: filter by classification, status, score range

### Acceptance criteria
- Pagination plus filters are indexed and performant.

## 6.3 Add Auth and Rate Limiting

### Implementation
1. Add API key or JWT auth for non-health endpoints.
2. Add per-IP rate limits for fetch/scan endpoints.
3. Log denied attempts with structured audit fields.

## 7. Testing and Quality Gaps (P0/P1)

## 7.1 Replace Script-Style Test with pytest Tests

Current tests/test_ml_engine.py is a script, not a standard assert-based pytest suite.

### Add tests
- tests/test_text_analyzer.py
- tests/test_email_service.py
- tests/test_scan_service.py
- tests/test_api_health.py
- tests/test_api_email.py
- tests/test_api_scan.py

### Implementation notes
1. Add fixtures for isolated test database.
2. Mock IMAP and VT integrations.
3. Add deterministic model fixture or monkeypatch analyzer predictions.

### Coverage target
- Minimum 70% for services and engines.

## 7.2 Add CI Checks

### Pipeline steps
1. Ruff/flake8 lint
2. pytest execution
3. Optional mypy for key modules
4. Build Docker image smoke check

## 8. Observability and Operations (P1)

## 8.1 Structured Logging

### Implementation
1. Replace ad-hoc messages with structured logger fields:
- request_id
- email_id
- scan_id
- stage
- latency_ms
2. Add log level policy and correlation id middleware.

## 8.2 Metrics

Add counters/timers for:
- emails fetched
- scan duration
- analyzer failure rate
- VT quota/rate-limit hits

## 9. Recommended Delivery Sequence

## Sprint 1 (Critical)
1. URL analyzer + VT integration
2. Attachment analyzer baseline
3. Alembic initial migration and migration-only DB bootstrap
4. Credential rotation and secret hardening

## Sprint 2 (Stabilization)
1. Result tables (UrlResult, AttachmentResult)
2. Async scan mode
3. Core pytest suite with mocks
4. Structured logging and error taxonomy

## Sprint 3 (Production Readiness)
1. Auth + rate limiting
2. Filters/search on list endpoints
3. CI pipeline + coverage gates
4. Performance tuning and caching

## 10. Definition of Done for V2

V2 is considered implementation-complete when all of the following are true:
- Scan pipeline includes ML, URL, and attachment engines with real scoring.
- Schema is fully migration-driven with Alembic revisions tracked.
- API is protected and rate-limited outside health endpoint.
- Test suite runs in CI with meaningful coverage and stable mocks.
- Logs and metrics allow operational troubleshooting.
- No plaintext secrets are present in repository-tracked files.

## 11. Quick Start Task Checklist

- [ ] Build app/integrations/virustotal.py
- [ ] Build app/engines/url_analyzer.py
- [ ] Build app/engines/attachment_analyzer.py
- [ ] Wire both analyzers into app/services/scan_service.py
- [ ] Add result models and migration scripts
- [ ] Remove startup schema create_all dependency
- [ ] Add pytest-based service and API tests
- [ ] Add auth, throttling, and structured logging
