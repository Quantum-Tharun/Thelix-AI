# Database Schema (AI & Risk Entities)

Tharika (Backend Engineer) is responsible for the overall PostgreSQL/Supabase database structure, but as the System Architect, I dictate the shape of the AI and Risk tables to ensure they perfectly accommodate the Risk Engine's output.

## Table: `ai_analysis_logs`
Stores the raw evidence and AI processing metadata for every request.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | Primary Key | Unique analysis ID |
| `user_id` | UUID | Foreign Key -> `users` | User who initiated the request |
| `request_type` | VARCHAR | NOT NULL | e.g., 'screenshot', 'url', 'qr' |
| `raw_input_hash` | VARCHAR | | Hash of input for deduplication/caching |
| `evidence_json` | JSONB | NOT NULL | Raw outputs from OCR, Safe Browsing, etc. |
| `model_versions` | JSONB | NOT NULL | E.g., `{"ocr": "v1.2", "scam_nlp": "gemma-2b"}` |
| `processed_offline`| BOOLEAN | NOT NULL | True if resolved without internet |
| `latency_ms` | INTEGER | NOT NULL | Total processing time for observability |
| `created_at` | TIMESTAMPTZ | Default NOW() | Timestamp of analysis |

## Table: `risk_reports`
Stores the finalized Trust Score and explanations shown to the user. This maps 1:1 to the `Base Uniform Response` contract.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | Primary Key | Unique report ID |
| `analysis_id` | UUID | Foreign Key -> `ai_analysis_logs` | Link to the raw AI data |
| `user_id` | UUID | Foreign Key -> `users` | User who received the report |
| `trust_score` | INTEGER | Check (0-100) | Final aggregated safe score |
| `risk_score` | INTEGER | Check (0-100) | Final aggregated danger score |
| `threat_level` | VARCHAR | NOT NULL | 'Low', 'Medium', 'High', 'Critical' |
| `reasons` | JSONB | NOT NULL | Array of strings (e.g., ["Suspicious URL"]) |
| `recommendations`| JSONB | NOT NULL | Array of strings (e.g., ["Delete message"]) |
| `explanation` | TEXT | | Human-readable LLM explanation |
| `user_feedback` | VARCHAR | | Optional user rating (e.g., 'helpful', 'inaccurate') |
| `created_at` | TIMESTAMPTZ | Default NOW() | |

## Privacy Rules
- PII (Personally Identifiable Information) extracted from OCR must **never** be stored in `evidence_json` unless explicitly required and consented to.
- Base64 image data is **never** stored in the database. It is processed in memory and discarded.
