# PatchPilot Backend

FastAPI backend for PatchPilot.

## Database Schema

SQLite database (`patchpilot.db`) is auto-created in `backend/` on first server startup.

### `jobs`

| Column         | Type | Description                 |
| -------------- | ---- | --------------------------- |
| `job_id`       | TEXT | Primary key                 |
| `project_name` | TEXT | Name of the scanned project |
| `scan_method`  | TEXT | `zip` or `url`              |
| `created_at`   | TEXT | Timestamp of job creation   |

### `findings`

| Column        | Type    | Description                                               |
| ------------- | ------- | --------------------------------------------------------- |
| `id`          | TEXT    | Primary key                                               |
| `job_id`      | TEXT    | Job ID this finding belongs to (references `jobs.job_id`) |
| `rule_id`     | TEXT    | Rule that triggered the finding                           |
| `severity`    | TEXT    | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`               |
| `category`    | TEXT    | Vulnerability category                                    |
| `file_path`   | TEXT    | File where finding was detected                           |
| `line_number` | INTEGER | Line number of the finding                                |
| `cwe`         | TEXT    | CWE identifier                                            |
| `scanner`     | TEXT    | `semgrep`, `osv`, or `gitleaks`                           |
| `message`        | TEXT    | Description of the finding                                |
| `created_at`     | TEXT    | Timestamp of finding creation                             |
| `severity_score` | REAL    | Normalized severity score (0.0–10.0 scale, default: 5.0)  |
| `ml_score`       | REAL    | Machine learning ranking score (0.0–1.0 scale)            |

### Severity Ranking (`severity_score`)

Findings are prioritized using a deterministic 0.0–10.0 normalized score following this precedence:
1. **CVSS Vectors (OSV-Scanner):** Parsed base score across CVSS v2, v3.0, v3.1, and v4.0.
2. **Semgrep Severity:** `CRITICAL` (9.0), `ERROR` (9.0), `WARNING` (6.0), `INFO` (3.0).
3. **Secrets / Entropy:** High entropy (>=4.5) -> 8.0, high-impact secret rules -> 8.0, moderate entropy (>=3.0) -> 6.0, default secrets fallback -> 5.0.
4. **Generic Severity Labels:** `CRITICAL` (9.0), `HIGH` (8.0), `MEDIUM` (5.0), `LOW` (2.0), `INFO` (1.0).
5. **Fallback:** Absent or unrecognized metadata defaults to `5.0` (Medium) to ensure unclassified issues are prioritized above confirmed low-risk issues for triage.
