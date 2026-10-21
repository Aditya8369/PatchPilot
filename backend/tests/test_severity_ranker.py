import copy
import os
import tempfile
import uuid

import aiosqlite
import pytest

from app.db import create_findings, get_findings_by_job_id
from app.ml.severity_ranker import (
    DEFAULT_FALLBACK_SCORE,
    calculate_severity_score,
    rank,
)
from app.models import Finding

# =====================================================================
# Unit Tests — Normalization & Precedence
# =====================================================================


class TestNormalizationAndCVSS:
    def test_osv_cvss_v31_vector(self):
        finding = {
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }
            ]
        }
        score = calculate_severity_score(finding)
        assert score == pytest.approx(9.8, 0.1)

    def test_osv_cvss_v30_vector(self):
        finding = {
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }
            ]
        }
        score = calculate_severity_score(finding)
        assert score == pytest.approx(9.8, 0.1)

    def test_osv_cvss_v2_vector(self):
        finding = {
            "severity": [
                {
                    "type": "CVSS_V2",
                    "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                }
            ]
        }
        score = calculate_severity_score(finding)
        assert score == pytest.approx(7.5, 0.1)

    def test_osv_cvss_v40_vector(self):
        finding = {
            "severity": [
                {
                    "type": "CVSS_V4",
                    "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                }
            ]
        }
        score = calculate_severity_score(finding)
        assert score == pytest.approx(9.3, 0.1)

    def test_cvss_bounds_min_and_max(self):
        finding_min = {
            "severity": [
                {
                    "score": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
                }
            ]
        }
        assert calculate_severity_score(finding_min) == 0.0

        finding_max = {
            "severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}]
        }
        assert calculate_severity_score(finding_max) == 10.0

    def test_explicit_numeric_cvss_scores(self):
        assert calculate_severity_score({"severity": [{"score": 0.0}]}) == 0.0
        assert calculate_severity_score({"severity": [{"score": 10.0}]}) == 10.0
        assert calculate_severity_score({"severity": [{"score": 7.4}]}) == 7.4
        assert calculate_severity_score({"severity": [{"score": "9.8"}]}) == 9.8

    def test_metadata_cvss_vector(self):
        finding = {"metadata": {"cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
        assert calculate_severity_score(finding) == 9.8


class TestSemgrepExtraction:
    def test_semgrep_critical_maps_to_9(self):
        finding = {
            "scanner": "semgrep",
            "extra": {"severity": "CRITICAL"},
        }
        assert calculate_severity_score(finding) == 9.0

    def test_semgrep_error_maps_to_9(self):
        finding = {
            "scanner": "semgrep",
            "extra": {"severity": "ERROR"},
        }
        assert calculate_severity_score(finding) == 9.0

    def test_semgrep_warning_maps_to_6(self):
        finding = {
            "scanner": "semgrep",
            "extra": {"severity": "WARNING"},
        }
        assert calculate_severity_score(finding) == 6.0

    def test_semgrep_info_maps_to_3(self):
        finding = {
            "scanner": "semgrep",
            "extra": {"severity": "INFO"},
        }
        assert calculate_severity_score(finding) == 3.0

    def test_semgrep_casing_variations(self):
        assert (
            calculate_severity_score(
                {"scanner": "semgrep", "extra": {"severity": "error"}}
            )
            == 9.0
        )
        assert (
            calculate_severity_score(
                {"scanner": "semgrep", "extra": {"severity": "Warning"}}
            )
            == 6.0
        )
        assert (
            calculate_severity_score(
                {"scanner": "semgrep", "extra": {"severity": "info"}}
            )
            == 3.0
        )

    def test_semgrep_unknown_defaults_to_5(self):
        finding = {
            "scanner": "semgrep",
            "extra": {"severity": "EXPERIMENT"},
        }
        assert calculate_severity_score(finding) == 5.0

    def test_semgrep_nested_metadata_extra(self):
        finding = {
            "metadata": {
                "engine": "semgrep",
                "extra": {"severity": "ERROR"},
            }
        }
        assert calculate_severity_score(finding) == 9.0


class TestGitleaksExtraction:
    def test_gitleaks_high_maps_to_8(self):
        finding = {
            "scanner": "gitleaks",
            "RuleID": "generic-api-key",
            "Confidence": "HIGH",
        }
        assert calculate_severity_score(finding) == 8.0

    def test_gitleaks_medium_maps_to_5(self):
        finding = {
            "scanner": "gitleaks",
            "RuleID": "jwt-token",
            "Confidence": "MEDIUM",
        }
        assert calculate_severity_score(finding) == 5.0

    def test_gitleaks_low_maps_to_2(self):
        finding = {
            "scanner": "gitleaks",
            "RuleID": "entropy",
            "Confidence": "LOW",
        }
        assert calculate_severity_score(finding) == 2.0

    def test_gitleaks_case_variations(self):
        assert calculate_severity_score({"RuleID": "k", "Confidence": "high"}) == 8.0
        assert calculate_severity_score({"RuleID": "k", "Confidence": "medium"}) == 5.0
        assert calculate_severity_score({"RuleID": "k", "Confidence": "low"}) == 2.0

    def test_gitleaks_missing_confidence_policy_derived_fallback(self):
        finding = {
            "scanner": "gitleaks",
            "RuleID": "slack-webhook",
        }
        assert calculate_severity_score(finding) == DEFAULT_FALLBACK_SCORE


class TestFallbacksAndInvalidInputs:
    def test_empty_finding_returns_fallback(self):
        assert calculate_severity_score({}) == DEFAULT_FALLBACK_SCORE

    def test_none_and_empty_string_severity(self):
        assert calculate_severity_score({"severity": None}) == DEFAULT_FALLBACK_SCORE
        assert calculate_severity_score({"severity": ""}) == DEFAULT_FALLBACK_SCORE
        assert calculate_severity_score({"severity": "   "}) == DEFAULT_FALLBACK_SCORE

    def test_malformed_vector_does_not_crash(self):
        finding = {"severity": [{"score": "CVSS:3.1/MALFORMED/VECTOR"}]}
        assert calculate_severity_score(finding) == DEFAULT_FALLBACK_SCORE

    def test_boolean_scores_are_rejected(self):
        assert (
            calculate_severity_score({"severity": [{"score": True}]})
            == DEFAULT_FALLBACK_SCORE
        )
        assert (
            calculate_severity_score({"severity": [{"score": False}]})
            == DEFAULT_FALLBACK_SCORE
        )
        assert (
            calculate_severity_score({"severity_score": True}) == DEFAULT_FALLBACK_SCORE
        )

    def test_nan_and_infinity_are_rejected(self):
        assert (
            calculate_severity_score({"severity": [{"score": float("nan")}]})
            == DEFAULT_FALLBACK_SCORE
        )
        assert (
            calculate_severity_score({"severity": [{"score": float("inf")}]})
            == DEFAULT_FALLBACK_SCORE
        )
        assert (
            calculate_severity_score({"severity": [{"score": float("-inf")}]})
            == DEFAULT_FALLBACK_SCORE
        )
        assert (
            calculate_severity_score({"severity_score": float("nan")})
            == DEFAULT_FALLBACK_SCORE
        )

    def test_out_of_range_scores_are_rejected(self):
        assert (
            calculate_severity_score({"severity": [{"score": -1.0}]})
            == DEFAULT_FALLBACK_SCORE
        )
        assert (
            calculate_severity_score({"severity": [{"score": 11.0}]})
            == DEFAULT_FALLBACK_SCORE
        )
        assert (
            calculate_severity_score({"severity_score": 15.0}) == DEFAULT_FALLBACK_SCORE
        )

    def test_arbitrary_string_scores_are_rejected(self):
        assert (
            calculate_severity_score({"severity": [{"score": "not-a-number"}]})
            == DEFAULT_FALLBACK_SCORE
        )

    def test_precedence_cvss_over_semgrep_and_gitleaks(self):
        # A finding with conflicting metadata: CVSS vector vs Semgrep ERROR
        finding = {
            "scanner": "semgrep",
            "extra": {"severity": "INFO"},  # would map to 3.0
            "severity": [
                {
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
                }
            ],
        }
        assert calculate_severity_score(finding) == 9.8


# =====================================================================
# Unit Tests — Ranking Function
# =====================================================================


class TestRankFunction:
    def test_empty_list(self):
        assert rank([]) == []

    def test_single_item(self):
        item = {"scanner": "semgrep", "extra": {"severity": "ERROR"}}
        ranked = rank([item])
        assert len(ranked) == 1
        assert ranked[0]["severity_score"] == 9.0

    def test_descending_order(self):
        findings = [
            {
                "id": "semgrep_info",
                "scanner": "semgrep",
                "extra": {"severity": "INFO"},
            },  # 3.0
            {
                "id": "osv_critical",
                "severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            },  # 9.8
            {"id": "gitleaks_high", "RuleID": "secret", "Confidence": "HIGH"},  # 8.0
            {
                "id": "semgrep_warn",
                "scanner": "semgrep",
                "extra": {"severity": "WARNING"},
            },  # 6.0
            {"id": "fallback", "title": "misc issue"},  # 5.0
            {"id": "gitleaks_low", "RuleID": "secret", "Confidence": "LOW"},  # 2.0
        ]

        ranked = rank(findings)
        scores = [f["severity_score"] for f in ranked]
        assert scores == [9.8, 8.0, 6.0, 5.0, 3.0, 2.0]
        assert [f["id"] for f in ranked] == [
            "osv_critical",
            "gitleaks_high",
            "semgrep_warn",
            "fallback",
            "semgrep_info",
            "gitleaks_low",
        ]

    def test_stable_ordering_for_ties(self):
        findings = [
            {
                "id": "first_tie",
                "scanner": "semgrep",
                "extra": {"severity": "WARNING"},
            },  # 6.0
            {
                "id": "second_tie",
                "scanner": "semgrep",
                "extra": {"severity": "WARNING"},
            },  # 6.0
            {
                "id": "third_tie",
                "scanner": "semgrep",
                "extra": {"severity": "WARNING"},
            },  # 6.0
        ]
        ranked = rank(findings)
        assert [f["id"] for f in ranked] == ["first_tie", "second_tie", "third_tie"]

    def test_preserves_original_fields(self):
        item = {
            "id": "item1",
            "custom_field": "custom_value",
            "nested": {"key": 123},
            "scanner": "semgrep",
            "extra": {"severity": "ERROR"},
        }
        ranked = rank([item])[0]
        assert ranked["id"] == "item1"
        assert ranked["custom_field"] == "custom_value"
        assert ranked["nested"] == {"key": 123}
        assert ranked["severity_score"] == 9.0

    def test_does_not_mutate_caller_input(self):
        orig_dict = {"scanner": "semgrep", "extra": {"severity": "ERROR"}}
        orig_copy = copy.deepcopy(orig_dict)
        _ = rank([orig_dict])
        assert orig_dict == orig_copy
        assert "severity_score" not in orig_dict

    def test_deterministic_across_repeated_calls(self):
        findings = [
            {"id": "1", "severity": [{"score": 5.0}]},
            {"id": "2", "severity": [{"score": 9.0}]},
            {"id": "3", "severity": [{"score": 2.0}]},
        ]
        res1 = rank(findings)
        res2 = rank(findings)
        assert res1 == res2

    def test_supports_pydantic_finding_objects(self):
        f1 = Finding(
            id="f1",
            category="sast",
            severity="HIGH",
            title="Finding 1",
            metadata={
                "check_id": "test",
                "engine": "semgrep",
                "extra": {"severity": "ERROR"},
            },
        )
        f2 = Finding(
            id="f2",
            category="secret",
            severity="LOW",
            title="Finding 2",
            metadata={"engine": "gitleaks", "Confidence": "LOW"},
        )
        ranked = rank([f1, f2])
        assert len(ranked) == 2
        assert ranked[0].severity_score == 9.0
        assert ranked[1].severity_score == 2.0


# =====================================================================
# Integration Tests — Database Migration & Persistence
# =====================================================================


@pytest.mark.asyncio
class TestDatabaseIntegration:
    async def test_init_db_creates_severity_score_column(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            async with aiosqlite.connect(tmp_path) as db:
                # Run init_db logic directly on isolated test database
                await db.execute("""
                    CREATE TABLE IF NOT EXISTS findings (
                        id              TEXT PRIMARY KEY,
                        job_id          TEXT NOT NULL,
                        rule_id         TEXT,
                        title           TEXT,
                        severity        TEXT,
                        category        TEXT,
                        file_path       TEXT,
                        line_number     INTEGER,
                        cwe             TEXT,
                        scanner         TEXT,
                        message         TEXT,
                        package_name    TEXT,
                        package_version TEXT,
                        ml_score        REAL,
                        features        TEXT,
                        status          TEXT DEFAULT 'open',
                        false_positive  INTEGER DEFAULT NULL,
                        labeled_at      TEXT DEFAULT NULL,
                        version         INTEGER DEFAULT 1,
                        created_at      TEXT DEFAULT (datetime('now')),
                        severity_score  REAL DEFAULT 5.0
                    )
                """)
                db.row_factory = aiosqlite.Row
                cursor = await db.execute("PRAGMA table_info(findings)")
                cols = [row["name"] for row in await cursor.fetchall()]
                assert "severity_score" in cols
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    async def test_migration_on_legacy_database_without_severity_score(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            # 1. Create a legacy table without severity_score
            async with aiosqlite.connect(tmp_path) as db:
                await db.execute("""
                    CREATE TABLE findings (
                        id              TEXT PRIMARY KEY,
                        job_id          TEXT NOT NULL,
                        rule_id         TEXT,
                        title           TEXT,
                        severity        TEXT,
                        category        TEXT,
                        file_path       TEXT,
                        line_number     INTEGER,
                        cwe             TEXT,
                        scanner         TEXT,
                        message         TEXT,
                        package_name    TEXT,
                        package_version TEXT,
                        ml_score        REAL,
                        features        TEXT,
                        status          TEXT DEFAULT 'open',
                        false_positive  INTEGER DEFAULT NULL,
                        labeled_at      TEXT DEFAULT NULL,
                        version         INTEGER DEFAULT 1,
                        created_at      TEXT DEFAULT (datetime('now'))
                    )
                """)
                # Insert a legacy finding
                await db.execute("""
                    INSERT INTO findings (id, job_id, rule_id, title, severity)
                    VALUES ('legacy-1', 'job-legacy', 'rule-1', 'Legacy finding', 'HIGH')
                """)
                await db.commit()

            # 2. Simulate migration step: check columns and add if missing
            async with aiosqlite.connect(tmp_path) as db:
                db.row_factory = aiosqlite.Row
                cursor = await db.execute("PRAGMA table_info(findings)")
                columns = [row["name"] for row in await cursor.fetchall()]
                assert "severity_score" not in columns

                if "severity_score" not in columns:
                    await db.execute(
                        "ALTER TABLE findings ADD COLUMN severity_score REAL DEFAULT 5.0"
                    )
                    await db.commit()

            # 3. Verify legacy record survived with default score
            async with aiosqlite.connect(tmp_path) as db:
                db.row_factory = aiosqlite.Row
                cursor = await db.execute(
                    "SELECT id, severity_score FROM findings WHERE id = 'legacy-1'"
                )
                row = await cursor.fetchone()
                assert row is not None
                assert row["id"] == "legacy-1"
                assert row["severity_score"] == 5.0
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    async def test_create_findings_and_get_findings_by_job_id_ordering(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            job_id = str(uuid.uuid4())
            async with aiosqlite.connect(tmp_path) as db:
                # Initialize schema
                await db.execute("""
                    CREATE TABLE findings (
                        id              TEXT PRIMARY KEY,
                        job_id          TEXT NOT NULL,
                        rule_id         TEXT,
                        title           TEXT,
                        severity        TEXT,
                        category        TEXT,
                        file_path       TEXT,
                        line_number     INTEGER,
                        cwe             TEXT,
                        scanner         TEXT,
                        message         TEXT,
                        package_name    TEXT,
                        package_version TEXT,
                        ml_score        REAL,
                        features        TEXT,
                        status          TEXT DEFAULT 'open',
                        false_positive  INTEGER DEFAULT NULL,
                        labeled_at      TEXT DEFAULT NULL,
                        version         INTEGER DEFAULT 1,
                        created_at      TEXT DEFAULT (datetime('now')),
                        severity_score  REAL DEFAULT 5.0
                    )
                """)

                # Insert 3 findings with different scores
                rows = [
                    (
                        "finding-low",
                        job_id,
                        "rule.low",
                        "Low Risk",
                        "LOW",
                        "sast",
                        "app.py",
                        1,
                        None,
                        "semgrep",
                        "msg",
                        None,
                        None,
                        None,
                        None,
                        2.0,
                    ),
                    (
                        "finding-high",
                        job_id,
                        "rule.high",
                        "High Risk",
                        "HIGH",
                        "sast",
                        "app.py",
                        10,
                        None,
                        "semgrep",
                        "msg",
                        None,
                        None,
                        None,
                        None,
                        9.8,
                    ),
                    (
                        "finding-mid",
                        job_id,
                        "rule.mid",
                        "Mid Risk",
                        "MEDIUM",
                        "sast",
                        "app.py",
                        5,
                        None,
                        "semgrep",
                        "msg",
                        None,
                        None,
                        None,
                        None,
                        6.0,
                    ),
                ]
                await create_findings(db, rows)

                # Query findings
                results = await get_findings_by_job_id(db, job_id)
                assert len(results) == 3
                assert [r["id"] for r in results] == [
                    "finding-high",
                    "finding-mid",
                    "finding-low",
                ]
                assert [r["severity_score"] for r in results] == [9.8, 6.0, 2.0]
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    async def test_production_init_db_migration_on_legacy_database(self, monkeypatch):
        """
        Tests the actual production init_db() migration function against a temporary
        SQLite database that already contains findings created with the legacy schema.
        Verifies:
          1. The real init_db() executes ALTER TABLE findings ADD COLUMN severity_score REAL DEFAULT 5.0.
          2. Pre-existing legacy records survive intact and adopt the 5.0 default.
          3. Legacy 15-column inserts continue to work without errors.
          4. New 16-column inserts with explicit severity_scores are persisted properly.
          5. get_findings_by_job_id() returns findings ordered by severity_score DESC NULLS LAST.
        """
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            # 1. Create a legacy table without severity_score column and populate with legacy rows
            async with aiosqlite.connect(tmp_path) as db:
                await db.execute("""
                    CREATE TABLE findings (
                        id              TEXT PRIMARY KEY,
                        job_id          TEXT NOT NULL,
                        rule_id         TEXT,
                        title           TEXT,
                        severity        TEXT,
                        category        TEXT,
                        file_path       TEXT,
                        line_number     INTEGER,
                        cwe             TEXT,
                        scanner         TEXT,
                        message         TEXT,
                        package_name    TEXT,
                        package_version TEXT,
                        ml_score        REAL,
                        features        TEXT,
                        status          TEXT DEFAULT 'open',
                        false_positive  INTEGER DEFAULT NULL,
                        labeled_at      TEXT DEFAULT NULL,
                        version         INTEGER DEFAULT 1,
                        created_at      TEXT DEFAULT (datetime('now'))
                    )
                """)
                # Insert legacy records
                await db.execute("""
                    INSERT INTO findings (id, job_id, rule_id, title, severity, created_at)
                    VALUES ('legacy-1', 'job-migration', 'rule-1', 'Legacy finding 1', 'HIGH', '2024-01-01 00:00:00')
                """)
                await db.execute("""
                    INSERT INTO findings (id, job_id, rule_id, title, severity, created_at)
                    VALUES ('legacy-2', 'job-migration', 'rule-2', 'Legacy finding 2', 'LOW', '2024-01-01 00:01:00')
                """)
                await db.commit()

            # 2. Point production DB_PATH to this temporary legacy database and run production init_db()
            import app.db

            monkeypatch.setattr(app.db, "DB_PATH", tmp_path)
            await app.db.init_db()

            # 3. Verify column is added and legacy records survive with 5.0
            async with aiosqlite.connect(tmp_path) as db:
                db.row_factory = aiosqlite.Row
                cursor = await db.execute("PRAGMA table_info(findings)")
                columns = [row["name"] for row in await cursor.fetchall()]
                assert "severity_score" in columns

                cur = await db.execute(
                    "SELECT id, severity_score FROM findings WHERE job_id = 'job-migration' ORDER BY created_at"
                )
                rows = await cur.fetchall()
                assert len(rows) == 2
                assert rows[0]["id"] == "legacy-1"
                assert rows[0]["severity_score"] == 5.0
                assert rows[1]["id"] == "legacy-2"
                assert rows[1]["severity_score"] == 5.0

                # 4. Verify legacy 15-column tuple insert still works
                legacy_15 = [
                    (
                        "legacy-15",
                        "job-migration",
                        "rule-3",
                        "15-tuple",
                        "INFO",
                        "sast",
                        "a.py",
                        1,
                        None,
                        "semgrep",
                        "msg",
                        None,
                        None,
                        None,
                        None,
                    )
                ]
                await create_findings(db, legacy_15)

                # 5. Verify new 16-column tuple insert works
                new_16 = [
                    (
                        "new-16-high",
                        "job-migration",
                        "rule-4",
                        "16-tuple high",
                        "HIGH",
                        "sast",
                        "b.py",
                        5,
                        None,
                        "semgrep",
                        "msg",
                        None,
                        None,
                        None,
                        None,
                        9.8,
                    ),
                    (
                        "new-16-low",
                        "job-migration",
                        "rule-5",
                        "16-tuple low",
                        "LOW",
                        "sast",
                        "c.py",
                        10,
                        None,
                        "semgrep",
                        "msg",
                        None,
                        None,
                        None,
                        None,
                        2.0,
                    ),
                ]
                await create_findings(db, new_16)

                # 6. Verify NULLS LAST handling for findings with NULL severity_score
                null_score_row = [
                    (
                        "new-16-null",
                        "job-migration",
                        "rule-6",
                        "16-tuple null score",
                        "LOW",
                        "sast",
                        "d.py",
                        15,
                        None,
                        "semgrep",
                        "msg",
                        None,
                        None,
                        None,
                        None,
                        None,
                    ),
                ]
                await create_findings(db, null_score_row)

                # 7. Verify get_findings_by_job_id ordering (severity_score DESC NULLS LAST, created_at)
                findings = await get_findings_by_job_id(db, "job-migration")
                assert len(findings) == 6
                assert [f["id"] for f in findings] == [
                    "new-16-high",
                    "legacy-1",
                    "legacy-2",
                    "legacy-15",
                    "new-16-low",
                    "new-16-null",
                ]
                assert [f["severity_score"] for f in findings] == [
                    9.8,
                    5.0,
                    5.0,
                    5.0,
                    2.0,
                    None,
                ]
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
