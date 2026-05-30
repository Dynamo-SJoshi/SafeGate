from __future__ import annotations

import os
from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .environment import load_local_env_files


load_local_env_files()


UPLOADS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS uploads (
    id BIGSERIAL PRIMARY KEY,
    upload_id UUID NOT NULL UNIQUE,
    original_filename TEXT NOT NULL,
    stored_filename TEXT NOT NULL,
    content_type TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    sha256 TEXT NOT NULL,
    claimed_content_type TEXT NOT NULL,
    detected_content_type TEXT NOT NULL,
    claimed_extension TEXT NOT NULL,
    detected_type TEXT NOT NULL,
    match_status TEXT NOT NULL,
    confidence TEXT NOT NULL,
    fingerprint JSONB NOT NULL,
    analysis_state TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""

UPLOADS_EXTRA_COLUMNS_SQL = """
ALTER TABLE uploads
    ADD COLUMN IF NOT EXISTS source_url TEXT,
    ADD COLUMN IF NOT EXISTS source_kind TEXT NOT NULL DEFAULT 'upload',
    ADD COLUMN IF NOT EXISTS source_state TEXT NOT NULL DEFAULT 'direct_file',
    ADD COLUMN IF NOT EXISTS selected_candidate_url TEXT,
    ADD COLUMN IF NOT EXISTS candidate_urls JSONB NOT NULL DEFAULT '[]'::jsonb;
"""


def get_database_url() -> str:
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError(
            "DATABASE_URL is not set. Example: postgresql://postgres:YOUR_PASSWORD@localhost:5432/postgres"
        )
    return database_url


@contextmanager
def db_connection():
    connection = psycopg.connect(get_database_url(), row_factory=dict_row)
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database() -> None:
    with db_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(UPLOADS_TABLE_SQL)
            cursor.execute(UPLOADS_EXTRA_COLUMNS_SQL)


def save_upload_record(
    *,
    upload_id: str,
    original_filename: str,
    stored_filename: str,
    content_type: str,
    size_bytes: int,
    sha256: str,
    fingerprint: dict[str, object],
    analysis_state: str,
    source_url: str | None = None,
    source_kind: str = "upload",
    source_state: str = "direct_file",
    selected_candidate_url: str | None = None,
    candidate_urls: list[str] | None = None,
) -> None:
    claimed_content_type = str(fingerprint["claimed_content_type"])
    detected_content_type = str(fingerprint["detected_content_type"])
    claimed_extension = str(fingerprint["claimed_extension"])
    detected_type = str(fingerprint["detected_type"])
    match_status = str(fingerprint["match_status"])
    confidence = str(fingerprint["confidence"])

    initialize_database()

    with db_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO uploads (
                    upload_id,
                    original_filename,
                    stored_filename,
                    content_type,
                    size_bytes,
                    sha256,
                    claimed_content_type,
                    detected_content_type,
                    claimed_extension,
                    detected_type,
                    match_status,
                    confidence,
                    fingerprint,
                    analysis_state,
                    source_url,
                    source_kind,
                    source_state,
                    selected_candidate_url,
                    candidate_urls
                )
                VALUES (
                    %(upload_id)s,
                    %(original_filename)s,
                    %(stored_filename)s,
                    %(content_type)s,
                    %(size_bytes)s,
                    %(sha256)s,
                    %(claimed_content_type)s,
                    %(detected_content_type)s,
                    %(claimed_extension)s,
                    %(detected_type)s,
                    %(match_status)s,
                    %(confidence)s,
                    %(fingerprint)s,
                    %(analysis_state)s,
                    %(source_url)s,
                    %(source_kind)s,
                    %(source_state)s,
                    %(selected_candidate_url)s,
                    %(candidate_urls)s
                )
                ON CONFLICT (upload_id)
                DO UPDATE SET
                    original_filename = EXCLUDED.original_filename,
                    stored_filename = EXCLUDED.stored_filename,
                    content_type = EXCLUDED.content_type,
                    size_bytes = EXCLUDED.size_bytes,
                    sha256 = EXCLUDED.sha256,
                    claimed_content_type = EXCLUDED.claimed_content_type,
                    detected_content_type = EXCLUDED.detected_content_type,
                    claimed_extension = EXCLUDED.claimed_extension,
                    detected_type = EXCLUDED.detected_type,
                    match_status = EXCLUDED.match_status,
                    confidence = EXCLUDED.confidence,
                    fingerprint = EXCLUDED.fingerprint,
                    analysis_state = EXCLUDED.analysis_state,
                    source_url = EXCLUDED.source_url,
                    source_kind = EXCLUDED.source_kind,
                    source_state = EXCLUDED.source_state,
                    selected_candidate_url = EXCLUDED.selected_candidate_url,
                    candidate_urls = EXCLUDED.candidate_urls
                """,
                {
                    "upload_id": upload_id,
                    "original_filename": original_filename,
                    "stored_filename": stored_filename,
                    "content_type": content_type,
                    "size_bytes": size_bytes,
                    "sha256": sha256,
                    "claimed_content_type": claimed_content_type,
                    "detected_content_type": detected_content_type,
                    "claimed_extension": claimed_extension,
                    "detected_type": detected_type,
                    "match_status": match_status,
                    "confidence": confidence,
                    "fingerprint": Jsonb(fingerprint),
                    "analysis_state": analysis_state,
                    "source_url": source_url,
                    "source_kind": source_kind,
                    "source_state": source_state,
                    "selected_candidate_url": selected_candidate_url,
                    "candidate_urls": Jsonb(candidate_urls or []),
                },
            )


def get_upload_record(upload_id: str) -> dict[str, object] | None:
    initialize_database()

    with db_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    upload_id,
                    original_filename,
                    stored_filename,
                    content_type,
                    size_bytes,
                    sha256,
                    claimed_content_type,
                    detected_content_type,
                    claimed_extension,
                    detected_type,
                    match_status,
                    confidence,
                    fingerprint,
                    analysis_state,
                    source_url,
                    source_kind,
                    source_state,
                    selected_candidate_url,
                    candidate_urls,
                    created_at
                FROM uploads
                WHERE upload_id = %s
                """,
                (upload_id,),
            )
            record = cursor.fetchone()
            if record is None:
                return None
            return dict(record)
