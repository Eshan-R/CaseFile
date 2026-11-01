"""DuckDB persistence layer.

One DuckDB connection per process (DuckDB is single-writer friendly in-process).
All heavy answers are stored pre-computed so the API can answer in <200 ms.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import threading
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

import duckdb

from app.config import settings

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_conn: duckdb.DuckDBPyConnection | None = None


def _get_conn() -> duckdb.DuckDBPyConnection:
    global _conn
    if _conn is None:
        os.makedirs(os.path.dirname(os.path.abspath(settings.duck_path)), exist_ok=True)
        _conn = duckdb.connect(settings.duck_path)
        mem_limit = getattr(settings, "duckdb_memory_limit_gb", 4)
        _conn.execute(f"SET memory_limit='{mem_limit}GB'")
        threads = getattr(settings, "duckdb_threads", 8)
        if threads:
            _conn.execute(f"SET threads={threads}")
        temp_dir = getattr(settings, "duckdb_temp_directory", "")
        if temp_dir:
            os.makedirs(temp_dir, exist_ok=True)
            _conn.execute(f"SET temp_directory='{temp_dir.replace('\\', '/')}'")
        _conn.execute("SET preserve_insertion_order=false")
        try:
            _conn.execute(
                """
                CREATE TABLE IF NOT EXISTS incident_stories (
                    incident_id   TEXT PRIMARY KEY,
                    story_json    TEXT NOT NULL,
                    story_source  TEXT NOT NULL,
                    facts_sha256  TEXT NOT NULL,
                    generated_at  TIMESTAMPTZ NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_story_incident ON incident_stories(incident_id);
                """
            )
        except Exception:
            pass
    return _conn


def close() -> None:
    """Close the shared database connection and reset the handle."""
    global _conn
    with _lock:
        if _conn is not None:
            try:
                _conn.close()
            except Exception:
                pass
            _conn = None


@contextmanager
def cursor() -> Generator[duckdb.DuckDBPyConnection, None, None]:
    """Yield the shared connection under the process-wide lock."""
    with _lock:
        yield _get_conn()


# ---------------------------------------------------------------------------
# ID helpers
# ---------------------------------------------------------------------------

def new_id(prefix: str) -> str:
    """Return prefix + '_' + 8 hex characters, e.g. 'job_3f2a1b4c'."""
    return f"{prefix}_{secrets.token_hex(4)}"


def utc_now() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Schema init / reset
# ---------------------------------------------------------------------------

DDL = """\
CREATE TABLE IF NOT EXISTS jobs (
    job_id      TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'queued',
    params      TEXT NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL,
    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    progress_pct DOUBLE,
    error       TEXT,
    result      TEXT
);

CREATE TABLE IF NOT EXISTS detections (
    detection_id TEXT PRIMARY KEY,
    rule_id      TEXT NOT NULL,
    rule_name    TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    tactic       TEXT NOT NULL,
    severity     INTEGER NOT NULL,
    host         TEXT NOT NULL,
    ts           TIMESTAMPTZ NOT NULL,
    event_ids    TEXT NOT NULL DEFAULT '[]',
    incident_id  TEXT,
    confidence   DOUBLE DEFAULT 0.8,
    kill_chain_stage TEXT,
    suppressed   BOOLEAN DEFAULT FALSE,
    suppress_reason TEXT
);

CREATE TABLE IF NOT EXISTS detection_events (
    detection_id TEXT NOT NULL,
    event_id     TEXT NOT NULL,
    technique_id TEXT,
    tactic       TEXT,
    PRIMARY KEY (detection_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_det_ev_event ON detection_events(event_id);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id  TEXT PRIMARY KEY,
    title        TEXT NOT NULL,
    severity     INTEGER NOT NULL,
    risk_score   DOUBLE DEFAULT 0.0,
    first_seen   TIMESTAMPTZ NOT NULL,
    last_seen    TIMESTAMPTZ NOT NULL,
    hosts        TEXT NOT NULL DEFAULT '[]',
    users        TEXT NOT NULL DEFAULT '[]',
    src_ips      TEXT NOT NULL DEFAULT '[]',
    techniques   TEXT NOT NULL DEFAULT '[]',
    steps        TEXT NOT NULL DEFAULT '[]',
    detection_ids TEXT NOT NULL DEFAULT '[]',
    detection_count INTEGER NOT NULL DEFAULT 0,
    event_count  INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT 'open',
    -- Pre-computed graph JSON so GET /graph is fast
    graph_json   TEXT,
    -- Pre-computed reach JSON
    reach_json   TEXT,
    ips_context  TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS incident_events (
    incident_id  TEXT NOT NULL,
    event_id     TEXT NOT NULL,
    PRIMARY KEY (incident_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_inc_ev_event ON incident_events(event_id);

CREATE TABLE IF NOT EXISTS incident_next (
    incident_id         TEXT PRIMARY KEY,
    blast_radius_hosts  INTEGER NOT NULL DEFAULT 0,
    blast_radius_users  INTEGER NOT NULL DEFAULT 0,
    critical_assets     TEXT NOT NULL DEFAULT '[]',
    data                TEXT NOT NULL DEFAULT '{}',
    computed_at         TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS rules (
    rule_id      TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    technique_id TEXT NOT NULL,
    tactic       TEXT NOT NULL,
    severity     INTEGER NOT NULL DEFAULT 5,
    log_formats  TEXT NOT NULL DEFAULT '[]',
    conditions   TEXT NOT NULL DEFAULT '[]',
    logic        TEXT NOT NULL DEFAULT 'all',
    enabled      BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS evaluations (
    eval_id          TEXT PRIMARY KEY,
    incident_id      TEXT NOT NULL,
    ground_truth     TEXT NOT NULL,
    result_json      TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS stats (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incident_stories (
    incident_id   TEXT PRIMARY KEY,
    story_json    TEXT NOT NULL,
    story_source  TEXT NOT NULL,
    facts_sha256  TEXT NOT NULL,
    generated_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS patterns (
    pattern_id          TEXT PRIMARY KEY,
    kind                TEXT NOT NULL,
    title               TEXT NOT NULL,
    support             INTEGER NOT NULL,
    first_seen          TIMESTAMPTZ,
    last_seen           TIMESTAMPTZ,
    entities            TEXT NOT NULL DEFAULT '[]',
    example_event_ids   TEXT NOT NULL DEFAULT '[]',
    score               DOUBLE NOT NULL,
    suggested_technique TEXT,
    suggested_tactic    TEXT,
    status              TEXT NOT NULL DEFAULT 'new',
    details_json        TEXT NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL
);
"""


CREATE_EVENTS_TABLE_DDL = """\
CREATE TABLE IF NOT EXISTS events (
    event_id      TEXT PRIMARY KEY,
    ts            TIMESTAMPTZ,
    timestamp     TEXT,
    host          TEXT,
    source_file   TEXT,
    log_format    TEXT,
    raw           TEXT,
    user_name     TEXT,
    user          TEXT,
    user_raw      TEXT,
    pid           INTEGER,
    ppid          INTEGER,
    process_name  TEXT,
    cmd           TEXT,
    src_ip        TEXT,
    dst_ip        TEXT,
    src_port      INTEGER,
    dst_port      INTEGER,
    event_type    TEXT,
    type          TEXT,
    subtype       TEXT,
    logid         TEXT,
    logdesc       TEXT,
    msg           TEXT,
    action        TEXT,
    outcome       TEXT,
    reason        TEXT,
    status        TEXT,
    bytes_out     BIGINT,
    bytes_in      BIGINT,
    sentbyte      BIGINT,
    rcvdbyte      BIGINT,
    service       TEXT,
    app           TEXT,
    proto         TEXT,
    virus         TEXT,
    devname       TEXT,
    devid         TEXT,
    url           TEXT,
    hostname      TEXT,
    attack        TEXT,
    attackid      TEXT,
    severity      TEXT,
    stream        INTEGER,
    source_offset BIGINT,
    extra         TEXT,
    file_path     TEXT,
    technique_id  TEXT,
    tactic        TEXT,
    rule_ids      TEXT NOT NULL DEFAULT '[]',
    detection_id  TEXT,
    incident_id   TEXT
);
"""


def ensure_events_view(parquet_dir: str | None = None) -> None:
    """Create or replace DuckDB events view over Parquet if parquet files exist, else base table."""
    import glob
    target_dir = parquet_dir if parquet_dir is not None else settings.parquet_dir
    parquet_glob = os.path.abspath(os.path.join(target_dir, "stream=*/*/*.parquet")).replace("\\", "/")
    matches = glob.glob(parquet_glob)
    with cursor() as con:
        if matches:
            try:
                con.execute("DROP VIEW IF EXISTS events")
            except Exception:
                pass
            try:
                con.execute("DROP TABLE IF EXISTS events")
            except Exception:
                pass
            con.execute(
                f"CREATE OR REPLACE VIEW events AS "
                f"SELECT * EXCLUDE (timestamp), timestamp, TRY_CAST(timestamp AS TIMESTAMPTZ) AS ts "
                f"FROM read_parquet('{parquet_glob}', union_by_name=True)"
            )
        else:
            try:
                con.execute("DROP VIEW IF EXISTS events")
            except Exception:
                pass
            try:
                con.execute(CREATE_EVENTS_TABLE_DDL)
            except Exception:
                pass


def init_db() -> None:
    """Create all tables (idempotent – CREATE IF NOT EXISTS)."""
    with cursor() as con:
        for stmt in DDL.split(";"):
            s = stmt.strip()
            if s:
                try:
                    con.execute(s)
                except duckdb.CatalogException:
                    pass
        try:
            con.execute("ALTER TABLE detections ADD COLUMN IF NOT EXISTS confidence DOUBLE DEFAULT 0.8;")
            con.execute("ALTER TABLE detections ADD COLUMN IF NOT EXISTS kill_chain_stage TEXT;")
            con.execute("ALTER TABLE detections ADD COLUMN IF NOT EXISTS suppressed BOOLEAN DEFAULT FALSE;")
            con.execute("ALTER TABLE detections ADD COLUMN IF NOT EXISTS suppress_reason TEXT;")
            con.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS risk_score DOUBLE DEFAULT 0.0;")
            con.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS detection_count INTEGER DEFAULT 0;")
            con.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS ips_context TEXT DEFAULT '[]';")
            con.execute("DROP INDEX IF EXISTS idx_det_incident;")
            con.execute("DROP INDEX IF EXISTS idx_det_ts;")
            con.execute("DROP INDEX IF EXISTS idx_story_incident;")
        except Exception:
            pass
    ensure_events_view()


def reset_all() -> None:
    """Drop all tables and recreate. Useful for dev resets."""
    tables = [
        "jobs", "events", "detections", "detection_events", "incidents",
        "incident_events", "incident_stories", "patterns", "rules", "evaluations", "stats"
    ]
    with cursor() as con:
        for t in tables:
            try:
                con.execute(f"DROP VIEW IF EXISTS {t}")
            except Exception:
                pass
            try:
                con.execute(f"DROP TABLE IF EXISTS {t}")
            except Exception:
                pass
    init_db()


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def _row_to_dict(con: duckdb.DuckDBPyConnection) -> dict[str, Any] | None:
    row = con.fetchone()
    if row is None:
        return None
    cols = [d[0] for d in con.description]
    return dict(zip(cols, row))


def _rows_to_dicts(con: duckdb.DuckDBPyConnection) -> list[dict[str, Any]]:
    cols = [d[0] for d in con.description]
    return [dict(zip(cols, r)) for r in con.fetchall()]


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------

def insert_job(job_id: str, kind: str, params: dict) -> dict:
    now = utc_now()
    with cursor() as con:
        con.execute(
            "INSERT INTO jobs (job_id,kind,status,params,created_at) VALUES (?,?,?,?,?)",
            [job_id, kind, "queued", json.dumps(params), now],
        )
    return {"job_id": job_id, "kind": kind, "status": "queued", "params": params,
            "created_at": now, "started_at": None, "finished_at": None,
            "progress_pct": None, "error": None, "result": None}


def get_job(job_id: str) -> dict | None:
    with cursor() as con:
        con.execute("SELECT * FROM jobs WHERE job_id=?", [job_id])
        return _row_to_dict(con)


def list_jobs(offset: int = 0, limit: int = 50) -> tuple[int, list[dict]]:
    with cursor() as con:
        con.execute("SELECT COUNT(*) FROM jobs")
        total = con.fetchone()[0]
        con.execute("SELECT * FROM jobs ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    [limit, offset])
        return total, _rows_to_dicts(con)


def update_job(job_id: str, **fields) -> None:
    if not fields:
        return
    set_clause = ", ".join(f"{k}=?" for k in fields)
    with cursor() as con:
        con.execute(
            f"UPDATE jobs SET {set_clause} WHERE job_id=?",  # noqa: S608
            [*fields.values(), job_id],
        )


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

def insert_events_batch(rows: list[dict]) -> None:
    """Bulk-insert a list of event dicts (fast path via executemany)."""
    if not rows:
        return
    keys = [
        "event_id", "ts", "host", "source_file", "log_format", "raw",
        "user_name", "pid", "ppid", "process_name", "cmd",
        "src_ip", "dst_ip", "dst_port", "file_path",
        "technique_id", "tactic", "rule_ids", "detection_id", "incident_id",
    ]
    values = []
    for r in rows:
        vals = []
        for k in keys:
            if k == "ts":
                vals.append(r.get("ts") or r.get("timestamp"))
            elif k == "rule_ids":
                vals.append(json.dumps(r.get("rule_ids", [])))
            else:
                vals.append(r.get(k))
        values.append(vals)

    placeholders = ",".join(["?"] * len(keys))
    with cursor() as con:
        con.executemany(
            f"INSERT OR REPLACE INTO events ({','.join(keys)}) VALUES ({placeholders})",  # noqa: S608
            values,
        )


def get_event(event_id: str) -> dict | None:
    with cursor() as con:
        con.execute("SELECT * FROM events WHERE event_id=?", [event_id])
        return _row_to_dict(con)


def get_events_batch(event_ids: list[str]) -> list[dict]:
    if not event_ids:
        return []
    placeholders = ", ".join(["?" for _ in event_ids])
    with cursor() as con:
        rows = con.execute(f"SELECT * FROM events WHERE event_id IN ({placeholders})", event_ids).fetchall()
        cols = [d[0] for d in con.description]
        return [dict(zip(cols, r)) for r in rows]



def list_events(
    incident_id: str | None = None,
    detection_id: str | None = None,
    host: str | None = None,
    offset: int = 0,
    limit: int = 100,
) -> tuple[int, list[dict]]:
    where, params = _build_event_where(incident_id, detection_id, host)
    with cursor() as con:
        con.execute(f"SELECT COUNT(*) FROM events{where}", params)  # noqa: S608
        total = con.fetchone()[0]
        con.execute(
            f"SELECT * FROM events{where} ORDER BY ts LIMIT ? OFFSET ?",  # noqa: S608
            params + [limit, offset],
        )
        return total, _rows_to_dicts(con)


def _build_event_where(
    incident_id: str | None,
    detection_id: str | None,
    host: str | None,
) -> tuple[str, list]:
    clauses, params = [], []
    if incident_id:
        clauses.append("event_id IN (SELECT event_id FROM incident_events WHERE incident_id=?)")
        params.append(incident_id)
    if detection_id:
        clauses.append("event_id IN (SELECT event_id FROM detection_events WHERE detection_id=?)")
        params.append(detection_id)
    if host:
        clauses.append("host=?")
        params.append(host)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def link_detection_events(
    detection_id: str,
    event_ids: list[str],
    technique_id: str = "",
    tactic: str = "",
) -> None:
    if not event_ids:
        return
    rows = [(detection_id, eid, technique_id, tactic) for eid in event_ids]
    with cursor() as con:
        con.executemany(
            "INSERT OR REPLACE INTO detection_events (detection_id, event_id, technique_id, tactic) VALUES (?, ?, ?, ?)",
            rows,
        )


def link_detection_events_batch(links: list[tuple[str, str, str, str]]) -> None:
    """Batch-insert detection-event links using chunked multi-row values."""
    if not links:
        return
    chunk_size = 500
    with cursor() as con:
        for i in range(0, len(links), chunk_size):
            chunk = links[i : i + chunk_size]
            val_placeholders = ", ".join(["(?, ?, ?, ?)" for _ in chunk])
            params = [v for tup in chunk for v in tup]
            con.execute(
                f"INSERT INTO detection_events (detection_id, event_id, technique_id, tactic) "
                f"VALUES {val_placeholders} ON CONFLICT DO NOTHING",
                params,
            )


def link_incident_events(incident_id: str, event_ids: list[str]) -> None:
    if not event_ids:
        return
    rows = [(incident_id, eid) for eid in event_ids]
    with cursor() as con:
        con.executemany(
            "INSERT OR REPLACE INTO incident_events (incident_id, event_id) VALUES (?, ?)",
            rows,
        )


def count_events() -> int:
    with cursor() as con:
        con.execute("SELECT COUNT(*) FROM events")
        return con.fetchone()[0]


# ---------------------------------------------------------------------------
# Detections
# ---------------------------------------------------------------------------

def insert_detection(d: dict) -> None:
    eids = d.get("event_ids", [])
    eids_str = eids if isinstance(eids, str) else json.dumps(eids)
    with cursor() as con:
        con.execute(
            "INSERT OR REPLACE INTO detections "
            "(detection_id,rule_id,rule_name,technique_id,tactic,severity,host,ts,event_ids,incident_id,confidence,kill_chain_stage,suppressed,suppress_reason) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                d["detection_id"], d["rule_id"], d["rule_name"],
                d["technique_id"], d["tactic"], d["severity"],
                d["host"], d["ts"],
                eids_str, d.get("incident_id"),
                float(d.get("confidence", 0.8)), d.get("kill_chain_stage", ""),
                bool(d.get("suppressed", False)), d.get("suppress_reason"),
            ],
        )


def insert_detections_batch(dets: list[dict]) -> None:
    """Batch-insert multiple detections in chunked multi-row transactions."""
    if not dets:
        return
    rows = [
        (
            d["detection_id"], d["rule_id"], d["rule_name"],
            d["technique_id"], d["tactic"], d["severity"],
            d["host"], d["ts"],
            d["event_ids"] if isinstance(d.get("event_ids"), str) else json.dumps(d.get("event_ids", [])),
            d.get("incident_id"),
            float(d.get("confidence", 0.8)), d.get("kill_chain_stage", ""),
            bool(d.get("suppressed", False)), d.get("suppress_reason"),
        )
        for d in dets
    ]
    chunk_size = 500
    with cursor() as con:
        for i in range(0, len(rows), chunk_size):
            chunk = rows[i : i + chunk_size]
            val_placeholders = ", ".join(["(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)" for _ in chunk])
            params = [v for tup in chunk for v in tup]
            con.execute(
                f"INSERT INTO detections (detection_id,rule_id,rule_name,technique_id,tactic,severity,host,ts,event_ids,incident_id,confidence,kill_chain_stage,suppressed,suppress_reason) "
                f"VALUES {val_placeholders} ON CONFLICT DO NOTHING",
                params,
            )


def count_suppressed_windows() -> int:
    """Return count of suppressed population artifact detections."""
    with cursor() as con:
        try:
            row = con.execute("SELECT count(*) FROM detections WHERE suppressed IS TRUE").fetchone()
            return int(row[0]) if row else 0
        except Exception:
            return 0


def delete_detections_for_rule(rule_id: str) -> None:
    with cursor() as con:
        con.execute(
            "DELETE FROM detection_events WHERE detection_id IN (SELECT detection_id FROM detections WHERE rule_id = ?)",
            [rule_id],
        )
        con.execute("DELETE FROM detections WHERE rule_id = ?", [rule_id])


def get_events_columns() -> set[str]:
    with cursor() as con:
        try:
            rows = con.execute("DESCRIBE events").fetchall()
            return {r[0].lower() for r in rows}
        except Exception:
            return set()


def get_detection(detection_id: str) -> dict | None:
    with cursor() as con:
        con.execute("SELECT * FROM detections WHERE detection_id=?", [detection_id])
        return _row_to_dict(con)


def list_detections(
    incident_id: str | None = None,
    offset: int = 0,
    limit: int | None = 100,
) -> tuple[int, list[dict]]:
    where = " WHERE incident_id=?" if incident_id else ""
    params: list = [incident_id] if incident_id else []
    limit_clause = f" LIMIT {int(limit)} OFFSET {int(offset)}" if limit is not None else ""
    with cursor() as con:
        con.execute(f"SELECT COUNT(*) FROM detections{where}", params)  # noqa: S608
        total = con.fetchone()[0]
        con.execute(
            f"SELECT * FROM detections{where} ORDER BY ts{limit_clause}",  # noqa: S608
            params,
        )
        return total, _rows_to_dicts(con)


def get_detection_entities_bulk() -> dict[str, dict[str, Any]]:
    """Fetch distinct src_ips, dst_ips, users, and raw event_count per detection in a single bulk query."""
    cols = get_events_columns()
    user_expr = "COALESCE(e.user, e.user_name, e.user_raw)" if "user_name" in cols else "COALESCE(e.user, e.user_raw)"
    host_expr = "COALESCE(e.host, e.hostname)" if "hostname" in cols else "e.host"
    sql = f"""
        SELECT 
            de.detection_id, 
            list_distinct(list(e.src_ip) FILTER (WHERE e.src_ip IS NOT NULL AND e.src_ip != '')) AS src_ips,
            list_distinct(list(e.dst_ip) FILTER (WHERE e.dst_ip IS NOT NULL AND e.dst_ip != '')) AS dst_ips,
            list_distinct(list({user_expr}) FILTER (WHERE {user_expr} IS NOT NULL AND {user_expr} != '')) AS users,
            list_distinct(list({host_expr}) FILTER (WHERE {host_expr} IS NOT NULL AND {host_expr} != '')) AS hosts,
            count(DISTINCT de.event_id) AS event_count
        FROM detection_events de
        JOIN events e ON de.event_id = e.event_id
        GROUP BY de.detection_id
    """
    result: dict[str, dict[str, Any]] = {}
    try:
        with cursor() as con:
            rows = con.execute(sql).fetchall()
            for r in rows:
                det_id, s_ips, d_ips, usrs, hsts, ev_cnt = r
                result[det_id] = {
                    "src_ips": [str(x) for x in (s_ips or []) if x],
                    "dst_ips": [str(x) for x in (d_ips or []) if x],
                    "users": [str(x) for x in (usrs or []) if x],
                    "hosts": [str(x) for x in (hsts or []) if x],
                    "event_count": int(ev_cnt or 0),
                }
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

def upsert_incident(inc: dict) -> None:
    ips_ctx = inc.get("ips_context", [])
    ips_ctx_str = json.dumps(ips_ctx) if isinstance(ips_ctx, list | dict) else str(ips_ctx or "[]")
    with cursor() as con:
        con.execute(
            "INSERT OR REPLACE INTO incidents "
            "(incident_id,title,severity,risk_score,first_seen,last_seen,hosts,users,src_ips,"
            "techniques,steps,detection_ids,detection_count,event_count,status,graph_json,reach_json,ips_context) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                inc["incident_id"], inc["title"], inc["severity"],
                float(inc.get("risk_score", 0.0) or 0.0),
                inc["first_seen"], inc["last_seen"],
                json.dumps(inc.get("hosts", [])),
                json.dumps(inc.get("users", [])),
                json.dumps(inc.get("src_ips", [])),
                json.dumps(inc.get("techniques", [])),
                json.dumps(inc.get("steps", [])),
                json.dumps(inc.get("detection_ids", [])),
                int(inc.get("detection_count", len(inc.get("detection_ids", [])))),
                int(inc.get("event_count", 0)),
                inc.get("status", "open"),
                inc.get("graph_json"),
                inc.get("reach_json"),
                ips_ctx_str,
            ],
        )


def get_incident(incident_id: str) -> dict | None:
    with cursor() as con:
        con.execute("SELECT * FROM incidents WHERE incident_id=?", [incident_id])
        return _row_to_dict(con)


def list_incidents(
    offset: int = 0,
    limit: int = 50,
    show_leads: bool = False,
    status: str | None = None,
) -> tuple[int, list[dict]]:
    where_clause = ""
    params: list[Any] = []
    if status:
        where_clause = "WHERE status = ?"
        params.append(status)
    elif not show_leads:
        where_clause = "WHERE status != 'lead'"

    with cursor() as con:
        con.execute(f"SELECT COUNT(*) FROM incidents {where_clause}", params)
        total = con.fetchone()[0]
        con.execute(
            f"SELECT * FROM incidents {where_clause} ORDER BY risk_score DESC, first_seen DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        )
        return total, _rows_to_dicts(con)


NARROW_CANDIDATE_COLUMNS = [
    "event_id",
    "source_offset",
    "ts",
    "timestamp",
    "host",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "user",
    "user_raw",
    "logid",
    "logdesc",
    "type",
    "subtype",
    "action",
    "sentbyte",
    "rcvdbyte",
    "bytes_out",
    "bytes_in",
    "proto",
    "sentpkt",
    "rcvdpkt",
    "service",
    "app",
    "srccountry",
    "dstcountry",
    "status",
    "outcome",
    "reason",
    "virus",
    "attack",
    "attackid",
    "severity",
    "hostname",
    "url",
    "msg",
    "cmd",
    "devname",
    "devid",
    "policyid",
    "sessionid",
    "srcintf",
    "dstintf",
]


def materialize_events_narrow() -> None:
    """Materialize a narrow in-memory table for rules to query without repeated full Parquet scans."""
    with cursor() as con:
        try:
            con.execute("SELECT 1 FROM events LIMIT 1")
            info = con.execute("PRAGMA table_info('events')").fetchall()
            existing_cols = {r[1] for r in info}
            selected_cols = [c for c in NARROW_CANDIDATE_COLUMNS if c in existing_cols]
            if not selected_cols or len(selected_cols) < 3:
                return
            col_str = ", ".join(selected_cols)
            con.execute(f"CREATE OR REPLACE TEMP TABLE events_narrow AS SELECT {col_str} FROM events")
            con.execute("CREATE OR REPLACE TEMP VIEW events AS SELECT * FROM events_narrow")
            logger.info("Materialized events_narrow table with %d columns and updated events view.", len(selected_cols))
        except Exception as exc:
            logger.debug("Could not materialize events_narrow table: %s", exc)


def set_incident_graph(incident_id: str, graph_json: str) -> None:
    with cursor() as con:
        con.execute(
            "UPDATE incidents SET graph_json=? WHERE incident_id=?",
            [graph_json, incident_id],
        )


def set_incident_reach(incident_id: str, reach_json: str) -> None:
    with cursor() as con:
        con.execute(
            "UPDATE incidents SET reach_json=? WHERE incident_id=?",
            [reach_json, incident_id],
        )


def get_incident_next(incident_id: str) -> dict | None:
    with cursor() as con:
        res = con.execute("SELECT * FROM incident_next WHERE incident_id=?", [incident_id]).fetchone()
        if not res:
            return None
        cols = [d[0] for d in con.description]
        return dict(zip(cols, res))


def set_incident_next(
    incident_id: str,
    data: dict,
    blast_hosts: int = 0,
    blast_users: int = 0,
    critical_assets: list[str] | None = None,
) -> None:
    critical_json = json.dumps(critical_assets or [])
    data_json = json.dumps(data) if isinstance(data, dict) else str(data)
    now = utc_now()
    with cursor() as con:
        con.execute(
            """
            INSERT OR REPLACE INTO incident_next
            (incident_id, blast_radius_hosts, blast_radius_users, critical_assets, data, computed_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [incident_id, blast_hosts, blast_users, critical_json, data_json, now],
        )


def list_incident_next(limit: int = 100) -> list[dict]:
    with cursor() as con:
        rows = con.execute("SELECT * FROM incident_next LIMIT ?", [limit]).fetchall()
        cols = [d[0] for d in con.description]
        return [dict(zip(cols, r)) for r in rows]


# ---------------------------------------------------------------------------
# Incident Stories
# ---------------------------------------------------------------------------

def get_incident_story(incident_id: str) -> dict | None:
    with cursor() as con:
        res = con.execute(
            "SELECT incident_id, story_json, story_source, facts_sha256, generated_at FROM incident_stories WHERE incident_id=?",
            [incident_id],
        ).fetchone()
        if not res:
            return None
        cols = [d[0] for d in con.description]
        return dict(zip(cols, res))


def save_incident_story(
    incident_id: str,
    story_json: str,
    story_source: str,
    facts_sha256: str,
    generated_at: str | None = None,
) -> None:
    now_ts = generated_at or utc_now()
    with cursor() as con:
        con.execute(
            "INSERT OR REPLACE INTO incident_stories "
            "(incident_id, story_json, story_source, facts_sha256, generated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            [incident_id, story_json, story_source, facts_sha256, now_ts],
        )



# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def upsert_rule(r: dict) -> None:
    with cursor() as con:
        con.execute(
            "INSERT OR REPLACE INTO rules "
            "(rule_id,name,description,technique_id,tactic,severity,"
            "log_formats,conditions,logic,enabled) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            [
                r["rule_id"], r["name"], r.get("description", ""),
                r["technique_id"], r["tactic"], r.get("severity", 5),
                json.dumps(r.get("log_formats", [])),
                json.dumps(r.get("conditions", [])),
                r.get("logic", "all"),
                r.get("enabled", True),
            ],
        )


def list_rules() -> list[dict]:
    with cursor() as con:
        con.execute("SELECT * FROM rules WHERE enabled=true ORDER BY rule_id")
        return _rows_to_dicts(con)


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def set_stat(key: str, value: str) -> None:
    with cursor() as con:
        con.execute(
            "INSERT OR REPLACE INTO stats (key,value) VALUES (?,?)",
            [key, value],
        )


def get_stat(key: str) -> str | None:
    with cursor() as con:
        con.execute("SELECT value FROM stats WHERE key=?", [key])
        row = con.fetchone()
        return row[0] if row else None


# ---------------------------------------------------------------------------
# Evaluations
# ---------------------------------------------------------------------------

def insert_evaluation(eval_id: str, incident_id: str, ground_truth: list, result: dict) -> None:
    with cursor() as con:
        con.execute(
            "INSERT INTO evaluations (eval_id,incident_id,ground_truth,result_json,created_at) "
            "VALUES (?,?,?,?,?)",
            [eval_id, incident_id, json.dumps(ground_truth), json.dumps(result), utc_now()],
        )


def get_evaluation(eval_id: str) -> dict | None:
    with cursor() as con:
        con.execute("SELECT * FROM evaluations WHERE eval_id=?", [eval_id])
        return _row_to_dict(con)


def list_evaluations(incident_id: str | None = None) -> list[dict]:
    where = " WHERE incident_id=?" if incident_id else ""
    params = [incident_id] if incident_id else []
    with cursor() as con:
        con.execute(f"SELECT * FROM evaluations{where} ORDER BY created_at DESC", params)  # noqa: S608
        return _rows_to_dicts(con)


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

def _deserialize_pattern(p: dict) -> dict:
    if not p:
        return p
    for k in ("entities", "example_event_ids", "details_json"):
        if isinstance(p.get(k), str):
            try:
                p[k] = json.loads(p[k])
            except Exception:
                pass
    return p


def upsert_pattern(p: dict | Any) -> None:
    """Insert or update pattern, strictly preserving existing approval status on re-mining."""
    data = p.__dict__ if hasattr(p, "__dict__") and not isinstance(p, dict) else dict(p)
    pid = data["pattern_id"]
    kind = data["kind"]
    title = data["title"]
    support = int(data["support"])
    first_seen = data.get("first_seen")
    last_seen = data.get("last_seen")
    entities = json.dumps(data.get("entities", []))
    example_event_ids = json.dumps(data.get("example_event_ids", []))
    score = float(data["score"])
    suggested_technique = data.get("suggested_technique")
    suggested_tactic = data.get("suggested_tactic")
    status = data.get("status", "new")
    details_json = json.dumps(data.get("details_json", {}))
    created_at = data.get("created_at") or utc_now()

    with cursor() as con:
        con.execute(
            """
            INSERT INTO patterns (
                pattern_id, kind, title, support, first_seen, last_seen,
                entities, example_event_ids, score, suggested_technique,
                suggested_tactic, status, details_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (pattern_id) DO UPDATE SET
                kind = EXCLUDED.kind,
                title = EXCLUDED.title,
                support = EXCLUDED.support,
                first_seen = EXCLUDED.first_seen,
                last_seen = EXCLUDED.last_seen,
                entities = EXCLUDED.entities,
                example_event_ids = EXCLUDED.example_event_ids,
                score = EXCLUDED.score,
                suggested_technique = EXCLUDED.suggested_technique,
                suggested_tactic = EXCLUDED.suggested_tactic,
                details_json = EXCLUDED.details_json
            """,
            [
                pid, kind, title, support, first_seen, last_seen,
                entities, example_event_ids, score, suggested_technique,
                suggested_tactic, status, details_json, created_at,
            ],
        )


def save_patterns_batch(patterns: list[Any]) -> int:
    """Batch-upsert patterns preserving existing statuses."""
    count = 0
    for p in patterns:
        upsert_pattern(p)
        count += 1
    return count


def get_pattern(pattern_id: str) -> dict | None:
    with cursor() as con:
        con.execute("SELECT * FROM patterns WHERE pattern_id=?", [pattern_id])
        res = _row_to_dict(con)
        return _deserialize_pattern(res) if res else None


def list_patterns(
    status: str | None = None,
    kind: str | None = None,
    limit: int | None = 100,
    offset: int = 0,
) -> tuple[int, list[dict]]:
    clauses = []
    params = []
    if status:
        clauses.append("status=?")
        params.append(status)
    if kind:
        clauses.append("kind=?")
        params.append(kind)

    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    limit_clause = f" LIMIT {int(limit)} OFFSET {int(offset)}" if limit is not None else ""

    with cursor() as con:
        con.execute(f"SELECT COUNT(*) FROM patterns{where}", params)  # noqa: S608
        total = con.fetchone()[0]
        con.execute(
            f"SELECT * FROM patterns{where} ORDER BY score DESC, support DESC, pattern_id ASC{limit_clause}",  # noqa: S608
            params,
        )
        rows = _rows_to_dicts(con)
        return total, [_deserialize_pattern(r) for r in rows]


def update_pattern_status(pattern_id: str, status: str) -> bool:
    with cursor() as con:
        con.execute("UPDATE patterns SET status=? WHERE pattern_id=?", [status, pattern_id])
        con.execute("SELECT COUNT(*) FROM patterns WHERE pattern_id=? AND status=?", [pattern_id, status])
        return con.fetchone()[0] > 0


