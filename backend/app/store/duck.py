"""DuckDB persistence layer.

One DuckDB connection per process (DuckDB is single-writer friendly in-process).
All heavy answers are stored pre-computed so the API can answer in <200 ms.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

import duckdb

from app.config import settings

_lock = threading.Lock()
_conn: duckdb.DuckDBPyConnection | None = None


def _get_conn() -> duckdb.DuckDBPyConnection:
    global _conn
    if _conn is None:
        os.makedirs(os.path.dirname(os.path.abspath(settings.duck_path)), exist_ok=True)
        _conn = duckdb.connect(settings.duck_path)
        _conn.execute(f"SET memory_limit='{settings.max_memory_gb}GB'")
    return _conn


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

CREATE TABLE IF NOT EXISTS events (
    event_id      TEXT PRIMARY KEY,
    ts            TIMESTAMPTZ NOT NULL,
    host          TEXT NOT NULL,
    source_file   TEXT NOT NULL,
    log_format    TEXT NOT NULL,
    raw           TEXT NOT NULL,
    user_name     TEXT,
    pid           INTEGER,
    ppid          INTEGER,
    process_name  TEXT,
    cmd           TEXT,
    src_ip        TEXT,
    dst_ip        TEXT,
    dst_port      INTEGER,
    file_path     TEXT,
    technique_id  TEXT,
    tactic        TEXT,
    rule_ids      TEXT NOT NULL DEFAULT '[]',
    detection_id  TEXT,
    incident_id   TEXT
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
    incident_id  TEXT
);

CREATE INDEX IF NOT EXISTS idx_det_incident ON detections(incident_id);
CREATE INDEX IF NOT EXISTS idx_det_ts       ON detections(ts);

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
    first_seen   TIMESTAMPTZ NOT NULL,
    last_seen    TIMESTAMPTZ NOT NULL,
    hosts        TEXT NOT NULL DEFAULT '[]',
    users        TEXT NOT NULL DEFAULT '[]',
    src_ips      TEXT NOT NULL DEFAULT '[]',
    techniques   TEXT NOT NULL DEFAULT '[]',
    steps        TEXT NOT NULL DEFAULT '[]',
    detection_ids TEXT NOT NULL DEFAULT '[]',
    event_count  INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT 'open',
    -- Pre-computed graph JSON so GET /graph is fast
    graph_json   TEXT,
    -- Pre-computed reach JSON
    reach_json   TEXT
);

CREATE TABLE IF NOT EXISTS incident_events (
    incident_id  TEXT NOT NULL,
    event_id     TEXT NOT NULL,
    PRIMARY KEY (incident_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_inc_ev_event ON incident_events(event_id);

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
    action        TEXT,
    outcome       TEXT,
    bytes_out     BIGINT,
    bytes_in      BIGINT,
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
            con.execute(f"CREATE OR REPLACE VIEW events AS SELECT *, timestamp AS ts FROM read_parquet('{parquet_glob}')")
        else:
            con.execute(CREATE_EVENTS_TABLE_DDL)


def init_db() -> None:
    """Create all tables (idempotent – CREATE IF NOT EXISTS)."""
    with cursor() as con:
        for stmt in DDL.split(";"):
            s = stmt.strip()
            if s:
                con.execute(s)
    ensure_events_view()


def reset_all() -> None:
    """Drop all tables and recreate. Useful for dev resets."""
    tables = [
        "jobs", "events", "detections", "detection_events", "incidents",
        "incident_events", "rules", "evaluations", "stats"
    ]
    with cursor() as con:
        for t in tables:
            con.execute(f"DROP TABLE IF EXISTS {t}")
            con.execute(f"DROP VIEW IF EXISTS {t}")
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
        clauses.append("(incident_id=? OR event_id IN (SELECT event_id FROM incident_events WHERE incident_id=?))")
        params.extend([incident_id, incident_id])
    if detection_id:
        clauses.append("(detection_id=? OR event_id IN (SELECT event_id FROM detection_events WHERE detection_id=?))")
        params.extend([detection_id, detection_id])
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
    with cursor() as con:
        con.execute(
            "INSERT OR REPLACE INTO detections "
            "(detection_id,rule_id,rule_name,technique_id,tactic,severity,host,ts,event_ids,incident_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            [
                d["detection_id"], d["rule_id"], d["rule_name"],
                d["technique_id"], d["tactic"], d["severity"],
                d["host"], d["ts"],
                json.dumps(d.get("event_ids", [])), d.get("incident_id"),
            ],
        )


def get_detection(detection_id: str) -> dict | None:
    with cursor() as con:
        con.execute("SELECT * FROM detections WHERE detection_id=?", [detection_id])
        return _row_to_dict(con)


def list_detections(
    incident_id: str | None = None,
    offset: int = 0,
    limit: int = 100,
) -> tuple[int, list[dict]]:
    where = " WHERE incident_id=?" if incident_id else ""
    params: list = [incident_id] if incident_id else []
    with cursor() as con:
        con.execute(f"SELECT COUNT(*) FROM detections{where}", params)  # noqa: S608
        total = con.fetchone()[0]
        con.execute(
            f"SELECT * FROM detections{where} ORDER BY ts LIMIT ? OFFSET ?",  # noqa: S608
            params + [limit, offset],
        )
        return total, _rows_to_dicts(con)


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

def upsert_incident(inc: dict) -> None:
    with cursor() as con:
        con.execute(
            "INSERT OR REPLACE INTO incidents "
            "(incident_id,title,severity,first_seen,last_seen,hosts,users,src_ips,"
            "techniques,steps,detection_ids,event_count,status,graph_json,reach_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                inc["incident_id"], inc["title"], inc["severity"],
                inc["first_seen"], inc["last_seen"],
                json.dumps(inc.get("hosts", [])),
                json.dumps(inc.get("users", [])),
                json.dumps(inc.get("src_ips", [])),
                json.dumps(inc.get("techniques", [])),
                json.dumps(inc.get("steps", [])),
                json.dumps(inc.get("detection_ids", [])),
                inc.get("event_count", 0),
                inc.get("status", "open"),
                inc.get("graph_json"),
                inc.get("reach_json"),
            ],
        )


def get_incident(incident_id: str) -> dict | None:
    with cursor() as con:
        con.execute("SELECT * FROM incidents WHERE incident_id=?", [incident_id])
        return _row_to_dict(con)


def list_incidents(offset: int = 0, limit: int = 50) -> tuple[int, list[dict]]:
    with cursor() as con:
        con.execute("SELECT COUNT(*) FROM incidents")
        total = con.fetchone()[0]
        con.execute(
            "SELECT * FROM incidents ORDER BY first_seen DESC LIMIT ? OFFSET ?",
            [limit, offset],
        )
        return total, _rows_to_dicts(con)


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

