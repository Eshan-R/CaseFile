"""Detection engine: set-based SQL compilation over DuckDB events view.

Compiles Match, Threshold, and Sequence detection rules to set-based DuckDB SQL queries,
persists detections with evidence event IDs, and records execution statistics.
"""

from __future__ import annotations

import logging
import math
import os
import re
import time
from typing import Any

from app.schemas.rule import Rule, RuleCondition
from app.store import duck

logger = logging.getLogger(__name__)


def _match_condition(cond: RuleCondition, event: dict[str, Any]) -> bool:
    """Test one condition against the event dict (Python test helper)."""
    value = event.get(cond.field, "") or ""
    value = str(value)
    test = cond.value

    match cond.op:
        case "eq" | "equals":
            return value.lower() == str(test).lower()
        case "contains":
            return str(test).lower() in value.lower()
        case "startswith":
            return value.lower().startswith(str(test).lower())
        case "endswith":
            return value.lower().endswith(str(test).lower())
        case "regex":
            try:
                return bool(re.search(str(test), value, re.IGNORECASE))
            except re.error:
                return False
        case "not_regex":
            try:
                return not bool(re.search(str(test), value, re.IGNORECASE))
            except re.error:
                return False
        case "not_startswith":
            return not value.lower().startswith(str(test).lower())
        case "not_contains":
            return str(test).lower() not in value.lower()
        case "not_in":
            tests = [str(x).lower() for x in (test if isinstance(test, list | tuple | set) else [test])]
            return value.lower() not in tests
        case _:
            return False


def _rule_matches(rule: Rule, event: dict[str, Any]) -> bool:
    """Return True if the rule fires on this event (Python test helper)."""
    if not rule.enabled:
        return False
    if rule.log_formats and event.get("log_format") not in rule.log_formats:
        return False
    if not rule.conditions:
        return False

    results = [_match_condition(c, event) for c in rule.conditions]
    if rule.logic == "any":
        return any(results)
    return all(results)


def _escape_val(val: Any) -> str:
    """Escape string values for safe inclusion in SQL string literals."""
    if val is None:
        return "''"
    s = str(val).replace("'", "''")
    return f"'{s}'"


def extract_referenced_fields(expr: Any) -> set[str]:
    """Extract all field names referenced in where, then, and exclude blocks."""
    fields: set[str] = set()
    if isinstance(expr, dict):
        if "field" in expr:
            fields.add(str(expr["field"]).lower())
        for k, v in expr.items():
            if k in ("and", "or", "not"):
                fields.update(extract_referenced_fields(v))
            elif k not in ("op", "value", "field", "logic"):
                fields.add(k.lower())
    elif isinstance(expr, list):
        for item in expr:
            fields.update(extract_referenced_fields(item))
    elif isinstance(expr, RuleCondition):
        fields.add(expr.field.lower())
    return fields


def _compile_condition(cond: Any, table_prefix: str = "", valid_columns: set[str] | None = None) -> str:
    """Compile a single condition or boolean branch into a SQL expression."""
    pfx = f"{table_prefix}." if table_prefix else ""
    allowed_virtual = {"user", "host", "ts", "timestamp", "event_id"}

    if isinstance(cond, RuleCondition):
        f = cond.field.lower()
        if valid_columns is not None and f not in valid_columns and f not in allowed_virtual:
            logger.info("Field '%s' not in events schema; condition evaluates to FALSE", f)
            return "FALSE"
        field = f"{pfx}{cond.field}"
        op = cond.op.lower()
        val = cond.value
        return _compile_op(field, op, val)

    if not isinstance(cond, dict):
        return "TRUE"

    # Handle boolean trees: and, or, not
    if "and" in cond:
        branches = [_compile_condition(sub, table_prefix, valid_columns) for sub in cond["and"]]
        return f"({' AND '.join(branches)})" if branches else "TRUE"

    if "or" in cond:
        branches = [_compile_condition(sub, table_prefix, valid_columns) for sub in cond["or"]]
        return f"({' OR '.join(branches)})" if branches else "TRUE"

    if "not" in cond:
        sub = _compile_condition(cond["not"], table_prefix, valid_columns)
        return f"NOT ({sub})"

    # Handle explicit {field: "...", op: "...", value: "..."}
    if "field" in cond and "op" in cond:
        f = str(cond["field"]).lower()
        if valid_columns is not None and f not in valid_columns and f not in allowed_virtual:
            logger.info("Field '%s' not in events schema; condition evaluates to FALSE", f)
            return "FALSE"
        field = f"{pfx}{cond['field']}"
        op = str(cond.get("op", "eq")).lower()
        val = cond.get("value")
        return _compile_op(field, op, val)

    # Handle key-value map: {outcome: failure, action: login} or {cmd: {op: contains, value: foo}}
    pairs = []
    for k, v in cond.items():
        if k in ("op", "field", "value", "logic"):
            continue
        k_lower = k.lower()
        if valid_columns is not None and k_lower not in valid_columns and k_lower not in allowed_virtual:
            logger.info("Field '%s' not in events schema; condition evaluates to FALSE", k)
            pairs.append("FALSE")
            continue
        field = f"{pfx}{k}"
        if isinstance(v, dict) and "op" in v:
            op = str(v.get("op", "eq")).lower()
            val = v.get("value")
            pairs.append(_compile_op(field, op, val))
        elif isinstance(v, list):
            quoted = ", ".join(_escape_val(x) for x in v)
            pairs.append(f"LOWER(CAST({field} AS VARCHAR)) IN ({quoted})")
        else:
            pairs.append(f"LOWER(CAST({field} AS VARCHAR)) = LOWER({_escape_val(v)})")

    return f"({' AND '.join(pairs)})" if pairs else "TRUE"


def _compile_op(field: str, op: str, val: Any) -> str:
    """Compile standard operators into SQL expressions."""
    f_cast = f"CAST({field} AS VARCHAR)"
    f_lower = f"LOWER({f_cast})"

    if op in ("eq", "equals"):
        return f"{f_lower} = LOWER({_escape_val(val)})"
    elif op == "in":
        vals = val if isinstance(val, list | tuple | set) else [val]
        quoted = ", ".join(f"LOWER({_escape_val(v)})" for v in vals)
        return f"{f_lower} IN ({quoted})"
    elif op == "contains":
        clean_v = str(val).lower().replace("'", "''")
        return f"{f_lower} LIKE '%{clean_v}%'"
    elif op == "startswith":
        clean_v = str(val).lower().replace("'", "''")
        return f"{f_lower} LIKE '{clean_v}%'"
    elif op == "endswith":
        clean_v = str(val).lower().replace("'", "''")
        return f"{f_lower} LIKE '%{clean_v}'"
    elif op == "regex":
        return f"regexp_matches({f_cast}, {_escape_val(val)})"
    elif op == "not_regex":
        return f"NOT regexp_matches({f_cast}, {_escape_val(val)})"
    elif op == "not_startswith":
        clean_v = str(val).lower().replace("'", "''")
        return f"{f_lower} NOT LIKE '{clean_v}%'"
    elif op == "not_contains":
        clean_v = str(val).lower().replace("'", "''")
        return f"{f_lower} NOT LIKE '%{clean_v}%'"
    elif op == "not_in":
        vals = val if isinstance(val, list | tuple | set) else [val]
        quoted = ", ".join(f"LOWER({_escape_val(v)})" for v in vals)
        return f"{f_lower} NOT IN ({quoted})"
    elif op in ("gt", ">"):
        return f"TRY_CAST({field} AS DOUBLE) > {float(val)}"
    elif op in ("lt", "<"):
        return f"TRY_CAST({field} AS DOUBLE) < {float(val)}"
    elif op in ("gte", ">="):
        return f"TRY_CAST({field} AS DOUBLE) >= {float(val)}"
    elif op in ("lte", "<="):
        return f"TRY_CAST({field} AS DOUBLE) <= {float(val)}"
    else:
        return f"{f_lower} = LOWER({_escape_val(val)})"


def _compile_exclude(exclude_dict: dict[str, Any], table_prefix: str = "") -> str:
    """Compile exclude block (e.g. service accounts, scanners) to SQL predicate."""
    if not exclude_dict:
        return ""
    pfx = f"{table_prefix}." if table_prefix else ""
    clauses = []
    for k, v in exclude_dict.items():
        field = f"{pfx}{k}"
        vals = v if isinstance(v, list | tuple | set) else [v]
        if vals:
            quoted = ", ".join(f"LOWER({_escape_val(x)})" for x in vals)
            clauses.append(f"LOWER(CAST({field} AS VARCHAR)) IN ({quoted})")
    if clauses:
        return f"AND NOT ({' OR '.join(clauses)})"
    return ""


def _entity_expr(candidates: list[str], valid_columns: set[str], prefix: str = "", default: str = "''") -> str:
    """Safely build a COALESCE expression from candidate columns that actually exist."""
    pfx = f"{prefix}." if prefix else ""
    present = [f"{pfx}{c}" for c in candidates if c in valid_columns]
    if not present:
        return default
    if len(present) == 1:
        return f"COALESCE(CAST({present[0]} AS VARCHAR), {default})"
    return f"COALESCE({', '.join(f'CAST({c} AS VARCHAR)' for c in present)}, {default})"


def _is_vacuous_false(expr_sql: str) -> bool:
    """Check if compiled SQL condition is fundamentally unsatisfiable."""
    clean = re.sub(r"[\s\(\)]", "", expr_sql).upper()
    if clean in ("FALSE", "NOTTRUE"):
        return True
    tokens = [t for t in re.split(r"[\s\(\)]+", expr_sql.upper()) if t]
    non_operators = [t for t in tokens if t not in ("AND", "OR", "NOT", "")]
    if non_operators and all(t == "FALSE" for t in non_operators):
        return True
    return False


def compile_rule_to_sql(rule: Rule, valid_columns: set[str]) -> str | None:
    """Compile a Rule model into a single set-based DuckDB SQL query.

    Checks referenced fields against valid_columns. If any field is missing,
    logs a warning and returns None (disabling the rule without crashing).
    """
    allowed_virtual = {"user", "host", "ts", "timestamp", "event_id"}

    # 1. Validate group_by
    if rule.group_by:
        missing_grp = [c.lower() for c in rule.group_by if c.lower() not in valid_columns and c.lower() not in allowed_virtual]
        if missing_grp:
            logger.warning(
                "Rule '%s' references missing group_by field(s) %s. Rule is disabled.",
                rule.id,
                missing_grp,
            )
            return None

    # Validate min_distinct_field
    if rule.min_distinct_field:
        mdf_lower = rule.min_distinct_field.lower()
        if valid_columns is not None and mdf_lower not in valid_columns and mdf_lower not in allowed_virtual:
            logger.warning(
                "Rule '%s' references missing min_distinct_field '%s'. Rule is disabled.",
                rule.id,
                rule.min_distinct_field,
            )
            return None

    # Track missing fields for informative logging
    all_refs = set()
    if rule.where:
        all_refs.update(extract_referenced_fields(rule.where))
    if rule.conditions:
        all_refs.update(extract_referenced_fields(rule.conditions))
    if rule.then:
        all_refs.update(extract_referenced_fields(rule.then))
    missing = [f for f in all_refs if f not in valid_columns and f not in allowed_virtual]

    r_type = rule.type.lower()
    if r_type == "sql":
        if rule.sql:
            return rule.sql
        if rule.sql_file:
            path = rule.sql_file
            if not os.path.isabs(path):
                candidates = [
                    os.path.join(os.getcwd(), path),
                    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), path),
                ]
                for cand in candidates:
                    if os.path.exists(cand):
                        path = cand
                        break
            if os.path.exists(path):
                with open(path, encoding="utf-8") as f:
                    return f.read()
            else:
                logger.error("SQL rule file not found: %s", rule.sql_file)
                return None
        logger.error("Rule '%s' has type 'sql' but neither 'sql' nor 'sql_file' is provided", rule.id)
        return None

    user_expr = _entity_expr(["user", "user_name", "user_raw", "account"], valid_columns)
    host_expr = _entity_expr(["host", "hostname", "devname", "computer_name"], valid_columns, default="'unknown'")
    src_ip_expr = _entity_expr(["src_ip", "srcip", "source_ip"], valid_columns)

    # 2. Type: MATCH
    if r_type == "match":
        where_parts = []
        if rule.where:
            where_parts.append(_compile_condition(rule.where, valid_columns=valid_columns))
        if rule.conditions:
            cond_clauses = [_compile_condition(c, valid_columns=valid_columns) for c in rule.conditions]
            sep = " OR " if rule.logic.lower() == "any" else " AND "
            where_parts.append(f"({sep.join(cond_clauses)})")

        where_sql = " AND ".join(where_parts) if where_parts else "TRUE"
        if _is_vacuous_false(where_sql):
            logger.warning(
                "Rule '%s' references missing field(s) %s. Rule is disabled.",
                rule.id,
                missing,
            )
            return None
        elif missing:
            logger.info(
                "Rule '%s' references missing field(s) %s; gracefully degrading with valid branches.",
                rule.id,
                missing,
            )

        exclude_sql = _compile_exclude(rule.exclude)

        return f"""
        SELECT
            event_id AS primary_event_id,
            ts,
            {host_expr} AS host,
            {user_expr} AS user_entity,
            {src_ip_expr} AS src_ip_entity,
            [event_id] AS evidence_event_ids,
            FALSE AS has_followup
        FROM events
        WHERE {where_sql} {exclude_sql}
        ORDER BY ts ASC, source_offset ASC
        """

    # 3. Type: THRESHOLD
    elif r_type == "threshold":
        where_sql = _compile_condition(rule.where, valid_columns=valid_columns) if rule.where else "TRUE"
        if _is_vacuous_false(where_sql):
            logger.warning(
                "Rule '%s' references missing field(s) %s. Rule is disabled.",
                rule.id,
                missing,
            )
            return None

        exclude_sql = _compile_exclude(rule.exclude)
        window_sec = rule.window_seconds or 600
        min_cnt = rule.min_count or 1
        group_keys = rule.group_by or ["src_ip"]

        if rule.then:
            then_raw = _compile_condition(rule.then, valid_columns=valid_columns)
            if _is_vacuous_false(then_raw):
                logger.warning(
                    "Rule '%s' references missing field(s) %s. Rule is disabled.",
                    rule.id,
                    missing,
                )
                return None

            a_raw = _compile_condition(rule.where, valid_columns=valid_columns) if rule.where else "TRUE"
            a_exclude_sql = _compile_exclude(rule.exclude)
            b_exclude_sql = _compile_exclude(rule.exclude)

            user_a = _entity_expr(["user", "user_name", "user_raw", "account"], valid_columns, prefix="A")
            user_b = _entity_expr(["user", "user_name", "user_raw", "account"], valid_columns, prefix="B")
            host_a = _entity_expr(["host", "hostname", "devname", "computer_name"], valid_columns, prefix="A", default="'unknown'")
            host_b = _entity_expr(["host", "hostname", "devname", "computer_name"], valid_columns, prefix="B", default="'unknown'")
            src_a = _entity_expr(["src_ip", "srcip", "source_ip"], valid_columns, prefix="A")
            src_b = _entity_expr(["src_ip", "srcip", "source_ip"], valid_columns, prefix="B")

            join_preds = []
            for k in group_keys:
                join_preds.append(f"LOWER(CAST(COALESCE(A.{k}, '') AS VARCHAR)) = LOWER(CAST(COALESCE(B.{k}, '') AS VARCHAR))")
            join_sql = " AND ".join(join_preds) if join_preds else "TRUE"

            b_group_select = ", ".join(f"B.{k}" for k in group_keys)

            return f"""
            WITH filtered_b AS (
                SELECT *
                FROM events
                WHERE {then_raw} {b_exclude_sql}
            ),
            filtered_a AS (
                SELECT *
                FROM events
                WHERE {a_raw} {a_exclude_sql}
            )
            SELECT
                B.event_id AS primary_event_id,
                B.ts,
                COALESCE(arg_min({host_b}, A.source_offset), arg_min({host_a}, A.source_offset), 'unknown') AS host,
                COALESCE(arg_min({user_b}, A.source_offset), arg_min({user_a}, A.source_offset), '') AS user_entity,
                COALESCE(arg_min({src_b}, A.source_offset), arg_min({src_a}, A.source_offset), '') AS src_ip_entity,
                list_sort(list_distinct(list_concat(
                    list_concat(
                        LIST(A.event_id ORDER BY A.ts, A.source_offset)[1:24],
                        LIST(A.event_id ORDER BY A.ts DESC, A.source_offset DESC)[1:25]
                    ),
                    [B.event_id]
                ))) AS evidence_event_ids,
                TRUE AS has_followup
            FROM filtered_b B
            JOIN filtered_a A ON {join_sql}
                         AND TRY_CAST(A.ts AS TIMESTAMPTZ) >= TRY_CAST(B.ts AS TIMESTAMPTZ) - INTERVAL '{window_sec} SECONDS'
                         AND TRY_CAST(A.ts AS TIMESTAMPTZ) <= TRY_CAST(B.ts AS TIMESTAMPTZ)
            GROUP BY B.event_id, B.ts, {b_group_select}
            HAVING COUNT(A.event_id) >= {min_cnt}
            ORDER BY B.ts ASC, primary_event_id ASC
            """
        else:
            group_cols_sql = ", ".join(group_keys)
            # Build HAVING clause: support both COUNT(*) and COUNT(DISTINCT field)
            having_clauses = [f"COUNT(*) >= {min_cnt}"]
            if rule.min_distinct_field and rule.min_distinct is not None:
                having_clauses.append(f"COUNT(DISTINCT {rule.min_distinct_field}) >= {rule.min_distinct}")
            having_sql = " AND ".join(having_clauses)
            return f"""
            SELECT
                arg_min(event_id, source_offset) AS primary_event_id,
                MAX(ts) AS ts,
                COALESCE(arg_min({host_expr}, source_offset), 'unknown') AS host,
                COALESCE(arg_min({user_expr}, source_offset), '') AS user_entity,
                COALESCE(arg_min({src_ip_expr}, source_offset), '') AS src_ip_entity,
                list_sort(list_distinct(list_concat(
                    LIST(event_id ORDER BY ts, source_offset)[1:25],
                    LIST(event_id ORDER BY ts DESC, source_offset DESC)[1:25]
                ))) AS evidence_event_ids,
                FALSE AS has_followup
            FROM events
            WHERE {where_sql} {exclude_sql}
            GROUP BY {group_cols_sql}, time_bucket(INTERVAL '{window_sec} SECONDS', TRY_CAST(ts AS TIMESTAMPTZ))
            HAVING {having_sql}
            ORDER BY ts ASC, primary_event_id ASC
            """

    # 4. Type: SEQUENCE
    elif r_type == "sequence":
        window_sec = rule.window_seconds or 600
        step_a = rule.steps[0].get("where", {}) if len(rule.steps) > 0 else (rule.where or {})
        step_b = rule.steps[1].get("where", {}) if len(rule.steps) > 1 else (rule.then or {})

        a_where = _compile_condition(step_a, table_prefix="A")
        b_where = _compile_condition(step_b, table_prefix="B")
        a_exclude = _compile_exclude(rule.exclude, table_prefix="A")
        b_exclude = _compile_exclude(rule.exclude, table_prefix="B")

        user_a = _entity_expr(["user", "user_name", "user_raw", "account"], valid_columns, prefix="A")
        user_b = _entity_expr(["user", "user_name", "user_raw", "account"], valid_columns, prefix="B")
        host_a = _entity_expr(["host", "hostname", "devname", "computer_name"], valid_columns, prefix="A", default="'unknown'")
        host_b = _entity_expr(["host", "hostname", "devname", "computer_name"], valid_columns, prefix="B", default="'unknown'")
        src_a = _entity_expr(["src_ip", "srcip", "source_ip"], valid_columns, prefix="A")
        src_b = _entity_expr(["src_ip", "srcip", "source_ip"], valid_columns, prefix="B")

        group_keys = rule.group_by or ["user", "host"]
        join_preds = []
        for k in group_keys:
            join_preds.append(f"LOWER(CAST(COALESCE(A.{k}, '') AS VARCHAR)) = LOWER(CAST(COALESCE(B.{k}, '') AS VARCHAR))")
        join_sql = " AND ".join(join_preds) if join_preds else "TRUE"

        return f"""
        SELECT
            B.event_id AS primary_event_id,
            B.ts,
            COALESCE({host_b}, {host_a}, 'unknown') AS host,
            COALESCE({user_b}, {user_a}, '') AS user_entity,
            COALESCE({src_b}, {src_a}, '') AS src_ip_entity,
            list_sort([A.event_id, B.event_id]) AS evidence_event_ids,
            TRUE AS has_followup
        FROM events A
        JOIN events B ON {join_sql}
                     AND TRY_CAST(B.ts AS TIMESTAMPTZ) >= TRY_CAST(A.ts AS TIMESTAMPTZ)
                     AND TRY_CAST(B.ts AS TIMESTAMPTZ) <= TRY_CAST(A.ts AS TIMESTAMPTZ) + INTERVAL '{window_sec} SECONDS'
                     AND A.event_id != B.event_id
        WHERE {a_where}
          AND {b_where}
          {a_exclude}
          {b_exclude}
        ORDER BY B.ts ASC, primary_event_id ASC
        """

    return None


def _is_internal_ip(ip: str) -> bool:
    """Check if IP belongs to private RFC1918 internal address space."""
    return bool(re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)", str(ip)))


def _to_epoch(ts: Any) -> float:
    """Parse timestamp into POSIX epoch seconds."""
    from datetime import datetime
    if isinstance(ts, int | float):
        return float(ts)
    if isinstance(ts, datetime):
        return ts.timestamp()
    if ts:
        try:
            clean = str(ts).replace("Z", "+00:00")
            return datetime.fromisoformat(clean).timestamp()
        except Exception:
            pass
    return 0.0


def apply_population_guard(
    dets: list[dict[str, Any]],
    burst_seconds: set[str] | None = None,
) -> int:
    """Flag windows where >= 10 distinct sources trip the same rule in a 15-minute window
    OR where rule events fall in a 1-second bucket holding > 200 events.

    Mutates detections in-place setting suppressed=True and suppress_reason.
    Returns the count of newly suppressed detections.
    """
    if not dets:
        return 0

    indexed_dets = sorted(enumerate(dets), key=lambda x: _to_epoch(x[1].get("ts")))
    n = len(indexed_dets)
    suppressed_count = 0

    # 1. 15-minute window (900s) with >= 10 distinct sources
    left = 0
    current_sources: dict[str, int] = {}
    for right in range(n):
        orig_idx_r, d_r = indexed_dets[right]
        src_r = str(d_r.get("src_ip") or d_r.get("host") or "").strip()
        if src_r:
            current_sources[src_r] = current_sources.get(src_r, 0) + 1

        t_r = _to_epoch(d_r.get("ts"))
        while left < right and t_r - _to_epoch(indexed_dets[left][1].get("ts")) > 900.0:
            _, d_l = indexed_dets[left]
            src_l = str(d_l.get("src_ip") or d_l.get("host") or "").strip()
            if src_l in current_sources:
                current_sources[src_l] -= 1
                if current_sources[src_l] == 0:
                    del current_sources[src_l]
            left += 1

        if len(current_sources) >= 10:
            for k in range(left, right + 1):
                orig_idx_k, d_k = indexed_dets[k]
                if not d_k.get("suppressed"):
                    d_k["suppressed"] = True
                    d_k["suppress_reason"] = "population-window-artifact (distinct_sources)"
                    suppressed_count += 1

    # 2. Rule events fall in a 1-second bucket holding > 200 events
    for _, d in indexed_dets:
        n_ev = d.get("n_events", 0)
        t_start = d.get("t_start") or d.get("ts")
        t_end = d.get("t_end") or d.get("ts")
        span = abs(_to_epoch(t_end) - _to_epoch(t_start))

        is_1s_burst = (n_ev > 200 and span <= 1.0)
        ts_str = str(d.get("ts") or "")[:19]
        if burst_seconds and any(b in ts_str for b in burst_seconds):
            is_1s_burst = True

        if is_1s_burst and not d.get("suppressed"):
            d["suppressed"] = True
            d["suppress_reason"] = "population-burst-1s (1sec_bucket)"
            suppressed_count += 1

    return suppressed_count


def check_prevalence_guard(
    rule: Rule,
    dets: list[dict[str, Any]],
    total_internal_ips: int,
) -> tuple[bool, int, float, float, str]:
    """Check rule firings against prevalence and entropy guards.

    If a rule fires for > 5% of distinct sources and near-uniformly across sources (> 0.90 entropy),
    or across > 50% of distinct sources, mark it as background=True.
    """
    if not dets:
        return False, 0, 0.0, 0.0, "ACTIVE"

    source_counts: dict[str, int] = {}
    for d in dets:
        src = str(d.get("src_ip") or d.get("host") or "").strip()
        if src:
            source_counts[src] = source_counts.get(src, 0) + 1

    k = len(source_counts)
    if k == 0:
        return False, 0, 0.0, 0.0, "ACTIVE"

    total_m = len(dets)
    norm_entropy = 0.0
    if k > 1:
        probs = [cnt / total_m for cnt in source_counts.values()]
        h = -sum(p * math.log2(p) for p in probs)
        norm_entropy = h / math.log2(k)

    denom = max(1, total_internal_ips)
    share = k / denom

    is_bg = ((share > 0.05 and norm_entropy > 0.90) or (share > 0.50)) and (k >= 10 and denom >= 10)
    decision = "BACKGROUND" if is_bg else "ACTIVE"
    return is_bg, k, share, norm_entropy, decision


def execute_rule(
    rule: Rule,
    valid_columns: set[str],
    burst_seconds: set[str] | None = None,
    total_internal_ips: int = 1386,
) -> tuple[Rule, int, float, str]:
    """Execute a single rule query against DuckDB, persisting detections idempotently."""
    t0 = time.perf_counter()
    sql = compile_rule_to_sql(rule, valid_columns)
    if not sql:
        return rule, 0, 0.0, "Disabled (missing field)"

    # Idempotent delete of existing detections for this rule
    duck.delete_detections_for_rule(rule.id)

    matches_count = 0
    suppressed_count = 0
    try:
        with duck.cursor() as con:
            rows = con.execute(sql).fetchmany(5000)

        if rows:
            dets_to_insert = []
            links_to_insert = []
            max_rule_matches = 5000
            is_sql_rule = (rule.type.lower() == "sql")

            for r in rows[:max_rule_matches]:
                det_id = duck.new_id("det")
                if is_sql_rule:
                    (
                        r_id,
                        tech_id,
                        tac,
                        src_ip,
                        dst_ip,
                        user_ent,
                        t_start,
                        t_end,
                        eids,
                        n_events,
                        metric,
                        sev,
                    ) = r
                    src_s = str(src_ip or "")
                    dst_s = str(dst_ip or "")
                    host = (
                        src_s
                        if _is_internal_ip(src_s)
                        else (dst_s if _is_internal_ip(dst_s) else (src_s or dst_s or "network"))
                    )
                    ts = t_start
                    eids_list = eids if isinstance(eids, list) else []
                    num_sev = int(sev) if sev is not None else rule.numeric_severity
                    dets_to_insert.append({
                        "detection_id": det_id,
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "technique_id": tech_id or rule.technique_id,
                        "tactic": tac or rule.tactic,
                        "severity": num_sev,
                        "host": host or "network",
                        "src_ip": src_s,
                        "dst_ip": dst_s,
                        "user": str(user_ent or ""),
                        "ts": ts,
                        "t_start": t_start,
                        "t_end": t_end,
                        "n_events": int(n_events or len(eids_list)),
                        "metric": metric,
                        "event_ids": eids_list[:50],
                        "confidence": round(rule.confidence, 2),
                        "kill_chain_stage": rule.kill_chain_stage or "",
                        "suppressed": False,
                        "suppress_reason": None,
                    })
                    for eid in eids_list[:20]:
                        links_to_insert.append((det_id, eid, tech_id or rule.technique_id, tac or rule.tactic))
                else:
                    ev_id, ts, host, user_ent, src_ip_ent, eids, has_followup = r
                    conf = rule.confidence
                    if has_followup:
                        conf = min(1.0, conf + 0.15)
                    eids_list = eids if isinstance(eids, list) else []
                    dets_to_insert.append({
                        "detection_id": det_id,
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "technique_id": rule.technique_id,
                        "tactic": rule.tactic,
                        "severity": rule.numeric_severity,
                        "host": host or "unknown",
                        "src_ip": str(src_ip_ent or ""),
                        "dst_ip": "",
                        "user": str(user_ent or ""),
                        "ts": ts,
                        "t_start": ts,
                        "t_end": ts,
                        "n_events": len(eids_list),
                        "metric": 1,
                        "event_ids": eids_list[:50],
                        "confidence": round(conf, 2),
                        "kill_chain_stage": rule.kill_chain_stage or "",
                        "suppressed": False,
                        "suppress_reason": None,
                    })
                    for eid in eids_list[:20]:
                        links_to_insert.append((det_id, eid, rule.technique_id, rule.tactic))

            suppressed_count = apply_population_guard(dets_to_insert, burst_seconds)

            # Generic Prevalence Guard
            is_bg, k, share, norm_entropy, decision = check_prevalence_guard(
                rule, dets_to_insert, total_internal_ips
            )
            rule.background = is_bg
            rule.prevalence_k = k
            rule.prevalence_share = share
            rule.prevalence_entropy = norm_entropy
            rule.prevalence_decision = decision

            if is_bg:
                for d in dets_to_insert:
                    d["suppressed"] = True
                    d["suppress_reason"] = "background-prevalence"
                suppressed_count = len(dets_to_insert)

            matches_count = len(dets_to_insert)

            duck.insert_detections_batch(dets_to_insert)
            duck.link_detection_events_batch(links_to_insert)

        elapsed = time.perf_counter() - t0
        rule.suppressed_count = suppressed_count
        return rule, matches_count, elapsed, "OK"
    except Exception as exc:
        elapsed = time.perf_counter() - t0
        logger.error("Error running rule '%s': %s", rule.id, exc)
        return rule, 0, elapsed, f"Error: {exc}"


def boost_multi_tactic_confidences() -> None:
    """Raise confidence for detections where the entity is confirmed by multiple distinct tactics."""
    with duck.cursor() as con:
        try:
            con.execute("""
            UPDATE detections
            SET confidence = LEAST(1.0, confidence + 0.10)
            WHERE host IN (
                SELECT host FROM detections GROUP BY host HAVING COUNT(DISTINCT tactic) > 1
            )
            """)
        except Exception:
            pass


def write_rule_stats_report(stats: list[dict[str, Any]], docs_path: str = "docs/rule_stats.md") -> None:
    """Write per-rule execution summary report to docs/rule_stats.md."""
    os.makedirs(os.path.dirname(os.path.abspath(docs_path)), exist_ok=True)
    total_matches = sum(s["matches"] for s in stats)
    total_suppressed = sum(s.get("suppressed", 0) for s in stats)
    active_matches = max(0, total_matches - total_suppressed)
    total_time = sum(s["runtime"] for s in stats)

    lines = [
        "# Detection Rules Execution Statistics",
        "",
        f"- **Total Rules Configured:** {len(stats)}",
        f"- **Total Raw Detections Generated:** {total_matches:,}",
        f"- **Active (Unsuppressed) Detections:** {active_matches:,}",
        f"- **Suppressed Detections (Background / Artifacts):** {total_suppressed:,}",
        f"- **Total Engine Runtime:** {total_time:.2f}s",
        "",
        "| Rule ID | Rule Name | Type | Technique | Tactic | Stage | Runtime (s) | Matches | Suppressed | Distinct Sources | Prevalence (%) | Entropy | Decision | Status |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]

    for s in stats:
        supp = s.get("suppressed", 0)
        lines.append(
            f"| `{s['rule_id']}` | {s['name']} | `{s['type']}` | `{s['technique']}` | "
            f"{s['tactic']} | {s['stage']} | {s['runtime']:.3f} | {s['matches']:,} | {supp:,} | "
            f"{s.get('distinct_sources', 0):,} | {s.get('prevalence_pct', 0.0):.2f}% | "
            f"{s.get('entropy', 0.0):.4f} | {s.get('decision', 'ACTIVE')} | {s['status']} |"
        )

    lines.append("")
    with open(docs_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def run_detection(
    rules: list[Rule],
    job_id: str,
    max_workers: int = 4,
    docs_dir: str = "docs",
) -> dict[str, Any]:
    """Execute all enabled rules using set-based DuckDB queries over narrow in-memory table."""
    t_start = time.perf_counter()
    duck.init_db()
    duck.materialize_events_narrow()
    valid_cols = duck.get_events_columns()

    # Pre-query global 1-second burst buckets (> 200 events)
    burst_seconds: set[str] = set()
    try:
        with duck.cursor() as con:
            rows = con.execute("""
                SELECT time_bucket(INTERVAL '1 SECOND', ts)::VARCHAR 
                FROM events 
                GROUP BY 1 
                HAVING count(*) > 200
            """).fetchall()
            burst_seconds = {str(r[0])[:19] for r in rows}
    except Exception as exc:
        logger.debug("Could not query 1-second burst buckets: %s", exc)

    # Cache total distinct internal sources
    total_internal_ips = 1386
    try:
        with duck.cursor() as con:
            res = con.execute(r"""
                SELECT count(DISTINCT src_ip)
                FROM events
                WHERE regexp_matches(src_ip, '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)')
            """).fetchone()
            if res and res[0] and res[0] > 0:
                total_internal_ips = res[0]
    except Exception as exc:
        logger.debug("Could not query total internal IPs: %s", exc)

    # Detect active log formats in dataset
    active_formats: set[str] = set()
    try:
        with duck.cursor() as con:
            f_rows = con.execute("SELECT DISTINCT log_format FROM events WHERE log_format IS NOT NULL").fetchall()
            active_formats = {str(r[0]).lower() for r in f_rows if r[0]}
    except Exception as exc:
        logger.debug("Could not query active log formats: %s", exc)
    if not active_formats:
        active_formats = {"firewall_kv", "fortigate_kv"}
    if "fortigate_kv" in active_formats or "firewall_kv" in active_formats:
        active_formats.add("fortigate_kv")
        active_formats.add("firewall_kv")

    stats: list[dict[str, Any]] = []
    total_detections = 0
    total_suppressed = 0

    # Execute rules
    for r in rules:
        if not r.enabled:
            reason = f"Disabled (superseded by {r.superseded_by})" if r.superseded_by else "Disabled"
            logger.info("Rule '%s' is disabled: %s", r.id, reason)
            stats.append({
                "rule_id": r.id,
                "name": r.name,
                "type": r.type,
                "technique": r.technique_id,
                "tactic": r.tactic,
                "stage": r.kill_chain_stage or "",
                "runtime": 0.0,
                "matches": 0,
                "suppressed": 0,
                "distinct_sources": 0,
                "prevalence_pct": 0.0,
                "entropy": 0.0,
                "decision": "DISABLED",
                "status": reason,
            })
            continue

        rule_applies = set(x.lower() for x in (r.applies_to or ["firewall_kv", "fortigate_kv"]))
        if "firewall_kv" in rule_applies:
            rule_applies.add("fortigate_kv")
        if not (rule_applies & active_formats):
            msg = f"Format does not apply ({r.applies_to})"
            logger.info("Rule '%s' skipped: current format %s does not match applies_to %s", r.id, list(active_formats), r.applies_to)
            stats.append({
                "rule_id": r.id,
                "name": r.name,
                "type": r.type,
                "technique": r.technique_id,
                "tactic": r.tactic,
                "stage": r.kill_chain_stage or "",
                "runtime": 0.0,
                "matches": 0,
                "suppressed": 0,
                "distinct_sources": 0,
                "prevalence_pct": 0.0,
                "entropy": 0.0,
                "decision": "SKIPPED",
                "status": msg,
            })
            continue

        rule, matches, duration, status = execute_rule(
            r, valid_cols, burst_seconds=burst_seconds, total_internal_ips=total_internal_ips
        )
        total_detections += matches
        suppressed_cnt = getattr(rule, "suppressed_count", 0)
        total_suppressed += suppressed_cnt
        stats.append({
            "rule_id": rule.id,
            "name": rule.name,
            "type": rule.type,
            "technique": rule.technique_id,
            "tactic": rule.tactic,
            "stage": rule.kill_chain_stage or "",
            "runtime": duration,
            "matches": matches,
            "suppressed": suppressed_cnt,
            "distinct_sources": getattr(rule, "prevalence_k", 0),
            "prevalence_pct": round(getattr(rule, "prevalence_share", 0.0) * 100, 2),
            "entropy": round(getattr(rule, "prevalence_entropy", 0.0), 4),
            "decision": getattr(rule, "prevalence_decision", "ACTIVE"),
            "status": status,
        })

    # Sort stats deterministically by rule_id
    stats.sort(key=lambda x: x["rule_id"])

    # Boost confidence for multi-tactic entity confirmation
    boost_multi_tactic_confidences()

    # Authoritative counts directly from DuckDB
    raw_detections = total_detections
    active_detections = max(0, total_detections - total_suppressed)
    suppressed_detections = total_suppressed
    suppressed_by_reason: dict[str, int] = {}
    try:
        with duck.cursor() as con:
            raw_detections = con.execute("SELECT count(*) FROM detections").fetchone()[0]
            active_detections = con.execute("SELECT count(*) FROM detections WHERE suppressed = false").fetchone()[0]
            suppressed_detections = con.execute("SELECT count(*) FROM detections WHERE suppressed = true").fetchone()[0]
            rows = con.execute(
                "SELECT coalesce(suppress_reason, 'unspecified'), count(*) "
                "FROM detections WHERE suppressed = true GROUP BY 1 ORDER BY 2 DESC"
            ).fetchall()
            suppressed_by_reason = {str(r[0]): int(r[1]) for r in rows}
    except Exception as exc:
        logger.debug("Could not query detection counts from duckdb: %s", exc)

    # Write rule statistics report
    stats_file = os.path.join(docs_dir, "rule_stats.md")
    write_rule_stats_report(stats, stats_file)

    elapsed = time.perf_counter() - t_start
    duck.update_job(job_id, progress_pct=100)

    return {
        "job_id": job_id,
        "total_rules": len(rules),
        "total_detections": raw_detections,
        "raw_detections": raw_detections,
        "active_detections": active_detections,
        "suppressed_detections": suppressed_detections,
        "suppressed_by_reason": suppressed_by_reason,
        "elapsed_seconds": round(elapsed, 2),
        "rule_stats_report": stats_file,
        "stats": stats,
    }
