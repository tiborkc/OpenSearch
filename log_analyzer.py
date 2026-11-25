from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import requests
import streamlit as st
import urllib3

from auth_playwright import refresh_security_cookie_silently

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REST_PATTERN = re.compile(
    r"(?P<dir>-->|<--)\s+(?P<kind>[A-Z_]+)\s+REST\s+(?P<status>\d{3})?\s*(?P<method>GET|POST|PUT|PATCH|DELETE)\s+(?P<path>\S+)"
)

ERROR_WORD_PATTERN = re.compile(
    r"\b(error|exception|fail|failed|timeout|invalid|unauthorized|forbidden)\b",
    re.IGNORECASE,
)


@dataclass
class ErrorCase:
    timestamp: str
    who: str
    what: str
    status: int | None
    request_summary: list[str] = field(default_factory=list)
    response_summary: list[str] = field(default_factory=list)
    context_logs: list[str] = field(default_factory=list)
    raw_sources: list[dict[str, Any]] = field(default_factory=list)


def _format_utc_ms(dt: datetime) -> str:
    utc_dt = dt.astimezone(timezone.utc)
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def get_nested(data: Any, dotted_key: str, default: Any = None) -> Any:
    if not isinstance(data, dict):
        return default
    if dotted_key in data:
        return data[dotted_key]
    cur: Any = data
    for part in dotted_key.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


def _extract_payload(src: dict[str, Any]) -> str:
    if not isinstance(src, dict) or not src:
        return ""

    raw_str = get_nested(src, "log.communicationPayload.payload.string")
    if isinstance(raw_str, str):
        cleaned = raw_str.strip()
        if not cleaned or cleaned in ('{"string":""}', '{"string": ""}'):
            return ""
        return cleaned

    payload_obj = get_nested(src, "log.communicationPayload.payload")
    if isinstance(payload_obj, dict):
        s = payload_obj.get("string")
        if isinstance(s, str) and s.strip():
            return s.strip()
        non_empty = {
            k: v
            for k, v in payload_obj.items()
            if k != "string" and v not in (None, "", {}, [])
        }
        if non_empty:
            return json.dumps(non_empty, ensure_ascii=False, indent=2)
        return ""

    return ""


def _format_payload_for_display(payload_str: str) -> str:
    if not payload_str:
        return ""
    stripped = payload_str.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            parsed = json.loads(stripped)
            return json.dumps(parsed, ensure_ascii=False, indent=2)
        except Exception:
            pass
    return payload_str


def _extract_request_id(src: dict[str, Any]) -> str:
    if not isinstance(src, dict) or not src:
        return ""
    for key in ("log.requestId", "log.params.x-request-id", "log.contextId"):
        val = get_nested(src, key)
        if val:
            return str(val).strip()
    return ""


def _extract_actor(src: dict[str, Any]) -> str:
    if not isinstance(src, dict) or not src:
        return ""
    parts = [
        get_nested(src, "kubernetes.container_name"),
        get_nested(src, "log.hostname"),
        get_nested(src, "log.loggerName"),
        get_nested(src, "log.initiatorChannel"),
    ]
    clean = [str(p).strip() for p in parts if p and str(p).strip()]
    if not clean:
        return ""
    return clean[0].split("|")[0].strip()


def parse_timestamp(ts_val: Any) -> datetime:
    if isinstance(ts_val, datetime):
        return ts_val if ts_val.tzinfo else ts_val.replace(tzinfo=timezone.utc)

    s = str(ts_val).strip()
    if " @ " in s:
        cleaned = s.replace(" @ ", " ")
        for fmt in ("%b %d, %Y %H:%M:%S.%f", "%b %d, %Y %H:%M:%S"):
            try:
                return datetime.strptime(cleaned, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue

    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _request_with_auto_reauth(
    method: str,
    url: str,
    base_url: str,
    session_cookie: str,
    headers: dict[str, str],
    **kwargs: Any,
) -> requests.Response:
    """Elküldi a kérést; 401/403 esetén háttérben frissíti a cookie-t és egyszer újrapróbálja."""
    active_cookie = (os.getenv("OS_SECURITY_COOKIE") or session_cookie or "").strip()
    req_headers = dict(headers)
    if active_cookie:
        req_headers["Cookie"] = f"security_authentication={active_cookie}"

    resp = requests.request(method, url, headers=req_headers, **kwargs)

    if resp.status_code in (401, 403):
        new_cookie = refresh_security_cookie_silently(
            base_url=base_url,
            env_path=Path(__file__).resolve().parent / ".env",
        )
        try:
            st.session_state["session_cookie_value"] = new_cookie
            st.session_state["cookie_just_refreshed"] = True
            st.toast("Auth key automatikusan frissült, tenantok frissítése...", icon="🔑")
        except Exception:
            pass

        req_headers["Cookie"] = f"security_authentication={new_cookie}"
        resp = requests.request(method, url, headers=req_headers, **kwargs)

    return resp


def fetch_tenants(session_cookie: str, base_url: str) -> dict[str, bool]:
    root_url = base_url.rstrip("/")
    url = f"{root_url}/api/v1/configuration/account?dataSourceId="

    headers = {
        "accept": "*/*",
        "content-type": "application/json",
        "osd-version": "3.7.0",
        "osd-xsrf": "osd-fetch",
    }

    EXCLUDED_TENANT_PATTERNS = re.compile(
        r"^(global|private|__user__|admin)$",
        re.IGNORECASE,
    )

    def _is_system_tenant(name: str) -> bool:
        if EXCLUDED_TENANT_PATTERNS.match(name):
            return True
        if not any(c in name for c in ("-", "_")):
            return True
        return False

    try:
        resp = _request_with_auto_reauth(
            "GET",
            url,
            base_url=root_url,
            session_cookie=session_cookie,
            headers=headers,
            verify=False,
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            tenants: dict[str, bool] = (
                data.get("tenants")
                or data.get("data", {}).get("tenants")
                or {}
            )
            return {
                name: enabled
                for name, enabled in tenants.items()
                if not _is_system_tenant(name)
            }
        else:
            print(f"Tenant API hiba: {resp.status_code} - {resp.text[:200]}")
    except Exception as e:
        print(f"Tenant fetch exception: {e}")
    return {}


def fetch_index_patterns(
    session_cookie: str,
    base_url: str,
    tenant: str = "global",
) -> list[str]:
    fallback_list = ["k8s-ict-cm-dev1-default*", "k8s-b2b-cm-dev1_tenant*"]
    root_url = base_url.rstrip("/")
    url = f"{root_url}/api/saved_objects/_find?type=index-pattern&per_page=100"

    headers = {
        "osd-xsrf": "osd-fetch",
        "Content-Type": "application/json",
        "securitytenant": tenant or "global",
    }

    try:
        resp = _request_with_auto_reauth(
            "GET",
            url,
            base_url=root_url,
            session_cookie=session_cookie,
            headers=headers,
            verify=False,
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            patterns = []
            for obj in data.get("saved_objects", []):
                title = obj.get("attributes", {}).get("title")
                if title:
                    patterns.append(title)
            return sorted(patterns) if patterns else fallback_list
    except Exception as e:
        print(f"Index lekérdezési hiba: {e}")
    return fallback_list


def fetch_logs_from_dashboards(
    correlation_id: str,
    start_utc: datetime,
    end_utc: datetime,
    session_cookie: str,
    base_url: str | None = None,
    index_pattern: str | None = None,
    size: int = 500,
    verify_ssl: bool | None = None,
    tenant: str = "global",
) -> pd.DataFrame:
    root_url = (base_url or os.getenv("OS_DASHBOARDS_URL", "")).rstrip("/")
    idx = index_pattern or os.getenv("OS_INDEX_PATTERN", "k8s-ict-cm-dev1-default*")
    ssl_verify = (
        verify_ssl
        if verify_ssl is not None
        else os.getenv("OS_VERIFY_SSL", "false").lower() == "true"
    )

    url = f"{root_url}/internal/search/opensearch-with-long-numerals"
    headers = {
        "Accept": "*/*",
        "Content-Type": "application/json",
        "Origin": root_url,
        "Referer": f"{root_url}/app/data-explorer/discover",
        "osd-version": "3.7.0",
        "osd-xsrf": "osd-fetch",
        "securitytenant": tenant or "global",
    }

    payload = {
        "params": {
            "index": idx,
            "body": {
                "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "boolean"}}],
                "size": size,
                "stored_fields": ["*"],
                "_source": {"excludes": []},
                "query": {
                    "bool": {
                        "must": [],
                        "filter": [
                            {
                                "multi_match": {
                                    "type": "phrase",
                                    "query": correlation_id.strip(),
                                    "lenient": True,
                                }
                            },
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": _format_utc_ms(start_utc),
                                        "lte": _format_utc_ms(end_utc),
                                        "format": "strict_date_optional_time",
                                    }
                                }
                            },
                        ],
                        "should": [],
                        "must_not": [],
                    }
                },
            },
        }
    }

    resp = _request_with_auto_reauth(
        "POST",
        url,
        base_url=root_url,
        session_cookie=session_cookie,
        json=payload,
        headers=headers,
        verify=ssl_verify,
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()

    raw_resp = data.get("rawResponse") or data
    hits = raw_resp.get("hits", {}).get("hits", [])

    rows: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []

    for h in hits:
        src = h.get("_source", {})
        sources.append(src)

        ts_raw = get_nested(src, "time") or get_nested(src, "@timestamp") or ""
        msg = (
            get_nested(src, "log.msg")
            or get_nested(src, "message")
            or get_nested(src, "msg")
            or str(src)
        )
        payload_str = _extract_payload(src)
        actor = _extract_actor(src)
        req_id = _extract_request_id(src)
        
        rows.append(
            {
                "@timestamp": ts_raw,
                "log.msg": msg,
                "payload": payload_str,
                "actor": actor,
                "request_id": req_id,
                "_source": src,
                "_id": h.get("_id"),
                "_index": h.get("_index"),
                "_score": h.get("_score"),
                "_type": h.get("_type"),
            }
        )

    base_df = pd.DataFrame(rows)

    if not base_df.empty and sources:
        flat_sources_df = pd.json_normalize(sources)
        

        combined_df = pd.concat([base_df, flat_sources_df], axis=1)
        # Eltávolítjuk a duplikált oszlopokat 
        combined_df = combined_df.loc[:, ~combined_df.columns.duplicated()]
        return normalize_logs_df(combined_df)

    return normalize_logs_df(base_df)



def normalize_logs_df(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(
            columns=[
                "dt",
                "@timestamp",
                "log.msg",
                "payload",
                "actor",
                "request_id",
                "dir",
                "kind",
                "status",
                "method",
                "path",
                "_source",
            ]
        )

    out = df.copy()
    for col, default in [("_source", {}), ("payload", ""), ("actor", ""), ("request_id", "")]:
        if col not in out.columns:
            out[col] = [default if default == {} else default for _ in range(len(out))]

    out["dt"] = out["@timestamp"].apply(parse_timestamp)
    out = out.sort_values("dt", ascending=False).reset_index(drop=True)

    dirs, kinds, statuses, methods, paths = [], [], [], [], []
    for msg in out["log.msg"].astype(str):
        m = REST_PATTERN.search(msg.strip())
        if m:
            dirs.append(m.group("dir"))
            kinds.append(m.group("kind"))
            statuses.append(int(m.group("status")) if m.group("status") else None)
            methods.append(m.group("method"))
            paths.append(m.group("path"))
        else:
            dirs.append(None)
            kinds.append(None)
            statuses.append(None)
            methods.append(None)
            paths.append(None)

    out["dir"] = dirs
    out["kind"] = kinds
    out["status"] = statuses
    out["method"] = methods
    out["path"] = paths
    return out


def _is_real_error(row: pd.Series) -> bool:
    status = row.get("status")
    if pd.notna(status) and int(status) >= 400:
        return True
    if pd.notna(status) and 200 <= int(status) < 300:
        return False

    msg = str(row.get("log.msg") or "")
    payload = str(row.get("payload") or "")
    if re.search(r'"severity"\s*:\s*"ERROR"', payload, re.IGNORECASE):
        return True
    if status is None and ERROR_WORD_PATTERN.search(msg):
        return True
    return False


def _format_log_with_payload(r: pd.Series) -> str:
    line = f"{r['@timestamp']} | {r['log.msg']}"
    p = str(r.get("payload") or "").strip()
    if p:
        line += f"\n{_format_payload_for_display(p)}"
    return line


def find_error_cases(df: pd.DataFrame, lookback_rows: int = 6, lookahead_rows: int = 1) -> list[ErrorCase]:
    if df.empty:
        return []

    work_df = (
        df.sort_values("dt", ascending=True).reset_index(drop=True)
        if "dt" in df.columns
        else df.reset_index(drop=True)
    )

    cases: list[ErrorCase] = []
    consumed_indices: set[int] = set()

    # Legfrissebb logtól indulunk visszafelé az időben
    for idx in range(len(work_df) - 1, -1, -1):
        row = work_df.iloc[idx]
        if idx in consumed_indices or not _is_real_error(row):
            continue

        msg = str(row["log.msg"])
        method = row.get("method")
        path = row.get("path")
        status = int(row["status"]) if pd.notna(row.get("status")) else None

        group_indices = [idx]
        for offset in (-1, 1):
            j = idx + offset
            if 0 <= j < len(work_df) and j not in consumed_indices:
                cand = work_df.iloc[j]
                cand_kind = str(cand.get("kind") or "")
                if (
                    "RESPONSE" in cand_kind
                    and cand.get("path") == path
                    and cand.get("status") == row.get("status")
                ):
                    group_indices.append(j)

        group_indices = sorted(set(group_indices))
        for gi in group_indices:
            consumed_indices.add(gi)

        req_blocks: list[str] = []
        search_start = max(0, group_indices[0] - lookback_rows)
        for j in range(group_indices[0] - 1, search_start - 1, -1):
            r = work_df.iloc[j]
            r_kind = str(r.get("kind") or "")
            if "REQUEST" in r_kind and "BODY" in r_kind and (not path or r.get("path") == path):
                req_blocks.insert(0, _format_log_with_payload(r))
                if len(req_blocks) >= 1:
                    break

        if not req_blocks:
            for j in range(group_indices[0] - 1, search_start - 1, -1):
                r = work_df.iloc[j]
                r_kind = str(r.get("kind") or "")
                if "REQUEST" in r_kind and (not path or r.get("path") == path):
                    req_blocks.insert(0, _format_log_with_payload(r))
                    break

        resp_blocks: list[str] = []
        raw_sources: list[dict[str, Any]] = []
        payload_snippets: list[str] = []
        for gi in group_indices:
            r = work_df.iloc[gi]
            r_kind = str(r.get("kind") or "")
            if "RESPONSE" in r_kind and "BODY" in r_kind:
                resp_blocks.append(_format_log_with_payload(r))
                p = str(r.get("payload") or "").strip()
                if p:
                    payload_snippets.append(p)
                src = r.get("_source")
                if isinstance(src, dict) and src:
                    raw_sources.append(src)

        if not resp_blocks:
            for gi in group_indices:
                r = work_df.iloc[gi]
                resp_blocks.append(_format_log_with_payload(r))
                src = r.get("_source")
                if isinstance(src, dict) and src:
                    raw_sources.append(src)

        ctx_start = max(0, group_indices[0] - 1)
        ctx_end = min(len(work_df), group_indices[-1] + lookahead_rows + 1)
        ctx_lines = [
            f"{r['@timestamp']} | {r['log.msg']}"
            for _, r in work_df.iloc[ctx_start:ctx_end].iterrows()
        ]

        actor = str(row.get("actor") or "").strip()
        endpoint_str = f"{method or ''} {path or ''}".strip()
        who = " — ".join([p for p in [endpoint_str, actor] if p]) or "Ismeretlen forrás"

        what_parts = []
        if status is not None:
            what_parts.append(f"HTTP {status}")
        what_parts.append(msg.strip())
        if payload_snippets:
            what_parts.append(payload_snippets[-1][:240])
        what = " | ".join(what_parts)

        cases.append(
            ErrorCase(
                timestamp=str(row["@timestamp"]),
                who=who,
                what=what,
                status=status,
                request_summary=req_blocks or ["(Nincs külön REQUEST sor ehhez a híváshoz)"],
                response_summary=resp_blocks,
                context_logs=ctx_lines,
                raw_sources=raw_sources,
            )
        )

    return cases


def extract_rest_calls(df: pd.DataFrame) -> list[dict[str, Any]]:
    if df.empty:
        return []
    calls = df[df["method"].notna()].copy()
    return calls[["@timestamp", "actor", "dir", "kind", "status", "method", "path", "log.msg", "payload"]].to_dict(orient="records")

def find_rest_call_pair(df: pd.DataFrame, selected_index: Any) -> dict[str, pd.Series | None] | None:
    """Párosítja a kijelölt REST sort a hozzá legközelebbi ellentétes irányú sorral."""
    if df.empty or selected_index not in df.index:
        return None

    selected = df.loc[selected_index]
    method = selected.get("method")
    path = selected.get("path")
    if pd.isna(method) or pd.isna(path) or not method or not path:
        return None

    kind = str(selected.get("kind") or "").upper()
    direction = str(selected.get("dir") or "")
    if "REQUEST" in kind or direction == "-->":
        selected_side = "request"
        counterpart_kind = "RESPONSE"
        time_relation = "after"
    elif "RESPONSE" in kind or direction == "<--":
        selected_side = "response"
        counterpart_kind = "REQUEST"
        time_relation = "before"
    else:
        return None

    candidates = df[
        (df["method"] == method)
        & (df["path"] == path)
        & df["kind"].fillna("").astype(str).str.upper().str.contains(counterpart_kind)
    ].copy()
    if candidates.empty:
        return None

    selected_dt = selected.get("dt")
    if not isinstance(selected_dt, datetime):
        try:
            selected_dt = parse_timestamp(selected.get("@timestamp"))
        except Exception:
            return None

    candidates["_pair_dt"] = candidates["dt"].apply(
        lambda value: value if isinstance(value, datetime) else parse_timestamp(value)
    )
    if time_relation == "after":
        candidates = candidates[candidates["_pair_dt"] >= selected_dt]
    else:
        candidates = candidates[candidates["_pair_dt"] <= selected_dt]
    if candidates.empty:
        return None

    candidates["_pair_distance"] = candidates["_pair_dt"].apply(
        lambda value: abs((value - selected_dt).total_seconds())
    )
    candidates["_pair_body"] = candidates["kind"].fillna("").astype(str).str.upper().str.contains("BODY")
    candidates = candidates.sort_values(
        ["_pair_distance", "_pair_body"], ascending=[True, False]
    )
    counterpart_dt = candidates.iloc[0]["_pair_dt"]

    def prefer_body(reference_row: pd.Series, side_token: str) -> pd.Series:
        reference_dt = reference_row.get("dt")
        if not isinstance(reference_dt, datetime):
            return reference_row
        same_side = df[
            (df["method"] == method)
            & (df["path"] == path)
            & df["kind"].fillna("").astype(str).str.upper().str.contains(side_token)
            & df["kind"].fillna("").astype(str).str.upper().str.contains("BODY")
        ].copy()
        if same_side.empty:
            return reference_row
        same_side["_body_distance"] = same_side["dt"].apply(
            lambda value: abs((value - reference_dt).total_seconds())
            if isinstance(value, datetime) else float("inf")
        )
        nearby_body = same_side[same_side["_body_distance"] <= 2.0]
        if nearby_body.empty:
            return reference_row
        return nearby_body.sort_values("_body_distance").iloc[0].drop(
            labels=["_body_distance"], errors="ignore"
        )

    counterpart = candidates.iloc[0].drop(
        labels=["_pair_dt", "_pair_distance", "_pair_body"], errors="ignore"
    )
    if selected_side == "request":
        return {
            "request": prefer_body(selected, "REQUEST"),
            "response": prefer_body(counterpart, "RESPONSE"),
        }
    return {
        "request": prefer_body(counterpart, "REQUEST"),
        "response": prefer_body(selected, "RESPONSE"),
    }
