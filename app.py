import json
import os
from datetime import datetime, time, timedelta, timezone

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from log_analyzer import (
    extract_rest_calls,
    fetch_index_patterns,
    fetch_logs_from_dashboards,
    fetch_tenants,
    find_error_cases,
    find_rest_call_pair,
)

load_dotenv()

st.set_page_config(page_title="OpenSearch Pro Max", layout="wide")


def render_smart_payload(text_content: str):
    lines = text_content.split("\n")
    if len(lines) > 1:
        header = lines[0]
        payload_body = "\n".join(lines[1:])
        st.caption(f"Log event: `{header}`")
        try:
            json_obj = json.loads(payload_body.strip())
            st.json(json_obj)
        except Exception:
            st.code(text_content,
                    language="json" if "{" in text_content else "text")
    else:
        st.code(text_content, language="text")


def _safe_remove_query_param(key: str) -> None:
    try:
        del st.query_params[key]
    except Exception:
        pass


def _now_utc_sec() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _compute_quick_window(window: str, ref_utc: datetime) -> tuple[datetime, datetime] | None:
    ref_sec = ref_utc.replace(microsecond=0)
    if window == "1 ó":
        return ref_sec - timedelta(hours=1), ref_sec
    if window == "4 ó":
        return ref_sec - timedelta(hours=4), ref_sec
    if window == "Ma":
        start_today = datetime.combine(
            ref_sec.date(), time.min, tzinfo=timezone.utc)
        return start_today, ref_sec
    return None


def _set_window_in_state(start_utc: datetime, end_utc: datetime) -> None:
    s = start_utc.astimezone(timezone.utc).replace(microsecond=0)
    e = end_utc.astimezone(timezone.utc).replace(microsecond=0)
    st.session_state["start_date_val"] = s.date()
    st.session_state["start_time_val"] = s.time()
    st.session_state["end_date_val"] = e.date()
    st.session_state["end_time_val"] = e.time()


def _refresh_time_window_to_now(ref_utc: datetime | None = None) -> tuple[datetime, datetime]:
    """Frissíti az időablakot a jelenlegi UTC időhöz a lekérdezés indításakor."""
    now_sec = (ref_utc or _now_utc_sec()).astimezone(
        timezone.utc).replace(microsecond=0)
    quick_window = st.session_state.get("quick_window_val", "1 ó")
    computed = _compute_quick_window(quick_window, now_sec)
    if computed is not None:
        start_utc, end_utc = computed
        _set_window_in_state(start_utc, end_utc)
        return start_utc, end_utc

    prev_start = datetime.combine(
        st.session_state["start_date_val"],
        st.session_state["start_time_val"],
        tzinfo=timezone.utc,
    ).replace(microsecond=0)
    prev_end = datetime.combine(
        st.session_state["end_date_val"],
        st.session_state["end_time_val"],
        tzinfo=timezone.utc,
    ).replace(microsecond=0)

    if prev_end > prev_start:
        duration = prev_end - prev_start
        start_utc = now_sec - duration
    else:
        start_utc = min(prev_start, now_sec)

    end_utc = now_sec
    _set_window_in_state(start_utc, end_utc)
    return start_utc, end_utc


# SESSION STATE INICIALIZÁLÁS
now_init = _now_utc_sec()
_env_cookie = os.getenv("OS_SECURITY_COOKIE", "").strip()

_defaults: dict = {
    "correlation_id_val": "",
    "quick_window_val": "1 ó",
    "selected_env": "Dev 1",
    "start_date_val": (now_init - timedelta(hours=1)).date(),
    "start_time_val": (now_init - timedelta(hours=1)).time(),
    "end_date_val": now_init.date(),
    "end_time_val": now_init.time(),
    "logs_df": None,
    "last_queried_range": None,
    "size_limit_val": 500,
    "show_all_tenants_val": False,
    "tenants_dict": {},
    "last_fetched_tenant": None,
    "tenants_loaded_for_cookie": None,
    "index_selectbox_idx": 0,
    "index_patterns": [],
    "selected_tenant_val": "",
    "selected_index_val": "",
    "last_selected_env": None,
    "url_state_restored": False,
    "session_cookie_value": _env_cookie,
}

for _k, _v in _defaults.items():
    if _k not in st.session_state:
        st.session_state[_k] = _v

if "cookie_input_widget" not in st.session_state or not st.session_state["cookie_input_widget"]:
    st.session_state["cookie_input_widget"] = st.session_state["session_cookie_value"]


# URL ÁLLAPOT VISSZAÁLLÍTÁS

_saved = st.query_params

if not st.session_state["url_state_restored"]:
    _env_from_url = _saved.get("env")
    if _env_from_url in ("Dev 1", "Dev 2"):
        st.session_state["selected_env"] = _env_from_url

    if "cols" in _saved and _saved["cols"].strip():
        _url_cols = [c.strip() for c in _saved["cols"].split(",") if c.strip()]
        if _url_cols:
            st.session_state["persistent_visible_columns"] = _url_cols

    if _saved.get("restore") == "1":
        for _param, _key in {
            "tenant": "selected_tenant_val",
            "index": "selected_index_val",
            "id": "correlation_id_val",
        }.items():
            if _param in _saved:
                st.session_state[_key] = _saved[_param]

        if "size" in _saved:
            try:
                st.session_state["size_limit_val"] = max(
                    10, min(5000, int(_saved["size"])))
            except ValueError:
                pass

        if "all_tenants" in _saved:
            st.session_state["show_all_tenants_val"] = _saved["all_tenants"] == "1"

        restored_any_time = False
        for _param, _key in (
            ("start_date", "start_date_val"),
            ("start_time", "start_time_val"),
            ("end_date", "end_date_val"),
            ("end_time", "end_time_val"),
        ):
            if _param in _saved:
                try:
                    st.session_state[_key] = (
                        datetime.fromisoformat(_saved[_param]).date()
                        if "date" in _param
                        else time.fromisoformat(_saved[_param]).replace(microsecond=0)
                    )
                    restored_any_time = True
                except ValueError:
                    pass

        if restored_any_time:
            st.session_state["quick_window_val"] = "Egyéni"

    st.session_state["url_state_restored"] = True


# SIDEBAR

ENV_MAP: dict[str, str] = {
    "Dev 1": "https://dashboards-dev1.os.telekom.intra",
    "Dev 2": "https://dashboards-dev2.os.telekom.intra",
}

with st.sidebar:
    st.header("Kapcsolat és szűrők")

    env_list = list(ENV_MAP.keys())
    chosen_env: str = st.selectbox(
        "Környezet",
        options=env_list,
        index=env_list.index(st.session_state["selected_env"])
        if st.session_state["selected_env"] in env_list
        else 0,
        key="selected_env",
        help="Válassz a Dev 1 és Dev 2 környezetek közül.",
    )
    base_url: str = ENV_MAP[chosen_env]

    if (
        st.session_state["last_selected_env"] is not None
        and st.session_state["last_selected_env"] != chosen_env
    ):
        st.session_state["tenants_dict"] = {}
        st.session_state["index_patterns"] = []
        st.session_state["last_fetched_tenant"] = None
        st.session_state["tenants_loaded_for_cookie"] = None
        st.session_state["selected_tenant_val"] = ""
        st.session_state["selected_index_val"] = ""
        st.session_state["logs_df"] = None
        st.session_state["last_queried_range"] = None
        st.session_state["last_selected_env"] = chosen_env
        st.query_params["env"] = chosen_env
        st.query_params["restore"] = "0"
        _safe_remove_query_param("tenant")
        _safe_remove_query_param("index")
        st.rerun()

    if st.session_state["last_selected_env"] is None:
        st.session_state["last_selected_env"] = chosen_env

    session_cookie: str = st.text_input(
        "security_authentication",
        key="cookie_input_widget",
        type="password",
        help="401-es válasznál automatikusan frissül a Playwright segítségével.",
    )
    if session_cookie != st.session_state["session_cookie_value"]:
        st.session_state["session_cookie_value"] = session_cookie

    active_cookie: str = (
        st.session_state.get("session_cookie_value", "").strip()
        or os.getenv("OS_SECURITY_COOKIE", "").strip()
        or ""
    )

    has_auth_source = bool(
        active_cookie
        or (os.getenv("OS_LOGIN_USER", "").strip() and os.getenv("OS_LOGIN_PASS", "").strip())
    )

    auto_refresh_tenants = bool(
        st.session_state.pop("cookie_just_refreshed", False))
    needs_initial_tenant_load = bool(
        has_auth_source
        and not st.session_state["tenants_dict"]
        and st.session_state["tenants_loaded_for_cookie"] != active_cookie
    )

    if has_auth_source:
        manual_refresh = st.button("Frissítés", use_container_width=True)
        if manual_refresh or auto_refresh_tenants or needs_initial_tenant_load:
            try:
                latest_cookie = (
                    st.session_state.get("session_cookie_value")
                    or os.getenv("OS_SECURITY_COOKIE")
                    or active_cookie
                    or ""
                ).strip()
                with st.spinner("Betöltés..."):
                    fetched_tenants = fetch_tenants(latest_cookie, base_url)
                    after_cookie = (
                        st.session_state.get("session_cookie_value")
                        or os.getenv("OS_SECURITY_COOKIE")
                        or latest_cookie
                        or ""
                    ).strip()
                    st.session_state["tenants_dict"] = fetched_tenants
                    st.session_state["tenants_loaded_for_cookie"] = after_cookie
                    st.session_state["last_fetched_tenant"] = None
                    if fetched_tenants:
                        enabled_count = sum(
                            1 for v in fetched_tenants.values() if v)
                        st.toast(
                            f"{len(fetched_tenants)} tenant betöltve ({enabled_count} aktív)")
            except Exception as exc:
                st.error(f"Tenant lekérdezési hiba: {exc}")

    tenants_dict: dict[str, bool] = st.session_state["tenants_dict"]
    saved_tenant: str = st.session_state.get("selected_tenant_val", "")

    show_all_tenants: bool = False
    selected_tenant: str = ""

    if tenants_dict:
        show_all_tenants = st.toggle(
            "Inaktív tenantok megjelenítése",
            key="show_all_tenants_val",
            help="Ha bekapcsolod, a false értékű tenantok is látszanak.",
        )
        tenant_options = (
            sorted(tenants_dict.keys())
            if show_all_tenants
            else sorted(k for k, v in tenants_dict.items() if v)
        )
        if tenant_options:
            selected_tenant = st.selectbox(
                "Tenantok",
                options=[""] + tenant_options,
                index=(tenant_options.index(saved_tenant) + 1)
                if saved_tenant in tenant_options
                else 0,
                key="selected_tenant_val",
                help="Válaszd ki a tenantot.",
                placeholder="Válassz...",
            )
        else:
            st.warning("Nincs találat a szűrőre.")
            selected_tenant = ""
    else:
        selected_tenant = st.selectbox(
            "Tenant",
            options=["global"],
            index=0,
            key="selected_tenant_val",
            help="A tenantok automatikusan frissülnek.",
        )
        st.caption(
            "A tenantok automatikusan frissülnek, amint érvényes a belépés.")

    has_selected_tenant = bool((selected_tenant or "").strip())

    if has_selected_tenant:
        if has_auth_source and selected_tenant != st.session_state["last_fetched_tenant"]:
            try:
                with st.spinner(f"Indexek betöltése ({selected_tenant})..."):
                    fetched = fetch_index_patterns(
                        active_cookie, base_url, tenant=selected_tenant)
                    st.session_state["index_patterns"] = fetched
                    st.session_state["last_fetched_tenant"] = selected_tenant
                    st.session_state["index_selectbox_idx"] = 0
            except Exception as exc:
                st.error(f"Index lekérdezési hiba: {exc}")

        index_options: list[str] = st.session_state.get("index_patterns") or []
        saved_index: str = st.session_state.get("selected_index_val", "")
        default_index = (
            index_options.index(saved_index)
            if saved_index in index_options
            else min(st.session_state["index_selectbox_idx"], max(0, len(index_options) - 1))
        )
        index_pattern: str = st.selectbox(
            "Index",
            options=index_options,
            index=default_index if index_options else None,
            key="selected_index_val",
            placeholder="Válassz indexet",
            disabled=len(index_options) == 0,
        )
    else:
        st.session_state["index_patterns"] = []
        st.session_state["last_fetched_tenant"] = None
        index_pattern = st.selectbox(
            "Index",
            options=[],
            index=None,
            placeholder="Nincs kiválasztva Tenant",
            disabled=True,
        )

    is_sidebar_disabled = not (has_selected_tenant and index_pattern)

    correlation_id: str = st.text_input(
        "ID",
        key="correlation_id_val",
        disabled=is_sidebar_disabled,
        placeholder="Nincs kiválasztva Tenant" if is_sidebar_disabled else "Keresés...",
    )

    st.write("**Időablak (UTC):**")
    q_col1, q_col2, q_col3 = st.columns(3)

    for col, label in ((q_col1, "1 ó"), (q_col2, "4 ó"), (q_col3, "Ma")):
        if col.button(
            label,
            use_container_width=True,
            disabled=is_sidebar_disabled,
            type="primary" if st.session_state["quick_window_val"] == label else "secondary",
        ):
            st.session_state["quick_window_val"] = label
            computed = _compute_quick_window(label, _now_utc_sec())
            if computed is not None:
                _set_window_in_state(*computed)
            st.rerun()

    previous_time_range = (
        st.session_state["start_date_val"],
        st.session_state["start_time_val"].replace(microsecond=0),
        st.session_state["end_date_val"],
        st.session_state["end_time_val"].replace(microsecond=0),
    )

    col_d1, col_d2 = st.columns(2)
    with col_d1:
        start_date = st.date_input(
            "Kezdő dátum",
            value=previous_time_range[0],
            disabled=is_sidebar_disabled,
        )
        start_t = st.time_input(
            "-tól",
            value=previous_time_range[1],
            step=timedelta(seconds=1),
            disabled=is_sidebar_disabled,
        ).replace(microsecond=0)
    with col_d2:
        end_date = st.date_input(
            "Záró dátum",
            value=previous_time_range[2],
            disabled=is_sidebar_disabled,
        )
        end_t = st.time_input(
            "-ig",
            value=previous_time_range[3],
            step=timedelta(seconds=1),
            disabled=is_sidebar_disabled,
        ).replace(microsecond=0)

    current_time_range = (start_date, start_t, end_date, end_t)
    if current_time_range != previous_time_range:
        st.session_state["quick_window_val"] = "Egyéni"

    st.session_state["start_date_val"] = start_date
    st.session_state["start_time_val"] = start_t
    st.session_state["end_date_val"] = end_date
    st.session_state["end_time_val"] = end_t

    size_limit: int = st.number_input(
        "Max találatok",
        min_value=10,
        max_value=5000,
        step=50,
        key="size_limit_val",
        disabled=is_sidebar_disabled,
    )

    run_btn = st.button(
        "Lekérdezés és elemzés",
        type="primary",
        use_container_width=True,
        disabled=is_sidebar_disabled,
    )

    if run_btn:
        _refreshed_start, _refreshed_end = _refresh_time_window_to_now(
            _now_utc_sec())

        st.query_params["restore"] = "1"
        st.query_params["env"] = chosen_env
        st.query_params["tenant"] = selected_tenant
        st.query_params["index"] = index_pattern or ""
        st.query_params["id"] = correlation_id
        st.query_params["start_date"] = _refreshed_start.date().isoformat()
        st.query_params["start_time"] = _refreshed_start.time().isoformat()
        st.query_params["end_date"] = _refreshed_end.date().isoformat()
        st.query_params["end_time"] = _refreshed_end.time().isoformat()
        st.query_params["size"] = str(size_limit)
        st.query_params["all_tenants"] = "1" if show_all_tenants else "0"


# LEKÉRDEZÉS

_saved_corr_id: str = st.session_state.get("correlation_id_val", "").strip()
_saved_index: str = st.session_state.get("selected_index_val", "").strip()
_saved_tenant: str = st.session_state.get("selected_tenant_val", "").strip()

restore_search = (
    st.query_params.get("restore") == "1"
    and st.session_state.get("logs_df") is None
    and bool(_saved_corr_id)
    and bool(_saved_index)
    and bool(_saved_tenant)
    and bool(active_cookie or os.getenv("OS_LOGIN_USER", "").strip())
)

if run_btn or restore_search:
    _corr_id = correlation_id.strip() if run_btn else _saved_corr_id
    _index = (index_pattern or "").strip() if run_btn else _saved_index
    _tenant = (selected_tenant or "").strip() if run_btn else _saved_tenant
    _base_url = base_url

    if run_btn:
        _start_utc, _end_utc = _refresh_time_window_to_now(_now_utc_sec())
    else:
        _start_utc = datetime.combine(
            st.session_state["start_date_val"],
            st.session_state["start_time_val"],
            tzinfo=timezone.utc,
        ).replace(microsecond=0)
        _end_utc = datetime.combine(
            st.session_state["end_date_val"],
            st.session_state["end_time_val"],
            tzinfo=timezone.utc,
        ).replace(microsecond=0)

    if not _corr_id:
        st.warning("Adj meg egy ID-t!")
    elif not _index:
        st.warning("Nincs kiválasztott index!")
    elif not _tenant:
        st.warning("Nincs kiválasztott tenant!")
    else:
        try:
            cookie_before: str = (
                st.session_state.get("session_cookie_value", "").strip()
                or os.getenv("OS_SECURITY_COOKIE", "").strip()
                or ""
            )
            with st.spinner("Logok betöltése..."):
                df_result = fetch_logs_from_dashboards(
                    correlation_id=_corr_id,
                    start_utc=_start_utc,
                    end_utc=_end_utc,
                    session_cookie=cookie_before,
                    base_url=_base_url,
                    index_pattern=_index,
                    size=int(st.session_state["size_limit_val"]),
                    tenant=_tenant,
                )
                st.session_state["logs_df"] = df_result
                st.session_state["last_queried_range"] = (
                    _start_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    _end_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
                )
                st.toast("Lekérdezés kész!")

            cookie_after: str = (
                st.session_state.get("session_cookie_value", "").strip()
                or os.getenv("OS_SECURITY_COOKIE", "").strip()
                or ""
            )
            if st.session_state.get("cookie_just_refreshed") or cookie_after != cookie_before:
                st.session_state["cookie_input_widget"] = cookie_after
                st.session_state["session_cookie_value"] = cookie_after
                st.session_state["tenants_dict"] = {}
                st.session_state["tenants_loaded_for_cookie"] = None
                st.session_state.pop("cookie_just_refreshed", None)
                st.rerun()

            if run_btn:
                st.rerun()

        except Exception as exc:
            st.error(f"Lekérdezési hiba: {exc}")


# EREDMÉNYEK 

df = st.session_state["logs_df"]
queried_range = st.session_state.get("last_queried_range")

st.markdown(
    """
    <style>
        section.main > div { max-width: 100% !important; }
        .block-container {
            padding-left: 1rem !important;
            padding-right: 1rem !important;
            padding-top: 3.75rem !important;
        }
        [data-testid="stAlert"] {
            margin-top: 0.25rem;
            z-index: 1;
        }
        button[data-baseweb="tab"] { font-size: 16px !important; font-weight: 600 !important; }
    </style>
    """,
    unsafe_allow_html=True,
)

if df is not None:
    if df.empty:
        st.warning("Nincs találat a megadott ID-ra az adott idősávban.")
    else:
        error_cases = find_error_cases(df)
        calls = extract_rest_calls(df)

        tab1, tab2 = st.tabs(
            ["1. Hibák és metrikák", "2. Összes hívás"])

        # TAB 1: HIBAKERESŐ & METRIKÁK

        with tab1:
            m1, m2, m3 = st.columns(3)
            m1.metric("Összes log", len(df))
            m2.metric("REST hívás", len(calls))
            m3.metric("Talált hibák / figyelmeztetések", len(error_cases))
            st.divider()

            if not error_cases:
                st.success("Nem találtam hibát a logokban. 🎉")
            else:
                for i, case in enumerate(error_cases, start=1):
                    title = f"#{i} | {case.timestamp} | {case.who} -> {case.what[:90]}"
                    with st.expander(title, expanded=(i == 1)):
                        st.markdown(f"**Ki dobta:** `{case.who}`")
                        st.markdown(f"**Mit dobott:** `{case.what}`")
                        col_req, col_resp = st.columns(2)
                        with col_req:
                            st.markdown("**Küldött Request Body / Payload:**")
                            for req_text in case.request_summary:
                                render_smart_payload(req_text)
                        with col_resp:
                            st.markdown(
                                "**Visszakapott Response Body / Payload:**")
                            for resp_text in case.response_summary:
                                render_smart_payload(resp_text)
                        with st.expander("Környező logsorok (időrendben)"):
                            st.code("\n".join(case.context_logs),
                                    language="text")
                        if case.raw_sources:
                            with st.expander("Nyers OpenSearch _source"):
                                st.json(case.raw_sources)

        # TAB 2: LISTA NÉZET

        with tab2:
            full_df = df.copy()
            for col_name in full_df.columns:
                full_df[col_name] = full_df[col_name].fillna("").astype(str)

            all_columns = list(full_df.columns)

            default_visible = [c for c in [
                "actor", "log.msg"] if c in all_columns]
            if not default_visible:
                default_visible = all_columns[:2]

            if "persistent_visible_columns" not in st.session_state:
                st.session_state["persistent_visible_columns"] = list(
                    default_visible)

            valid_persistent_cols = [
                c for c in st.session_state["persistent_visible_columns"] if c in all_columns
            ]
            if not valid_persistent_cols:
                valid_persistent_cols = list(default_visible)

            st.session_state["persistent_visible_columns"] = valid_persistent_cols
            st.session_state["temp_multiselect_key"] = list(
                valid_persistent_cols)

            def on_column_change():
                updated = [
                    c for c in st.session_state.get("temp_multiselect_key", []) if c in all_columns
                ]
                st.session_state["persistent_visible_columns"] = updated
                if updated:
                    st.query_params["cols"] = ",".join(updated)
                else:
                    _safe_remove_query_param("cols")

            ctrl_col1, ctrl_col2, ctrl_col3 = st.columns([5, 4, 2])

            with ctrl_col1:
                st.multiselect(
                    "Oszlopok ki/be kapcsolása:",
                    options=all_columns,
                    key="temp_multiselect_key",
                    on_change=on_column_change,
                    label_visibility="collapsed",
                )

            with ctrl_col2:
                global_search = st.text_input(
                    "Kereső",
                    key="tab2_global_search",
                    placeholder="Keresés az összes mezőben...",
                    label_visibility="collapsed",
                ).strip()

            filtered_df = full_df.copy()
            if global_search:
                mask = filtered_df.apply(
                    lambda row: row.str.contains(
                        global_search, case=False, na=False).any(),
                    axis=1,
                )
                filtered_df = filtered_df[mask]

            with ctrl_col3:
                st.markdown(
                    f"<div style='text-align: right; padding-top: 6px; font-weight: bold; color: #aaa;'>"
                    f"Sorok: {len(filtered_df)} / {len(full_df)}"
                    f"</div>",
                    unsafe_allow_html=True,
                )

            col_cfg: dict = {}
            for c in all_columns:
                if c == "actor":
                    col_cfg[c] = st.column_config.TextColumn("name", width=120)
                elif c == "status":
                    col_cfg[c] = st.column_config.TextColumn("HTTP", width=70)
                elif c == "log.msg":
                    col_cfg[c] = st.column_config.TextColumn(
                        "log.msg", width="large")
                elif c == "payload":
                    col_cfg[c] = st.column_config.TextColumn(
                        "payload", width="large")
                else:
                    col_cfg[c] = st.column_config.TextColumn(c, width="medium")

            active_cols = st.session_state["persistent_visible_columns"]

            try:
                selection = st.dataframe(
                    filtered_df,
                    use_container_width=True,
                    hide_index=True,
                    column_order=active_cols,
                    column_config=col_cfg,
                    height=750,
                    on_select="rerun",
                    selection_mode="single-row",
                )

                selected_rows = (
                    selection.selection.rows if selection and selection.selection else []
                )
                if selected_rows:
                    row_pos = selected_rows[0]
                    raw_row = filtered_df.iloc[row_pos]

                    st.markdown("---")
                    st.markdown("### Kijelölt sor részletei")

                    def build_filled_details(row):
                        details = {}
                        for col_name, val in row.items():
                            if col_name == "_source":
                                continue
                            if val is None or (not isinstance(val, (dict, list)) and pd.isna(val)):
                                continue
                            val_str = str(val).strip()
                            if val_str in ("", "None", "nan", "{}", "[]",
                                           '{"string":""}', '{"string": ""}'):
                                continue
                            parsed_val = val
                            if isinstance(val, str) and (val.startswith("{") or val.startswith("[")):
                                try:
                                    parsed_val = json.loads(val)
                                except Exception:
                                    pass
                            details[col_name] = parsed_val
                        return details

                    paired = find_rest_call_pair(df, raw_row.name)
                    if paired:
                        req_row = paired["request"]
                        resp_row = paired["response"]
                        col_req, col_resp = st.columns(2)
                        with col_req:
                            st.markdown("#### Küldött REQUEST")
                            st.caption(f"{req_row.get('@timestamp', '')} | {req_row.get('method', '')} {req_row.get('path', '')}")
                            st.json(build_filled_details(req_row))
                        with col_resp:
                            st.markdown("#### Kapott RESPONSE")
                            st.caption(f"{resp_row.get('@timestamp', '')} | HTTP {resp_row.get('status', '')}")
                            st.json(build_filled_details(resp_row))
                    else:
                        st.caption("Ehhez a sorhoz nem található párosítható REST Request/Response. A klasszikus részletező nézet látható.")
                        main_details = {}
                        other_details = {}
                        for col_name, val in raw_row.items():
                            if col_name == "_source":
                                continue
                            details_val = build_filled_details(pd.Series({col_name: val}))
                            if details_val:
                                if col_name in active_cols:
                                    main_details[col_name] = details_val[col_name]
                                else:
                                    other_details[col_name] = details_val[col_name]

                        det_col1, det_col2 = st.columns(2)
                        with det_col1:
                            st.markdown("**Aktív nézetben lévő mezők**")
                            if main_details:
                                st.json(main_details)
                            else:
                                st.caption("Nincs kitöltött érték az aktív oszlopokban.")
                        with det_col2:
                            st.markdown("**Minden egyéb kitöltött háttér adat**")
                            if other_details:
                                st.json(other_details)
                            else:
                                st.caption("Nincs egyéb kitöltött háttér adat.")

            except TypeError:
                st.dataframe(
                    filtered_df,
                    use_container_width=True,
                    hide_index=True,
                    column_order=active_cols,
                    column_config=col_cfg,
                    height=750,
                )
                st.info(
                    "Sor részletek megtekintéséhez frissítsd a Streamlit-et ≥ 1.35 verzióra.")
