"""Helpers runtime de administracion enlazados desde main."""


def build_admin_runtime_helpers(g):
    def _admin_stats():
        return g["_admin_stats_core"]()

    def _admin_dashboard_charts(days=7):
        return g["_admin_dashboard_charts_core"](days=days, utcnow_naive_fn=g["utcnow_naive"])

    def _format_uptime_compact(start_dt, now_dt):
        return g["_format_uptime_compact_core"](start_dt=start_dt, now_dt=now_dt)

    def _admin_system_health():
        return g["_admin_system_health_core"](
            utcnow_naive_fn=g["utcnow_naive"],
            db_session=g["db"].session,
            sql_text_fn=g["text"],
            perf_counter_fn=g["time"].perf_counter,
            gemini_keys=g["LISTA_DE_CLAVES"],
            reset_mode=g["RESET_MODE"],
            brevo_api_key=g["BREVO_API_KEY"],
            brevo_sender_email=g["BREVO_SENDER_EMAIL"],
            mail_server=g["MAIL_SERVER"],
            mail_username=g["MAIL_USERNAME"],
            mail_password=g["MAIL_PASSWORD"],
            cloudinary_config_fn=g["cloudinary"].config,
            cloudinary_url=g["CLOUDINARY_URL"],
            app_started_at=g["APP_STARTED_AT"],
            format_dt_human_fn=_format_dt_human,
            format_uptime_compact_fn=_format_uptime_compact,
        )

    def _admin_admins_data():
        return g["_admin_admins_data_core"](
            loads_permissions_fn=g["_loads_permissions"],
            permission_label_fn=g["_permission_label_es"],
        )

    def _admin_users_data():
        return g["_admin_users_data_core"]()

    def _admin_recent_logs(limit=30):
        return g["_admin_recent_logs_core"](limit=limit)

    def _mask_email_for_logs(email: str):
        return g["_mask_email_for_logs_core"](email)

    def _mask_sensitive_text(text: str):
        return g["_mask_sensitive_text_core"](text)

    def _extract_detail_pairs(detail: str):
        return g["_extract_detail_pairs_core"](detail)

    def _extract_request_id(detail: str):
        return g["_extract_request_id_core"](detail)

    def _extract_meta_from_detail(detail: str):
        return g["_extract_meta_from_detail_core"](detail)

    def _admin_log_module(action: str):
        return g["_admin_log_module_core"](action)

    def _admin_log_severity(action: str, detail: str = ""):
        return g["_admin_log_severity_core"](action, detail)

    def _admin_filter_logs_rows(
        rows,
        q="",
        action="",
        actor="",
        ip="",
        target_user="",
        event_id="",
        request_id="",
        severity="",
        date_from=None,
        date_to=None,
    ):
        return g["_admin_filter_logs_rows_core"](
            rows=rows,
            q=q,
            action=action,
            actor=actor,
            ip=ip,
            target_user=target_user,
            event_id=event_id,
            request_id=request_id,
            severity=severity,
            date_from=date_from,
            date_to=date_to,
            to_naive_utc_fn=g["to_naive_utc"],
        )

    def _admin_enrich_logs_rows(rows, now_utc=None):
        now_utc = now_utc or g["utcnow_naive"]()
        return g["_admin_enrich_logs_rows_core"](
            rows=rows,
            now_utc=now_utc,
            action_meta_fn=_admin_action_meta,
            log_severity_fn=_admin_log_severity,
            extract_meta_fn=_extract_meta_from_detail,
            extract_request_id_fn=_extract_request_id,
            log_module_fn=_admin_log_module,
            mask_sensitive_text_fn=_mask_sensitive_text,
            extract_detail_pairs_fn=_extract_detail_pairs,
            time_ago_fn=_time_ago_es,
            url_for_fn=g["url_for"],
        )

    def _admin_logs_filters_from_request():
        return g["_admin_logs_filters_from_request_core"](
            request_obj=g["request"],
            parse_date_ymd_fn=_parse_date_ymd,
        )

    def _admin_logs_for_export(limit=5000):
        rows = _admin_recent_logs(limit=limit)
        filters = _admin_logs_filters_from_request()
        return _admin_filter_logs_rows(rows, **filters)

    def _time_ago_es(dt, now_dt=None):
        return g["_time_ago_es_core"](
            dt=dt,
            now_dt=now_dt,
            to_naive_utc_fn=g["to_naive_utc"],
            utcnow_naive_fn=g["utcnow_naive"],
        )

    def _admin_action_meta(action):
        return g["_admin_action_meta_core"](action)

    def _admin_activity_feed(limit=12):
        rows = _admin_recent_logs(limit=limit)
        now_utc = g["utcnow_naive"]()
        return g["_admin_activity_feed_core"](
            rows=rows,
            now_utc=now_utc,
            action_meta_fn=_admin_action_meta,
            time_ago_fn=_time_ago_es,
            format_dt_human_fn=_format_dt_human,
        )

    def _admin_alerts_payload():
        return g["_admin_alerts_payload_core"](
            gemini_keys=g["LISTA_DE_CLAVES"],
            format_dt_human_fn=_format_dt_human,
            now_utc=g["utcnow_naive"](),
        )

    def _admin_security_data(limit=100):
        return g["_admin_security_data_core"](limit=limit)

    def _security_can_manage_actions(user):
        return g["_security_can_manage_actions_core"](
            user=user,
            effective_admin_role_fn=g["_effective_admin_role"],
            effective_admin_permissions_fn=g["_effective_admin_permissions"],
        )

    def _security_block_state(blocked_until, now_utc=None):
        now_utc = now_utc or g["utcnow_naive"]()
        return g["_security_block_state_core"](
            blocked_until=blocked_until,
            now_utc=now_utc,
            to_naive_utc_fn=g["to_naive_utc"],
        )

    def _admin_security_redirect():
        return g["_admin_security_redirect_core"](
            request_obj=g["request"],
            url_for_fn=g["url_for"],
            redirect_fn=g["redirect"],
            endpoint_name="admin_security_page",
        )

    def _safe_int(value, default):
        return g["_safe_int_core"](value=value, default=default)

    def _security_duration_delta(value_raw, unit_raw):
        return g["_security_duration_delta_core"](
            value_raw=value_raw,
            unit_raw=unit_raw,
            safe_int_fn=_safe_int,
        )

    def _parse_date_ymd(value: str):
        return g["_parse_date_ymd_core"](value=value)

    def _slice_with_pagination(items, page, per_page):
        return g["_slice_with_pagination_core"](items=items, page=page, per_page=per_page)

    def _build_pagination_links(endpoint, args_dict, page_key, per_key, page, per_page, total_pages):
        return g["_build_pagination_links_core"](
            endpoint=endpoint,
            args_dict=args_dict,
            page_key=page_key,
            per_key=per_key,
            page=page,
            per_page=per_page,
            total_pages=total_pages,
            url_for_fn=g["url_for"],
            urlencode_fn=g["urlencode"],
        )

    def _build_xlsx_response(filename_base: str, sheet_name: str, headers: list, rows: list):
        return g["_build_xlsx_response_core"](
            filename_base=filename_base,
            sheet_name=sheet_name,
            headers=headers,
            rows=rows,
            response_cls=g["Response"],
        )

    def _build_users_export_rows(users, now_utc):
        return g["_build_users_export_rows_core"](
            users=users,
            now_utc=now_utc,
            user_status_data_fn=g["_user_status_data"],
            format_dt_human_fn=_format_dt_human,
        )

    def _build_login_attempt_export_rows(rows):
        return g["_build_login_attempt_export_rows_core"](login_attempt_rows=rows)

    def _build_audit_export_rows(enriched_rows):
        return g["_build_audit_export_rows_core"](
            enriched_rows=enriched_rows,
            mask_sensitive_text_fn=_mask_sensitive_text,
        )

    def _build_audit_csv_response(enriched_rows):
        return g["_build_audit_csv_response_core"](
            enriched_rows=enriched_rows,
            mask_sensitive_text_fn=_mask_sensitive_text,
            response_cls=g["Response"],
        )

    def _build_audit_pdf_response(enriched_rows):
        return g["_build_audit_pdf_response_core"](
            enriched_rows=enriched_rows,
            mask_sensitive_text_fn=_mask_sensitive_text,
            response_cls=g["Response"],
        )

    def _build_users_json_payload(rows, now_utc):
        return g["_build_users_json_payload_core"](
            users=rows,
            now_utc=now_utc,
            user_status_data_fn=g["_user_status_data"],
            format_dt_human_fn=_format_dt_human,
        )

    def _build_audit_json_payload(enriched_rows):
        return g["_build_audit_json_payload_core"](
            enriched_rows=enriched_rows,
            mask_sensitive_text_fn=_mask_sensitive_text,
        )

    def _build_security_json_payload(login_rows, reset_rows, rate_rows):
        return g["_build_security_json_payload_core"](
            login_rows=login_rows,
            reset_rows=reset_rows,
            rate_rows=rate_rows,
        )

    def _grant_admin_role(email_raw, role_raw, requested_permissions):
        return g["_grant_admin_role_core"](
            email_raw=email_raw,
            role_raw=role_raw,
            requested_permissions=requested_permissions,
            current_user_id=g["current_user"].id,
            db_session=g["db"].session,
            normalize_email_fn=g["_normalize_email"],
            is_super_admin_email_fn=g["_is_super_admin_email"],
            dumps_permissions_fn=g["_dumps_permissions"],
            utcnow_naive_fn=g["utcnow_naive"],
            add_admin_audit_fn=g["_add_admin_audit"],
            all_admin_permissions=g["ALL_ADMIN_PERMISSIONS"],
            default_admin_permissions=g["DEFAULT_ADMIN_PERMISSIONS"],
        )

    def _revoke_admin_role(target_user_id: int):
        return g["_revoke_admin_role_core"](
            target_user_id=target_user_id,
            current_user_id=g["current_user"].id,
            db_session=g["db"].session,
            is_super_admin_email_fn=g["_is_super_admin_email"],
            utcnow_naive_fn=g["utcnow_naive"],
            add_admin_audit_fn=g["_add_admin_audit"],
        )

    def _admin_user_status_action(user_id: int, action_raw: str):
        return g["_admin_user_status_action_core"](
            user_id=user_id,
            action_raw=action_raw,
            current_user_id=g["current_user"].id,
            current_role=g["_effective_admin_role"](g["current_user"]),
            db_session=g["db"].session,
            is_super_admin_email_fn=g["_is_super_admin_email"],
            add_admin_audit_fn=g["_add_admin_audit"],
        )

    def _admin_users_bulk_action(action_raw: str, raw_ids):
        return g["_admin_users_bulk_action_core"](
            action_raw=action_raw,
            raw_ids=raw_ids,
            current_user_id=g["current_user"].id,
            current_role=g["_effective_admin_role"](g["current_user"]),
            can_export=("export_reports" in g["_effective_admin_permissions"](g["current_user"])),
            db_session=g["db"].session,
            is_super_admin_email_fn=g["_is_super_admin_email"],
            add_admin_audit_fn=g["_add_admin_audit"],
            admin_users_data_fn=_admin_users_data,
            build_users_export_rows_fn=_build_users_export_rows,
            build_xlsx_response_fn=_build_xlsx_response,
            now_utc=g["utcnow_naive"](),
        )

    def _admin_user_suspend_action(user_id: int, action_raw: str, duration_value_raw, duration_unit_raw: str):
        return g["_admin_user_suspend_action_core"](
            user_id=user_id,
            action_raw=action_raw,
            duration_value_raw=duration_value_raw,
            duration_unit_raw=duration_unit_raw,
            current_user_id=g["current_user"].id,
            current_role=g["_effective_admin_role"](g["current_user"]),
            db_session=g["db"].session,
            is_super_admin_email_fn=g["_is_super_admin_email"],
            add_admin_audit_fn=g["_add_admin_audit"],
            safe_int_fn=_safe_int,
            utcnow_naive_fn=g["utcnow_naive"],
            format_dt_human_fn=_format_dt_human,
        )

    def _admin_user_delete_action(user_id: int):
        return g["_admin_user_delete_action_core"](
            user_id=user_id,
            current_user_id=g["current_user"].id,
            db_session=g["db"].session,
            is_super_admin_email_fn=g["_is_super_admin_email"],
            add_admin_audit_fn=g["_add_admin_audit"],
        )

    # Reusar formato global ya existente
    _format_dt_human = g["_format_dt_human"]

    return {
        "_admin_stats": _admin_stats,
        "_admin_dashboard_charts": _admin_dashboard_charts,
        "_format_uptime_compact": _format_uptime_compact,
        "_admin_system_health": _admin_system_health,
        "_admin_admins_data": _admin_admins_data,
        "_admin_users_data": _admin_users_data,
        "_admin_recent_logs": _admin_recent_logs,
        "_mask_email_for_logs": _mask_email_for_logs,
        "_mask_sensitive_text": _mask_sensitive_text,
        "_extract_detail_pairs": _extract_detail_pairs,
        "_extract_request_id": _extract_request_id,
        "_extract_meta_from_detail": _extract_meta_from_detail,
        "_admin_log_module": _admin_log_module,
        "_admin_log_severity": _admin_log_severity,
        "_admin_filter_logs_rows": _admin_filter_logs_rows,
        "_admin_enrich_logs_rows": _admin_enrich_logs_rows,
        "_admin_logs_filters_from_request": _admin_logs_filters_from_request,
        "_admin_logs_for_export": _admin_logs_for_export,
        "_time_ago_es": _time_ago_es,
        "_admin_action_meta": _admin_action_meta,
        "_admin_activity_feed": _admin_activity_feed,
        "_admin_alerts_payload": _admin_alerts_payload,
        "_admin_security_data": _admin_security_data,
        "_security_can_manage_actions": _security_can_manage_actions,
        "_security_block_state": _security_block_state,
        "_admin_security_redirect": _admin_security_redirect,
        "_security_duration_delta": _security_duration_delta,
        "_safe_int": _safe_int,
        "_parse_date_ymd": _parse_date_ymd,
        "_slice_with_pagination": _slice_with_pagination,
        "_build_pagination_links": _build_pagination_links,
        "_build_xlsx_response": _build_xlsx_response,
        "_build_users_export_rows": _build_users_export_rows,
        "_build_login_attempt_export_rows": _build_login_attempt_export_rows,
        "_build_audit_export_rows": _build_audit_export_rows,
        "_build_audit_csv_response": _build_audit_csv_response,
        "_build_audit_pdf_response": _build_audit_pdf_response,
        "_build_users_json_payload": _build_users_json_payload,
        "_build_audit_json_payload": _build_audit_json_payload,
        "_build_security_json_payload": _build_security_json_payload,
        "_grant_admin_role": _grant_admin_role,
        "_revoke_admin_role": _revoke_admin_role,
        "_admin_user_status_action": _admin_user_status_action,
        "_admin_users_bulk_action": _admin_users_bulk_action,
        "_admin_user_suspend_action": _admin_user_suspend_action,
        "_admin_user_delete_action": _admin_user_delete_action,
    }
