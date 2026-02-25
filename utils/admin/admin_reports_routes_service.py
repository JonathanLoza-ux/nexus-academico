"""Servicios para rutas de reportes y exportaciones administrativas."""


def build_admin_reports_context(
    current_user,
    effective_admin_role_fn,
    effective_admin_permissions_fn,
    permission_label_fn,
    admin_stats_fn,
    report_export_history_payload_fn,
):
    role = effective_admin_role_fn(current_user)
    perms = effective_admin_permissions_fn(current_user)
    stats = admin_stats_fn()
    return {
        "admin_role": role,
        "admin_permissions": sorted(perms, key=lambda p: permission_label_fn(p)),
        "total_users": stats["total_users"],
        "total_chats": stats["total_chats"],
        "total_messages": stats["total_messages"],
        "total_admins": stats["total_admins"],
        "report_history": report_export_history_payload_fn(limit=20),
    }


def count_rows_from_report_payload(payload):
    sections = payload.get("sections") if isinstance(payload, dict) else []
    if not isinstance(sections, list):
        return 0
    total = 0
    for section in sections:
        rows = section.get("rows") if isinstance(section, dict) else []
        if isinstance(rows, list):
            total += len(rows)
    return int(total)


def record_report_export_action(
    db_session,
    report_export_log_model,
    actor_user_id,
    report_module,
    export_format,
    status,
    detail,
    ip,
    rows_count=None,
):
    row = report_export_log_model(
        actor_user_id=actor_user_id,
        report_module=(report_module or "").strip().lower() or "general",
        export_format=(export_format or "").strip().lower() or "unknown",
        status=(status or "").strip().lower() or "ok",
        rows_count=(int(rows_count) if rows_count is not None else None),
        detail=(detail or "").strip()[:255] or None,
        ip=(ip or "").strip()[:64] or None,
    )
    db_session.add(row)
    db_session.commit()
    return row


def report_export_history_payload(
    db_session,
    report_export_log_model,
    user_model,
    format_dt_human_fn,
    limit=20,
):
    try:
        row_limit = max(1, min(100, int(limit or 20)))
    except Exception:
        row_limit = 20

    rows = (
        db_session.query(report_export_log_model)
        .order_by(report_export_log_model.created_at.desc(), report_export_log_model.id.desc())
        .limit(row_limit)
        .all()
    )

    actor_ids = sorted({int(r.actor_user_id) for r in rows if r.actor_user_id})
    actors = {}
    if actor_ids:
        actor_rows = db_session.query(user_model.id, user_model.email).filter(user_model.id.in_(actor_ids)).all()
        actors = {int(uid): (email or "-") for uid, email in actor_rows}

    result = []
    for r in rows:
        status = (r.status or "ok").strip().lower()
        status_text = {
            "ok": "Completado",
            "error": "Error",
            "warn": "Advertencia",
        }.get(status, status.title())
        result.append({
            "id": int(r.id),
            "at_iso": r.created_at.isoformat() if r.created_at else "",
            "at_human": format_dt_human_fn(r.created_at),
            "module": (r.report_module or "-").capitalize(),
            "format": (r.export_format or "-").upper(),
            "status": status,
            "status_text": status_text,
            "rows_count": int(r.rows_count) if r.rows_count is not None else None,
            "detail": r.detail or "-",
            "actor_email": actors.get(int(r.actor_user_id), "-") if r.actor_user_id else "-",
            "ip": r.ip or "-",
        })
    return result


def export_users_xlsx_action(
    admin_users_data_fn,
    utcnow_naive_fn,
    build_users_export_rows_fn,
    build_xlsx_response_fn,
):
    rows = admin_users_data_fn()
    headers = ["ID", "Nombre", "Email", "Registro", "Estado", "Suspendida hasta", "Chats", "Mensajes"]
    now_utc = utcnow_naive_fn()
    values = build_users_export_rows_fn(rows, now_utc)
    return build_xlsx_response_fn("usuarios_nexus", "Usuarios", headers, values)


def export_login_attempts_xlsx_action(
    admin_security_data_fn,
    build_login_attempt_export_rows_fn,
    build_xlsx_response_fn,
):
    rows, _, _ = admin_security_data_fn(limit=5000)
    headers = ["ID", "IP", "Email", "Intentos", "Primer intento", "Bloqueado hasta"]
    values = build_login_attempt_export_rows_fn(rows)
    return build_xlsx_response_fn("seguridad_login_attempts", "LoginAttempts", headers, values)


def export_audit_xlsx_action(
    admin_logs_for_export_fn,
    admin_enrich_logs_rows_fn,
    utcnow_naive_fn,
    build_audit_export_rows_fn,
    build_xlsx_response_fn,
):
    rows = admin_logs_for_export_fn(limit=5000)
    enriched = admin_enrich_logs_rows_fn(rows, utcnow_naive_fn())
    headers = ["Fecha", "Severidad", "Actor email", "Accion", "Usuario objetivo", "IP", "Request ID", "Metodo", "Ruta", "Modulo", "Detalle"]
    values = build_audit_export_rows_fn(enriched)
    return build_xlsx_response_fn("auditoria_admin", "Auditoria", headers, values)


def export_audit_csv_action(
    admin_logs_for_export_fn,
    admin_enrich_logs_rows_fn,
    utcnow_naive_fn,
    build_audit_csv_response_fn,
):
    rows = admin_logs_for_export_fn(limit=5000)
    enriched = admin_enrich_logs_rows_fn(rows, utcnow_naive_fn())
    return build_audit_csv_response_fn(enriched)


def export_audit_pdf_action(
    admin_logs_for_export_fn,
    admin_enrich_logs_rows_fn,
    utcnow_naive_fn,
    build_audit_pdf_response_fn,
):
    rows = admin_logs_for_export_fn(limit=3000)
    enriched = admin_enrich_logs_rows_fn(rows, utcnow_naive_fn())
    return build_audit_pdf_response_fn(enriched)


def export_users_json_payload_action(
    admin_users_data_fn,
    utcnow_naive_fn,
    build_users_json_payload_fn,
):
    rows = admin_users_data_fn()
    now_utc = utcnow_naive_fn()
    return build_users_json_payload_fn(rows, now_utc)


def export_audit_json_payload_action(
    admin_logs_for_export_fn,
    admin_enrich_logs_rows_fn,
    utcnow_naive_fn,
    build_audit_json_payload_fn,
):
    rows = admin_logs_for_export_fn(limit=5000)
    enriched = admin_enrich_logs_rows_fn(rows, utcnow_naive_fn())
    return build_audit_json_payload_fn(enriched)


def export_security_json_payload_action(
    admin_security_data_fn,
    build_security_json_payload_fn,
):
    login_rows, reset_rows, rate_rows = admin_security_data_fn(limit=5000)
    return build_security_json_payload_fn(login_rows, reset_rows, rate_rows)
