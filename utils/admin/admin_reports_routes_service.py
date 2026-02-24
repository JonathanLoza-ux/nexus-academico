"""Servicios para rutas de reportes y exportaciones administrativas."""


def build_admin_reports_context(
    current_user,
    effective_admin_role_fn,
    effective_admin_permissions_fn,
    permission_label_fn,
    admin_stats_fn,
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
    }


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
