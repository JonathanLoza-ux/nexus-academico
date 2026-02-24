"""Servicios para construir contexto de paginas administrativas."""

from collections import Counter
from datetime import timedelta

from sqlalchemy import func

from models import AdminAuditLog, Conversation, SecurityBlock, User


def build_admin_panel_context(
    current_user,
    effective_admin_role_fn,
    effective_admin_permissions_fn,
    permission_label_fn,
    admin_stats_fn,
    admin_dashboard_charts_fn,
    admin_system_health_fn,
    admin_activity_feed_fn,
    admin_alerts_payload_fn,
    db_session,
):
    role = effective_admin_role_fn(current_user)
    perms = effective_admin_permissions_fn(current_user)
    stats = admin_stats_fn()
    charts = admin_dashboard_charts_fn(days=7)
    system_health = admin_system_health_fn()
    activity_feed = admin_activity_feed_fn(limit=12)
    alerts_payload = admin_alerts_payload_fn()

    top_chat_users = (
        db_session.query(
            User.id,
            User.name,
            User.email,
            func.count(Conversation.id).label("chat_count"),
        )
        .outerjoin(Conversation, Conversation.user_id == User.id)
        .group_by(User.id, User.name, User.email)
        .order_by(func.count(Conversation.id).desc(), User.id.asc())
        .limit(8)
        .all()
    )

    top_chat_labels = [r.name for r in top_chat_users]
    top_chat_values = [int(r.chat_count or 0) for r in top_chat_users]

    return {
        "admin_role": role,
        "admin_permissions": sorted(perms, key=lambda p: permission_label_fn(p)),
        "total_users": stats["total_users"],
        "total_chats": stats["total_chats"],
        "total_messages": stats["total_messages"],
        "total_admins": stats["total_admins"],
        "top_chat_labels": top_chat_labels,
        "top_chat_values": top_chat_values,
        "message_day_labels": charts["message_day_labels"],
        "message_day_values": charts["message_day_values"],
        "account_status_labels": charts["account_status_labels"],
        "account_status_values": charts["account_status_values"],
        "failed_ip_labels": charts["failed_ip_labels"],
        "failed_ip_values": charts["failed_ip_values"],
        "system_health": system_health,
        "activity_feed": activity_feed,
        "alerts_payload": alerts_payload,
        "can_view_logs": ("view_logs" in perms),
    }


def build_admin_admins_context(
    request_obj,
    current_user,
    super_admin_emails,
    all_admin_permissions,
    default_admin_permissions,
    permission_labels_es,
    permission_groups_es,
    effective_admin_role_fn,
    effective_admin_permissions_fn,
    permission_label_fn,
    admin_stats_fn,
    admin_admins_data_fn,
    admin_recent_logs_fn,
    admin_activity_feed_fn,
    admin_action_meta_fn,
    time_ago_fn,
    parse_date_ymd_fn,
    safe_int_fn,
    slice_with_pagination_fn,
    build_pagination_links_fn,
    db_session,
):
    role = effective_admin_role_fn(current_user)
    perms = effective_admin_permissions_fn(current_user)
    stats = admin_stats_fn()
    args = request_obj.args.to_dict(flat=True)
    per_options = [5, 10, 20, 50, 100]

    admins_data_all = admin_admins_data_fn()
    admin_last_activity_rows = (
        db_session.query(
            AdminAuditLog.actor_user_id.label("uid"),
            func.max(AdminAuditLog.created_at).label("last_at"),
        )
        .filter(AdminAuditLog.actor_user_id.isnot(None))
        .group_by(AdminAuditLog.actor_user_id)
        .all()
    )
    admin_last_activity_map = {int(r.uid): r.last_at for r in admin_last_activity_rows if r.uid}
    for row in admins_data_all:
        uid = int(row["user_row"].id)
        last_at = admin_last_activity_map.get(uid)
        row["last_activity_at"] = last_at
        row["last_activity_ago"] = time_ago_fn(last_at) if last_at else "Sin actividad"
        row["role_label"] = "Super Admin" if row["role_row"].role == "super_admin" else "Admin"
        row["is_protected"] = bool(row["role_row"].role == "super_admin")

    admins_super_total = sum(1 for row in admins_data_all if row["role_row"].role == "super_admin")
    admins_standard_total = sum(1 for row in admins_data_all if row["role_row"].role == "admin")
    admins_active_total = sum(1 for row in admins_data_all if bool(row["role_row"].is_active))
    admins_inactive_total = max(0, len(admins_data_all) - admins_active_total)
    admins_with_activity_total = sum(1 for row in admins_data_all if row["last_activity_at"])
    admins_recent_activity = admin_activity_feed_fn(limit=4)
    admins_q = (request_obj.args.get("admins_q") or "").strip().lower()
    admins_role = (request_obj.args.get("admins_role") or "").strip().lower()
    admins_state = (request_obj.args.get("admins_state") or "").strip().lower()

    if admins_q:
        admins_data_all = [
            row for row in admins_data_all
            if admins_q in (row["user_row"].name or "").lower()
            or admins_q in (row["user_row"].email or "").lower()
            or admins_q == str(row["user_row"].id)
        ]
    if admins_role in {"admin", "super_admin"}:
        admins_data_all = [row for row in admins_data_all if row["role_row"].role == admins_role]
    if admins_state in {"activo", "inactivo"}:
        is_active = admins_state == "activo"
        admins_data_all = [row for row in admins_data_all if bool(row["role_row"].is_active) == is_active]

    per_admins = safe_int_fn(request_obj.args.get("per_admins"), 10)
    if per_admins not in per_options:
        per_admins = 10
    page_admins = safe_int_fn(request_obj.args.get("page_admins"), 1)
    admins_data, admins_total, admins_total_pages, page_admins = slice_with_pagination_fn(
        admins_data_all, page_admins, per_admins
    )
    admins_pagination = build_pagination_links_fn(
        "admin_admins_page", args, "page_admins", "per_admins", page_admins, per_admins, admins_total_pages
    )

    logs_all = admin_recent_logs_fn(limit=3000)
    logs_q = (request_obj.args.get("logs_q") or "").strip().lower()
    logs_actor = (request_obj.args.get("logs_actor") or "").strip().lower()
    logs_action = (request_obj.args.get("logs_action") or "").strip().lower()
    logs_date_from = parse_date_ymd_fn(request_obj.args.get("logs_date_from"))
    logs_date_to = parse_date_ymd_fn(request_obj.args.get("logs_date_to"))
    if logs_date_to:
        logs_date_to = logs_date_to + timedelta(days=1)

    if logs_q:
        logs_all = [
            row for row in logs_all
            if logs_q in ((row[1].email if row[1] else "") or "").lower()
            or logs_q in (row[0].action or "").lower()
            or logs_q in (row[0].detail or "").lower()
            or logs_q == str(row[0].id)
            or logs_q == str(row[0].target_user_id or "")
        ]
    if logs_actor:
        logs_all = [
            row for row in logs_all
            if logs_actor in ((row[1].email if row[1] else "") or "").lower()
            or logs_actor in ((row[1].name if row[1] else "") or "").lower()
        ]
    if logs_action:
        logs_all = [row for row in logs_all if logs_action in (row[0].action or "").lower()]
    if logs_date_from:
        logs_all = [row for row in logs_all if row[0].created_at and row[0].created_at >= logs_date_from]
    if logs_date_to:
        logs_all = [row for row in logs_all if row[0].created_at and row[0].created_at < logs_date_to]

    per_logs = safe_int_fn(request_obj.args.get("per_logs"), 20)
    if per_logs not in per_options:
        per_logs = 20
    page_logs = safe_int_fn(request_obj.args.get("page_logs"), 1)
    recent_admin_logs, logs_total, logs_total_pages, page_logs = slice_with_pagination_fn(
        logs_all, page_logs, per_logs
    )
    logs_pagination = build_pagination_links_fn(
        "admin_admins_page", args, "page_logs", "per_logs", page_logs, per_logs, logs_total_pages
    )
    logs_timeline = []
    for log_row, actor_user in recent_admin_logs:
        title, icon, tone = admin_action_meta_fn(log_row.action)
        logs_timeline.append({
            "log_row": log_row,
            "actor_user": actor_user,
            "title": title,
            "icon": icon,
            "tone": tone,
            "when": time_ago_fn(log_row.created_at),
        })
    logs_action_options = sorted({
        (row[0].action or "").strip()
        for row in logs_all
        if (row[0].action or "").strip()
    })

    return {
        "admin_role": role,
        "admin_permissions": sorted(perms, key=lambda p: permission_label_fn(p)),
        "total_users": stats["total_users"],
        "total_chats": stats["total_chats"],
        "total_messages": stats["total_messages"],
        "total_admins": stats["total_admins"],
        "admins_data": admins_data,
        "recent_admin_logs": recent_admin_logs,
        "logs_timeline": logs_timeline,
        "admins_q": admins_q,
        "admins_role": admins_role,
        "admins_state": admins_state,
        "logs_q": logs_q,
        "logs_actor": logs_actor,
        "logs_action": logs_action,
        "logs_date_from": (request_obj.args.get("logs_date_from") or ""),
        "logs_date_to": (request_obj.args.get("logs_date_to") or ""),
        "logs_action_options": logs_action_options,
        "per_options": per_options,
        "per_admins": per_admins,
        "per_logs": per_logs,
        "admins_total": admins_total,
        "logs_total": logs_total,
        "admins_super_total": admins_super_total,
        "admins_standard_total": admins_standard_total,
        "admins_active_total": admins_active_total,
        "admins_inactive_total": admins_inactive_total,
        "admins_with_activity_total": admins_with_activity_total,
        "admins_recent_activity": admins_recent_activity,
        "admins_pagination": admins_pagination,
        "logs_pagination": logs_pagination,
        "all_permissions": sorted(all_admin_permissions, key=lambda p: permission_label_fn(p)),
        "default_permissions": sorted(default_admin_permissions, key=lambda p: permission_label_fn(p)),
        "permission_labels_es": permission_labels_es,
        "permission_groups_es": permission_groups_es,
        "super_admin_emails": super_admin_emails,
    }


def build_admin_users_context(
    request_obj,
    current_user,
    super_admin_emails,
    effective_admin_role_fn,
    effective_admin_permissions_fn,
    permission_label_fn,
    admin_stats_fn,
    admin_users_data_fn,
    user_status_data_fn,
    parse_date_ymd_fn,
    safe_int_fn,
    slice_with_pagination_fn,
    build_pagination_links_fn,
    utcnow_naive_fn,
):
    role = effective_admin_role_fn(current_user)
    perms = effective_admin_permissions_fn(current_user)
    stats = admin_stats_fn()
    args = request_obj.args.to_dict(flat=True)
    per_options = [5, 10, 20, 50, 100]
    now_utc = utcnow_naive_fn()

    users_all = admin_users_data_fn()
    q = (request_obj.args.get("q") or "").strip().lower()
    estado = (request_obj.args.get("estado") or "").strip().lower()
    date_from = parse_date_ymd_fn(request_obj.args.get("date_from"))
    date_to = parse_date_ymd_fn(request_obj.args.get("date_to"))
    if date_to:
        date_to = date_to + timedelta(days=1)

    if q:
        users_all = [
            u for u in users_all
            if q in (u.name or "").lower() or q in (u.email or "").lower() or q == str(u.id)
        ]
    if estado in {"activa", "desactivada", "suspendida"}:
        users_all = [u for u in users_all if user_status_data_fn(u, now_utc)[0] == estado]
    if date_from:
        users_all = [u for u in users_all if u.created_at and u.created_at >= date_from]
    if date_to:
        users_all = [u for u in users_all if u.created_at and u.created_at < date_to]

    per_page = safe_int_fn(request_obj.args.get("per_page"), 10)
    if per_page not in per_options:
        per_page = 10
    page = safe_int_fn(request_obj.args.get("page"), 1)
    all_users, users_total, users_total_pages, page = slice_with_pagination_fn(users_all, page, per_page)
    users_pagination = build_pagination_links_fn(
        "admin_users_page", args, "page", "per_page", page, per_page, users_total_pages
    )

    return {
        "admin_role": role,
        "super_admin_emails": super_admin_emails,
        "admin_permissions": sorted(perms, key=lambda p: permission_label_fn(p)),
        "can_manage_users": ("manage_users" in perms),
        "can_export_reports": ("export_reports" in perms),
        "is_super_admin": (role == "super_admin"),
        "total_users": stats["total_users"],
        "total_chats": stats["total_chats"],
        "total_messages": stats["total_messages"],
        "total_admins": stats["total_admins"],
        "all_users": all_users,
        "q": q,
        "estado": estado,
        "now_utc": now_utc,
        "date_from": (request_obj.args.get("date_from") or ""),
        "date_to": (request_obj.args.get("date_to") or ""),
        "per_page": per_page,
        "per_options": per_options,
        "users_total": users_total,
        "users_pagination": users_pagination,
    }


def build_admin_logs_context(
    request_obj,
    current_user,
    admin_log_retention_days,
    effective_admin_role_fn,
    effective_admin_permissions_fn,
    permission_label_fn,
    admin_stats_fn,
    admin_recent_logs_fn,
    admin_filter_logs_rows_fn,
    admin_enrich_logs_rows_fn,
    safe_int_fn,
    slice_with_pagination_fn,
    build_pagination_links_fn,
    urlencode_fn,
    to_naive_utc_fn,
    utcnow_naive_fn,
):
    role = effective_admin_role_fn(current_user)
    perms = effective_admin_permissions_fn(current_user)
    stats = admin_stats_fn()
    now_utc = utcnow_naive_fn()
    args = request_obj.args.to_dict(flat=True)
    per_options = [5, 10, 20, 50, 100]
    logs_all = admin_recent_logs_fn(limit=5000)
    q = (request_obj.args.get("q") or "").strip().lower()
    action = (request_obj.args.get("action") or "").strip().lower()
    actor = (request_obj.args.get("actor") or "").strip().lower()
    ip = (request_obj.args.get("ip") or "").strip().lower()
    target_user = (request_obj.args.get("target_user") or "").strip().lower()
    event_id = (request_obj.args.get("event_id") or "").strip()
    request_id = (request_obj.args.get("request_id") or "").strip().lower()
    severity = (request_obj.args.get("severity") or "").strip().lower()
    date_from = request_obj.args.get("date_from")
    date_to = request_obj.args.get("date_to")

    logs_action_options = sorted({
        (row[0].action or "").strip()
        for row in logs_all
        if (row[0].action or "").strip()
    })
    logs_actor_options = sorted({
        ((row[1].email if row[1] else "") or "").strip()
        for row in logs_all
        if ((row[1].email if row[1] else "") or "").strip()
    })[:120]

    filtered_logs = admin_filter_logs_rows_fn(logs_all)
    enriched_all = admin_enrich_logs_rows_fn(filtered_logs, now_utc)

    events_today = 0
    critical_today = 0
    actors_unique = set()
    ip_counter = Counter()
    for item in enriched_all:
        created = to_naive_utc_fn(item["log_row"].created_at)
        if created and created.date() == now_utc.date():
            events_today += 1
            if item["severity_key"] == "critical":
                critical_today += 1
        actor_email = ((item["actor_user"].email if item["actor_user"] else "") or "").strip().lower()
        if actor_email:
            actors_unique.add(actor_email)
        ip_val = (item["log_row"].ip or "").strip()
        if ip_val:
            ip_counter[ip_val] += 1
    suspicious_ips = len([ip_key for ip_key, cnt in ip_counter.items() if cnt >= 3])
    timeline_items = enriched_all[:12]

    per_page = safe_int_fn(request_obj.args.get("per_page"), 20)
    if per_page not in per_options:
        per_page = 20
    page = safe_int_fn(request_obj.args.get("page"), 1)
    paginated_rows, logs_total, logs_total_pages, page = slice_with_pagination_fn(filtered_logs, page, per_page)
    logs_pagination = build_pagination_links_fn(
        "admin_logs_page", args, "page", "per_page", page, per_page, logs_total_pages
    )
    table_rows = admin_enrich_logs_rows_fn(paginated_rows, now_utc)

    export_args = {}
    for key in ["q", "action", "actor", "ip", "target_user", "event_id", "request_id", "severity", "date_from", "date_to"]:
        val = request_obj.args.get(key)
        if val:
            export_args[key] = val
    export_query = urlencode_fn(export_args)

    return {
        "admin_role": role,
        "admin_permissions": sorted(perms, key=lambda p: permission_label_fn(p)),
        "total_users": stats["total_users"],
        "total_chats": stats["total_chats"],
        "total_messages": stats["total_messages"],
        "total_admins": stats["total_admins"],
        "timeline_items": timeline_items,
        "table_rows": table_rows,
        "q": q,
        "action": action,
        "actor": actor,
        "ip": ip,
        "target_user": target_user,
        "event_id": event_id,
        "request_id": request_id,
        "severity": severity,
        "logs_action_options": logs_action_options,
        "logs_actor_options": logs_actor_options,
        "date_from": (date_from or ""),
        "date_to": (date_to or ""),
        "per_page": per_page,
        "per_options": per_options,
        "logs_total": logs_total,
        "events_today": events_today,
        "critical_today": critical_today,
        "actors_unique": len(actors_unique),
        "suspicious_ips": suspicious_ips,
        "export_query": export_query,
        "can_cleanup_logs": (role == "super_admin"),
        "retention_days": admin_log_retention_days,
        "logs_pagination": logs_pagination,
    }


def build_admin_security_context(
    request_obj,
    current_user,
    login_max_attempts,
    effective_admin_role_fn,
    effective_admin_permissions_fn,
    permission_label_fn,
    admin_stats_fn,
    admin_security_data_fn,
    security_can_manage_actions_fn,
    security_block_state_fn,
    parse_date_ymd_fn,
    safe_int_fn,
    slice_with_pagination_fn,
    build_pagination_links_fn,
    format_dt_human_fn,
    utcnow_naive_fn,
):
    role = effective_admin_role_fn(current_user)
    perms = effective_admin_permissions_fn(current_user)
    stats = admin_stats_fn()
    now_utc = utcnow_naive_fn()
    can_security_actions = security_can_manage_actions_fn(current_user)
    args = request_obj.args.to_dict(flat=True)
    per_options = [5, 10, 20, 50, 100]
    login_attempts_all, reset_ip_all, rate_limit_all = admin_security_data_fn(limit=5000)
    security_blocks_all = (
        SecurityBlock.query.filter_by(is_active=True)
        .filter(SecurityBlock.blocked_until > now_utc)
        .order_by(SecurityBlock.blocked_until.desc(), SecurityBlock.id.desc())
        .limit(5000)
        .all()
    )

    login_blocked_active = 0
    reset_blocked_active = 0
    rate_blocked_active = 0
    login_risky_rows = 0
    recent_lock_events = 0

    for row in login_attempts_all:
        is_blocked, until = security_block_state_fn(row.blocked_until, now_utc)
        attempts = int(row.attempts or 0)
        row.status_key = "off" if is_blocked else ("warn" if attempts > 0 else "ok")
        row.status_label = "Bloqueado" if is_blocked else ("En observacion" if attempts > 0 else "Normal")
        row.blocked_until_human = format_dt_human_fn(until) if until else "-"
        row.can_unlock = bool(is_blocked or attempts > 0)
        if is_blocked:
            login_blocked_active += 1
        if attempts >= max(3, login_max_attempts - 2):
            login_risky_rows += 1
        first_at = row.first_attempt_at
        if first_at and (now_utc - first_at) <= timedelta(hours=24) and is_blocked:
            recent_lock_events += 1

    for row in reset_ip_all:
        is_blocked, until = security_block_state_fn(row.blocked_until, now_utc)
        attempts = int(row.attempts or 0)
        row.status_key = "off" if is_blocked else ("warn" if attempts > 0 else "ok")
        row.status_label = "Bloqueado" if is_blocked else ("En observacion" if attempts > 0 else "Normal")
        row.blocked_until_human = format_dt_human_fn(until) if until else "-"
        row.can_unlock = bool(is_blocked or attempts > 0)
        if is_blocked:
            reset_blocked_active += 1

    for row in rate_limit_all:
        is_blocked, until = security_block_state_fn(row.blocked_until, now_utc)
        count = int(row.count or 0)
        row.status_key = "off" if is_blocked else ("warn" if count > 0 else "ok")
        row.status_label = "Bloqueado" if is_blocked else ("Activo" if count > 0 else "Limpio")
        row.blocked_until_human = format_dt_human_fn(until) if until else "-"
        row.can_unlock = bool(is_blocked or count > 0)
        if is_blocked:
            rate_blocked_active += 1

    manual_block_active = len(security_blocks_all)
    total_active_blocks = login_blocked_active + reset_blocked_active + rate_blocked_active + manual_block_active
    if total_active_blocks >= 10:
        security_risk_label = "Riesgo alto"
        security_risk_tone = "off"
    elif total_active_blocks >= 3:
        security_risk_label = "Riesgo medio"
        security_risk_tone = "warn"
    else:
        security_risk_label = "Riesgo controlado"
        security_risk_tone = "ok"

    login_q = (request_obj.args.get("login_q") or "").strip().lower()
    if login_q:
        login_attempts_all = [
            r for r in login_attempts_all
            if login_q in (r.ip or "").lower() or login_q in (r.email or "").lower() or login_q == str(r.id)
        ]
    reset_q = (request_obj.args.get("reset_q") or "").strip().lower()
    if reset_q:
        reset_ip_all = [
            r for r in reset_ip_all
            if reset_q in (r.ip or "").lower() or reset_q == str(r.id)
        ]
    rate_q = (request_obj.args.get("rate_q") or "").strip().lower()
    if rate_q:
        rate_limit_all = [
            r for r in rate_limit_all
            if rate_q in (r.key or "").lower() or rate_q == str(r.id)
        ]

    block_q = (request_obj.args.get("block_q") or "").strip().lower()
    if block_q:
        security_blocks_all = [
            b for b in security_blocks_all
            if block_q in (b.target or "").lower()
            or block_q in (b.reason or "").lower()
            or block_q in (b.block_type or "").lower()
            or block_q == str(b.id)
        ]
    for row in security_blocks_all:
        row.type_label = "Correo" if row.block_type == "email" else "IP"
        row.until_human = format_dt_human_fn(row.blocked_until)
        row.status_key = "off"

    per_login = safe_int_fn(request_obj.args.get("per_login"), 10)
    if per_login not in per_options:
        per_login = 10
    page_login = safe_int_fn(request_obj.args.get("page_login"), 1)
    login_attempts, login_total, login_total_pages, page_login = slice_with_pagination_fn(
        login_attempts_all, page_login, per_login
    )
    login_pagination = build_pagination_links_fn(
        "admin_security_page", args, "page_login", "per_login", page_login, per_login, login_total_pages
    )

    per_reset = safe_int_fn(request_obj.args.get("per_reset"), 10)
    if per_reset not in per_options:
        per_reset = 10
    page_reset = safe_int_fn(request_obj.args.get("page_reset"), 1)
    reset_ip_rows, reset_total, reset_total_pages, page_reset = slice_with_pagination_fn(
        reset_ip_all, page_reset, per_reset
    )
    reset_pagination = build_pagination_links_fn(
        "admin_security_page", args, "page_reset", "per_reset", page_reset, per_reset, reset_total_pages
    )

    per_rate = safe_int_fn(request_obj.args.get("per_rate"), 10)
    if per_rate not in per_options:
        per_rate = 10
    page_rate = safe_int_fn(request_obj.args.get("page_rate"), 1)
    rate_limit_rows, rate_total, rate_total_pages, page_rate = slice_with_pagination_fn(
        rate_limit_all, page_rate, per_rate
    )
    rate_pagination = build_pagination_links_fn(
        "admin_security_page", args, "page_rate", "per_rate", page_rate, per_rate, rate_total_pages
    )

    per_block = safe_int_fn(request_obj.args.get("per_block"), 10)
    if per_block not in per_options:
        per_block = 10
    page_block = safe_int_fn(request_obj.args.get("page_block"), 1)
    security_blocks, block_total, block_total_pages, page_block = slice_with_pagination_fn(
        security_blocks_all, page_block, per_block
    )
    block_pagination = build_pagination_links_fn(
        "admin_security_page", args, "page_block", "per_block", page_block, per_block, block_total_pages
    )

    return {
        "admin_role": role,
        "admin_permissions": sorted(perms, key=lambda p: permission_label_fn(p)),
        "can_security_actions": can_security_actions,
        "total_users": stats["total_users"],
        "total_chats": stats["total_chats"],
        "total_messages": stats["total_messages"],
        "total_admins": stats["total_admins"],
        "security_risk_label": security_risk_label,
        "security_risk_tone": security_risk_tone,
        "total_active_blocks": total_active_blocks,
        "login_blocked_active": login_blocked_active,
        "reset_blocked_active": reset_blocked_active,
        "rate_blocked_active": rate_blocked_active,
        "manual_block_active": manual_block_active,
        "login_risky_rows": login_risky_rows,
        "recent_lock_events": recent_lock_events,
        "login_attempts": login_attempts,
        "reset_ip_rows": reset_ip_rows,
        "rate_limit_rows": rate_limit_rows,
        "security_blocks": security_blocks,
        "login_q": login_q,
        "reset_q": reset_q,
        "rate_q": rate_q,
        "block_q": block_q,
        "per_options": per_options,
        "per_login": per_login,
        "per_reset": per_reset,
        "per_rate": per_rate,
        "per_block": per_block,
        "login_total": login_total,
        "reset_total": reset_total,
        "rate_total": rate_total,
        "block_total": block_total,
        "login_pagination": login_pagination,
        "reset_pagination": reset_pagination,
        "rate_pagination": rate_pagination,
        "block_pagination": block_pagination,
    }
