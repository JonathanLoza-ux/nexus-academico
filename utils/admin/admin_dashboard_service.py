"""Servicios para dashboard administrativo (metricas y salud)."""

from datetime import timedelta

from models import User, Conversation, Message, AdminRole, LoginAttempt


def admin_stats():
    return {
        "total_users": User.query.count(),
        "total_chats": Conversation.query.count(),
        "total_messages": Message.query.count(),
        "total_admins": AdminRole.query.filter_by(is_active=True).count(),
    }


def admin_dashboard_charts(days=7, utcnow_naive_fn=None):
    if utcnow_naive_fn is None:
        raise ValueError("utcnow_naive_fn es requerido")

    now_utc = utcnow_naive_fn()
    span_days = max(1, int(days or 1))
    start_day = (now_utc - timedelta(days=span_days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)

    day_labels = []
    day_map = {}
    for i in range(span_days):
        d = (start_day + timedelta(days=i)).date()
        key = d.strftime("%Y-%m-%d")
        day_labels.append(key)
        day_map[key] = 0

    rows = (
        Message.query
        .filter(Message.timestamp >= start_day)
        .order_by(Message.timestamp.asc())
        .all()
    )
    for m in rows:
        if not m.timestamp:
            continue
        key = m.timestamp.date().strftime("%Y-%m-%d")
        if key in day_map:
            day_map[key] += 1
    message_day_values = [day_map[k] for k in day_labels]

    active_users = User.query.filter(User.is_active_account == True).count()  # noqa: E712
    inactive_users = User.query.filter(User.is_active_account == False).count()  # noqa: E712

    ip_rows = (
        LoginAttempt.query
        .filter(LoginAttempt.attempts > 0)
        .order_by(LoginAttempt.attempts.desc(), LoginAttempt.id.desc())
        .limit(8)
        .all()
    )
    ip_labels = [r.ip or "-" for r in ip_rows]
    ip_values = [int(r.attempts or 0) for r in ip_rows]

    return {
        "message_day_labels": day_labels,
        "message_day_values": message_day_values,
        "account_status_labels": ["Activas", "Desactivadas"],
        "account_status_values": [active_users, inactive_users],
        "failed_ip_labels": ip_labels,
        "failed_ip_values": ip_values,
    }


def format_uptime_compact(start_dt, now_dt):
    if not start_dt or not now_dt or now_dt < start_dt:
        return "-"
    total_seconds = int((now_dt - start_dt).total_seconds())
    days, rem = divmod(total_seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def admin_system_health(
    utcnow_naive_fn,
    db_session,
    sql_text_fn,
    perf_counter_fn,
    gemini_keys,
    reset_mode,
    brevo_api_key,
    brevo_sender_email,
    mail_server,
    mail_username,
    mail_password,
    cloudinary_config_fn,
    cloudinary_url,
    app_started_at,
    format_dt_human_fn,
    format_uptime_compact_fn,
):
    now_utc = utcnow_naive_fn()
    items = []

    db_status = "off"
    db_label = "Error"
    db_detail = "Sin respuesta"
    try:
        t0 = perf_counter_fn()
        db_session.execute(sql_text_fn("SELECT 1"))
        latency_ms = int((perf_counter_fn() - t0) * 1000)
        if latency_ms <= 120:
            db_status, db_label = "ok", "Conectada"
        elif latency_ms <= 350:
            db_status, db_label = "warn", "Lenta"
        else:
            db_status, db_label = "warn", "Latencia alta"
        db_detail = f"Ping: {latency_ms} ms"
    except Exception:
        pass
    items.append({
        "name": "Base de datos",
        "status": db_status,
        "label": db_label,
        "detail": db_detail,
        "icon": "fa-database",
    })

    gemini_count = len([k for k in (gemini_keys or []) if k])
    if gemini_count >= 3:
        gem_status, gem_label = "ok", "Lista"
    elif gemini_count >= 1:
        gem_status, gem_label = "warn", "Parcial"
    else:
        gem_status, gem_label = "off", "Sin claves"
    items.append({
        "name": "Gemini",
        "status": gem_status,
        "label": gem_label,
        "detail": f"Claves cargadas: {gemini_count}",
        "icon": "fa-robot",
    })

    mode = (reset_mode or "dev").strip().lower()
    if mode == "brevo_api":
        mail_ok = bool(brevo_api_key and brevo_sender_email)
        mail_status, mail_label = ("ok", "Brevo API") if mail_ok else ("off", "Brevo incompleto")
    elif mode == "smtp":
        mail_ok = bool(mail_server and mail_username and mail_password)
        mail_status, mail_label = ("ok", "SMTP listo") if mail_ok else ("off", "SMTP incompleto")
    else:
        mail_status, mail_label = "warn", "Modo dev"
    items.append({
        "name": "Correo",
        "status": mail_status,
        "label": mail_label,
        "detail": f"Modo: {mode}",
        "icon": "fa-envelope",
    })

    cfg = cloudinary_config_fn()
    cloud_ok = bool(cfg and cfg.cloud_name and (cfg.api_key or cloudinary_url))
    items.append({
        "name": "Cloudinary",
        "status": "ok" if cloud_ok else "off",
        "label": "Listo" if cloud_ok else "No configurado",
        "detail": f"Cloud: {cfg.cloud_name if cfg and cfg.cloud_name else '-'}",
        "icon": "fa-cloud",
    })

    items.append({
        "name": "Uptime",
        "status": "ok",
        "label": format_uptime_compact_fn(app_started_at, now_utc),
        "detail": f"Inicio: {format_dt_human_fn(app_started_at)} UTC",
        "icon": "fa-clock",
    })

    try:
        high_risk = LoginAttempt.query.filter(LoginAttempt.attempts >= 5).count()
    except Exception:
        high_risk = 0
    if high_risk >= 20:
        sec_status, sec_label = "off", "Alta actividad"
    elif high_risk >= 5:
        sec_status, sec_label = "warn", "Moderada"
    else:
        sec_status, sec_label = "ok", "Normal"
    items.append({
        "name": "Seguridad reciente",
        "status": sec_status,
        "label": sec_label,
        "detail": f"IPs con >=5 intentos: {high_risk}",
        "icon": "fa-shield-halved",
    })

    return items
