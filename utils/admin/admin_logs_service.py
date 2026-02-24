"""Servicios de logs administrativos: filtros, severidad, enriquecimiento y alertas."""

import re
from datetime import timedelta

from flask import url_for, request

from models import AdminAuditLog, LoginAttempt, RateLimit, ResetIPRequest, User


def mask_email_for_logs(email: str):
    email = (email or "").strip()
    if "@" not in email:
        return email
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        local_masked = local[:1] + "*"
    else:
        local_masked = local[:2] + ("*" * max(2, len(local) - 2))
    domain_parts = domain.split(".")
    if domain_parts and domain_parts[0]:
        dom0 = domain_parts[0]
        domain_parts[0] = dom0[:1] + ("*" * max(2, len(dom0) - 1))
    return local_masked + "@" + ".".join(domain_parts)


def mask_sensitive_text(text: str):
    raw = (text or "").strip()
    if not raw:
        return "-"
    masked = re.sub(
        r"(?i)\b(api[_-]?key|token|secret|password|authorization)\s*=\s*([^;,\s]+)",
        r"\1=***",
        raw,
    )
    masked = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*", "Bearer ***", masked)
    masked = re.sub(r"AIza[0-9A-Za-z\-_]{20,}", "AIza***", masked)
    masked = re.sub(
        r"([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})",
        lambda m: mask_email_for_logs(m.group(0)),
        masked,
    )
    return masked


def extract_detail_pairs(detail: str):
    raw = (detail or "").strip()
    if not raw:
        return []
    chunks = [c.strip() for c in raw.split(";") if c.strip()]
    out = []
    for ch in chunks:
        if "=" not in ch:
            out.append(("detalle", mask_sensitive_text(ch)))
            continue
        k, v = ch.split("=", 1)
        out.append((k.strip().lower(), mask_sensitive_text(v.strip())))
    return out


def extract_request_id(detail: str):
    raw = (detail or "").strip()
    if not raw:
        return ""
    m = re.search(r"(?:^|[;\s,])rid=([A-Za-z0-9_-]{6,64})", raw)
    return m.group(1) if m else ""


def extract_meta_from_detail(detail: str):
    pairs = dict(extract_detail_pairs(detail))
    return {
        "rid": pairs.get("rid", ""),
        "method": pairs.get("method", ""),
        "path": pairs.get("path", ""),
        "endpoint": pairs.get("endpoint", ""),
    }


def admin_log_module(action: str):
    key = (action or "").lower()
    if key.startswith("security_"):
        return "Seguridad", "admin_security_page"
    if key.startswith("user_"):
        return "Usuarios", "admin_users_page"
    if key.startswith("admin_"):
        return "Administradores", "admin_admins_page"
    return "Logs", "admin_logs_page"


def admin_log_severity(action: str, detail: str = ""):
    key = (action or "").lower()
    d = (detail or "").lower()
    critical_words = ("delete", "revoke", "force_logout", "block")
    warn_words = ("suspend", "unlock", "clear", "status_change")
    if any(w in key for w in critical_words):
        return "critical", "Critico"
    if any(w in key for w in warn_words):
        return "warn", "Advertencia"
    if "error" in d or "fail" in d:
        return "warn", "Advertencia"
    return "info", "Info"


def admin_filter_logs_rows(
    rows,
    to_naive_utc_fn,
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
    q = (q or "").strip().lower()
    action = (action or "").strip().lower()
    actor = (actor or "").strip().lower()
    ip = (ip or "").strip().lower()
    target_user = (target_user or "").strip().lower()
    event_id = (event_id or "").strip()
    request_id = (request_id or "").strip().lower()
    severity = (severity or "").strip().lower()

    filtered = []
    for log_row, actor_user in rows:
        actor_email = ((actor_user.email if actor_user else "") or "").lower()
        actor_name = ((actor_user.name if actor_user else "") or "").lower()
        action_val = (log_row.action or "").lower()
        detail_val = (log_row.detail or "").lower()
        ip_val = (log_row.ip or "").lower()
        rid_val = extract_request_id(log_row.detail).lower()
        sev_key, _sev_label = admin_log_severity(log_row.action, log_row.detail)
        created = to_naive_utc_fn(log_row.created_at)

        if q and not (
            q in actor_email
            or q in actor_name
            or q in action_val
            or q in detail_val
            or q in ip_val
            or q in str(log_row.id)
            or q in str(log_row.target_user_id or "")
            or q in rid_val
        ):
            continue
        if action and action not in action_val:
            continue
        if actor and actor not in actor_email and actor not in actor_name:
            continue
        if ip and ip not in ip_val:
            continue
        if target_user and target_user not in str(log_row.target_user_id or ""):
            continue
        if event_id and event_id != str(log_row.id):
            continue
        if request_id and request_id != rid_val:
            continue
        if severity and severity != sev_key:
            continue
        if date_from and (not created or created < date_from):
            continue
        if date_to and (not created or created >= date_to):
            continue
        filtered.append((log_row, actor_user))

    return filtered


def admin_logs_filters_from_request(request_obj=None, parse_date_ymd_fn=None):
    req = request_obj or request
    if parse_date_ymd_fn is None:
        raise ValueError("parse_date_ymd_fn es requerido")
    filters = {
        "q": (req.args.get("q") or "").strip().lower(),
        "action": (req.args.get("action") or "").strip().lower(),
        "actor": (req.args.get("actor") or "").strip().lower(),
        "ip": (req.args.get("ip") or "").strip().lower(),
        "target_user": (req.args.get("target_user") or "").strip().lower(),
        "event_id": (req.args.get("event_id") or "").strip(),
        "request_id": (req.args.get("request_id") or "").strip().lower(),
        "severity": (req.args.get("severity") or "").strip().lower(),
        "date_from": parse_date_ymd_fn(req.args.get("date_from")),
        "date_to": parse_date_ymd_fn(req.args.get("date_to")),
    }
    if filters["date_to"]:
        filters["date_to"] = filters["date_to"] + timedelta(days=1)
    return filters


def admin_action_meta(action):
    action_key = (action or "").strip().lower()
    mapping = {
        "admin_grant": ("Permisos admin actualizados", "fa-user-shield", "ok"),
        "admin_revoke": ("Acceso admin revocado", "fa-user-slash", "warn"),
        "user_status_change": ("Estado de cuenta cambiado", "fa-user-gear", "warn"),
        "user_suspend": ("Cuenta suspendida", "fa-clock", "warn"),
        "user_unsuspend": ("Suspension retirada", "fa-unlock", "ok"),
        "user_delete": ("Cuenta eliminada", "fa-trash", "off"),
        "user_bulk_status_change": ("Cambio masivo de cuentas", "fa-users-gear", "warn"),
        "user_bulk_export": ("Exportacion masiva", "fa-file-export", "ok"),
    }
    return mapping.get(action_key, ("Evento administrativo", "fa-clipboard-list", "ok"))


def admin_enrich_logs_rows(
    rows,
    now_utc,
    action_meta_fn,
    log_severity_fn,
    extract_meta_fn,
    extract_request_id_fn,
    log_module_fn,
    mask_sensitive_text_fn,
    extract_detail_pairs_fn,
    time_ago_fn,
    url_for_fn=url_for,
):
    target_ids = {int(r[0].target_user_id) for r in rows if r[0].target_user_id}
    target_map = {}
    if target_ids:
        target_users = User.query.filter(User.id.in_(list(target_ids))).all()
        target_map = {u.id: u for u in target_users}

    enriched = []
    for log_row, actor_user in rows:
        title, icon, tone = action_meta_fn(log_row.action)
        severity_key, severity_label = log_severity_fn(log_row.action, log_row.detail or "")
        meta = extract_meta_fn(log_row.detail or "")
        rid_val = extract_request_id_fn(log_row.detail or "")
        module_name, module_endpoint = log_module_fn(log_row.action)
        module_url = url_for_fn(module_endpoint)
        target_user = target_map.get(int(log_row.target_user_id or 0))
        detail_masked = mask_sensitive_text_fn(log_row.detail or "-")
        detail_pairs = extract_detail_pairs_fn(log_row.detail or "")

        summary = detail_masked
        if len(summary) > 150:
            summary = summary[:147] + "..."

        enriched.append({
            "log_row": log_row,
            "actor_user": actor_user,
            "target_user": target_user,
            "title": title,
            "icon": icon,
            "tone": tone,
            "severity_key": severity_key,
            "severity_label": severity_label,
            "when": time_ago_fn(log_row.created_at, now_utc),
            "summary": summary,
            "detail_masked": detail_masked,
            "detail_pairs": detail_pairs,
            "request_id": rid_val,
            "method": meta.get("method", ""),
            "path": meta.get("path", ""),
            "endpoint": meta.get("endpoint", ""),
            "module_name": module_name,
            "module_url": module_url,
        })
    return enriched


def admin_activity_feed(rows, now_utc, action_meta_fn, time_ago_fn, format_dt_human_fn):
    items = []
    for log_row, actor_user in rows:
        title, icon, tone = action_meta_fn(log_row.action)
        actor_name = "Sistema"
        if actor_user:
            actor_name = (actor_user.name or actor_user.email or "Sistema").strip()
        target = f"Usuario #{log_row.target_user_id}" if log_row.target_user_id else "Sin objetivo"
        detail = (log_row.detail or "").strip()
        if len(detail) > 160:
            detail = detail[:157] + "..."
        items.append({
            "title": title,
            "icon": icon,
            "tone": tone,
            "actor": actor_name,
            "target": target,
            "detail": detail or "-",
            "when": time_ago_fn(log_row.created_at, now_utc),
            "at": format_dt_human_fn(log_row.created_at),
        })
    return items


def admin_alerts_payload(gemini_keys, format_dt_human_fn, now_utc):
    items = []
    critical = 0
    warning = 0

    blocked_login = LoginAttempt.query.filter(
        LoginAttempt.blocked_until.isnot(None),
        LoginAttempt.blocked_until > now_utc,
    ).count()
    if blocked_login > 0:
        items.append({
            "tone": "off",
            "icon": "fa-user-lock",
            "title": "Cuentas bloqueadas por intentos",
            "detail": f"Bloqueos activos en login: {blocked_login}",
        })
        critical += 1

    blocked_rate = RateLimit.query.filter(
        RateLimit.blocked_until.isnot(None),
        RateLimit.blocked_until > now_utc,
    ).count()
    if blocked_rate > 0:
        items.append({
            "tone": "warn",
            "icon": "fa-gauge-high",
            "title": "Rate limits activos",
            "detail": f"Claves temporalmente bloqueadas: {blocked_rate}",
        })
        warning += 1

    blocked_reset_ip = ResetIPRequest.query.filter(
        ResetIPRequest.blocked_until.isnot(None),
        ResetIPRequest.blocked_until > now_utc,
    ).count()
    if blocked_reset_ip > 0:
        items.append({
            "tone": "warn",
            "icon": "fa-shield-halved",
            "title": "Bloqueos en recuperacion por IP",
            "detail": f"IPs bloqueadas en reset: {blocked_reset_ip}",
        })
        warning += 1

    suspended_users = User.query.filter(
        User.suspended_until.isnot(None),
        User.suspended_until > now_utc,
    ).count()
    if suspended_users > 0:
        items.append({
            "tone": "warn",
            "icon": "fa-clock",
            "title": "Cuentas suspendidas",
            "detail": f"Cuentas con suspension activa: {suspended_users}",
        })
        warning += 1

    recent_critical_events = AdminAuditLog.query.filter(
        AdminAuditLog.created_at >= (now_utc - timedelta(hours=12)),
        AdminAuditLog.action.in_(["user_delete", "admin_revoke"]),
    ).count()
    if recent_critical_events > 0:
        items.append({
            "tone": "off",
            "icon": "fa-triangle-exclamation",
            "title": "Eventos administrativos criticos",
            "detail": f"Eventos en ultimas 12h: {recent_critical_events}",
        })
        critical += 1

    gemini_count = len([k for k in (gemini_keys or []) if k])
    if gemini_count == 0:
        items.append({
            "tone": "off",
            "icon": "fa-robot",
            "title": "Gemini sin claves",
            "detail": "No hay claves disponibles para responder.",
        })
        critical += 1

    if not items:
        items.append({
            "tone": "ok",
            "icon": "fa-circle-check",
            "title": "Sin alertas criticas",
            "detail": "El sistema se mantiene estable en este momento.",
        })

    return {
        "critical_count": critical,
        "warning_count": warning,
        "items": items,
        "generated_at": format_dt_human_fn(now_utc),
    }
