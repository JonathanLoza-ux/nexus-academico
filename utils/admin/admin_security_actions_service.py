"""Acciones POST de seguridad para panel administrativo."""


def unlock_login_attempt_action(
    row_id,
    db_session,
    login_attempt_model,
    format_dt_human_fn,
    add_admin_audit_fn,
):
    row = db_session.get(login_attempt_model, row_id)
    if not row:
        return False, "Registro de login no encontrado."

    attempts_before = int(row.attempts or 0)
    blocked_before = format_dt_human_fn(row.blocked_until)
    row.attempts = 0
    row.first_attempt_at = None
    row.blocked_until = None
    db_session.commit()

    add_admin_audit_fn(
        "security_login_unlock",
        detail=(
            f"id={row.id}; email={row.email or '-'}; ip={row.ip or '-'}; "
            f"attempts_before={attempts_before}; blocked_until_before={blocked_before}"
        ),
    )
    return True, "Login desbloqueado y contador reiniciado."


def unlock_reset_ip_action(
    row_id,
    db_session,
    reset_ip_model,
    format_dt_human_fn,
    add_admin_audit_fn,
):
    row = db_session.get(reset_ip_model, row_id)
    if not row:
        return False, "Registro de reset por IP no encontrado."

    attempts_before = int(row.attempts or 0)
    blocked_before = format_dt_human_fn(row.blocked_until)
    row.attempts = 0
    row.first_attempt_at = None
    row.last_sent_at = None
    row.blocked_until = None
    db_session.commit()

    add_admin_audit_fn(
        "security_reset_ip_unlock",
        detail=(
            f"id={row.id}; ip={row.ip or '-'}; attempts_before={attempts_before}; "
            f"blocked_until_before={blocked_before}"
        ),
    )
    return True, "Registro de reset por IP desbloqueado."


def clear_rate_limit_action(
    row_id,
    db_session,
    rate_limit_model,
    utcnow_naive_fn,
    format_dt_human_fn,
    add_admin_audit_fn,
):
    row = db_session.get(rate_limit_model, row_id)
    if not row:
        return False, "Registro de rate limit no encontrado."

    count_before = int(row.count or 0)
    blocked_before = format_dt_human_fn(row.blocked_until)
    row.count = 0
    row.window_start = utcnow_naive_fn()
    row.blocked_until = None
    db_session.commit()

    add_admin_audit_fn(
        "security_rate_limit_clear",
        detail=(
            f"id={row.id}; key={row.key or '-'}; count_before={count_before}; "
            f"blocked_until_before={blocked_before}"
        ),
    )
    return True, "Rate limit reiniciado correctamente."


def block_email_action(
    email,
    reason,
    delta,
    current_user_id,
    db_session,
    security_block_model,
    utcnow_naive_fn,
    format_dt_human_fn,
    add_admin_audit_fn,
):
    until = utcnow_naive_fn() + delta
    row = security_block_model.query.filter_by(block_type="email", target=email).first()
    if not row:
        row = security_block_model(
            block_type="email",
            target=email,
            created_by_user_id=current_user_id,
        )
        db_session.add(row)
    row.reason = reason or "Bloqueo manual de correo"
    row.blocked_until = until
    row.is_active = True
    row.created_by_user_id = current_user_id
    row.updated_at = utcnow_naive_fn()
    db_session.commit()

    add_admin_audit_fn(
        "security_block_email_set",
        detail=f"email={email}; until={format_dt_human_fn(until)}; reason={row.reason}",
    )
    return True, f"Bloqueo por correo activo hasta {format_dt_human_fn(until)}."


def block_ip_action(
    ip,
    reason,
    delta,
    current_user_id,
    db_session,
    security_block_model,
    utcnow_naive_fn,
    format_dt_human_fn,
    add_admin_audit_fn,
):
    until = utcnow_naive_fn() + delta
    row = security_block_model.query.filter_by(block_type="ip", target=ip).first()
    if not row:
        row = security_block_model(
            block_type="ip",
            target=ip,
            created_by_user_id=current_user_id,
        )
        db_session.add(row)
    row.reason = reason or "Bloqueo manual de IP"
    row.blocked_until = until
    row.is_active = True
    row.created_by_user_id = current_user_id
    row.updated_at = utcnow_naive_fn()
    db_session.commit()

    add_admin_audit_fn(
        "security_block_ip_set",
        detail=f"ip={ip}; until={format_dt_human_fn(until)}; reason={row.reason}",
    )
    return True, f"Bloqueo por IP activo hasta {format_dt_human_fn(until)}."


def remove_security_block_action(
    block_id,
    db_session,
    security_block_model,
    utcnow_naive_fn,
    add_admin_audit_fn,
):
    row = db_session.get(security_block_model, block_id)
    if not row:
        return False, "Bloqueo no encontrado."

    row.is_active = False
    row.updated_at = utcnow_naive_fn()
    db_session.commit()

    add_admin_audit_fn(
        "security_block_remove",
        detail=f"id={row.id}; type={row.block_type}; target={row.target}",
    )
    return True, "Bloqueo manual retirado."


def force_logout_action(
    email,
    db_session,
    user_model,
    sql_lower_fn,
    mark_force_logout_fn,
    add_admin_audit_fn,
):
    user = user_model.query.filter(sql_lower_fn(user_model.email) == email).first()
    if not user:
        return False, "No existe un usuario con ese correo."

    mark_force_logout_fn(user.id)
    add_admin_audit_fn(
        "security_force_logout",
        target_user_id=user.id,
        detail=f"email={user.email}",
    )
    return True, f"Se marco cierre forzado de sesion para {user.email}."
