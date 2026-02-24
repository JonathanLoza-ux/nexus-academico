"""Servicios de seguridad del panel admin."""

from datetime import timedelta

from models import LoginAttempt, ResetIPRequest, RateLimit


def admin_security_data(limit=100):
    login_attempts = LoginAttempt.query.order_by(LoginAttempt.id.desc()).limit(limit).all()
    reset_ip_rows = ResetIPRequest.query.order_by(ResetIPRequest.id.desc()).limit(limit).all()
    rate_limit_rows = RateLimit.query.order_by(RateLimit.id.desc()).limit(limit).all()
    return login_attempts, reset_ip_rows, rate_limit_rows


def security_can_manage_actions(user, effective_admin_role_fn, effective_admin_permissions_fn) -> bool:
    role = effective_admin_role_fn(user)
    perms = effective_admin_permissions_fn(user)
    return bool(
        role == "super_admin"
        or "manage_users" in perms
        or "manage_settings" in perms
    )


def security_block_state(blocked_until, now_utc, to_naive_utc_fn):
    until = to_naive_utc_fn(blocked_until)
    is_blocked = bool(until and until > now_utc)
    return is_blocked, until


def security_duration_delta(value_raw, unit_raw, safe_int_fn):
    value = safe_int_fn(value_raw, 0)
    unit = (unit_raw or "").strip().lower()
    if value < 1:
        return None
    if unit == "minutes":
        return timedelta(minutes=value)
    if unit == "hours":
        return timedelta(hours=value)
    if unit == "days":
        return timedelta(days=value)
    return None
