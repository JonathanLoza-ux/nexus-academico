"""Control de intentos anti-spam / anti-bruteforce."""

from datetime import datetime, timedelta, timezone

from extensions import db
from models import ResetRequest, ResetIPRequest, LoginAttempt, utcnow_naive
from utils.core.security_helpers import _active_security_block, _security_block_wait_seconds


def _to_naive_utc(dt):
    if dt is None:
        return None
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            return dt
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return None


def can_send_reset(email: str, reset_window_minutes: int, reset_cooldown_seconds: int, reset_max_attempts: int):
    now = utcnow_naive()
    rr = ResetRequest.query.filter_by(email=email).first()

    if not rr:
        rr = ResetRequest(email=email, last_sent_at=None, attempts=0, first_attempt_at=None)
        db.session.add(rr)
        db.session.commit()

    first = _to_naive_utc(rr.first_attempt_at)
    last = _to_naive_utc(rr.last_sent_at)

    if first and now - first > timedelta(minutes=reset_window_minutes):
        rr.attempts = 0
        rr.first_attempt_at = None
        rr.last_sent_at = None
        db.session.commit()

    if last and (now - last).total_seconds() < reset_cooldown_seconds:
        wait = reset_cooldown_seconds - int((now - last).total_seconds())
        return False, wait, (rr.attempts >= reset_max_attempts)

    if rr.attempts >= reset_max_attempts:
        return False, 0, True

    return True, 0, False


def register_reset_sent(email: str):
    now = utcnow_naive()
    rr = ResetRequest.query.filter_by(email=email).first()
    if not rr:
        rr = ResetRequest(email=email)
        db.session.add(rr)

    if rr.attempts == 0 or rr.first_attempt_at is None:
        rr.first_attempt_at = now

    rr.attempts = (rr.attempts or 0) + 1
    rr.last_sent_at = now
    db.session.commit()


def can_send_reset_ip(ip: str, reset_ip_window_minutes: int, reset_ip_max_attempts: int, reset_ip_block_minutes: int):
    now = utcnow_naive()
    manual_ip_block = _active_security_block("ip", ip, now)
    if manual_ip_block:
        wait = _security_block_wait_seconds(manual_ip_block, now)
        return False, wait, True

    row = ResetIPRequest.query.filter_by(ip=ip).first()
    if not row:
        row = ResetIPRequest(ip=ip)
        db.session.add(row)
        db.session.commit()

    blocked_until = _to_naive_utc(row.blocked_until)
    first_attempt_at = _to_naive_utc(row.first_attempt_at)

    if blocked_until and now < blocked_until:
        wait = int((blocked_until - now).total_seconds())
        return False, wait, True

    if first_attempt_at and now - first_attempt_at > timedelta(minutes=reset_ip_window_minutes):
        row.attempts = 0
        row.first_attempt_at = None
        row.last_sent_at = None
        row.blocked_until = None
        db.session.commit()

    if (row.attempts or 0) >= reset_ip_max_attempts:
        row.blocked_until = now + timedelta(minutes=reset_ip_block_minutes)
        db.session.commit()
        wait = int((row.blocked_until - now).total_seconds())
        return False, wait, True

    return True, 0, False


def register_reset_ip_sent(ip: str):
    now = utcnow_naive()
    row = ResetIPRequest.query.filter_by(ip=ip).first()
    if not row:
        row = ResetIPRequest(ip=ip)
        db.session.add(row)

    if (row.attempts or 0) == 0 or row.first_attempt_at is None:
        row.first_attempt_at = now

    row.attempts = (row.attempts or 0) + 1
    row.last_sent_at = now
    db.session.commit()


def can_login(ip: str, email: str, login_window_minutes: int, login_max_attempts: int, login_block_minutes: int):
    now = utcnow_naive()
    manual_email_block = _active_security_block("email", email, now)
    manual_ip_block = _active_security_block("ip", ip, now)
    if manual_email_block or manual_ip_block:
        wait = max(
            _security_block_wait_seconds(manual_email_block, now),
            _security_block_wait_seconds(manual_ip_block, now),
        )
        return False, wait

    row = LoginAttempt.query.filter_by(ip=ip, email=email).first()
    if not row:
        row = LoginAttempt(ip=ip, email=email)
        db.session.add(row)
        db.session.commit()

    blocked_until = _to_naive_utc(row.blocked_until)
    first_attempt_at = _to_naive_utc(row.first_attempt_at)

    if blocked_until and now < blocked_until:
        wait = int((blocked_until - now).total_seconds())
        return False, wait

    if first_attempt_at and now - first_attempt_at > timedelta(minutes=login_window_minutes):
        row.attempts = 0
        row.first_attempt_at = None
        row.blocked_until = None
        db.session.commit()

    if (row.attempts or 0) >= login_max_attempts:
        row.blocked_until = now + timedelta(minutes=login_block_minutes)
        db.session.commit()
        wait = int((row.blocked_until - now).total_seconds())
        return False, wait

    return True, 0


def register_login_fail(ip: str, email: str):
    now = utcnow_naive()
    row = LoginAttempt.query.filter_by(ip=ip, email=email).first()
    if not row:
        row = LoginAttempt(ip=ip, email=email)
        db.session.add(row)

    if (row.attempts or 0) == 0 or row.first_attempt_at is None:
        row.first_attempt_at = now

    row.attempts = (row.attempts or 0) + 1
    db.session.commit()


def clear_login_attempts(ip: str, email: str):
    row = LoginAttempt.query.filter_by(ip=ip, email=email).first()
    if row:
        db.session.delete(row)
        db.session.commit()
