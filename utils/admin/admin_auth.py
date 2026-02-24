"""Helpers de autenticacion/autorizacion del panel admin."""

import json
import os
from functools import wraps

from flask import abort
from flask_login import current_user
from sqlalchemy import func

from extensions import db, login_manager
from models import AdminRole, User, utcnow_naive


_super_admin_env = (os.getenv("SUPER_ADMIN_EMAILS") or "jonathandavidloza@gmail.com").strip()
SUPER_ADMIN_EMAILS = {
    e.strip().lower() for e in _super_admin_env.split(",") if e.strip()
}

ALL_ADMIN_PERMISSIONS = {
    "view_dashboard",
    "view_users",
    "view_conversations",
    "view_logs",
    "view_security",
    "export_reports",
    "manage_users",
    "manage_admins",
    "manage_settings",
}

DEFAULT_ADMIN_PERMISSIONS = {
    "view_dashboard",
    "view_users",
    "view_conversations",
    "view_logs",
    "export_reports",
}

PERMISSION_LABELS_ES = {
    "view_dashboard": "Ver panel general",
    "view_users": "Ver usuarios",
    "view_conversations": "Ver conversaciones",
    "view_logs": "Ver registros (logs)",
    "view_security": "Ver seguridad",
    "export_reports": "Exportar reportes",
    "manage_users": "Gestionar usuarios",
    "manage_admins": "Gestionar administradores",
    "manage_settings": "Gestionar configuracion",
}

PERMISSION_GROUPS_ES = [
    {
        "title": "Panel y reportes",
        "icon": "fa-chart-line",
        "codes": ["view_dashboard", "export_reports"],
    },
    {
        "title": "Usuarios y conversaciones",
        "icon": "fa-users",
        "codes": ["view_users", "view_conversations", "manage_users"],
    },
    {
        "title": "Seguridad y registros",
        "icon": "fa-shield-halved",
        "codes": ["view_security", "view_logs"],
    },
    {
        "title": "Administracion",
        "icon": "fa-user-shield",
        "codes": ["manage_admins", "manage_settings"],
    },
]


def _normalize_email(value: str) -> str:
    return (value or "").strip().lower()


def _loads_permissions(raw: str):
    if not raw:
        return set()
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return {str(x).strip() for x in data if str(x).strip()}
    except Exception:
        pass
    return set()


def _dumps_permissions(perms):
    clean = sorted({p for p in perms if p in ALL_ADMIN_PERMISSIONS})
    return json.dumps(clean, ensure_ascii=True)


def _permission_label_es(code: str):
    return PERMISSION_LABELS_ES.get(code, code)


def _is_super_admin_email(email: str) -> bool:
    return _normalize_email(email) in SUPER_ADMIN_EMAILS


def _get_admin_role_record(user_id: int):
    if not user_id:
        return None
    return AdminRole.query.filter_by(user_id=user_id, is_active=True).first()


def _effective_admin_role(user: User):
    if not user:
        return None
    if _is_super_admin_email(user.email):
        return "super_admin"
    rec = _get_admin_role_record(user.id)
    if rec and rec.role in ("admin", "super_admin"):
        return rec.role
    return None


def _effective_admin_permissions(user: User):
    role = _effective_admin_role(user)
    if role == "super_admin":
        return set(ALL_ADMIN_PERMISSIONS)
    if role == "admin":
        rec = _get_admin_role_record(user.id)
        if not rec:
            return set(DEFAULT_ADMIN_PERMISSIONS)
        perms = _loads_permissions(rec.permissions_json)
        return perms or set(DEFAULT_ADMIN_PERMISSIONS)
    return set()


def _admin_has_permission(user: User, permission: str):
    if not user:
        return False
    perms = _effective_admin_permissions(user)
    return permission in perms


def _ensure_super_admin_membership(user: User):
    if not user or not _is_super_admin_email(user.email):
        return
    rec = AdminRole.query.filter_by(user_id=user.id).first()
    if not rec:
        rec = AdminRole(
            user_id=user.id,
            role="super_admin",
            permissions_json=_dumps_permissions(ALL_ADMIN_PERMISSIONS),
            is_active=True,
            granted_by_user_id=user.id,
        )
        db.session.add(rec)
        db.session.commit()
        return

    changed = False
    if rec.role != "super_admin":
        rec.role = "super_admin"
        changed = True
    if not rec.is_active:
        rec.is_active = True
        changed = True

    desired = _dumps_permissions(ALL_ADMIN_PERMISSIONS)
    if rec.permissions_json != desired:
        rec.permissions_json = desired
        changed = True

    if changed:
        rec.updated_at = utcnow_naive()
        db.session.commit()


def _bootstrap_super_admin_roles():
    if not SUPER_ADMIN_EMAILS:
        return
    users = User.query.filter(func.lower(User.email).in_(list(SUPER_ADMIN_EMAILS))).all()
    for user in users:
        _ensure_super_admin_membership(user)


def admin_required(permission=None, super_only=False):
    def _decorator(fn):
        @wraps(fn)
        def _wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()

            role = _effective_admin_role(current_user)
            if not role:
                abort(403)
            if super_only and role != "super_admin":
                abort(403)
            if permission and not _admin_has_permission(current_user, permission):
                abort(403)
            return fn(*args, **kwargs)

        return _wrapped

    return _decorator
