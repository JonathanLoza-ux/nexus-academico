"""Servicio para asignar y revocar roles administrativos."""

from sqlalchemy import func

from models import AdminRole, User


def grant_admin_role(
    *,
    email_raw,
    role_raw,
    requested_permissions,
    current_user_id: int,
    db_session,
    normalize_email_fn,
    is_super_admin_email_fn,
    dumps_permissions_fn,
    utcnow_naive_fn,
    add_admin_audit_fn,
    all_admin_permissions,
    default_admin_permissions,
):
    email = normalize_email_fn(email_raw)
    role = (role_raw or "admin").strip().lower()
    requested_permissions = set(requested_permissions or [])

    if not email:
        return {"success": False, "message": "Debes escribir un correo para asignar permisos.", "category": "error"}

    user = User.query.filter(func.lower(User.email) == email).first()
    if not user:
        return {"success": False, "message": "No existe un usuario con ese correo.", "category": "error"}

    if role not in {"admin", "super_admin"}:
        return {"success": False, "message": "Rol invalido.", "category": "error"}

    if role == "super_admin" and not is_super_admin_email_fn(user.email):
        return {
            "success": False,
            "message": "Solo correos de SUPER_ADMIN_EMAILS pueden ser super admin.",
            "category": "error",
        }

    if role == "super_admin":
        granted_permissions = set(all_admin_permissions)
    else:
        granted_permissions = {p for p in requested_permissions if p in all_admin_permissions}
        if not granted_permissions:
            granted_permissions = set(default_admin_permissions)

    rec = AdminRole.query.filter_by(user_id=user.id).first()
    if not rec:
        rec = AdminRole(
            user_id=user.id,
            role=role,
            permissions_json=dumps_permissions_fn(granted_permissions),
            is_active=True,
            granted_by_user_id=current_user_id,
        )
        db_session.add(rec)
    else:
        rec.role = role
        rec.permissions_json = dumps_permissions_fn(granted_permissions)
        rec.is_active = True
        rec.granted_by_user_id = current_user_id
        rec.updated_at = utcnow_naive_fn()

    db_session.commit()
    add_admin_audit_fn(
        "admin_grant",
        target_user_id=user.id,
        detail=f"email={user.email}; role={role}; permissions={sorted(granted_permissions)}",
    )
    return {"success": True, "message": "Permisos de administrador actualizados.", "category": "success"}


def revoke_admin_role(
    *,
    target_user_id: int,
    current_user_id: int,
    db_session,
    is_super_admin_email_fn,
    utcnow_naive_fn,
    add_admin_audit_fn,
):
    if target_user_id == current_user_id:
        return {"success": False, "message": "No puedes revocar tu propio acceso desde aqui.", "category": "error"}

    user = db_session.get(User, target_user_id)
    if not user:
        return {"success": False, "message": "Usuario no encontrado.", "category": "error"}

    if is_super_admin_email_fn(user.email):
        return {"success": False, "message": "No puedes revocar un super admin por correo protegido.", "category": "error"}

    rec = AdminRole.query.filter_by(user_id=target_user_id).first()
    if not rec:
        return {"success": False, "message": "Ese usuario no tiene rol admin asignado.", "category": "error"}

    rec.is_active = False
    rec.updated_at = utcnow_naive_fn()
    db_session.commit()
    add_admin_audit_fn("admin_revoke", target_user_id=user.id, detail=f"email={user.email}")
    return {"success": True, "message": "Acceso admin revocado.", "category": "success"}
