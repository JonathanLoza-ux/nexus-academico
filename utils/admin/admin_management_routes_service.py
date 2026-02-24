"""Servicios para rutas POST de gestion administrativa de usuarios y admins."""


def admin_grant_route_action(email_raw, role_raw, requested_permissions, grant_admin_role_fn):
    return grant_admin_role_fn(
        email_raw=email_raw,
        role_raw=role_raw,
        requested_permissions=requested_permissions,
    )


def admin_revoke_route_action(target_user_id, revoke_admin_role_fn):
    return revoke_admin_role_fn(target_user_id=target_user_id)


def admin_user_status_route_action(user_id, action_raw, admin_user_status_action_fn):
    return admin_user_status_action_fn(
        user_id=user_id,
        action_raw=action_raw,
    )


def admin_users_bulk_route_action(action_raw, raw_ids, admin_users_bulk_action_fn):
    return admin_users_bulk_action_fn(
        action_raw=action_raw,
        raw_ids=raw_ids,
    )


def admin_user_suspend_route_action(
    user_id,
    action_raw,
    duration_value_raw,
    duration_unit_raw,
    admin_user_suspend_action_fn,
):
    return admin_user_suspend_action_fn(
        user_id=user_id,
        action_raw=action_raw,
        duration_value_raw=duration_value_raw,
        duration_unit_raw=duration_unit_raw,
    )


def admin_user_delete_route_action(user_id, admin_user_delete_action_fn):
    return admin_user_delete_action_fn(user_id=user_id)
