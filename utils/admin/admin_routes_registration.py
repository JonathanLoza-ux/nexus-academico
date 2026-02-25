"""Registro de rutas administrativas."""

from flask import flash, jsonify, redirect, render_template, request, url_for


def register_admin_routes(
    app,
    login_required,
    admin_required,
    current_user,
    security_can_manage_actions_fn,
    admin_security_redirect_fn,
    normalize_email_fn,
    normalize_ip_fn,
    email_re,
    security_duration_delta_fn,
    build_admin_panel_context_fn,
    admin_alerts_payload_fn,
    build_admin_admins_context_fn,
    build_admin_users_context_fn,
    build_admin_logs_context_fn,
    cleanup_old_admin_logs_fn,
    add_admin_audit_fn,
    admin_log_retention_days,
    build_admin_security_context_fn,
    unlock_login_attempt_action_fn,
    unlock_reset_ip_action_fn,
    clear_rate_limit_action_fn,
    block_email_action_fn,
    block_ip_action_fn,
    remove_security_block_action_fn,
    force_logout_action_fn,
    build_admin_reports_context_fn,
    export_users_xlsx_action_fn,
    export_login_attempts_xlsx_action_fn,
    export_audit_xlsx_action_fn,
    export_audit_csv_action_fn,
    export_audit_pdf_action_fn,
    export_users_json_payload_action_fn,
    export_audit_json_payload_action_fn,
    export_security_json_payload_action_fn,
    report_payload_rows_count_fn,
    record_report_export_action_fn,
    report_export_history_payload_fn,
    admin_grant_route_action_fn,
    admin_revoke_route_action_fn,
    admin_user_status_route_action_fn,
    admin_users_bulk_route_action_fn,
    admin_user_suspend_route_action_fn,
    admin_user_delete_route_action_fn,
):
    @app.route('/admin')
    @login_required
    @admin_required(permission="view_dashboard")
    def admin_panel():
        return render_template('admin_panel.html', **build_admin_panel_context_fn())

    @app.route('/admin/alerts_feed')
    @login_required
    @admin_required(permission="view_dashboard")
    def admin_alerts_feed():
        payload = admin_alerts_payload_fn()
        return jsonify({"success": True, **payload})

    @app.route('/admin/admins')
    @login_required
    @admin_required(super_only=True)
    def admin_admins_page():
        return render_template('admin_admins.html', **build_admin_admins_context_fn())

    @app.route('/admin/usuarios')
    @login_required
    @admin_required(permission="view_users")
    def admin_users_page():
        return render_template('admin_users.html', **build_admin_users_context_fn())

    @app.route('/admin/logs')
    @login_required
    @admin_required(permission="view_logs")
    def admin_logs_page():
        return render_template('admin_logs.html', **build_admin_logs_context_fn())

    @app.route('/admin/logs/cleanup', methods=['POST'])
    @login_required
    @admin_required(super_only=True)
    def admin_logs_cleanup():
        deleted = cleanup_old_admin_logs_fn(force=True)
        if deleted > 0:
            add_admin_audit_fn(
                "logs_cleanup",
                detail=f"deleted={deleted}; retention_days={admin_log_retention_days}",
            )
            flash(f"Limpieza aplicada: {deleted} logs eliminados por retencion.", "success")
        else:
            flash("No habia logs antiguos para limpiar.", "warning")
        return redirect(url_for('admin_logs_page'))

    @app.route('/admin/seguridad')
    @login_required
    @admin_required(permission="view_security")
    def admin_security_page():
        return render_template('admin_security.html', **build_admin_security_context_fn())

    @app.route('/admin/seguridad/login/unlock/<int:row_id>', methods=['POST'])
    @login_required
    @admin_required(permission="view_security")
    def admin_security_unlock_login(row_id):
        if not security_can_manage_actions_fn(current_user):
            flash("No tienes permisos para ejecutar acciones de seguridad.", "error")
            return admin_security_redirect_fn()
        ok, message = unlock_login_attempt_action_fn(row_id)
        flash(message, "success" if ok else "error")
        return admin_security_redirect_fn()

    @app.route('/admin/seguridad/reset_ip/unlock/<int:row_id>', methods=['POST'])
    @login_required
    @admin_required(permission="view_security")
    def admin_security_unlock_reset_ip(row_id):
        if not security_can_manage_actions_fn(current_user):
            flash("No tienes permisos para ejecutar acciones de seguridad.", "error")
            return admin_security_redirect_fn()
        ok, message = unlock_reset_ip_action_fn(row_id)
        flash(message, "success" if ok else "error")
        return admin_security_redirect_fn()

    @app.route('/admin/seguridad/rate_limit/clear/<int:row_id>', methods=['POST'])
    @login_required
    @admin_required(permission="view_security")
    def admin_security_clear_rate_limit(row_id):
        if not security_can_manage_actions_fn(current_user):
            flash("No tienes permisos para ejecutar acciones de seguridad.", "error")
            return admin_security_redirect_fn()
        ok, message = clear_rate_limit_action_fn(row_id)
        flash(message, "success" if ok else "error")
        return admin_security_redirect_fn()

    @app.route('/admin/seguridad/block/email', methods=['POST'])
    @login_required
    @admin_required(permission="view_security")
    def admin_security_block_email():
        if not security_can_manage_actions_fn(current_user):
            flash("No tienes permisos para ejecutar acciones de seguridad.", "error")
            return admin_security_redirect_fn()

        email = normalize_email_fn(request.form.get("email"))
        reason = (request.form.get("reason") or "").strip()
        delta = security_duration_delta_fn(request.form.get("duration_value"), request.form.get("duration_unit"))

        if not email or not email_re.match(email):
            flash("Debes ingresar un correo valido para bloquear.", "error")
            return admin_security_redirect_fn()
        if not delta:
            flash("Duracion invalida para bloqueo de correo.", "error")
            return admin_security_redirect_fn()

        _ok, message = block_email_action_fn(email, reason, delta)
        flash(message, "success")
        return admin_security_redirect_fn()

    @app.route('/admin/seguridad/block/ip', methods=['POST'])
    @login_required
    @admin_required(permission="view_security")
    def admin_security_block_ip():
        if not security_can_manage_actions_fn(current_user):
            flash("No tienes permisos para ejecutar acciones de seguridad.", "error")
            return admin_security_redirect_fn()

        ip = normalize_ip_fn(request.form.get("ip"))
        reason = (request.form.get("reason") or "").strip()
        delta = security_duration_delta_fn(request.form.get("duration_value"), request.form.get("duration_unit"))

        if not ip:
            flash("Debes ingresar una IP valida para bloquear.", "error")
            return admin_security_redirect_fn()
        if not delta:
            flash("Duracion invalida para bloqueo de IP.", "error")
            return admin_security_redirect_fn()

        _ok, message = block_ip_action_fn(ip, reason, delta)
        flash(message, "success")
        return admin_security_redirect_fn()

    @app.route('/admin/seguridad/block/remove/<int:block_id>', methods=['POST'])
    @login_required
    @admin_required(permission="view_security")
    def admin_security_remove_block(block_id):
        if not security_can_manage_actions_fn(current_user):
            flash("No tienes permisos para ejecutar acciones de seguridad.", "error")
            return admin_security_redirect_fn()
        ok, message = remove_security_block_action_fn(block_id)
        flash(message, "success" if ok else "error")
        return admin_security_redirect_fn()

    @app.route('/admin/seguridad/force_logout', methods=['POST'])
    @login_required
    @admin_required(permission="view_security")
    def admin_security_force_logout():
        if not security_can_manage_actions_fn(current_user):
            flash("No tienes permisos para ejecutar acciones de seguridad.", "error")
            return admin_security_redirect_fn()

        email = normalize_email_fn(request.form.get("email"))
        if not email:
            flash("Debes ingresar un correo para cierre forzado.", "error")
            return admin_security_redirect_fn()
        ok, message = force_logout_action_fn(email)
        flash(message, "success" if ok else "error")
        return admin_security_redirect_fn()

    @app.route('/admin/reportes')
    @login_required
    @admin_required(permission="export_reports")
    def admin_reports_page():
        return render_template('admin_reports.html', **build_admin_reports_context_fn())

    @app.route('/admin/reportes/historial.json')
    @login_required
    @admin_required(permission="export_reports")
    def admin_reports_history_json():
        return jsonify({
            "success": True,
            "items": report_export_history_payload_fn(limit=20),
        })

    @app.route('/admin/export/usuarios.xlsx')
    @login_required
    @admin_required(permission="export_reports")
    def admin_export_users_xlsx():
        response = export_users_xlsx_action_fn()
        record_report_export_action_fn(
            report_module="usuarios",
            export_format="xlsx",
            status="ok",
            detail="Exportacion XLSX de usuarios",
            rows_count=None,
        )
        return response

    @app.route('/admin/export/login_attempts.xlsx')
    @login_required
    @admin_required(permission="export_reports")
    def admin_export_login_attempts_xlsx():
        response = export_login_attempts_xlsx_action_fn()
        record_report_export_action_fn(
            report_module="seguridad",
            export_format="xlsx",
            status="ok",
            detail="Exportacion XLSX de seguridad",
            rows_count=None,
        )
        return response

    @app.route('/admin/export/auditoria.xlsx')
    @login_required
    @admin_required(permission="export_reports")
    def admin_export_audit_xlsx():
        response = export_audit_xlsx_action_fn()
        record_report_export_action_fn(
            report_module="auditoria",
            export_format="xlsx",
            status="ok",
            detail="Exportacion XLSX de auditoria",
            rows_count=None,
        )
        return response

    @app.route('/admin/export/auditoria.csv')
    @login_required
    @admin_required(permission="export_reports")
    def admin_export_audit_csv():
        response = export_audit_csv_action_fn()
        record_report_export_action_fn(
            report_module="auditoria",
            export_format="csv",
            status="ok",
            detail="Exportacion CSV de auditoria",
            rows_count=None,
        )
        return response

    @app.route('/admin/export/auditoria.pdf')
    @login_required
    @admin_required(permission="export_reports")
    def admin_export_audit_pdf():
        try:
            response = export_audit_pdf_action_fn()
            record_report_export_action_fn(
                report_module="auditoria",
                export_format="pdf",
                status="ok",
                detail="Exportacion PDF de auditoria",
                rows_count=None,
            )
            return response
        except RuntimeError as exc:
            if str(exc) != "reportlab_missing":
                raise
            record_report_export_action_fn(
                report_module="auditoria",
                export_format="pdf",
                status="error",
                detail="Fallo exportacion PDF: falta reportlab",
                rows_count=None,
            )
            flash("No se pudo generar PDF. Falta dependencia reportlab.", "error")
            return redirect(url_for("admin_logs_page"))

    @app.route('/admin/export/usuarios.json')
    @login_required
    @admin_required(permission="export_reports")
    def admin_export_users_json():
        payload = export_users_json_payload_action_fn()
        purpose = (request.args.get("purpose") or "").strip().lower()
        if purpose == "export":
            rows_count = report_payload_rows_count_fn(payload)
            record_report_export_action_fn(
                report_module="usuarios",
                export_format="pdf",
                status="ok",
                detail=f"Exportacion PDF de usuarios ({rows_count} filas)",
                rows_count=rows_count,
            )
        return jsonify(payload)

    @app.route('/admin/export/auditoria.json')
    @login_required
    @admin_required(permission="export_reports")
    def admin_export_audit_json():
        payload = export_audit_json_payload_action_fn()
        purpose = (request.args.get("purpose") or "").strip().lower()
        if purpose == "export":
            rows_count = report_payload_rows_count_fn(payload)
            record_report_export_action_fn(
                report_module="auditoria",
                export_format="pdf",
                status="ok",
                detail=f"Exportacion PDF de auditoria ({rows_count} filas)",
                rows_count=rows_count,
            )
        return jsonify(payload)

    @app.route('/admin/export/seguridad.json')
    @login_required
    @admin_required(permission="export_reports")
    def admin_export_security_json():
        payload = export_security_json_payload_action_fn()
        purpose = (request.args.get("purpose") or "").strip().lower()
        if purpose == "export":
            rows_count = report_payload_rows_count_fn(payload)
            record_report_export_action_fn(
                report_module="seguridad",
                export_format="pdf",
                status="ok",
                detail=f"Exportacion PDF de seguridad ({rows_count} filas)",
                rows_count=rows_count,
            )
        return jsonify(payload)

    @app.route('/admin/grant', methods=['POST'])
    @login_required
    @admin_required(super_only=True)
    def admin_grant():
        result = admin_grant_route_action_fn(
            email_raw=request.form.get('email'),
            role_raw=request.form.get('role'),
            requested_permissions=request.form.getlist('permissions'),
        )
        flash(result["message"], result["category"])
        return redirect(url_for('admin_admins_page'))

    @app.route('/admin/revoke/<int:user_id>', methods=['POST'])
    @login_required
    @admin_required(super_only=True)
    def admin_revoke(user_id):
        result = admin_revoke_route_action_fn(target_user_id=user_id)
        flash(result["message"], result["category"])
        return redirect(url_for('admin_admins_page'))

    @app.route('/admin/user_status/<int:user_id>', methods=['POST'])
    @login_required
    @admin_required(permission="manage_users")
    def admin_user_status(user_id):
        result = admin_user_status_route_action_fn(
            user_id=user_id,
            action_raw=request.form.get("action"),
        )
        flash(result["message"], result["category"])
        return redirect(url_for('admin_users_page'))

    @app.route('/admin/users_bulk', methods=['POST'])
    @login_required
    @admin_required(permission="manage_users")
    def admin_users_bulk():
        result = admin_users_bulk_route_action_fn(
            action_raw=request.form.get("bulk_action"),
            raw_ids=request.form.getlist("user_ids"),
        )
        if result.get("kind") == "response":
            return result["response"]
        flash(result["message"], result["category"])
        return redirect(url_for('admin_users_page'))

    @app.route('/admin/user_suspend/<int:user_id>', methods=['POST'])
    @login_required
    @admin_required(permission="manage_users")
    def admin_user_suspend(user_id):
        result = admin_user_suspend_route_action_fn(
            user_id=user_id,
            action_raw=request.form.get("action"),
            duration_value_raw=request.form.get("duration_value"),
            duration_unit_raw=request.form.get("duration_unit"),
        )
        flash(result["message"], result["category"])
        return redirect(url_for('admin_users_page'))

    @app.route('/admin/user_delete/<int:user_id>', methods=['POST'])
    @login_required
    @admin_required(super_only=True)
    def admin_user_delete(user_id):
        result = admin_user_delete_route_action_fn(user_id=user_id)
        flash(result["message"], result["category"])
        return redirect(url_for('admin_users_page'))
