"""Helpers para enlaces de soporte y estado de UI en login."""

from urllib.parse import urlencode


def set_login_help_mode(session_obj, mode: str = "", email_hint: str = ""):
    """
    mode:
      - forgot: mostrar solo enlace de recuperacion
      - support: mostrar solo enlace de soporte
      - otro/empty: ocultar ambos
    """
    mode = (mode or "").strip().lower()
    email_hint = (email_hint or "").strip().lower()

    if mode == "forgot":
        session_obj["show_forgot"] = True
        session_obj["show_inactive_support"] = False
        session_obj.pop("support_email_hint", None)
        return

    if mode == "support":
        session_obj["show_forgot"] = False
        session_obj["show_inactive_support"] = True
        if email_hint:
            session_obj["support_email_hint"] = email_hint
        return

    session_obj.pop("show_forgot", None)
    session_obj.pop("show_inactive_support", None)
    session_obj.pop("support_email_hint", None)


def build_support_whatsapp_link(session_obj, support_whatsapp: str) -> str:
    clean_phone = (support_whatsapp or "").strip().replace("+", "")
    if not clean_phone:
        return ""

    base = f"https://wa.me/{clean_phone}"
    email_hint = (session_obj.get("support_email_hint") or "").strip()
    msg = "Hola, necesito ayuda con mi cuenta de Nexus."
    if email_hint:
        msg += f" Mi correo es: {email_hint}."
    msg += " Me aparece como desactivada."
    return f"{base}?{urlencode({'text': msg})}"
