"""Helpers web reutilizables para redirecciones seguras."""

from urllib.parse import urlparse


def admin_security_redirect(request_obj, url_for_fn, redirect_fn, endpoint_name: str):
    base = url_for_fn(endpoint_name)
    candidate = (request_obj.form.get("return_to") or request_obj.referrer or "").strip()
    if not candidate:
        return redirect_fn(base)
    if candidate.startswith(base):
        return redirect_fn(candidate)
    try:
        parsed = urlparse(candidate)
    except Exception:
        parsed = None
    if parsed and parsed.path == base:
        safe = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        return redirect_fn(safe)
    return redirect_fn(base)
