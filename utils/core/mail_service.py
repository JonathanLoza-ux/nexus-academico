"""Servicio de correo para reset de contrasena (dev / smtp / brevo_api)."""

import requests
from flask_mail import Message as MailMessage


def build_reset_email_html(name: str, link: str, support_email: str, support_whatsapp: str) -> str:
    return f"""
<div style="margin:0; padding:0; background:#0b1220; font-family:Segoe UI, Arial, sans-serif;">
  <div style="max-width:640px; margin:0 auto; padding:28px 16px;">

    <div style="
      background:linear-gradient(180deg,#0f172a 0%, #0b1220 100%);
      border:1px solid #1f2a44;
      border-radius:18px;
      overflow:hidden;
      box-shadow:0 12px 30px rgba(0,0,0,.35);
    ">

      <div style="padding:22px 20px; text-align:center; border-bottom:1px solid #1f2a44;">
        <div style="font-size:30px; font-weight:900; letter-spacing:1px; color:#22d3ee;">NEXUS</div>
        <div style="margin-top:6px; color:#94a3b8; font-size:13px;">Recuperacion de contrasena</div>

        <div style="margin-top:14px;">
          <span style="
            display:inline-block;
            padding:9px 14px;
            border-radius:999px;
            background:rgba(34,211,238,.08);
            border:1px solid rgba(34,211,238,.35);
            color:#cbd5e1;
            font-size:12px;
            font-weight:700;
          ">
            Enlace valido por <span style="color:#7dd3fc; font-weight:900;">20 minutos</span>
          </span>
        </div>
      </div>

      <div style="padding:22px 20px; color:#e2e8f0;">
        <p style="margin:0 0 12px 0; font-size:15px;">
          Hola <b style="color:#ffffff;">{name}</b>,
        </p>

        <p style="margin:0 0 16px 0; font-size:14px; color:#cbd5e1; line-height:1.65;">
          Recibimos una solicitud para restablecer tu contrasena. Si fuiste tu, presiona el boton:
        </p>

        <div style="text-align:center; margin:18px 0 14px 0;">
          <a href="{link}" style="
            display:inline-block;
            padding:13px 18px;
            border-radius:12px;
            background:#22d3ee;
            color:#06212a;
            text-decoration:none;
            font-weight:900;
            font-size:14px;
            box-shadow:0 10px 22px rgba(34,211,238,.20);
          ">
            Restablecer contrasena
          </a>
        </div>

        <p style="margin:0; font-size:12.5px; color:#94a3b8; line-height:1.6;">
          Si tu no hiciste esta solicitud, puedes ignorar este correo.
        </p>

        <div style="margin-top:18px; padding-top:16px; border-top:1px solid #1f2a44;">
          <div style="font-size:12px; color:#94a3b8; margin-bottom:10px;">
            Si el boton no funciona, copia y pega este enlace:
          </div>

          <div style="
            word-break:break-all;
            padding:12px 12px;
            border-radius:12px;
            background:#07101f;
            border:1px solid #1f2a44;
            color:#cbd5e1;
            font-size:12.5px;
            line-height:1.6;
          ">{link}</div>
        </div>

        <div style="margin-top:18px; padding-top:16px; border-top:1px solid #1f2a44;">
          <div style="
            display:inline-block;
            font-size:11px;
            letter-spacing:.6px;
            text-transform:uppercase;
            color:#94a3b8;
            background:#07101f;
            border:1px solid #1f2a44;
            padding:6px 10px;
            border-radius:999px;
          ">
            Soporte Nexus
          </div>

          <p style="margin:12px 0 12px 0; font-size:12.5px; color:#94a3b8; line-height:1.6;">
            Este es un correo automatico. Si necesitas ayuda, contactanos:
          </p>

          <div style="text-align:center; margin:8px 0 2px 0;">
            <a href="mailto:{support_email}" style="
              display:inline-block;
              margin:6px 6px;
              padding:10px 14px;
              border-radius:12px;
              background:#07101f;
              border:1px solid #1f2a44;
              color:#e2e8f0;
              text-decoration:none;
              font-weight:800;
              font-size:13px;
            ">Escribir a soporte</a>

            <a href="https://wa.me/{support_whatsapp}?text=Hola%20Nexus%2C%20necesito%20ayuda%20con%20mi%20cuenta." style="
              display:inline-block;
              margin:6px 6px;
              padding:10px 14px;
              border-radius:12px;
              background:#22d3ee;
              border:1px solid rgba(34,211,238,.55);
              color:#06212a;
              text-decoration:none;
              font-weight:900;
              font-size:13px;
              box-shadow:0 10px 22px rgba(34,211,238,.18);
            ">WhatsApp soporte</a>
          </div>

          <div style="text-align:center; color:#64748b; font-size:12px; margin-top:14px;">
            ? 2026 Nexus ? Seguridad de cuenta
          </div>
        </div>

      </div>
    </div>
  </div>
</div>
"""


def send_reset_link(
    email,
    name,
    link,
    mode,
    brevo_api_key,
    brevo_sender_name,
    brevo_sender_email,
    mail_client,
    log_event_fn,
    support_email,
    support_whatsapp,
):
    clean_mode = (mode or "dev").strip().lower()

    if clean_mode == "dev":
        print("\n==============================")
        print("LINK RESET (DEV):", link)
        print("==============================\n")
        log_event_fn("EMAIL_SENT", provider="dev_console", to=email, ok=True)
        return True

    if clean_mode == "brevo_api":
        try:
            subject = "Recuperacion de contrasena - Nexus"
            text_body = f"""Hola {name},

Recibimos una solicitud para restablecer tu contrasena.
Este enlace es valido por 20 minutos:

{link}

Si tu no hiciste esta solicitud, ignora este mensaje.

---
Soporte:
Correo: {support_email}
WhatsApp: https://wa.me/{support_whatsapp}
"""
            html_body = build_reset_email_html(
                name=name,
                link=link,
                support_email=support_email,
                support_whatsapp=support_whatsapp,
            )

            url = "https://api.brevo.com/v3/smtp/email"
            headers = {
                "accept": "application/json",
                "api-key": brevo_api_key,
                "content-type": "application/json",
            }
            payload = {
                "sender": {"name": brevo_sender_name, "email": brevo_sender_email},
                "to": [{"email": email, "name": name}],
                "subject": subject,
                "htmlContent": html_body,
                "textContent": text_body,
                "replyTo": {"email": support_email, "name": "Soporte Nexus"},
            }

            r = requests.post(url, headers=headers, json=payload, timeout=10)

            if 200 <= r.status_code < 300:
                log_event_fn("EMAIL_SENT", provider="brevo_api", to=email, ok=True, status=r.status_code)
                return True

            print("Error Brevo API:", r.status_code, r.text)
            print("LINK RESET (FALLBACK):", link)
            log_event_fn("EMAIL_SENT", provider="brevo_api", to=email, ok=False, status=r.status_code)
            return False

        except Exception as e:
            print("Exception Brevo API:", repr(e))
            print("LINK RESET (FALLBACK):", link)
            log_event_fn("EMAIL_SENT", provider="brevo_api", to=email, ok=False, error=str(e))
            return False

    try:
        msg = MailMessage(
            subject="Recuperacion de contrasena - Nexus",
            recipients=[email],
        )

        msg.reply_to = support_email

        msg.body = f"""Hola {name},

Recibimos una solicitud para restablecer tu contrasena.
Este enlace es valido por 20 minutos:

{link}

Si tu no hiciste esta solicitud, ignora este mensaje.
"""

        msg.html = build_reset_email_html(
            name=name,
            link=link,
            support_email=support_email,
            support_whatsapp=support_whatsapp,
        )

        mail_client.send(msg)
        log_event_fn("EMAIL_SENT", provider="smtp", to=email, ok=True)
        return True

    except Exception as e:
        print("Error enviando correo (SMTP/Brevo):", repr(e))
        print("LINK RESET (FALLBACK DEV):", link)
        log_event_fn("EMAIL_SENT", provider="smtp", to=email, ok=False, error=str(e))
        return True
