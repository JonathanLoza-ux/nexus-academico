"""Configuracion compartida para bootstrap de la app."""

import os


def normalize_database_url(url: str) -> str:
    """
    Normaliza DATABASE_URL para SQLAlchemy + PyMySQL.
    Mantiene intactas URLs ya compatibles.
    """
    clean = (url or "").strip()
    if clean.startswith("mysql://"):
        return "mysql+pymysql://" + clean[len("mysql://"):]
    return clean


def apply_runtime_config(app, environment: str):
    """Config base de cookies/scheme para ejecucion local/prod."""
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = (environment == "prod")

    server_name = (os.getenv("SERVER_NAME") or "").strip()
    if server_name:
        app.config["SERVER_NAME"] = server_name

    if environment == "prod":
        app.config["PREFERRED_URL_SCHEME"] = "https"


def load_mail_settings():
    """Lee SMTP desde variables de entorno y devuelve un dict normalizado."""
    username = (os.getenv("MAIL_USERNAME") or "").strip()
    timeout_raw = (os.getenv("MAIL_TIMEOUT") or "10").strip()
    return {
        "MAIL_SERVER": (os.getenv("MAIL_SERVER") or "").strip(),
        "MAIL_PORT": int((os.getenv("MAIL_PORT") or "587").strip()),
        "MAIL_USE_TLS": (os.getenv("MAIL_USE_TLS") or "1").strip() == "1",
        "MAIL_USERNAME": username,
        "MAIL_PASSWORD": (os.getenv("MAIL_PASSWORD") or "").strip(),
        "MAIL_DEFAULT_SENDER": (os.getenv("MAIL_DEFAULT_SENDER") or username).strip(),
        "MAIL_TIMEOUT": int(timeout_raw),
    }


def apply_mail_config(app, mail_settings: dict):
    """Aplica config SMTP en app.config."""
    app.config["MAIL_SERVER"] = mail_settings["MAIL_SERVER"]
    app.config["MAIL_PORT"] = mail_settings["MAIL_PORT"]
    app.config["MAIL_USE_TLS"] = mail_settings["MAIL_USE_TLS"]
    app.config["MAIL_USERNAME"] = mail_settings["MAIL_USERNAME"]
    app.config["MAIL_PASSWORD"] = mail_settings["MAIL_PASSWORD"]
    app.config["MAIL_DEFAULT_SENDER"] = mail_settings["MAIL_DEFAULT_SENDER"]
    app.config["MAIL_TIMEOUT"] = mail_settings["MAIL_TIMEOUT"]


def apply_sqlalchemy_config(app, database_url_raw: str):
    """Aplica config de SQLAlchemy y devuelve URI normalizada."""
    uri_db = normalize_database_url(database_url_raw)
    app.config["SQLALCHEMY_DATABASE_URI"] = uri_db
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
        "pool_recycle": 280,
        "connect_args": {"connect_timeout": 10},
    }
    return uri_db
