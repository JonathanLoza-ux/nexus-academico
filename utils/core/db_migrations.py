"""Migraciones ligeras de columnas para compatibilidad de despliegue."""

from sqlalchemy import inspect, text

from extensions import db


def ensure_user_created_at_column():
    try:
        inspector = inspect(db.engine)
        cols = {c["name"] for c in inspector.get_columns("user")}
        if "created_at" in cols:
            return False

        dialect = (db.engine.dialect.name or "").lower()
        if dialect in ("mysql", "mariadb"):
            db.session.execute(text("ALTER TABLE `user` ADD COLUMN created_at DATETIME NULL"))
            db.session.execute(text("UPDATE `user` SET created_at = UTC_TIMESTAMP() WHERE created_at IS NULL"))
        elif dialect == "sqlite":
            db.session.execute(text('ALTER TABLE "user" ADD COLUMN created_at DATETIME'))
            db.session.execute(text('UPDATE "user" SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL'))
        else:
            db.session.execute(text('ALTER TABLE "user" ADD COLUMN created_at TIMESTAMP NULL'))
            db.session.execute(text('UPDATE "user" SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL'))

        db.session.commit()
        print("Migracion aplicada: user.created_at agregado y rellenado para usuarios existentes.")
        return True
    except Exception as e:
        db.session.rollback()
        print(f"No se pudo aplicar migracion user.created_at: {e}")
        return False


def ensure_user_is_active_account_column():
    try:
        inspector = inspect(db.engine)
        cols = {c["name"] for c in inspector.get_columns("user")}
        if "is_active_account" in cols:
            return False

        dialect = (db.engine.dialect.name or "").lower()
        if dialect in ("mysql", "mariadb"):
            db.session.execute(
                text("ALTER TABLE `user` ADD COLUMN is_active_account TINYINT(1) NOT NULL DEFAULT 1")
            )
            db.session.execute(
                text("UPDATE `user` SET is_active_account = 1 WHERE is_active_account IS NULL")
            )
        elif dialect == "sqlite":
            db.session.execute(
                text('ALTER TABLE "user" ADD COLUMN is_active_account BOOLEAN NOT NULL DEFAULT 1')
            )
            db.session.execute(
                text('UPDATE "user" SET is_active_account = 1 WHERE is_active_account IS NULL')
            )
        else:
            db.session.execute(
                text('ALTER TABLE "user" ADD COLUMN is_active_account BOOLEAN NOT NULL DEFAULT TRUE')
            )
            db.session.execute(
                text('UPDATE "user" SET is_active_account = TRUE WHERE is_active_account IS NULL')
            )

        db.session.commit()
        print("Migracion aplicada: user.is_active_account agregado y rellenado.")
        return True
    except Exception as e:
        db.session.rollback()
        print(f"No se pudo aplicar migracion user.is_active_account: {e}")
        return False


def ensure_user_suspended_until_column():
    try:
        inspector = inspect(db.engine)
        cols = {c["name"] for c in inspector.get_columns("user")}
        if "suspended_until" in cols:
            return False

        dialect = (db.engine.dialect.name or "").lower()
        if dialect in ("mysql", "mariadb"):
            db.session.execute(text("ALTER TABLE `user` ADD COLUMN suspended_until DATETIME NULL"))
        elif dialect == "sqlite":
            db.session.execute(text('ALTER TABLE "user" ADD COLUMN suspended_until DATETIME'))
        else:
            db.session.execute(text('ALTER TABLE "user" ADD COLUMN suspended_until TIMESTAMP NULL'))

        db.session.commit()
        print("Migracion aplicada: user.suspended_until agregado.")
        return True
    except Exception as e:
        db.session.rollback()
        print(f"No se pudo aplicar migracion user.suspended_until: {e}")
        return False
