"""Instancias globales de extensiones Flask.

Se inicializan con init_app(app) desde main.py para evitar acoplamiento.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail


db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()

