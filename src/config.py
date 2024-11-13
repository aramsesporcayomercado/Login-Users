import os

SECRET_KEY = os.getenv("SECRET_KEY",  "zerotwo")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Token expirará en 30 minutos

# Configuración de la base de datos
MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")  # Host de la base de datos
MYSQL_USER = os.getenv("MYSQL_USER", "root")       # Usuario de la base de datos
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")    # Contraseña de la base de datos (vacía)
MYSQL_DB = os.getenv("MYSQL_DB", "prueb2")          # Nombre de la base de datos