# Usamos Python 3.10
FROM python:3.10-slim

# Directorio de trabajo
WORKDIR /app

# Instalamos dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install gunicorn

# Copiamos todo el proyecto
COPY . .

# Puerto para Hugging Face (lo definimos como 8080 en el README)
ENV PORT=8080
EXPOSE 8080

# Comando de arranque estable
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "main:app"]