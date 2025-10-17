# Usar Python 3.11 slim para menor tamaño
FROM python:3.11-slim

# Establecer directorio de trabajo
WORKDIR /app

# Variables de entorno para optimización
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Instalar dependencias del sistema necesarias
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copiar requirements.txt primero para aprovechar cache de Docker
COPY requirements.txt .

# Instalar dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el resto de archivos
COPY main.py .
COPY index.html .
COPY style.css .
COPY .env .

# Crear directorio de datos
RUN mkdir -p /app/data

# Exponer puerto del dashboard
EXPOSE 5000

# Comando para ejecutar el bot
CMD ["python", "-u", "main.py"]
