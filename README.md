# 🛡️ AEC Anti-links Bot

<div align="center">

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![Discord.py](https://img.shields.io/badge/discord.py-2.3.0+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-purple.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

**Sistema avanzado de protección contra enlaces maliciosos para Discord**

[Características](#-características) • [Instalación](#-instalación) • [Comandos](#-comandos) • [Seguridad](#-seguridad) • [Soporte](#-soporte)

</div>

---

## 📋 Descripción

**AEC Anti-links** es un bot de Discord desarrollado en Python que proporciona protección avanzada contra enlaces maliciosos, spam y técnicas de evasión. Utiliza detección inteligente con múltiples patrones, base de datos actualizada automáticamente y sistema de logs completo.

### ✨ ¿Por qué AEC Anti-links?

- 🔒 **Seguridad Total**: Detecta 9+ tipos diferentes de enlaces, incluyendo técnicas de bypass
- 🌐 **Base de Datos Gratuita**: Actualización automática desde URLhaus con miles de sitios maliciosos
- ⚙️ **Altamente Configurable**: Whitelist, blacklist personalizada, roles permitidos y más
- 📊 **Sistema de Logs**: Registro detallado de todas las infracciones
- 🚀 **Fácil de Usar**: Comandos slash intuitivos en español
- 🎉 **Easter Egg Incluido**: Descubre el secreto del Galaxy A06

---

## 🚀 Características

### Detección Avanzada de Enlaces

El bot detecta los siguientes tipos de enlaces:

- ✅ URLs con protocolo (http/https)
- ✅ URLs sin protocolo (www.ejemplo.com)
- ✅ Links enmascarados en Markdown `[texto](url)`
- ✅ Caracteres Unicode sospechosos (bypass común: h‌t‌t‌p‌s://ejemplo.com)
- ✅ Links con espacios insertados (h t t p s : / / ejemplo.com)
- ✅ "Dot com" escrito (ejemplo dot com)
- ✅ Invitaciones de Discord (discord.gg/xyz)
- ✅ URLs acortadas (bit.ly, tinyurl.com, etc.)
- ✅ Direcciones IP directas (192.168.1.1)

### Sistema de Protección

- 🛡️ **Muteo automático** configurable por servidor
- 📈 **Muteo progresivo** para reincidentes
- 👮 **Inmunidad para administradores**
- 🎭 **Sistema de roles permitidos**
- 📝 **Registro completo** en canal de logs
- ⚡ **Rate limiting** anti-spam en comandos

### Personalización

- 🔒 **Blacklist personalizada** por servidor
- ✅ **Whitelist de dominios** siempre permitidos
- 📁 **Importación masiva** desde archivos .txt
- ⏱️ **Tiempo de muteo** configurable (1 min - 28 días)

---

## 📦 Requisitos Previos

Antes de instalar el bot, asegúrate de tener:

- **Python 3.8 o superior** instalado ([Descargar Python](https://www.python.org/downloads/))
- **pip** (gestor de paquetes de Python)
- **Git** (opcional, para clonar el repositorio)
- Una cuenta de **Discord**
- Permisos de **administrador** en el servidor donde lo usarás

---

## 🔧 Instalación

### Paso 1: Descargar el Bot

Opción A - Con Git:
```

git clone https://github.com/asus1m415da/AEC-Anti-links.git
cd aec-antilinks-bot

```

Opción B - Descarga manual:
1. Descarga el archivo `main.py`
2. Crea una carpeta para el proyecto
3. Coloca `main.py` dentro

### Paso 2: Instalar Dependencias

```

pip install discord.py python-dotenv aiohttp

```

O usando el archivo `requirements.txt`:
```

pip install -r requirements.txt

```

### Paso 3: Crear el Bot en Discord

1. Ve al [Portal de Desarrolladores de Discord](https://discord.com/developers/applications)
2. Haz clic en **"New Application"**
3. Dale un nombre a tu aplicación (ej: "AEC Anti-links")
4. Ve a la sección **"Bot"** en el menú lateral
5. Haz clic en **"Add Bot"** y confirma

### Paso 4: Configurar Intents

En la sección **Bot**, activa los siguientes **Privileged Gateway Intents**:

- ✅ **SERVER MEMBERS INTENT**
- ✅ **MESSAGE CONTENT INTENT**
- ✅ **PRESENCE INTENT** (opcional)

### Paso 5: Obtener el Token

1. En la sección **Bot**, haz clic en **"Reset Token"**
2. Copia el token generado (¡guárdalo de forma segura!)

### Paso 6: Configurar Variables de Entorno

Crea un archivo llamado `.env` en la carpeta del bot:

```


# Windows

notepad .env

# Linux/Mac

nano .env

```

Agrega el siguiente contenido (reemplaza con tus datos):

```


# Token del bot de Discord

DISCORD_TOKEN=tu_token_aqui_copiado_del_portal

# Tu ID de Discord (haz clic derecho en tu perfil con modo desarrollador activo)

OWNER_ID=123456789012345678

# Modo de depuración (opcional)

DEBUG_MODE=False

```

### Paso 7: Invitar el Bot a tu Servidor

1. Ve a **OAuth2 > URL Generator** en el Portal de Desarrolladores
2. Selecciona los siguientes **scopes**:
   - ✅ `bot`
   - ✅ `applications.commands`

3. Selecciona los siguientes **permisos**:
   - ✅ Moderate Members (Timeout Members)
   - ✅ Manage Messages
   - ✅ Send Messages
   - ✅ Embed Links
   - ✅ Read Message History
   - ✅ Use Slash Commands

4. Copia la URL generada y ábrela en tu navegador
5. Selecciona tu servidor y autoriza el bot

### Paso 8: Ejecutar el Bot

```

python main.py

```

Si todo está correcto, verás:

```

==================================================
🛡️  AEC ANTI-LINKS BOT v2.0
==================================================
🔐 Sistema de Seguridad: ACTIVO
📊 Detección Avanzada: 11 patrones
🔒 Caracteres Unicode Monitoreados: 20
==================================================
🚀 Iniciando bot...

✅ Bot AECAntiLinks\#1234 conectado correctamente
🛡️ AEC Anti-links activo en 1 servidores
🔒 12547 sitios maliciosos en base de datos

```

---

## 📚 Comandos

### Configuración Básica

| Comando | Descripción | Ejemplo |
|---------|-------------|---------|
| `/configurar_logs` | Define el canal donde se registrarán las infracciones | `/configurar_logs #logs` |
| `/configurar_tiempo_muteo` | Establece la duración del muteo en segundos | `/configurar_tiempo_muteo 600` |
| `/activar_antilinks` | Activa el sistema de protección | `/activar_antilinks` |
| `/desactivar_antilinks` | Desactiva temporalmente el sistema | `/desactivar_antilinks` |

### Gestión de Roles

| Comando | Descripción | Ejemplo |
|---------|-------------|---------|
| `/agregar_rol_permitido` | Permite a un rol enviar enlaces | `/agregar_rol_permitido @Moderador` |
| `/quitar_rol_permitido` | Remueve el permiso de un rol | `/quitar_rol_permitido @Moderador` |

### Dominios Personalizados

| Comando | Descripción | Ejemplo |
|---------|-------------|---------|
| `/agregar_dominio_bloqueado` | Bloquea un dominio específico | `/agregar_dominio_bloqueado ejemplo.com` |
| `/quitar_dominio_bloqueado` | Desbloquea un dominio | `/quitar_dominio_bloqueado ejemplo.com` |
| `/agregar_whitelist` | Siempre permite un dominio | `/agregar_whitelist youtube.com` |
| `/importar_sitios` | Importa lista desde archivo .txt | `/importar_sitios` (luego sube el archivo) |

### Monitoreo y Estadísticas

| Comando | Descripción | Ejemplo |
|---------|-------------|---------|
| `/ver_configuracion` | Muestra la configuración actual | `/ver_configuracion` |
| `/estadisticas` | Top 10 usuarios con más infracciones | `/estadisticas` |
| `/limpiar_infracciones` | Limpia el historial de un usuario | `/limpiar_infracciones @Usuario` |
| `/probar_detector` | Prueba la detección con un texto | `/probar_detector http://ejemplo.com` |

### Extras

| Comando | Descripción | Ejemplo |
|---------|-------------|---------|
| `/ayuda_antilinks` | Muestra todos los comandos disponibles | `/ayuda_antilinks` |
| `/galaxya06` | 🎉 Easter Egg del Samsung Galaxy A06 | `/galaxya06` |

---

## 🔐 Seguridad

### Protección de Tokens

- ✅ Token almacenado en archivo `.env` (nunca en el código fuente)
- ✅ Validación automática al inicio del bot
- ✅ Archivo `.gitignore` incluido para prevenir commits accidentales
- ✅ Ejemplo de configuración en `.env.example`

### Sanitización de Entradas

- ✅ Todas las entradas de usuario son sanitizadas
- ✅ Límite de caracteres en inputs
- ✅ Eliminación de caracteres de control peligrosos
- ✅ Validación de formatos (dominios, URLs, etc.)

### Rate Limiting

- ✅ Anti-spam en comandos (cooldown configurable)
- ✅ Límites en importación de sitios (10,000 máximo)
- ✅ Límites en roles permitidos (10 máximo)
- ✅ Límites en dominios personalizados (500 por servidor)

### Base de Datos de Malware

El bot utiliza **URLhaus API** de abuse.ch:
- 🆓 Completamente gratuita
- 🔄 Actualización automática cada hora
- 🌐 Miles de URLs maliciosas activas
- 📊 Datos verificados por la comunidad de seguridad

---

## 📁 Estructura del Proyecto

```

aec-antilinks-bot/
│
├── main.py                 \# Código principal del bot
├── .env                    \# Variables de entorno (NO SUBIR A GIT)
├── .env.example            \# Ejemplo de configuración
├── .gitignore              \# Archivos ignorados por Git
├── requirements.txt        \# Dependencias de Python
└── README.md              \# Este archivo

```

---

## 🎉 Easter Egg - Galaxy A06

El bot incluye un Easter Egg dedicado al **Samsung Galaxy A06**. Usa el comando `/galaxya06` para descubrir:

- 📱 Especificaciones completas del dispositivo
- ✨ Características especiales
- 🎁 Bonus secreto para tu servidor

**Especificaciones del Galaxy A06:**
- Pantalla: 6.7" HD+ (1600x720)
- Procesador: MediaTek Helio G85
- RAM: 4GB/6GB
- Almacenamiento: 64GB/128GB
- Cámara: 50MP + 2MP
- Batería: 5000 mAh con carga rápida 25W
- Sistema: Android 14 con One UI 6.1

---

## 🛠️ Configuración Recomendada

### Para Servidores Pequeños (< 100 miembros)

```

/configurar_tiempo_muteo 300        \# 5 minutos
/activar_antilinks
/configurar_logs \#logs

```

### Para Servidores Medianos (100-1000 miembros)

```

/configurar_tiempo_muteo 600        \# 10 minutos
/agregar_rol_permitido @Moderador
/agregar_whitelist youtube.com
/agregar_whitelist discord.gg
/activar_antilinks
/configurar_logs \#mod-logs

```

### Para Servidores Grandes (> 1000 miembros)

```

/configurar_tiempo_muteo 1800       \# 30 minutos
/agregar_rol_permitido @Staff
/agregar_rol_permitido @VIP
/agregar_whitelist youtube.com
/agregar_whitelist discord.gg
/agregar_whitelist twitch.tv
/importar_sitios                    \# Importa tu lista personalizada
/activar_antilinks
/configurar_logs \#security-logs

```

---

## 🐛 Solución de Problemas

### El bot no responde

1. Verifica que el bot tenga los permisos necesarios
2. Revisa que los intents estén activados en el Portal de Desarrolladores
3. Comprueba que el token en `.env` sea correcto

### Los enlaces no se detectan

1. Verifica que el bot tenga permiso para **leer mensajes**
2. Asegúrate de que el sistema esté activado (`/activar_antilinks`)
3. Comprueba que el usuario no sea administrador o tenga un rol permitido

### Error al mutear usuarios

1. El bot necesita el permiso **"Moderate Members"**
2. La jerarquía del rol del bot debe ser superior al del usuario a mutear
3. No se puede mutear al propietario del servidor

### Error al importar

```

FileNotFoundError: [Errno 2] No such file or directory: '.env'

```

**Solución**: Crea el archivo `.env` con tu token:
```

echo "DISCORD_TOKEN=tu_token_aqui" > .env

```

---

## 📊 Características Avanzadas

### Detección de Bypass

El bot detecta las siguientes técnicas de evasión:

1. **Unicode Zero-Width**: Caracteres invisibles entre letras
2. **Homóglifos**: Caracteres que se ven iguales pero son diferentes
3. **Markdown Abuse**: Uso de formato para ocultar enlaces
4. **Espaciado**: Insertar espacios en la URL
5. **Dot Spelling**: Escribir "punto" o "dot" en lugar de "."

### Sistema de Muteo Progresivo

El tiempo de muteo aumenta automáticamente para reincidentes:

| Infracciones | Tiempo de Muteo |
|--------------|-----------------|
| 1-3 | Tiempo configurado |
| 4-6 | Tiempo x2 |
| 7-10 | Tiempo x3 |
| 10+ | Tiempo x4 (máx 28 días) |

---

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Si quieres mejorar el bot:

1. Haz un Fork del proyecto
2. Crea una rama para tu característica (`git checkout -b feature/NuevaCaracteristica`)
3. Commit tus cambios (`git commit -m 'Agregar nueva característica'`)
4. Push a la rama (`git push origin feature/NuevaCaracteristica`)
5. Abre un Pull Request

---

## 📝 Licencia

Este proyecto está bajo la Licencia MIT. Consulta el archivo `LICENSE` para más detalles.

```

MIT License

Copyright (c) 2025 AEC

Se concede permiso, de forma gratuita, a cualquier persona que obtenga una copia
de este software y archivos de documentación asociados (el "Software"), para
utilizar el Software sin restricciones, incluyendo sin limitación los derechos
de usar, copiar, modificar, fusionar, publicar, distribuir, sublicenciar, y/o
vender copias del Software.

```

---

## 📈 Roadmap

Características planeadas para futuras versiones:

- [ ] Dashboard web para configuración
- [ ] Sistema de reportes automáticos
- [ ] Integración con VirusTotal API
- [ ] Machine Learning para detección predictiva
- [ ] Soporte multi-idioma
- [ ] Base de datos persistente (SQLite/PostgreSQL)
- [ ] Sistema de reputación de usuarios
- [ ] Alertas por webhook

---

## 🌟 Estrellas en el Tiempo

Si este proyecto te fue útil, ¡considera darle una estrella ⭐ en GitHub!

---

<div align="center">

**Desarrollado con ❤️ por AEC**

**AEC Anti-links Bot v2.0** | 2025

[⬆ Volver arriba](#-aec-anti-links-bot)

</div>
