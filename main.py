import discord
from discord import app_commands
from discord.ext import commands, tasks
import json
import re
import aiohttp
import asyncio
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from typing import Set, List, Tuple
import hashlib

# Cargar variables de entorno de forma segura
load_dotenv()

# ============ CONFIGURACIÓN DE SEGURIDAD ============

class SecurityConfig:
    """Clase de seguridad centralizada"""
    
    # Token protegido desde archivo .env
    TOKEN = os.getenv("DISCORD_TOKEN")
    OWNER_ID = int(os.getenv("OWNER_ID", "0"))
    
    # Límites de seguridad
    MAX_MUTEO = 2419200  # 28 días máximo
    MIN_MUTEO = 60       # 1 minuto mínimo
    MAX_ROLES_PERMITIDOS = 10
    MAX_IMPORTACION_SITIOS = 10000
    
    # Caracteres Unicode sospechosos para bypass
    CARACTERES_UNICODE_SOSPECHOSOS = {
        # Similares a /
        '╱', '⁄', '∕', '⧸', '／', '᜵', '჻', '᛫', '⼁', '⼃',
        # Similares a :
        '։', '׃', '˸', '᛬', 'ː', 'ꓽ', '⁚', '⁏', '୵', '⠐',
        # Similares a .
        '․', '‥', '⋯', '…', '܁', '܂', '。', '·',
        # Espacios invisibles
        '\u200b', '\u200c', '\u200d', '\ufeff', '\u2060',
    }
    
    @staticmethod
    def validar_token():
        """Valida que el token esté configurado correctamente"""
        if not SecurityConfig.TOKEN or len(SecurityConfig.TOKEN) < 50:
            raise ValueError(
                "❌ ERROR CRÍTICO: Token de Discord no configurado.\n"
                "Crea un archivo .env con:\n"
                "DISCORD_TOKEN=tu_token_aqui\n"
                "OWNER_ID=tu_id_aqui"
            )
        return True
    
    @staticmethod
    def sanitizar_entrada(texto: str, max_len: int = 2000) -> str:
        """Limpia y valida entrada del usuario para prevenir inyecciones"""
        if not texto:
            return ""
        # Limitar longitud
        texto = texto[:max_len]
        # Remover caracteres de control peligrosos
        texto = ''.join(char for char in texto if ord(char) >= 32 or char in '\n\t')
        return texto

# ============ DETECTOR AVANZADO DE LINKS ============

class AdvancedLinkDetector:
    """Detector avanzado con protección contra bypass y enmascaramiento"""
    
    def __init__(self):
        self.patrones = self._compilar_patrones()
        self.caracteres_sospechosos = SecurityConfig.CARACTERES_UNICODE_SOSPECHOSOS
    
    def _compilar_patrones(self) -> dict:
        """Compila todos los patrones de detección"""
        return {
            # URLs con protocolo
            'url_protocolo': re.compile(
                r'https?://(?:[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=]|%[0-9a-fA-F]{2})+',
                re.IGNORECASE
            ),
            
            # URLs sin protocolo pero con www
            'url_www': re.compile(
                r'www\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(?:[/?#][^\s]*)?',
                re.IGNORECASE
            ),
            
            # Dominios completos sin protocolo
            'dominio_completo': re.compile(
                r'\b[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
                r'(?:\.[a-zA-Z]{2,})+(?:/[^\s]*)?',
                re.IGNORECASE
            ),
            
            # Links enmascarados en Markdown [texto](url)
            'markdown_link': re.compile(
                r'\[([^\]]+)\]\(([^)]+)\)'
            ),
            
            # Invitaciones de Discord
            'discord_invite': re.compile(
                r'(?:discord\.gg|discord\.com/invite|discordapp\.com/invite)/[a-zA-Z0-9\-]+',
                re.IGNORECASE
            ),
            
            # URLs acortadas
            'url_corta': re.compile(
                r'\b(?:bit\.ly|tinyurl\.com|goo\.gl|ow\.ly|short\.io|t\.co|'
                r'is\.gd|buff\.ly|adf\.ly|bc\.vc)/[a-zA-Z0-9]+',
                re.IGNORECASE
            ),
            
            # IPs directas (IPv4)
            'ipv4': re.compile(
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b(?::[0-9]+)?(?:/[^\s]*)?'
            ),
            
            # Links con espacios insertados (ej: "h t t p s : / / google.com")
            'espacios_insertados': re.compile(
                r'h\s*t\s*t\s*p\s*s?\s*:\s*[/\s]*\s*[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+',
                re.IGNORECASE
            ),
            
            # Detección de dot/com escrito (ej: "google dot com")
            'dot_com_escrito': re.compile(
                r'\b[a-z0-9\-]+\s+(?:dot|punto)\s+(?:com|net|org|io|gg|xyz)',
                re.IGNORECASE
            ),
        }
    
    def limpiar_markdown(self, texto: str) -> str:
        """Elimina formato Markdown para detectar links ocultos"""
        # Eliminar bold, italic, underline, strikethrough, spoilers
        texto = re.sub(r'\*\*([^*]+)\*\*', r'\1', texto)  # Bold
        texto = re.sub(r'__([^_]+)__', r'\1', texto)      # Bold
        texto = re.sub(r'\*([^*]+)\*', r'\1', texto)      # Italic
        texto = re.sub(r'_([^_]+)_', r'\1', texto)        # Italic
        texto = re.sub(r'~~([^~]+)~~', r'\1', texto)      # Strikethrough
        texto = re.sub(r'\|\|([^|]+)\|\|', r'\1', texto)  # Spoilers
        texto = re.sub(r'`([^`]+)`', r'\1', texto)        # Code
        return texto
    
    def normalizar_unicode(self, texto: str) -> str:
        """Normaliza caracteres Unicode sospechosos"""
        for char in self.caracteres_sospechosos:
            if char in {'╱', '⁄', '∕', '⧸', '／', '᜵', '჻', '᛫', '⼁', '⼃'}:
                texto = texto.replace(char, '/')
            elif char in {'։', '׃', '˸', '᛬', 'ː', 'ꓽ', '⁚', '⁏', '୵', '⠐'}:
                texto = texto.replace(char, ':')
            elif char in {'․', '‥', '⋯', '…', '܁', '܂', '。', '·'}:
                texto = texto.replace(char, '.')
            else:
                # Eliminar espacios invisibles
                texto = texto.replace(char, '')
        return texto
    
    def detectar_todas_urls(self, texto: str) -> List[Tuple[str, str]]:
        """
        Detecta TODAS las URLs incluyendo técnicas de bypass
        Retorna: Lista de tuplas (url, tipo_deteccion)
        """
        urls_encontradas = []
        texto_original = texto
        
        # Paso 1: Limpiar markdown
        texto_limpio = self.limpiar_markdown(texto)
        
        # Paso 2: Normalizar Unicode
        texto_normalizado = self.normalizar_unicode(texto_limpio)
        
        # Paso 3: Detectar links enmascarados en markdown
        for match in self.patrones['markdown_link'].finditer(texto_original):
            texto_visible = match.group(1)
            url_real = match.group(2)
            urls_encontradas.append((url_real, "LINK_ENMASCARADO"))
        
        # Paso 4: URLs con protocolo
        for match in self.patrones['url_protocolo'].finditer(texto_normalizado):
            url = match.group(0)
            if not any(u[0] == url for u in urls_encontradas):
                urls_encontradas.append((url, "URL_PROTOCOLO"))
        
        # Paso 5: URLs con www
        for match in self.patrones['url_www'].finditer(texto_normalizado):
            url = match.group(0)
            if not any(u[0] == url for u in urls_encontradas):
                urls_encontradas.append((url, "URL_WWW"))
        
        # Paso 6: Invitaciones de Discord
        for match in self.patrones['discord_invite'].finditer(texto_normalizado):
            urls_encontradas.append((match.group(0), "DISCORD_INVITE"))
        
        # Paso 7: URLs acortadas
        for match in self.patrones['url_corta'].finditer(texto_normalizado):
            urls_encontradas.append((match.group(0), "URL_ACORTADA"))
        
        # Paso 8: IPs directas
        for match in self.patrones['ipv4'].finditer(texto_normalizado):
            urls_encontradas.append((match.group(0), "IP_ADDRESS"))
        
        # Paso 9: Links con espacios insertados
        for match in self.patrones['espacios_insertados'].finditer(texto_normalizado):
            url = match.group(0).replace(' ', '')
            urls_encontradas.append((url, "URL_ESPACIADA"))
        
        # Paso 10: "dot com" escrito
        for match in self.patrones['dot_com_escrito'].finditer(texto_normalizado):
            url = match.group(0).replace(' dot ', '.').replace(' punto ', '.')
            urls_encontradas.append((url, "DOT_COM_ESCRITO"))
        
        # Paso 11: Dominios completos (última verificación)
        for match in self.patrones['dominio_completo'].finditer(texto_normalizado):
            url = match.group(0)
            # Evitar falsos positivos (archivos, etc)
            if '.' in url and len(url) > 5:
                # Verificar que tenga al menos una TLD válida
                tld = url.split('.')[-1].split('/')[0].split('?')[0]
                if len(tld) >= 2 and not any(u[0] == url for u in urls_encontradas):
                    urls_encontradas.append((url, "DOMINIO_DETECTADO"))
        
        return urls_encontradas
    
    def verificar_url_maliciosa(self, url: str, sitios_bloqueados: Set[str]) -> bool:
        """Verifica si una URL está en la lista de sitios maliciosos"""
        url_limpia = url.lower()
        url_limpia = url_limpia.replace('http://', '').replace('https://', '')
        url_limpia = url_limpia.replace('www.', '').split('/')[0].split('?')[0]
        
        for sitio in sitios_bloqueados:
            if sitio in url_limpia or url_limpia in sitio:
                return True
        return False

# ============ BOT CLASS ============

class AECAntiLinks(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.members = True
        super().__init__(command_prefix="!", intents=intents)
        
        # Bases de datos en memoria
        self.config = {}
        self.infracciones = {}
        self.sitios_bloqueados = set()
        self.sitios_personalizados = {}  # Por servidor
        
        # Detector avanzado
        self.link_detector = AdvancedLinkDetector()
        
        # Rate limiting (anti-spam de comandos)
        self.command_cooldowns = {}
        
        # Easter Egg Galaxy A06
        self.galaxy_a06_activado = {}
        
    async def setup_hook(self):
        await self.tree.sync()
        self.actualizar_base_maliciosa.start()
        print("🔐 Sistema de seguridad inicializado")
        
    async def on_ready(self):
        print(f'✅ Bot {self.user} conectado correctamente')
        print(f'🛡️ AEC Anti-links activo en {len(self.guilds)} servidores')
        print(f'🔒 {len(self.sitios_bloqueados)} sitios maliciosos en base de datos')
        
        # Establecer estado del bot
        await self.change_presence(
            activity=discord.Activity(
                type=discord.ActivityType.watching,
                name="🛡️ enlaces maliciosos | /ayuda_antilinks"
            )
        )

# Inicializar bot
SecurityConfig.validar_token()
bot = AECAntiLinks()

# ============ FUNCIONES AUXILIARES ============

def get_config(guild_id):
    """Obtiene o crea configuración por servidor"""
    if str(guild_id) not in bot.config:
        bot.config[str(guild_id)] = {
            "canal_logs": None,
            "roles_permitidos": [],
            "tiempo_muteo": 300,
            "activado": True,
            "detectar_maliciosos": True,
            "modo_estricto": False,  # Bloquea incluso dominios conocidos
            "whitelist_dominios": []  # Dominios siempre permitidos
        }
    return bot.config[str(guild_id)]

def verificar_rate_limit(user_id: int, comando: str, segundos: int = 5) -> bool:
    """Sistema anti-spam para comandos"""
    ahora = datetime.utcnow()
    key = f"{user_id}:{comando}"
    
    if key in bot.command_cooldowns:
        ultimo_uso = bot.command_cooldowns[key]
        if (ahora - ultimo_uso).total_seconds() < segundos:
            return False
    
    bot.command_cooldowns[key] = ahora
    return True

# ============ ACTUALIZACIÓN DE BASE DE DATOS ============

@tasks.loop(hours=1)
async def actualizar_base_maliciosa():
    """Actualiza base de datos desde URLhaus (gratis)"""
    try:
        async with aiohttp.ClientSession() as session:
            url_api = "https://urlhaus.abuse.ch/downloads/csv_online/"
            async with session.get(url_api, timeout=30) as resp:
                if resp.status == 200:
                    contenido = await resp.text()
                    lineas = contenido.split('\n')
                    
                    sitios_nuevos = set()
                    for linea in lineas:
                        if linea.startswith('#') or not linea.strip():
                            continue
                        partes = linea.split(',')
                        if len(partes) > 2:
                            url = partes[2].strip('"')
                            dominio = url.replace('http://', '').replace('https://', '')
                            dominio = dominio.split('/')[0].replace('www.', '').lower()
                            if dominio:
                                sitios_nuevos.add(dominio)
                    
                    bot.sitios_bloqueados.update(sitios_nuevos)
                    print(f"🔄 Base actualizada: {len(bot.sitios_bloqueados)} sitios maliciosos")
                    
    except Exception as e:
        print(f"❌ Error al actualizar base: {e}")

# ============ EVENTO DE MENSAJES ============

@bot.event
async def on_message(message):
    # Ignorar bots
    if message.author.bot:
        return
    
    # Ignorar DMs
    if not message.guild:
        return
    
    config = get_config(message.guild.id)
    
    # Sistema desactivado
    if not config["activado"]:
        await bot.process_commands(message)
        return
    
    # Los administradores son inmunes
    if message.author.guild_permissions.administrator:
        await bot.process_commands(message)
        return
    
    # Verificar roles permitidos
    roles_usuario = [role.id for role in message.author.roles]
    if any(rol in config["roles_permitidos"] for rol in roles_usuario):
        await bot.process_commands(message)
        return
    
    # Sanitizar entrada
    texto_seguro = SecurityConfig.sanitizar_entrada(message.content)
    
    # Detectar URLs con sistema avanzado
    urls_detectadas = bot.link_detector.detectar_todas_urls(texto_seguro)
    
    if urls_detectadas:
        # Filtrar whitelist
        urls_filtradas = []
        for url, tipo in urls_detectadas:
            en_whitelist = False
            for dominio_permitido in config["whitelist_dominios"]:
                if dominio_permitido.lower() in url.lower():
                    en_whitelist = True
                    break
            
            if not en_whitelist:
                urls_filtradas.append((url, tipo))
        
        # Si no quedan URLs después del filtro
        if not urls_filtradas:
            await bot.process_commands(message)
            return
        
        # Verificar si alguna es maliciosa
        es_maliciosa = False
        url_maliciosa = None
        
        if config["detectar_maliciosos"]:
            todos_sitios = bot.sitios_bloqueados.copy()
            if str(message.guild.id) in bot.sitios_personalizados:
                todos_sitios.update(bot.sitios_personalizados[str(message.guild.id)])
            
            for url, tipo in urls_filtradas:
                if bot.link_detector.verificar_url_maliciosa(url, todos_sitios):
                    es_maliciosa = True
                    url_maliciosa = url
                    break
        
        # Eliminar mensaje
        try:
            await message.delete()
        except discord.errors.Forbidden:
            print(f"⚠️ No tengo permisos para eliminar mensajes en {message.guild.name}")
            await bot.process_commands(message)
            return
        
        # Registrar infracción
        user_id = str(message.author.id)
        guild_id = str(message.guild.id)
        
        if guild_id not in bot.infracciones:
            bot.infracciones[guild_id] = {}
        
        if user_id not in bot.infracciones[guild_id]:
            bot.infracciones[guild_id][user_id] = {
                "count": 0,
                "muteos": 0,
                "ultimo_muteo": None
            }
        
        bot.infracciones[guild_id][user_id]["count"] += 1
        infracciones_total = bot.infracciones[guild_id][user_id]["count"]
        
        # Aplicar muteo
        duracion = config["tiempo_muteo"]
        # Aumentar tiempo si es reincidente
        if infracciones_total > 3:
            duracion = min(duracion * infracciones_total // 2, SecurityConfig.MAX_MUTEO)
        
        timeout_hasta = discord.utils.utcnow() + timedelta(seconds=duracion)
        
        try:
            await message.author.timeout(timeout_hasta, reason="Envío de enlaces no autorizados - AEC Anti-links")
            bot.infracciones[guild_id][user_id]["muteos"] += 1
            bot.infracciones[guild_id][user_id]["ultimo_muteo"] = datetime.utcnow()
            
            # Crear embed de advertencia
            tipo_deteccion = urls_filtradas[0][1] if urls_filtradas else "DESCONOCIDO"
            
            embed_advertencia = discord.Embed(
                title="🛡️ AEC Anti-links - Protección Activa",
                description=f"{message.author.mention}, los enlaces no están permitidos en este servidor.",
                color=discord.Color.red() if es_maliciosa else discord.Color.orange()
            )
            
            embed_advertencia.add_field(
                name="🚨 Tipo de Enlace",
                value=f"**{'MALICIOSO' if es_maliciosa else tipo_deteccion}**",
                inline=True
            )
            embed_advertencia.add_field(
                name="📊 Infracción #",
                value=f"**{infracciones_total}**",
                inline=True
            )
            embed_advertencia.add_field(
                name="⏱️ Sanción",
                value=f"**{duracion//60} minutos**",
                inline=True
            )
            
            if es_maliciosa:
                embed_advertencia.add_field(
                    name="⚠️ Advertencia",
                    value=f"Este enlace ha sido identificado como **malicioso** y ha sido reportado.",
                    inline=False
                )
            
            embed_advertencia.add_field(
                name="📋 Enlaces Detectados",
                value=f"{len(urls_filtradas)} URL(s)",
                inline=True
            )
            
            embed_advertencia.set_footer(text="Para apelar contacta a un administrador")
            
            await message.channel.send(embed=embed_advertencia, delete_after=15)
            
            # Registrar en logs
            if config["canal_logs"]:
                canal_logs = bot.get_channel(config["canal_logs"])
                if canal_logs:
                    embed_log = discord.Embed(
                        title="📋 Registro de Infracción - AEC Anti-links",
                        color=discord.Color.red() if es_maliciosa else discord.Color.orange(),
                        timestamp=datetime.utcnow()
                    )
                    
                    embed_log.add_field(
                        name="👤 Usuario",
                        value=f"{message.author.mention} ({message.author.id})",
                        inline=False
                    )
                    embed_log.add_field(
                        name="📍 Canal",
                        value=message.channel.mention,
                        inline=True
                    )
                    embed_log.add_field(
                        name="📊 Infracción #",
                        value=infracciones_total,
                        inline=True
                    )
                    embed_log.add_field(
                        name="🔗 URLs Detectadas",
                        value=len(urls_filtradas),
                        inline=True
                    )
                    embed_log.add_field(
                        name="🚨 Malicioso",
                        value="✅ Sí" if es_maliciosa else "❌ No",
                        inline=True
                    )
                    embed_log.add_field(
                        name="⏱️ Duración Muteo",
                        value=f"{duracion//60} minutos",
                        inline=True
                    )
                    
                    # Mostrar tipos de detección
                    tipos = ", ".join(set([tipo for _, tipo in urls_filtradas[:3]]))
                    embed_log.add_field(
                        name="🔍 Métodos de Detección",
                        value=tipos,
                        inline=False
                    )
                    
                    # Mostrar mensaje (truncado)
                    mensaje_truncado = message.content[:500]
                    if len(message.content) > 500:
                        mensaje_truncado += "..."
                    
                    embed_log.add_field(
                        name="💬 Mensaje Original",
                        value=f"``````",
                        inline=False
                    )
                    
                    if es_maliciosa and url_maliciosa:
                        embed_log.add_field(
                            name="⚠️ URL Maliciosa Detectada",
                            value=f"||{url_maliciosa[:100]}||",
                            inline=False
                        )
                    
                    await canal_logs.send(embed=embed_log)
                    
        except discord.errors.Forbidden:
            await message.channel.send(
                f"⚠️ {message.author.mention} envió un enlace pero no tengo permisos para mutear.",
                delete_after=5
            )
        except Exception as e:
            print(f"Error al procesar infracción: {e}")
    
    await bot.process_commands(message)

# ============ COMANDOS SLASH ============

@bot.tree.command(name="configurar_logs", description="[ADMIN] Configura el canal de logs")
@app_commands.describe(canal="Canal donde se enviarán los registros")
async def configurar_logs(interaction: discord.Interaction, canal: discord.TextChannel):
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("❌ Solo administradores pueden usar este comando.", ephemeral=True)
        return
    
    config = get_config(interaction.guild.id)
    config["canal_logs"] = canal.id
    
    embed = discord.Embed(
        title="✅ Canal de Logs Configurado",
        description=f"Los registros se enviarán a {canal.mention}",
        color=discord.Color.green()
    )
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="agregar_rol_permitido", description="[ADMIN] Permite a un rol enviar enlaces")
@app_commands.describe(rol="Rol que podrá enviar enlaces")
async def agregar_rol_permitido(interaction: discord.Interaction, rol: discord.Role):
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("❌ Solo administradores.", ephemeral=True)
        return
    
    config = get_config(interaction.guild.id)
    
    if len(config["roles_permitidos"]) >= SecurityConfig.MAX_ROLES_PERMITIDOS:
        await interaction.response.send_message(
            f"❌ Límite máximo de roles permitidos alcanzado ({SecurityConfig.MAX_ROLES_PERMITIDOS}).",
            ephemeral=True
        )
        return
    
    if rol.id not in config["roles_permitidos"]:
        config["roles_permitidos"].append(rol.id)
        await interaction.response.send_message(
            f"✅ El rol {rol.mention} ahora puede enviar enlaces.",
            ephemeral=True
        )
    else:
        await interaction.response.send_message(
            f"⚠️ El rol {rol.mention} ya está permitido.",
            ephemeral=True
        )

@bot.tree.command(name="quitar_rol_permitido", description="[ADMIN] Remueve permiso de un rol")
@app_commands.describe(rol="Rol que dejará de poder enviar enlaces")
async def quitar_rol_permitido(interaction: discord.Interaction, rol: discord.Role):
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("❌ Solo administradores.", ephemeral=True)
        return
    
    config = get_config(interaction.guild.id)
    if rol.id in config["roles_permitidos"]:
        config["roles_permitidos"].remove(rol.id)
        await interaction.response.send_message(
            f"✅ El rol {rol.mention} ya no puede enviar enlaces.",
            ephemeral=True
        )
    else:
        await interaction.response.send_message(
            f"⚠️ El rol {rol.mention} no estaba en la lista.",
            ephemeral=True
        )

@bot.tree.command(name="configurar_tiempo_muteo", description="[ADMIN] Configura duración del muteo")
@app_commands.describe(segundos="Tiempo en segundos (60-2419200)")
async def configurar_tiempo_muteo(interaction: discord.Interaction, segundos: int):
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("❌ Solo administradores.", ephemeral=True)
        return
    
    if segundos < SecurityConfig.MIN_MUTEO or segundos > SecurityConfig.MAX_MUTEO:
        await interaction.response.send_message(
            f"❌ El tiempo debe estar entre {SecurityConfig.MIN_MUTEO} segundos (1 min) y "
            f"{SecurityConfig.MAX_MUTEO} segundos (28 días).",
            ephemeral=True
        )
        return
    
    config = get_config(interaction.guild.id)
    config["tiempo_muteo"] = segundos
    
    minutos = segundos // 60
    horas = minutos // 60
    dias = horas // 24
    
    tiempo_texto = f"{segundos} segundos"
    if dias > 0:
        tiempo_texto = f"{dias} días"
    elif horas > 0:
        tiempo_texto = f"{horas} horas"
    elif minutos > 0:
        tiempo_texto = f"{minutos} minutos"
    
    await interaction.response.send_message(
        f"✅ Tiempo de muteo configurado a **{tiempo_texto}**.",
        ephemeral=True
    )

@bot.tree.command(name="agregar_dominio_bloqueado", description="[ADMIN] Bloquea un dominio personalizado")
@app_commands.describe(dominio="Dominio a bloquear (ej: ejemplo.com)")
async def agregar_dominio_bloqueado(interaction: discord.Interaction, dominio: str):
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("❌ Solo administradores.", ephemeral=True)
        return
    
    # Sanitizar dominio
    dominio = SecurityConfig.sanitizar_entrada(dominio, 100).lower()
    dominio = dominio.replace('http://', '').replace('https://', '').replace('www.', '')
    dominio = dominio.split('/')[0]
    
    if not dominio or len(dominio) < 3:
        await interaction.response.send_message("❌ Dominio inválido.", ephemeral=True)
        return
    
    guild_id = str(interaction.guild.id)
    if guild_id not in bot.sitios_personalizados:
        bot.sitios_personalizados[guild_id] = set()
    
    if len(bot.sitios_personalizados[guild_id]) >= 500:
        await interaction.response.send_message("❌ Límite de dominios personalizados alcanzado (500).", ephemeral=True)
        return
    
    bot.sitios_personalizados[guild_id].add(dominio)
    
    await interaction.response.send_message(
        f"✅ Dominio **{dominio}** bloqueado exitosamente.",
        ephemeral=True
    )

@bot.tree.command(name="quitar_dominio_bloqueado", description="[ADMIN] Desbloquea un dominio personalizado")
@app_commands.describe(dominio="Dominio a desbloquear")
async def quitar_dominio_bloqueado(interaction: discord.Interaction, dominio: str):
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("❌ Solo administradores.", ephemeral=True)
        return
    
    dominio = dominio.lower().replace('http://', '').replace('https://', '').replace('www.', '').split('/')[0]
    guild_id = str(interaction.guild.id)
    
    if guild_id in bot.sitios_personalizados and dominio in bot.sitios_personalizados[guild_id]:
        bot.sitios_personalizados[guild_id].remove(dominio)
        await interaction.response.send_message(
            f"✅ Dominio **{dominio}** desbloqueado.",
            ephemeral=True
        )
    else:
        await interaction.response.send_message(
            f"⚠️ El dominio **{dominio}** no está en la lista bloqueada.",
            ephemeral=True
        )

@bot.tree.command(name="agregar_whitelist", description="[ADMIN] Permite siempre un dominio específico")
@app_commands.describe(dominio="Dominio a permitir (ej: youtube.com)")
async def agregar_whitelist(interaction: discord.Interaction, dominio: str):
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("❌ Solo administradores.", ephemeral=True)
        return
    
    dominio = SecurityConfig.sanitizar_entrada(dominio, 100).lower()
    dominio = dominio.replace('http://', '').replace('https://', '').replace('www.', '').split('/')[0]
    
    config = get_config(interaction.guild.id)
    
    if dominio not in config["whitelist_dominios"]:
        config["whitelist_dominios"].append(dominio)
        await interaction.response.send_message(
            f"✅ Dominio **{dominio}** agregado a la whitelist.",
            ephemeral=True
        )
    else:
        await interaction.response.send_message(
            f"⚠️ El dominio **{dominio}** ya está en la whitelist.",
            ephemeral=True
        )

@bot.tree.command(name="importar_sitios", description="[ADMIN] Importa sitios bloqueados desde archivo .txt")
async def importar_sitios(interaction: discord.Interaction):
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("❌ Solo administradores.", ephemeral=True)
        return
    
    await interaction.response.send_message(
        "📁 Sube un archivo .txt con los sitios a bloquear (uno por línea).\n"
        "Responde en este canal en los próximos 60 segundos.",
        ephemeral=True
    )
    
    def check(m):
        return (m.author == interaction.user and 
                m.channel == interaction.channel and 
                len(m.attachments) > 0)
    
    try:
        msg = await bot.wait_for('message', timeout=60.0, check=check)
        
        for attachment in msg.attachments:
            if attachment.filename.endswith('.txt'):
                if attachment.size > 1024 * 1024:  # 1MB máximo
                    await msg.reply("❌ Archivo demasiado grande (máximo 1MB).")
                    return
                
                contenido = await attachment.read()
                lineas = contenido.decode('utf-8').split('\n')
                
                guild_id = str(interaction.guild.id)
                if guild_id not in bot.sitios_personalizados:
                    bot.sitios_personalizados[guild_id] = set()
                
                sitios_agregados = 0
                for linea in lineas[:SecurityConfig.MAX_IMPORTACION_SITIOS]:
                    sitio = SecurityConfig.sanitizar_entrada(linea.strip(), 100).lower()
                    sitio = sitio.replace('http://', '').replace('https://', '').replace('www.', '').split('/')[0]
                    
                    if sitio and len(sitio) >= 3:
                        bot.sitios_personalizados[guild_id].add(sitio)
                        sitios_agregados += 1
                
                await msg.reply(
                    f"✅ Se han importado **{sitios_agregados}** sitios bloqueados correctamente."
                )
                return
        
        await msg.reply("❌ No se encontró ningún archivo .txt válido.")
        
    except asyncio.TimeoutError:
        await interaction.followup.send("⏰ Tiempo agotado.", ephemeral=True)

@bot.tree.command(name="activar_antilinks", description="[ADMIN] Activa el sistema anti-links")
async def activar_antilinks(interaction: discord.Interaction):
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("❌ Solo administradores.", ephemeral=True)
        return
    
    config = get_config(interaction.guild.id)
    config["activado"] = True
    await interaction.response.send_message("✅ Sistema anti-links **ACTIVADO**.", ephemeral=True)

@bot.tree.command(name="desactivar_antilinks", description="[ADMIN] Desactiva el sistema anti-links")
async def desactivar_antilinks(interaction: discord.Interaction):
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("❌ Solo administradores.", ephemeral=True)
        return
    
    config = get_config(interaction.guild.id)
    config["activado"] = False
    await interaction.response.send_message("⚠️ Sistema anti-links **DESACTIVADO**.", ephemeral=True)

@bot.tree.command(name="ver_configuracion", description="Muestra la configuración actual del bot")
async def ver_configuracion(interaction: discord.Interaction):
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("❌ Solo administradores.", ephemeral=True)
        return
    
    config = get_config(interaction.guild.id)
    guild_id = str(interaction.guild.id)
    
    canal_logs = bot.get_channel(config["canal_logs"]) if config["canal_logs"] else None
    roles_texto = ", ".join([f"<@&{rol}>" for rol in config["roles_permitidos"]]) if config["roles_permitidos"] else "Ninguno"
    
    sitios_personalizados = len(bot.sitios_personalizados.get(guild_id, set()))
    whitelist_count = len(config["whitelist_dominios"])
    
    embed = discord.Embed(
        title="⚙️ Configuración AEC Anti-links",
        description="Sistema de protección avanzada contra enlaces",
        color=discord.Color.blue()
    )
    
    embed.add_field(
        name="🟢 Estado",
        value="✅ Activado" if config["activado"] else "❌ Desactivado",
        inline=True
    )
    embed.add_field(
        name="📋 Canal de Logs",
        value=canal_logs.mention if canal_logs else "No configurado",
        inline=True
    )
    embed.add_field(
        name="⏱️ Tiempo de Muteo",
        value=f"{config['tiempo_muteo']//60} minutos",
        inline=True
    )
    embed.add_field(
        name="👥 Roles Permitidos",
        value=roles_texto,
        inline=False
    )
    embed.add_field(
        name="🌐 Sitios Bloqueados (Global)",
        value=f"{len(bot.sitios_bloqueados)} dominios",
        inline=True
    )
    embed.add_field(
        name="🔒 Sitios Bloqueados (Personalizados)",
        value=f"{sitios_personalizados} dominios",
        inline=True
    )
    embed.add_field(
        name="✅ Whitelist",
        value=f"{whitelist_count} dominios",
        inline=True
    )
    embed.add_field(
        name="🔍 Detección Maliciosa",
        value="✅ Activa" if config["detectar_maliciosos"] else "❌ Inactiva",
        inline=True
    )
    
    embed.set_footer(text="AEC Anti-links v2.0 • Sistema de Seguridad Avanzado")
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="estadisticas", description="Muestra estadísticas de infracciones")
async def estadisticas(interaction: discord.Interaction):
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("❌ Solo administradores.", ephemeral=True)
        return
    
    guild_id = str(interaction.guild.id)
    
    if guild_id not in bot.infracciones or not bot.infracciones[guild_id]:
        await interaction.response.send_message("📊 No hay estadísticas disponibles aún.", ephemeral=True)
        return
    
    infracciones_servidor = bot.infracciones[guild_id]
    usuarios_ordenados = sorted(
        infracciones_servidor.items(),
        key=lambda x: x[1]["count"],
        reverse=True
    )[:10]
    
    embed = discord.Embed(
        title="📊 Estadísticas de Infracciones",
        description=f"Top 10 usuarios con más infracciones",
        color=discord.Color.gold(),
        timestamp=datetime.utcnow()
    )
    
    descripcion = ""
    for i, (user_id, data) in enumerate(usuarios_ordenados, 1):
        try:
            usuario = await bot.fetch_user(int(user_id))
            medal = "🥇" if i == 1 else "🥈" if i == 2 else "🥉" if i == 3 else f"{i}."
            descripcion += f"{medal} {usuario.mention} - **{data['count']}** infracciones ({data['muteos']} muteos)\n"
        except:
            pass
    
    embed.description = descripcion if descripcion else "No hay datos"
    embed.set_footer(text=f"Total de usuarios con infracciones: {len(infracciones_servidor)}")
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="limpiar_infracciones", description="[ADMIN] Limpia infracciones de un usuario")
@app_commands.describe(usuario="Usuario a limpiar")
async def limpiar_infracciones(interaction: discord.Interaction, usuario: discord.Member):
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("❌ Solo administradores.", ephemeral=True)
        return
    
    guild_id = str(interaction.guild.id)
    user_id = str(usuario.id)
    
    if guild_id in bot.infracciones and user_id in bot.infracciones[guild_id]:
        infracciones = bot.infracciones[guild_id][user_id]["count"]
        del bot.infracciones[guild_id][user_id]
        await interaction.response.send_message(
            f"✅ Se limpiaron **{infracciones}** infracciones de {usuario.mention}.",
            ephemeral=True
        )
    else:
        await interaction.response.send_message(
            f"⚠️ {usuario.mention} no tiene infracciones.",
            ephemeral=True
        )

@bot.tree.command(name="probar_detector", description="Prueba el detector de enlaces con un texto")
@app_commands.describe(texto="Texto a analizar")
async def probar_detector(interaction: discord.Interaction, texto: str):
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("❌ Solo administradores.", ephemeral=True)
        return
    
    if not verificar_rate_limit(interaction.user.id, "probar_detector", 10):
        await interaction.response.send_message("⏰ Espera 10 segundos antes de usar este comando nuevamente.", ephemeral=True)
        return
    
    texto_seguro = SecurityConfig.sanitizar_entrada(texto, 500)
    urls_detectadas = bot.link_detector.detectar_todas_urls(texto_seguro)
    
    embed = discord.Embed(
        title="🔍 Resultado del Análisis",
        color=discord.Color.blue()
    )
    
    if urls_detectadas:
        embed.description = f"✅ Se detectaron **{len(urls_detectadas)}** URL(s)"
        
        for i, (url, tipo) in enumerate(urls_detectadas[:5], 1):
            embed.add_field(
                name=f"URL #{i}",
                value=f"**Tipo:** {tipo}\n**URL:** ||{url[:50]}{'...' if len(url) > 50 else ''}||",
                inline=False
            )
        
        if len(urls_detectadas) > 5:
            embed.add_field(
                name="ℹ️ Información",
                value=f"Se detectaron {len(urls_detectadas) - 5} URLs adicionales.",
                inline=False
            )
    else:
        embed.description = "❌ No se detectaron enlaces en el texto."
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

# ============ EASTER EGG GALAXY A06 ============

@bot.tree.command(name="galaxya06", description="🎉 Descubre el secreto del Galaxy A06")
async def galaxya06(interaction: discord.Interaction):
    guild_id = str(interaction.guild.id)
    
    if guild_id not in bot.galaxy_a06_activado:
        bot.galaxy_a06_activado[guild_id] = False
    
    embed = discord.Embed(
        title="📱 Samsung Galaxy A06 - Easter Egg",
        description="¡Has descubierto el secreto del Galaxy A06!",
        color=0x1428A0  # Color azul Samsung
    )
    
    embed.add_field(
        name="📊 Especificaciones",
        value=(
            "🔹 **Pantalla:** 6.7\" HD+ (1600x720)\n"
            "🔹 **Procesador:** MediaTek Helio G85\n"
            "🔹 **RAM:** 4GB/6GB\n"
            "🔹 **Almacenamiento:** 64GB/128GB\n"
            "🔹 **Cámara:** 50MP + 2MP\n"
            "🔹 **Batería:** 5000 mAh con carga rápida 25W"
        ),
        inline=False
    )
    
    embed.add_field(
        name="✨ Características Especiales",
        value=(
            "• Sistema operativo Android 14 con One UI 6.1\n"
            "• Diseño moderno con acabado mate\n"
            "• Sensor de huellas lateral\n"
            "• Jack de 3.5mm para auriculares\n"
            "• Dual SIM + microSD\n"
            "• Disponible en azul, negro y dorado"
        ),
        inline=False
    )
    
    embed.add_field(
        name="🎁 Bonus Desbloqueado",
        value=(
            "Por descubrir este Easter Egg, has activado el **Modo Galaxy A06** "
            "en el bot. Los mensajes de advertencia ahora incluirán emojis especiales. 📱✨"
        ),
        inline=False
    )
    
    embed.set_footer(text="Samsung Galaxy A06 • Lanzado en 2024 • AEC Bot Easter Egg")
    embed.set_thumbnail(url="https://i.imgur.com/8EhqgGQ.png")  # Placeholder
    
    bot.galaxy_a06_activado[guild_id] = True
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="ayuda_antilinks", description="Muestra todos los comandos disponibles")
async def ayuda_antilinks(interaction: discord.Interaction):
    embed = discord.Embed(
        title="🛡️ AEC Anti-links - Guía Completa",
        description="Sistema avanzado de protección contra enlaces maliciosos",
        color=discord.Color.purple()
    )
    
    embed.add_field(
        name="📋 Configuración Básica",
        value=(
            "`/configurar_logs` - Configura canal de logs\n"
            "`/configurar_tiempo_muteo` - Duración del muteo\n"
            "`/activar_antilinks` - Activa protección\n"
            "`/desactivar_antilinks` - Desactiva protección"
        ),
        inline=False
    )
    
    embed.add_field(
        name="👥 Gestión de Roles",
        value=(
            "`/agregar_rol_permitido` - Permite enlaces a un rol\n"
            "`/quitar_rol_permitido` - Quita permiso a un rol"
        ),
        inline=False
    )
    
    embed.add_field(
        name="🔒 Dominios Personalizados",
        value=(
            "`/agregar_dominio_bloqueado` - Bloquea un dominio\n"
            "`/quitar_dominio_bloqueado` - Desbloquea un dominio\n"
            "`/agregar_whitelist` - Siempre permite un dominio\n"
            "`/importar_sitios` - Importa lista desde .txt"
        ),
        inline=False
    )
    
    embed.add_field(
        name="📊 Monitoreo",
        value=(
            "`/ver_configuracion` - Ver configuración actual\n"
            "`/estadisticas` - Ver estadísticas del servidor\n"
            "`/limpiar_infracciones` - Limpiar historial de usuario\n"
            "`/probar_detector` - Probar detección de enlaces"
        ),
        inline=False
    )
    
    embed.add_field(
        name="🔍 Detección Avanzada",
        value=(
            "✅ Links con protocolo (http/https)\n"
            "✅ Links sin protocolo\n"
            "✅ Links enmascarados en markdown\n"
            "✅ URLs con Unicode sospechoso\n"
            "✅ Links con espacios insertados\n"
            "✅ Invitaciones de Discord\n"
            "✅ URLs acortadas (bit.ly, etc)\n"
            "✅ IPs directas\n"
            "✅ 'dot com' escrito en texto"
        ),
        inline=False
    )
    
    embed.add_field(
        name="🎉 Easter Egg",
        value="Usa `/galaxya06` para descubrir un secreto especial 📱",
        inline=False
    )
    
    embed.set_footer(text="AEC Anti-links v2.0 • Desarrollado por AEC • 100% Gratuito")
    
    await interaction.response.send_message(embed=embed)

# ============ ARCHIVO .env ============

def crear_archivo_env_ejemplo():
    """Crea archivo .env.example si no existe"""
    contenido_env = """# Configuración del Bot AEC Anti-links
# Copia este archivo como .env y completa los valores

# Token del bot de Discord (REQUERIDO)
# Obtén tu token en: https://discord.com/developers/applications
DISCORD_TOKEN=tu_token_aqui

# ID del propietario del bot (REQUERIDO)
# Tu ID de Discord (habilita modo desarrollador y haz clic derecho en tu perfil)
OWNER_ID=tu_id_aqui

# Modo de depuración (opcional)
DEBUG_MODE=False
"""
    
    if not os.path.exists('.env.example'):
        with open('.env.example', 'w', encoding='utf-8') as f:
            f.write(contenido_env)
        print("✅ Archivo .env.example creado")

# ============ EJECUTAR BOT ============

if __name__ == "__main__":
    # Crear archivo de ejemplo
    crear_archivo_env_ejemplo()
    
    # Información de inicio
    print("=" * 50)
    print("🛡️  AEC ANTI-LINKS BOT v2.0")
    print("=" * 50)
    print("🔐 Sistema de Seguridad: ACTIVO")
    print(f"📊 Detección Avanzada: {len(bot.link_detector.patrones)} patrones")
    print(f"🔒 Caracteres Unicode Monitoreados: {len(SecurityConfig.CARACTERES_UNICODE_SOSPECHOSOS)}")
    print("=" * 50)
    print("🚀 Iniciando bot...")
    print("")
    
    try:
        bot.run(SecurityConfig.TOKEN)
    except KeyboardInterrupt:
        print("\n⚠️ Bot detenido por el usuario")
    except Exception as e:
        print(f"\n❌ Error crítico: {e}")
        print("\n💡 Verifica que:")
        print("  1. El archivo .env existe y contiene DISCORD_TOKEN")
        print("  2. El token es válido")
        print("  3. Los intents están habilitados en Discord Developer Portal")
