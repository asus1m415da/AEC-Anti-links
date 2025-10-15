import discord
from discord import app_commands
from discord.ext import commands, tasks
import json
import re
import aiohttp
import asyncio
from datetime import datetime, timedelta, timezone
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
    CLIENT_ID = os.getenv("CLIENT_ID")
    OWNER_ID = int(os.getenv("OWNER_ID", "0"))
    
    # IDs adicionales con permisos de owner
    ADDITIONAL_OWNERS = [1404572152014962708]
    
    # Límites de seguridad
    MAX_MUTEO = 2419200  # 28 días máximo
    MIN_MUTEO = 60       # 1 minuto mínimo
    MAX_ROLES_PERMITIDOS = 100
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
                "CLIENT_ID=tu_client_id_aqui\n"
                "OWNER_ID=tu_id_aqui"
            )
        return True
    
    @staticmethod
    def es_owner(user_id: int) -> bool:
        """Verifica si un usuario es owner del bot"""
        return user_id == SecurityConfig.OWNER_ID or user_id in SecurityConfig.ADDITIONAL_OWNERS
    
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

# ============ SISTEMA DE PERSISTENCIA JSON ============

class JSONDatabase:
    """Sistema de base de datos en archivos JSON"""
    
    def __init__(self):
        self.data_dir = "data"
        self.config_file = os.path.join(self.data_dir, "config.json")
        self.infracciones_file = os.path.join(self.data_dir, "infracciones.json")
        self.sitios_personalizados_file = os.path.join(self.data_dir, "sitios_personalizados.json")
        self.blacklist_global_file = os.path.join(self.data_dir, "blacklist_global.json")
        
        # Crear directorio data si no existe
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
            print(f"✅ Directorio '{self.data_dir}' creado")
    
    def cargar_config(self) -> dict:
        """Carga configuración de servidores"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"⚠️ Error al cargar config.json: {e}")
                return {}
        return {}
    
    def guardar_config(self, config: dict):
        """Guarda configuración de servidores"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"❌ Error al guardar config.json: {e}")
    
    def cargar_infracciones(self) -> dict:
        """Carga infracciones"""
        if os.path.exists(self.infracciones_file):
            try:
                with open(self.infracciones_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # Convertir strings de fecha a datetime
                    for guild_id in data:
                        for user_id in data[guild_id]:
                            if data[guild_id][user_id].get("ultimo_muteo"):
                                try:
                                    data[guild_id][user_id]["ultimo_muteo"] = datetime.fromisoformat(
                                        data[guild_id][user_id]["ultimo_muteo"]
                                    )
                                except:
                                    data[guild_id][user_id]["ultimo_muteo"] = None
                    return data
            except Exception as e:
                print(f"⚠️ Error al cargar infracciones.json: {e}")
                return {}
        return {}
    
    def guardar_infracciones(self, infracciones: dict):
        """Guarda infracciones"""
        try:
            # Convertir datetime a string para JSON
            data_serializable = {}
            for guild_id in infracciones:
                data_serializable[guild_id] = {}
                for user_id in infracciones[guild_id]:
                    data_serializable[guild_id][user_id] = infracciones[guild_id][user_id].copy()
                    if data_serializable[guild_id][user_id].get("ultimo_muteo"):
                        data_serializable[guild_id][user_id]["ultimo_muteo"] = (
                            data_serializable[guild_id][user_id]["ultimo_muteo"].isoformat()
                        )
            
            with open(self.infracciones_file, 'w', encoding='utf-8') as f:
                json.dump(data_serializable, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"❌ Error al guardar infracciones.json: {e}")
    
    def cargar_sitios_personalizados(self) -> dict:
        """Carga sitios bloqueados personalizados por servidor"""
        if os.path.exists(self.sitios_personalizados_file):
            try:
                with open(self.sitios_personalizados_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # Convertir listas a sets
                    return {guild_id: set(sitios) for guild_id, sitios in data.items()}
            except Exception as e:
                print(f"⚠️ Error al cargar sitios_personalizados.json: {e}")
                return {}
        return {}
    
    def guardar_sitios_personalizados(self, sitios: dict):
        """Guarda sitios bloqueados personalizados"""
        try:
            # Convertir sets a listas para JSON
            data_serializable = {guild_id: list(sitios_set) for guild_id, sitios_set in sitios.items()}
            with open(self.sitios_personalizados_file, 'w', encoding='utf-8') as f:
                json.dump(data_serializable, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"❌ Error al guardar sitios_personalizados.json: {e}")
    
    def cargar_blacklist_global(self) -> dict:
        """Carga blacklist global de usuarios/servidores"""
        if os.path.exists(self.blacklist_global_file):
            try:
                with open(self.blacklist_global_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"⚠️ Error al cargar blacklist_global.json: {e}")
                return {"usuarios": [], "servidores": []}
        return {"usuarios": [], "servidores": []}
    
    def guardar_blacklist_global(self, blacklist: dict):
        """Guarda blacklist global"""
        try:
            with open(self.blacklist_global_file, 'w', encoding='utf-8') as f:
                json.dump(blacklist, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"❌ Error al guardar blacklist_global.json: {e}")

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
            
            # Links con espacios insertados
            'espacios_insertados': re.compile(
                r'h\s*t\s*t\s*p\s*s?\s*:\s*[/\s]*\s*[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+',
                re.IGNORECASE
            ),
            
            # Detección de dot/com escrito
            'dot_com_escrito': re.compile(
                r'\b[a-z0-9\-]+\s+(?:dot|punto)\s+(?:com|net|org|io|gg|xyz)',
                re.IGNORECASE
            ),
        }
    
    def limpiar_markdown(self, texto: str) -> str:
        """Elimina formato Markdown para detectar links ocultos"""
        texto = re.sub(r'\*\*([^*]+)\*\*', r'\1', texto)
        texto = re.sub(r'__([^_]+)__', r'\1', texto)
        texto = re.sub(r'\*([^*]+)\*', r'\1', texto)
        texto = re.sub(r'_([^_]+)_', r'\1', texto)
        texto = re.sub(r'~~([^~]+)~~', r'\1', texto)
        texto = re.sub(r'\|\|([^|]+)\|\|', r'\1', texto)
        texto = re.sub(r'`([^`]+)`', r'\1', texto)
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
                texto = texto.replace(char, '')
        return texto
    
    def detectar_todas_urls(self, texto: str) -> List[Tuple[str, str]]:
        """Detecta TODAS las URLs incluyendo técnicas de bypass"""
        urls_encontradas = []
        texto_original = texto
        
        texto_limpio = self.limpiar_markdown(texto)
        texto_normalizado = self.normalizar_unicode(texto_limpio)
        
        # Detectar links enmascarados
        for match in self.patrones['markdown_link'].finditer(texto_original):
            texto_visible = match.group(1)
            url_real = match.group(2)
            urls_encontradas.append((url_real, "LINK_ENMASCARADO"))
        
        # URLs con protocolo
        for match in self.patrones['url_protocolo'].finditer(texto_normalizado):
            url = match.group(0)
            if not any(u[0] == url for u in urls_encontradas):
                urls_encontradas.append((url, "URL_PROTOCOLO"))
        
        # URLs con www
        for match in self.patrones['url_www'].finditer(texto_normalizado):
            url = match.group(0)
            if not any(u[0] == url for u in urls_encontradas):
                urls_encontradas.append((url, "URL_WWW"))
        
        # Invitaciones de Discord
        for match in self.patrones['discord_invite'].finditer(texto_normalizado):
            urls_encontradas.append((match.group(0), "DISCORD_INVITE"))
        
        # URLs acortadas
        for match in self.patrones['url_corta'].finditer(texto_normalizado):
            urls_encontradas.append((match.group(0), "URL_ACORTADA"))
        
        # IPs directas
        for match in self.patrones['ipv4'].finditer(texto_normalizado):
            urls_encontradas.append((match.group(0), "IP_ADDRESS"))
        
        # Links con espacios
        for match in self.patrones['espacios_insertados'].finditer(texto_normalizado):
            url = match.group(0).replace(' ', '')
            urls_encontradas.append((url, "URL_ESPACIADA"))
        
        # "dot com" escrito
        for match in self.patrones['dot_com_escrito'].finditer(texto_normalizado):
            url = match.group(0).replace(' dot ', '.').replace(' punto ', '.')
            urls_encontradas.append((url, "DOT_COM_ESCRITO"))
        
        # Dominios completos
        for match in self.patrones['dominio_completo'].finditer(texto_normalizado):
            url = match.group(0)
            if '.' in url and len(url) > 5:
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
        
        # Sistema de persistencia
        self.db = JSONDatabase()
        
        # Cargar datos desde JSON
        self.config = self.db.cargar_config()
        self.infracciones = self.db.cargar_infracciones()
        self.sitios_personalizados = self.db.cargar_sitios_personalizados()
        self.blacklist_global = self.db.cargar_blacklist_global()
        self.sitios_bloqueados = set()
        
        # Detector avanzado
        self.link_detector = AdvancedLinkDetector()
        
        # Rate limiting
        self.command_cooldowns = {}
        
        # Easter Egg Galaxy A06
        self.galaxy_a06_activado = {}
        
        # Estadísticas
        self.start_time = datetime.now(timezone.utc)
        
    async def setup_hook(self):
        await self.tree.sync()
        actualizar_base_maliciosa.start()
        guardar_datos_periodicamente.start()
        print("🔐 Sistema de seguridad inicializado")
        print(f"👑 Owners: {SecurityConfig.OWNER_ID}, {SecurityConfig.ADDITIONAL_OWNERS}")
        
    async def on_ready(self):
        print(f'✅ Bot {self.user} conectado correctamente')
        print(f'🛡️ AEC Anti-links activo en {len(self.guilds)} servidores')
        print(f'🔒 {len(self.sitios_bloqueados)} sitios maliciosos en base de datos')
        print(f'📊 {len(self.config)} servidores configurados')
        print(f'⚠️ {sum(len(inf) for inf in self.infracciones.values())} usuarios con infracciones')
        
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
            "modo_estricto": False,
            "whitelist_dominios": []
        }
    return bot.config[str(guild_id)]

def verificar_rate_limit(user_id: int, comando: str, segundos: int = 5) -> bool:
    """Sistema anti-spam para comandos"""
    ahora = datetime.now(timezone.utc)
    key = f"{user_id}:{comando}"
    
    if key in bot.command_cooldowns:
        ultimo_uso = bot.command_cooldowns[key]
        if (ahora - ultimo_uso).total_seconds() < segundos:
            return False
    
    bot.command_cooldowns[key] = ahora
    return True

# ============ GUARDADO AUTOMÁTICO ============

@tasks.loop(minutes=5)
async def guardar_datos_periodicamente():
    """Guarda todos los datos cada 5 minutos"""
    try:
        bot.db.guardar_config(bot.config)
        bot.db.guardar_infracciones(bot.infracciones)
        bot.db.guardar_sitios_personalizados(bot.sitios_personalizados)
        bot.db.guardar_blacklist_global(bot.blacklist_global)
        print(f"💾 Datos guardados automáticamente - {datetime.now().strftime('%H:%M:%S')}")
    except Exception as e:
        print(f"❌ Error al guardar datos: {e}")

# ============ ACTUALIZACIÓN DE BASE DE DATOS ============

@tasks.loop(hours=1)
async def actualizar_base_maliciosa():
    """Actualiza base de datos desde URLhaus"""
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
    if message.author.bot:
        return
    
    if not message.guild:
        return
    
    # Verificar blacklist global
    if str(message.author.id) in bot.blacklist_global.get("usuarios", []):
        try:
            await message.delete()
            return
        except:
            pass
    
    if str(message.guild.id) in bot.blacklist_global.get("servidores", []):
        return
    
    config = get_config(message.guild.id)
    
    if not config["activado"]:
        await bot.process_commands(message)
        return
    
    if message.author.guild_permissions.administrator:
        await bot.process_commands(message)
        return
    
    roles_usuario = [role.id for role in message.author.roles]
    if any(rol in config["roles_permitidos"] for rol in roles_usuario):
        await bot.process_commands(message)
        return
    
    texto_seguro = SecurityConfig.sanitizar_entrada(message.content)
    urls_detectadas = bot.link_detector.detectar_todas_urls(texto_seguro)
    
    if urls_detectadas:
        urls_filtradas = []
        for url, tipo in urls_detectadas:
            en_whitelist = False
            for dominio_permitido in config["whitelist_dominios"]:
                if dominio_permitido.lower() in url.lower():
                    en_whitelist = True
                    break
            
            if not en_whitelist:
                urls_filtradas.append((url, tipo))
        
        if not urls_filtradas:
            await bot.process_commands(message)
            return
        
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
        
        try:
            await message.delete()
        except discord.errors.Forbidden:
            print(f"⚠️ No tengo permisos para eliminar mensajes en {message.guild.name}")
            await bot.process_commands(message)
            return
        
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
        
        duracion = config["tiempo_muteo"]
        if infracciones_total > 3:
            duracion = min(duracion * infracciones_total // 2, SecurityConfig.MAX_MUTEO)
        
        timeout_hasta = discord.utils.utcnow() + timedelta(seconds=duracion)
        
        try:
            await message.author.timeout(timeout_hasta, reason="Envío de enlaces no autorizados - AEC Anti-links")
            bot.infracciones[guild_id][user_id]["muteos"] += 1
            bot.infracciones[guild_id][user_id]["ultimo_muteo"] = datetime.now(timezone.utc)
            
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
            
            embed_advertencia.set_footer(text="Para apelar contacta a un administrador")
            
            await message.channel.send(embed=embed_advertencia, delete_after=15)
            
            if config["canal_logs"]:
                canal_logs = bot.get_channel(config["canal_logs"])
                if canal_logs:
                    embed_log = discord.Embed(
                        title="📋 Registro de Infracción - AEC Anti-links",
                        color=discord.Color.red() if es_maliciosa else discord.Color.orange(),
                        timestamp=datetime.now(timezone.utc)
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
                    
                    tipos = ", ".join(set([tipo for _, tipo in urls_filtradas[:3]]))
                    embed_log.add_field(
                        name="🔍 Métodos de Detección",
                        value=tipos,
                        inline=False
                    )
                    
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

# ============ COMANDOS NORMALES (continuación en siguiente mensaje por límite de caracteres) ============

# [Los comandos normales que ya tenías se quedan igual: configurar_logs, agregar_rol_permitido, etc.]
# Ahora añado los COMANDOS DE OWNER:

# ============ COMANDOS EXCLUSIVOS PARA OWNERS ============

@bot.tree.command(name="owner_shutdown", description="[OWNER] Apaga el bot de forma segura")
async def owner_shutdown(interaction: discord.Interaction):
    if not SecurityConfig.es_owner(interaction.user.id):
        await interaction.response.send_message("❌ Este comando es exclusivo para owners del bot.", ephemeral=True)
        return
    
    # Guardar todos los datos antes de apagar
    bot.db.guardar_config(bot.config)
    bot.db.guardar_infracciones(bot.infracciones)
    bot.db.guardar_sitios_personalizados(bot.sitios_personalizados)
    bot.db.guardar_blacklist_global(bot.blacklist_global)
    
    await interaction.response.send_message("🔴 Apagando bot... Todos los datos han sido guardados.", ephemeral=True)
    print(f"🔴 Bot apagado por {interaction.user} (ID: {interaction.user.id})")
    await bot.close()

@bot.tree.command(name="owner_stats", description="[OWNER] Estadísticas globales del bot")
async def owner_stats(interaction: discord.Interaction):
    if not SecurityConfig.es_owner(interaction.user.id):
        await interaction.response.send_message("❌ Solo para owners.", ephemeral=True)
        return
    
    total_infracciones = sum(
        sum(data["count"] for data in infracciones.values())
        for infracciones in bot.infracciones.values()
    )
    
    total_usuarios_infractores = sum(
        len(infracciones) for infracciones in bot.infracciones.values()
    )
    
    total_usuarios = sum(g.member_count for g in bot.guilds)
    uptime = datetime.now(timezone.utc) - bot.start_time
    horas_uptime = uptime.total_seconds() // 3600
    
    embed = discord.Embed(
        title="📊 Estadísticas Globales - AEC Anti-links",
        description=f"Estadísticas del bot solicitadas por {interaction.user.mention}",
        color=discord.Color.gold(),
        timestamp=datetime.now(timezone.utc)
    )
    
    embed.add_field(name="🌐 Servidores Activos", value=len(bot.guilds), inline=True)
    embed.add_field(name="👥 Usuarios Totales", value=f"{total_usuarios:,}", inline=True)
    embed.add_field(name="⏰ Uptime", value=f"{int(horas_uptime)}h", inline=True)
    embed.add_field(name="🚨 Total Infracciones", value=f"{total_infracciones:,}", inline=True)
    embed.add_field(name="⚠️ Usuarios Infractores", value=f"{total_usuarios_infractores:,}", inline=True)
    embed.add_field(name="🔒 Sitios Bloqueados (Global)", value=f"{len(bot.sitios_bloqueados):,}", inline=True)
    
    total_sitios_personalizados = sum(len(sitios) for sitios in bot.sitios_personalizados.values())
    embed.add_field(name="🛡️ Sitios Personalizados", value=f"{total_sitios_personalizados:,}", inline=True)
    embed.add_field(name="🚫 Usuarios en Blacklist", value=len(bot.blacklist_global.get("usuarios", [])), inline=True)
    embed.add_field(name="⛔ Servidores Bloqueados", value=len(bot.blacklist_global.get("servidores", [])), inline=True)
    
    embed.set_footer(text=f"Bot ejecutándose como {bot.user.name}")
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="owner_sync", description="[OWNER] Sincroniza los comandos slash globalmente")
async def owner_sync(interaction: discord.Interaction):
    if not SecurityConfig.es_owner(interaction.user.id):
        await interaction.response.send_message("❌ Solo para owners.", ephemeral=True)
        return
    
    await interaction.response.defer(ephemeral=True)
    
    try:
        synced = await bot.tree.sync()
        await interaction.followup.send(f"✅ {len(synced)} comandos sincronizados correctamente.", ephemeral=True)
        print(f"✅ Comandos sincronizados por {interaction.user}")
    except Exception as e:
        await interaction.followup.send(f"❌ Error al sincronizar: {e}", ephemeral=True)

@bot.tree.command(name="owner_blacklist_add", description="[OWNER] Añade un usuario o servidor a la blacklist global")
@app_commands.describe(
    tipo="Tipo de blacklist (usuario o servidor)",
    id="ID del usuario o servidor"
)
@app_commands.choices(tipo=[
    app_commands.Choice(name="Usuario", value="usuario"),
    app_commands.Choice(name="Servidor", value="servidor")
])
async def owner_blacklist_add(interaction: discord.Interaction, tipo: str, id: str):
    if not SecurityConfig.es_owner(interaction.user.id):
        await interaction.response.send_message("❌ Solo para owners.", ephemeral=True)
        return
    
    if tipo == "usuario":
        if id not in bot.blacklist_global.get("usuarios", []):
            if "usuarios" not in bot.blacklist_global:
                bot.blacklist_global["usuarios"] = []
            bot.blacklist_global["usuarios"].append(id)
            bot.db.guardar_blacklist_global(bot.blacklist_global)
            
            try:
                user = await bot.fetch_user(int(id))
                await interaction.response.send_message(
                    f"✅ Usuario **{user.name}** ({id}) añadido a la blacklist global.",
                    ephemeral=True
                )
            except:
                await interaction.response.send_message(
                    f"✅ ID de usuario {id} añadido a la blacklist global.",
                    ephemeral=True
                )
        else:
            await interaction.response.send_message("⚠️ Este usuario ya está en la blacklist.", ephemeral=True)
    
    elif tipo == "servidor":
        if id not in bot.blacklist_global.get("servidores", []):
            if "servidores" not in bot.blacklist_global:
                bot.blacklist_global["servidores"] = []
            bot.blacklist_global["servidores"].append(id)
            bot.db.guardar_blacklist_global(bot.blacklist_global)
            
            try:
                guild = bot.get_guild(int(id))
                nombre = guild.name if guild else id
                await interaction.response.send_message(
                    f"✅ Servidor **{nombre}** ({id}) añadido a la blacklist global.",
                    ephemeral=True
                )
            except:
                await interaction.response.send_message(
                    f"✅ ID de servidor {id} añadido a la blacklist global.",
                    ephemeral=True
                )
        else:
            await interaction.response.send_message("⚠️ Este servidor ya está en la blacklist.", ephemeral=True)

@bot.tree.command(name="owner_blacklist_remove", description="[OWNER] Quita un usuario o servidor de la blacklist")
@app_commands.describe(
    tipo="Tipo de blacklist (usuario o servidor)",
    id="ID del usuario o servidor"
)
@app_commands.choices(tipo=[
    app_commands.Choice(name="Usuario", value="usuario"),
    app_commands.Choice(name="Servidor", value="servidor")
])
async def owner_blacklist_remove(interaction: discord.Interaction, tipo: str, id: str):
    if not SecurityConfig.es_owner(interaction.user.id):
        await interaction.response.send_message("❌ Solo para owners.", ephemeral=True)
        return
    
    if tipo == "usuario":
        if id in bot.blacklist_global.get("usuarios", []):
            bot.blacklist_global["usuarios"].remove(id)
            bot.db.guardar_blacklist_global(bot.blacklist_global)
            await interaction.response.send_message(f"✅ Usuario {id} removido de la blacklist.", ephemeral=True)
        else:
            await interaction.response.send_message("⚠️ Este usuario no está en la blacklist.", ephemeral=True)
    
    elif tipo == "servidor":
        if id in bot.blacklist_global.get("servidores", []):
            bot.blacklist_global["servidores"].remove(id)
            bot.db.guardar_blacklist_global(bot.blacklist_global)
            await interaction.response.send_message(f"✅ Servidor {id} removido de la blacklist.", ephemeral=True)
        else:
            await interaction.response.send_message("⚠️ Este servidor no está en la blacklist.", ephemeral=True)

@bot.tree.command(name="owner_blacklist_list", description="[OWNER] Lista todos los elementos en la blacklist global")
async def owner_blacklist_list(interaction: discord.Interaction):
    if not SecurityConfig.es_owner(interaction.user.id):
        await interaction.response.send_message("❌ Solo para owners.", ephemeral=True)
        return
    
    embed = discord.Embed(
        title="🚫 Blacklist Global",
        color=discord.Color.dark_red(),
        timestamp=datetime.now(timezone.utc)
    )
    
    usuarios_bl = bot.blacklist_global.get("usuarios", [])
    servidores_bl = bot.blacklist_global.get("servidores", [])
    
    if usuarios_bl:
        usuarios_texto = "\n".join([f"• `{uid}`" for uid in usuarios_bl[:10]])
        if len(usuarios_bl) > 10:
            usuarios_texto += f"\n*...y {len(usuarios_bl) - 10} más*"
        embed.add_field(name=f"👤 Usuarios ({len(usuarios_bl)})", value=usuarios_texto, inline=False)
    else:
        embed.add_field(name="👤 Usuarios", value="Ninguno", inline=False)
    
    if servidores_bl:
        servidores_texto = "\n".join([f"• `{sid}`" for sid in servidores_bl[:10]])
        if len(servidores_bl) > 10:
            servidores_texto += f"\n*...y {len(servidores_bl) - 10} más*"
        embed.add_field(name=f"🏢 Servidores ({len(servidores_bl)})", value=servidores_texto, inline=False)
    else:
        embed.add_field(name="🏢 Servidores", value="Ninguno", inline=False)
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="owner_save", description="[OWNER] Guarda manualmente todos los datos en JSON")
async def owner_save(interaction: discord.Interaction):
    if not SecurityConfig.es_owner(interaction.user.id):
        await interaction.response.send_message("❌ Solo para owners.", ephemeral=True)
        return
    
    await interaction.response.defer(ephemeral=True)
    
    try:
        bot.db.guardar_config(bot.config)
        bot.db.guardar_infracciones(bot.infracciones)
        bot.db.guardar_sitios_personalizados(bot.sitios_personalizados)
        bot.db.guardar_blacklist_global(bot.blacklist_global)
        
        await interaction.followup.send(
            "✅ Todos los datos han sido guardados exitosamente:\n"
            f"• `config.json` - {len(bot.config)} servidores\n"
            f"• `infracciones.json` - {sum(len(inf) for inf in bot.infracciones.values())} usuarios\n"
            f"• `sitios_personalizados.json` - {len(bot.sitios_personalizados)} servidores\n"
            f"• `blacklist_global.json` - {len(bot.blacklist_global.get('usuarios', [])) + len(bot.blacklist_global.get('servidores', []))} entradas",
            ephemeral=True
        )
        print(f"💾 Guardado manual ejecutado por {interaction.user}")
    except Exception as e:
        await interaction.followup.send(f"❌ Error al guardar: {e}", ephemeral=True)

@bot.tree.command(name="owner_servidores", description="[OWNER] Lista todos los servidores donde está el bot")
async def owner_servidores(interaction: discord.Interaction):
    if not SecurityConfig.es_owner(interaction.user.id):
        await interaction.response.send_message("❌ Solo para owners.", ephemeral=True)
        return
    
    guilds_ordenados = sorted(bot.guilds, key=lambda g: g.member_count, reverse=True)
    
    embed = discord.Embed(
        title=f"🌐 Servidores ({len(bot.guilds)})",
        description="Lista de servidores ordenados por miembros",
        color=discord.Color.blue(),
        timestamp=datetime.now(timezone.utc)
    )
    
    for i, guild in enumerate(guilds_ordenados[:15], 1):
        config_activa = "✅" if get_config(guild.id).get("activado", True) else "❌"
        embed.add_field(
            name=f"{i}. {guild.name}",
            value=f"👥 {guild.member_count} • ID: `{guild.id}` • {config_activa}",
            inline=False
        )
    
    if len(bot.guilds) > 15:
        embed.set_footer(text=f"Mostrando 15 de {len(bot.guilds)} servidores")
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="owner_eval", description="[OWNER] Evalúa código Python (PELIGROSO)")
@app_commands.describe(codigo="Código Python a evaluar")
async def owner_eval(interaction: discord.Interaction, codigo: str):
    if not SecurityConfig.es_owner(interaction.user.id):
        await interaction.response.send_message("❌ Solo para owners.", ephemeral=True)
        return
    
    await interaction.response.defer(ephemeral=True)
    
    try:
        resultado = eval(codigo)
        await interaction.followup.send(f"``````", ephemeral=True)
        print(f"⚠️ EVAL ejecutado por {interaction.user}: {codigo}")
    except Exception as e:
        await interaction.followup.send(f"❌ Error:\n``````", ephemeral=True)

# ============ COMANDOS NORMALES (ADMINISTRADORES) ============

@bot.tree.command(name="configurar_logs", description="[ADMIN] Configura el canal de logs")
@app_commands.describe(canal="Canal donde se enviarán los registros")
async def configurar_logs(interaction: discord.Interaction, canal: discord.TextChannel):
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("❌ Solo administradores pueden usar este comando.", ephemeral=True)
        return
    
    config = get_config(interaction.guild.id)
    config["canal_logs"] = canal.id
    bot.db.guardar_config(bot.config)
    
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
        bot.db.guardar_config(bot.config)
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
        bot.db.guardar_config(bot.config)
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
    bot.db.guardar_config(bot.config)
    
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
    bot.db.guardar_sitios_personalizados(bot.sitios_personalizados)
    
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
        bot.db.guardar_sitios_personalizados(bot.sitios_personalizados)
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
        bot.db.guardar_config(bot.config)
        await interaction.response.send_message(
            f"✅ Dominio **{dominio}** agregado a la whitelist.",
            ephemeral=True
        )
    else:
        await interaction.response.send_message(
            f"⚠️ El dominio **{dominio}** ya está en la whitelist.",
            ephemeral=True
        )

@bot.tree.command(name="quitar_whitelist", description="[ADMIN] Quita un dominio de la whitelist")
@app_commands.describe(dominio="Dominio a quitar de la whitelist")
async def quitar_whitelist(interaction: discord.Interaction, dominio: str):
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("❌ Solo administradores.", ephemeral=True)
        return
    
    dominio = dominio.lower().replace('http://', '').replace('https://', '').replace('www.', '').split('/')[0]
    config = get_config(interaction.guild.id)
    
    if dominio in config["whitelist_dominios"]:
        config["whitelist_dominios"].remove(dominio)
        bot.db.guardar_config(bot.config)
        await interaction.response.send_message(
            f"✅ Dominio **{dominio}** quitado de la whitelist.",
            ephemeral=True
        )
    else:
        await interaction.response.send_message(
            f"⚠️ El dominio **{dominio}** no está en la whitelist.",
            ephemeral=True
        )

@bot.tree.command(name="lista_whitelist", description="[ADMIN] Muestra todos los dominios en la whitelist")
async def lista_whitelist(interaction: discord.Interaction):
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("❌ Solo administradores.", ephemeral=True)
        return
    
    config = get_config(interaction.guild.id)
    whitelist = config.get("whitelist_dominios", [])
    
    if not whitelist:
        await interaction.response.send_message("⚠️ No hay dominios en la whitelist.", ephemeral=True)
        return
    
    embed = discord.Embed(
        title="✅ Whitelist de Dominios",
        description=f"Dominios siempre permitidos en este servidor ({len(whitelist)})",
        color=discord.Color.green()
    )
    
    dominios_texto = "\n".join([f"• `{dom}`" for dom in whitelist[:20]])
    if len(whitelist) > 20:
        dominios_texto += f"\n*...y {len(whitelist) - 20} más*"
    
    embed.add_field(name="Dominios", value=dominios_texto, inline=False)
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="lista_bloqueados", description="[ADMIN] Muestra dominios bloqueados personalizados")
async def lista_bloqueados(interaction: discord.Interaction):
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("❌ Solo administradores.", ephemeral=True)
        return
    
    guild_id = str(interaction.guild.id)
    sitios = bot.sitios_personalizados.get(guild_id, set())
    
    if not sitios:
        await interaction.response.send_message("⚠️ No hay dominios personalizados bloqueados.", ephemeral=True)
        return
    
    embed = discord.Embed(
        title="🔒 Dominios Bloqueados Personalizados",
        description=f"Lista de dominios bloqueados en este servidor ({len(sitios)})",
        color=discord.Color.red()
    )
    
    sitios_lista = list(sitios)[:20]
    dominios_texto = "\n".join([f"• `{dom}`" for dom in sitios_lista])
    if len(sitios) > 20:
        dominios_texto += f"\n*...y {len(sitios) - 20} más*"
    
    embed.add_field(name="Dominios", value=dominios_texto, inline=False)
    
    await interaction.response.send_message(embed=embed, ephemeral=True)

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
                if attachment.size > 1024 * 1024:
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
                
                bot.db.guardar_sitios_personalizados(bot.sitios_personalizados)
                
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
    bot.db.guardar_config(bot.config)
    await interaction.response.send_message("✅ Sistema anti-links **ACTIVADO**.", ephemeral=True)

@bot.tree.command(name="desactivar_antilinks", description="[ADMIN] Desactiva el sistema anti-links")
async def desactivar_antilinks(interaction: discord.Interaction):
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("❌ Solo administradores.", ephemeral=True)
        return
    
    config = get_config(interaction.guild.id)
    config["activado"] = False
    bot.db.guardar_config(bot.config)
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
        value=f"{len(bot.sitios_bloqueados):,} dominios",
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
        timestamp=datetime.now(timezone.utc)
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
        bot.db.guardar_infracciones(bot.infracciones)
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
        color=0x1428A0
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
            "`/quitar_whitelist` - Quita dominio de whitelist\n"
            "`/lista_whitelist` - Ver dominios permitidos\n"
            "`/lista_bloqueados` - Ver dominios bloqueados\n"
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
    
    # Solo mostrar comandos de owner a los owners
    if SecurityConfig.es_owner(interaction.user.id):
        embed.add_field(
            name="👑 Comandos de Owner",
            value=(
                "`/owner_stats` - Estadísticas globales\n"
                "`/owner_servidores` - Lista de servidores\n"
                "`/owner_save` - Guardar datos manualmente\n"
                "`/owner_sync` - Sincronizar comandos\n"
                "`/owner_blacklist_add` - Añadir a blacklist\n"
                "`/owner_blacklist_remove` - Quitar de blacklist\n"
                "`/owner_blacklist_list` - Ver blacklist\n"
                "`/owner_shutdown` - Apagar bot\n"
                "`/owner_eval` - Evaluar código Python"
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

# ============ FUNCIÓN PARA CREAR ARCHIVOS DE EJEMPLO ============

def crear_archivos_ejemplo():
    """Crea archivos de ejemplo si no existen"""
    
    # .env.example
    contenido_env = """# Configuración del Bot AEC Anti-links
# Copia este archivo como .env y completa los valores

# Token del bot de Discord (REQUERIDO)
# Obtén tu token en: https://discord.com/developers/applications
DISCORD_TOKEN=tu_token_aqui

# Client ID del bot (REQUERIDO para registro de comandos)
# Se encuentra en la sección General Information de tu aplicación
CLIENT_ID=tu_client_id_aqui

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
    
    # .gitignore
    contenido_gitignore = """# Variables de entorno sensibles
.env

# Cache de Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python

# Archivos de datos (JSON)
data/
*.json

# Archivos de configuración sensibles
config.json

# Archivos temporales
temp/
*.tmp
*.log

# IDE
.vscode/
.idea/
*.swp
*.swo

# Sistema operativo
.DS_Store
Thumbs.db
"""
    
    if not os.path.exists('.gitignore'):
        with open('.gitignore', 'w', encoding='utf-8') as f:
            f.write(contenido_gitignore)
        print("✅ Archivo .gitignore creado")
    
    # requirements.txt
    contenido_requirements = """discord.py>=2.3.0
python-dotenv>=1.0.0
aiohttp>=3.9.0
"""
    
    if not os.path.exists('requirements.txt'):
        with open('requirements.txt', 'w', encoding='utf-8') as f:
            f.write(contenido_requirements)
        print("✅ Archivo requirements.txt creado")

# ============ EJECUTAR BOT ============

if __name__ == "__main__":
    # Crear archivos de ejemplo
    crear_archivos_ejemplo()
    
    # Información de inicio
    print("=" * 60)
    print("🛡️  AEC ANTI-LINKS BOT v2.0")
    print("=" * 60)
    print("🔐 Sistema de Seguridad: ACTIVO")
    print(f"📊 Detección Avanzada: {len(bot.link_detector.patrones)} patrones")
    print(f"🔒 Caracteres Unicode Monitoreados: {len(SecurityConfig.CARACTERES_UNICODE_SOSPECHOSOS)}")
    print(f"👑 Owner Principal: {SecurityConfig.OWNER_ID}")
    print(f"👑 Owners Adicionales: {SecurityConfig.ADDITIONAL_OWNERS}")
    print(f"💾 Sistema de Persistencia JSON: ACTIVADO")
    print("=" * 60)
    print("🚀 Iniciando bot...")
    print("")
    
    try:
        bot.run(SecurityConfig.TOKEN)
    except KeyboardInterrupt:
        print("\n⚠️ Bot detenido por el usuario")
        print("💾 Guardando datos antes de salir...")
        bot.db.guardar_config(bot.config)
        bot.db.guardar_infracciones(bot.infracciones)
        bot.db.guardar_sitios_personalizados(bot.sitios_personalizados)
        bot.db.guardar_blacklist_global(bot.blacklist_global)
        print("✅ Datos guardados correctamente")
    except Exception as e:
        print(f"\n❌ Error crítico: {e}")
        print("\n💡 Verifica que:")
        print("  1. El archivo .env existe y contiene DISCORD_TOKEN y CLIENT_ID")
        print("  2. El token es válido")
        print("  3. Los intents están habilitados en Discord Developer Portal")
        print("  4. Las dependencias están instaladas: pip install -r requirements.txt")
