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
from typing import Set, List, Tuple, Dict
import hashlib
from flask import Flask, render_template, request, jsonify, send_from_directory
from threading import Thread
import time

load_dotenv()

# ============ CONFIGURACIÓN DE SEGURIDAD ============

class SecurityConfig:
    TOKEN = os.getenv("DISCORD_TOKEN")
    CLIENT_ID = os.getenv("CLIENT_ID")
    OWNER_ID = int(os.getenv("OWNER_ID", "0"))
    WEB_PORT = int(os.getenv("PORT", "5000"))

    ADDITIONAL_OWNERS = [1404572152014962708]
    MAX_MUTEO = 2419200
    MIN_MUTEO = 60
    MAX_ROLES_PERMITIDOS = 100
    MAX_IMPORTACION_SITIOS = 10000

    CARACTERES_UNICODE_SOSPECHOSOS = {
        '╱', '⁄', '∕', '⧸', '／', '᜵', '჻', '᛫', '⼁', '⼃',
        '։', '׃', '˸', '᛬', 'ː', 'ꓽ', '⁚', '⁏', '୵', '⠐',
        '․', '‥', '⋯', '…', '܁', '܂', '。', '·',
        '\u200b', '\u200c', '\u200d', '\ufeff', '\u2060',
    }

    @staticmethod
    def validar_token():
        if not SecurityConfig.TOKEN or len(SecurityConfig.TOKEN) < 50:
            raise ValueError("❌ ERROR: Token no configurado correctamente en .env")
        return True

    @staticmethod
    def es_owner(user_id: int) -> bool:
        return user_id == SecurityConfig.OWNER_ID or user_id in SecurityConfig.ADDITIONAL_OWNERS

    @staticmethod
    def sanitizar_entrada(texto: str, max_len: int = 2000) -> str:
        if not texto:
            return ""
        texto = texto[:max_len]
        texto = ''.join(char for char in texto if ord(char) >= 32 or char in '\n\t')
        return texto

# ============ SISTEMA DE PERSISTENCIA JSON ============

class JSONDatabase:
    def __init__(self):
        self.data_dir = "data"
        self.config_file = os.path.join(self.data_dir, "config.json")
        self.infracciones_file = os.path.join(self.data_dir, "infracciones.json")
        self.sitios_personalizados_file = os.path.join(self.data_dir, "sitios_personalizados.json")
        self.blacklist_global_file = os.path.join(self.data_dir, "blacklist_global.json")

        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
            print(f"✅ Carpeta '{self.data_dir}' creada")

    def cargar_config(self) -> dict:
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"⚠️ Error cargando config: {e}")
                return {}
        return {}

    def guardar_config(self, config: dict):
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"❌ Error guardando config: {e}")

    def cargar_infracciones(self) -> dict:
        if os.path.exists(self.infracciones_file):
            try:
                with open(self.infracciones_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
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
                print(f"⚠️ Error cargando infracciones: {e}")
                return {}
        return {}

    def guardar_infracciones(self, infracciones: dict):
        try:
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
            print(f"❌ Error guardando infracciones: {e}")

    def cargar_sitios_personalizados(self) -> dict:
        if os.path.exists(self.sitios_personalizados_file):
            try:
                with open(self.sitios_personalizados_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return {guild_id: set(sitios) for guild_id, sitios in data.items()}
            except Exception as e:
                print(f"⚠️ Error cargando sitios: {e}")
                return {}
        return {}

    def guardar_sitios_personalizados(self, sitios: dict):
        try:
            data_serializable = {guild_id: list(sitios_set) for guild_id, sitios_set in sitios.items()}
            with open(self.sitios_personalizados_file, 'w', encoding='utf-8') as f:
                json.dump(data_serializable, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"❌ Error guardando sitios: {e}")

    def cargar_blacklist_global(self) -> dict:
        if os.path.exists(self.blacklist_global_file):
            try:
                with open(self.blacklist_global_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"⚠️ Error cargando blacklist: {e}")
                return {"usuarios": [], "servidores": []}
        return {"usuarios": [], "servidores": []}

    def guardar_blacklist_global(self, blacklist: dict):
        try:
            with open(self.blacklist_global_file, 'w', encoding='utf-8') as f:
                json.dump(blacklist, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"❌ Error guardando blacklist: {e}")

# ============ DETECTOR AVANZADO DE LINKS ============

class AdvancedLinkDetector:
    def __init__(self):
        self.patrones = self._compilar_patrones()
        self.caracteres_sospechosos = SecurityConfig.CARACTERES_UNICODE_SOSPECHOSOS

    def _compilar_patrones(self) -> dict:
        return {
            'url_protocolo': re.compile(r'https?://(?:[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=]|%[0-9a-fA-F]{2})+', re.IGNORECASE),
            'url_www': re.compile(r'www\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(?:[/?#][^\s]*)?', re.IGNORECASE),
            'dominio_completo': re.compile(r'\b[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+(?:/[^\s]*)?', re.IGNORECASE),
            'markdown_link': re.compile(r'\[([^\]]+)\]\(([^)]+)\)'),
            'discord_invite': re.compile(r'(?:discord\.gg|discord\.com/invite|discordapp\.com/invite)/[a-zA-Z0-9\-]+', re.IGNORECASE),
        }

    def detectar_todas_urls(self, texto: str) -> List[Tuple[str, str]]:
        urls_encontradas = []
        for nombre, patron in self.patrones.items():
            for match in patron.finditer(texto):
                url = match.group(0) if nombre != 'markdown_link' else match.group(2)
                urls_encontradas.append((url, nombre.upper()))
        return urls_encontradas

    def verificar_url_maliciosa(self, url: str, sitios_bloqueados: Set[str]) -> bool:
        url_limpia = url.lower().replace('http://', '').replace('https://', '').replace('www.', '').split('/')[0]
        for sitio in sitios_bloqueados:
            if sitio in url_limpia or url_limpia in sitio:
                return True
        return False

# ============ SISTEMA ANTI-SPAM BALANCEADO ============

class AntiSpamSystem:
    def __init__(self):
        self.message_history: Dict[str, List[Tuple[str, datetime]]] = {}
        self.spam_chains: Dict[str, Dict[str, List[Tuple[str, datetime]]]] = {}
        self.flood_history: Dict[str, List[datetime]] = {}

    def verificar_spam(self, guild_id: str, user_id: str, mensaje: str, max_mensajes: int, tiempo_ventana: int) -> bool:
        """Verifica SPAM INDIVIDUAL - Solo mensajes IDÉNTICOS"""
        ahora = datetime.now(timezone.utc)
        key = f"{guild_id}:{user_id}"

        if key not in self.message_history:
            self.message_history[key] = []

        self.message_history[key] = [
            (msg, timestamp) for msg, timestamp in self.message_history[key]
            if (ahora - timestamp).total_seconds() < tiempo_ventana
        ]

        self.message_history[key].append((mensaje, ahora))

        if len(self.message_history[key]) < max_mensajes:
            return False

        ultimos_mensajes = [msg for msg, _ in self.message_history[key][-max_mensajes:]]

        # Solo si TODOS son EXACTAMENTE iguales
        if len(set(ultimos_mensajes)) == 1 and len(ultimos_mensajes[0].strip()) >= 2:
            print(f"[ANTI-SPAM] ⚠️ Usuario {user_id[-4:]} - {max_mensajes} mensajes idénticos")
            return True

        return False

    def verificar_flood(self, guild_id: str, user_id: str, limite_mensajes: int = 4, ventana_segundos: int = 4) -> bool:
        """Detecta FLOOD - 7 mensajes en 4 segundos"""
        ahora = datetime.now(timezone.utc)
        key = f"{guild_id}:{user_id}"

        if key not in self.flood_history:
            self.flood_history[key] = []

        self.flood_history[key] = [
            timestamp for timestamp in self.flood_history[key]
            if (ahora - timestamp).total_seconds() < ventana_segundos
        ]

        self.flood_history[key].append(ahora)

        if len(self.flood_history[key]) >= limite_mensajes:
            print(f"[ANTI-FLOOD] 🚨 Usuario {user_id[-4:]} - {len(self.flood_history[key])} msgs en {ventana_segundos}s")
            return True

        return False

    def detectar_cadena_spam(self, guild_id: str, user_id: str, mensaje: str, ventana_segundos: int = 8) -> List[str]:
        """Detecta CADENAS - 5+ usuarios, 10+ caracteres, 3+ palabras, 95% similitud"""
        ahora = datetime.now(timezone.utc)

        mensaje_limpio = mensaje.strip()
        if len(mensaje_limpio) < 10:
            return []

        palabras = mensaje_limpio.split()
        if len(palabras) < 3:
            return []

        if guild_id not in self.spam_chains:
            self.spam_chains[guild_id] = {}

        # Limpiar antiguas
        mensajes_a_eliminar = []
        for msg_contenido in list(self.spam_chains[guild_id].keys()):
            self.spam_chains[guild_id][msg_contenido] = [
                (uid, ts) for uid, ts in self.spam_chains[guild_id][msg_contenido]
                if (ahora - ts).total_seconds() < ventana_segundos
            ]

            if not self.spam_chains[guild_id][msg_contenido]:
                mensajes_a_eliminar.append(msg_contenido)

        for msg in mensajes_a_eliminar:
            del self.spam_chains[guild_id][msg]

        mensaje_normalizado = mensaje.lower().strip()

        mensaje_key = mensaje_normalizado
        for msg_existente in list(self.spam_chains[guild_id].keys()):
            similitud = self._calcular_similitud(mensaje_normalizado, msg_existente.lower())

            if similitud > 0.95:
                mensaje_key = msg_existente
                break

        if mensaje_key not in self.spam_chains[guild_id]:
            self.spam_chains[guild_id][mensaje_key] = []

        usuarios_existentes = [uid for uid, _ in self.spam_chains[guild_id][mensaje_key]]
        if user_id not in usuarios_existentes:
            self.spam_chains[guild_id][mensaje_key].append((user_id, ahora))

        usuarios_unicos = list(set([uid for uid, _ in self.spam_chains[guild_id][mensaje_key]]))

        if len(usuarios_unicos) >= 5:
            print(f"[CADENA-SPAM] 🔥 {len(usuarios_unicos)} usuarios: '{mensaje_normalizado[:40]}'")
            return usuarios_unicos

        return []

    def _calcular_similitud(self, msg1: str, msg2: str) -> float:
        if msg1 == msg2:
            return 1.0

        len1, len2 = len(msg1), len(msg2)
        if len1 == 0 or len2 == 0:
            return 0.0

        if abs(len1 - len2) > min(len1, len2) * 0.2:
            return 0.0

        comunes = sum(1 for c in msg1 if c in msg2)
        return comunes / max(len1, len2)

    def limpiar_historial(self, guild_id: str, user_id: str):
        key = f"{guild_id}:{user_id}"

        if key in self.message_history:
            del self.message_history[key]

        if key in self.flood_history:
            del self.flood_history[key]

    def limpiar_cadena(self, guild_id: str, mensaje: str):
        mensaje_normalizado = mensaje.lower().strip()

        if guild_id in self.spam_chains:
            if mensaje_normalizado in self.spam_chains[guild_id]:
                del self.spam_chains[guild_id][mensaje_normalizado]

# ============ BOT CLASS ============

class AECAntiLinks(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.members = True
        super().__init__(command_prefix="!", intents=intents)

        self.db = JSONDatabase()
        self.config = self.db.cargar_config()
        self.infracciones = self.db.cargar_infracciones()
        self.sitios_personalizados = self.db.cargar_sitios_personalizados()
        self.blacklist_global = self.db.cargar_blacklist_global()
        self.sitios_bloqueados = set()

        self.link_detector = AdvancedLinkDetector()
        self.anti_spam = AntiSpamSystem()

        self.command_cooldowns = {}
        self.start_time = datetime.now(timezone.utc)

    async def setup_hook(self):
        await self.tree.sync()
        actualizar_base_maliciosa.start()
        guardar_datos_periodicamente.start()
        print("🔐 Sistema de seguridad BALANCEADO inicializado")

    async def on_ready(self):
        print(f'✅ Bot {self.user} conectado correctamente')
        print(f'🛡️ Activo en {len(self.guilds)} servidores')
        print(f'🌐 Dashboard: http://0.0.0.0:{SecurityConfig.WEB_PORT}')
        print(f'🔒 Sitios bloqueados: {len(self.sitios_bloqueados)}')
        print(f'⚖️ Modo Anti-Spam: BALANCEADO Y EFECTIVO')

        await self.change_presence(
            activity=discord.Activity(
                type=discord.ActivityType.watching,
                name="🛡️ spam y enlaces | /ayuda_antilinks"
            )
        )

SecurityConfig.validar_token()
bot = AECAntiLinks()

# ============ FLASK WEB DASHBOARD ============

app = Flask(__name__, static_folder='.', template_folder='.')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/style.css')
def css():
    return send_from_directory('.', 'style.css')

@app.route('/api/stats')
def api_stats():
    try:
        total_infracciones = sum(sum(data.get("count", 0) for data in infracciones.values()) for infracciones in bot.infracciones.values())
        total_usuarios_infractores = sum(len(infracciones) for infracciones in bot.infracciones.values())
        uptime = datetime.now(timezone.utc) - bot.start_time

        return jsonify({
            "success": True,
            "data": {
                "servidores": len(bot.guilds),
                "infracciones_totales": total_infracciones,
                "usuarios_infractores": total_usuarios_infractores,
                "sitios_bloqueados": len(bot.sitios_bloqueados),
                "uptime_horas": int(uptime.total_seconds() // 3600),
                "estado": "online"
            }
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/guilds')
def api_guilds():
    try:
        guilds_data = []
        for guild in bot.guilds:
            config = get_config(guild.id)
            guilds_data.append({
                "id": str(guild.id),
                "nombre": guild.name,
                "miembros": guild.member_count,
                "activo": config.get("activado", True),
                "icon": str(guild.icon.url) if guild.icon else None
            })
        return jsonify({"success": True, "data": guilds_data})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/config/<guild_id>', methods=['GET'])
def api_get_config(guild_id):
    try:
        config = get_config(int(guild_id))
        sitios_custom = list(bot.sitios_personalizados.get(guild_id, set()))

        return jsonify({
            "success": True,
            "data": {
                "activado": config.get("activado", True),
                "canal_logs": config.get("canal_logs"),
                "tiempo_muteo": config.get("tiempo_muteo", 300),
                "roles_permitidos": config.get("roles_permitidos", []),
                "whitelist_dominios": config.get("whitelist_dominios", []),
                "sitios_personalizados": sitios_custom,
                "detectar_maliciosos": config.get("detectar_maliciosos", True),
                "anti_spam_mensajes": config.get("anti_spam_mensajes", 5),
                "anti_spam_tiempo": config.get("anti_spam_tiempo", 10),
                "anti_spam_mute_duracion": config.get("anti_spam_mute_duracion", 300),
                "anti_spam_activado": config.get("anti_spam_activado", True)
            }
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/config/<guild_id>', methods=['POST'])
def api_update_config(guild_id):
    try:
        data = request.json
        config = get_config(int(guild_id))

        for key in ["activado", "tiempo_muteo", "roles_permitidos", "whitelist_dominios", 
                    "detectar_maliciosos", "anti_spam_mensajes", "anti_spam_tiempo", 
                    "anti_spam_mute_duracion", "anti_spam_activado"]:
            if key in data:
                config[key] = data[key]

        bot.db.guardar_config(bot.config)
        return jsonify({"success": True, "message": "Configuración actualizada"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/custom-sites/<guild_id>', methods=['POST'])
def api_add_custom_site(guild_id):
    try:
        data = request.json
        sitio = data.get("sitio", "").strip().lower()
        sitio = sitio.replace('http://', '').replace('https://', '').replace('www.', '').split('/')[0]

        if not sitio:
            return jsonify({"success": False, "error": "Sitio inválido"}), 400

        if guild_id not in bot.sitios_personalizados:
            bot.sitios_personalizados[guild_id] = set()

        bot.sitios_personalizados[guild_id].add(sitio)
        bot.db.guardar_sitios_personalizados(bot.sitios_personalizados)

        return jsonify({"success": True, "message": f"Sitio {sitio} bloqueado"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/custom-sites/<guild_id>/<sitio>', methods=['DELETE'])
def api_remove_custom_site(guild_id, sitio):
    try:
        if guild_id in bot.sitios_personalizados and sitio in bot.sitios_personalizados[guild_id]:
            bot.sitios_personalizados[guild_id].remove(sitio)
            bot.db.guardar_sitios_personalizados(bot.sitios_personalizados)
            return jsonify({"success": True, "message": f"Sitio {sitio} desbloqueado"})
        return jsonify({"success": False, "error": "Sitio no encontrado"}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/export/<guild_id>')
def api_export_config(guild_id):
    try:
        config = get_config(int(guild_id))
        sitios_custom = list(bot.sitios_personalizados.get(guild_id, set()))

        return jsonify({
            "success": True,
            "data": {
                "guild_id": guild_id,
                "config": config,
                "sitios_personalizados": sitios_custom,
                "exportado_en": datetime.now(timezone.utc).isoformat()
            }
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/import/<guild_id>', methods=['POST'])
def api_import_config(guild_id):
    try:
        data = request.json
        if "config" in data:
            config = get_config(int(guild_id))
            config.update(data["config"])
            bot.db.guardar_config(bot.config)

        if "sitios_personalizados" in data:
            bot.sitios_personalizados[guild_id] = set(data["sitios_personalizados"])
            bot.db.guardar_sitios_personalizados(bot.sitios_personalizados)

        return jsonify({"success": True, "message": "Configuración importada"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/health')
def health_check():
    return jsonify({"status": "healthy", "bot": "online"}), 200

def run_flask():
    app.run(host='0.0.0.0', port=SecurityConfig.WEB_PORT, debug=False)

# ============ FUNCIONES AUXILIARES ============

def get_config(guild_id):
    if str(guild_id) not in bot.config:
        bot.config[str(guild_id)] = {
            "canal_logs": None,
            "roles_permitidos": [],
            "tiempo_muteo": 300,
            "activado": True,
            "detectar_maliciosos": True,
            "whitelist_dominios": [],
            "anti_spam_mensajes": 5,
            "anti_spam_tiempo": 10,
            "anti_spam_mute_duracion": 300,
            "anti_spam_activado": True
        }
    return bot.config[str(guild_id)]

@tasks.loop(minutes=5)
async def guardar_datos_periodicamente():
    try:
        bot.db.guardar_config(bot.config)
        bot.db.guardar_infracciones(bot.infracciones)
        bot.db.guardar_sitios_personalizados(bot.sitios_personalizados)
        bot.db.guardar_blacklist_global(bot.blacklist_global)
    except Exception as e:
        print(f"❌ Error guardando: {e}")

@tasks.loop(hours=1)
async def actualizar_base_maliciosa():
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("https://urlhaus.abuse.ch/downloads/csv_online/", timeout=30) as resp:
                if resp.status == 200:
                    contenido = await resp.text()
                    sitios_nuevos = 0
                    for linea in contenido.split('\n'):
                        if not linea.startswith('#') and linea.strip():
                            partes = linea.split(',')
                            if len(partes) > 2:
                                dominio = partes[2].strip('"').replace('http://', '').replace('https://', '').split('/')[0].lower()
                                if dominio and dominio not in bot.sitios_bloqueados:
                                    bot.sitios_bloqueados.add(dominio)
                                    sitios_nuevos += 1
                    if sitios_nuevos > 0:
                        print(f"🔄 Base actualizada: +{sitios_nuevos} sitios ({len(bot.sitios_bloqueados)} total)")
    except Exception as e:
        print(f"❌ Error actualizando base: {e}")

# ============ EVENTO PRINCIPAL - BALANCEADO ============

@bot.event
async def on_message(message):
    if message.author.bot or not message.guild:
        await bot.process_commands(message)
        return

    if str(message.author.id) in bot.blacklist_global.get("usuarios", []):
        try:
            await message.delete()
        except:
            pass
        return

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

    # ============ ANTI-SPAM BALANCEADO ============
    if config.get("anti_spam_activado", True):
        guild_id_str = str(message.guild.id)
        user_id_str = str(message.author.id)
        mensaje_contenido = message.content

        # 1. VERIFICAR FLOOD
        es_flood = bot.anti_spam.verificar_flood(guild_id_str, user_id_str, limite_mensajes=7, ventana_segundos=4)

        if es_flood:
            try:
                await message.delete()

                duracion_mute = config.get("anti_spam_mute_duracion", 300)
                timeout_hasta = discord.utils.utcnow() + timedelta(seconds=duracion_mute)
                await message.author.timeout(timeout_hasta, reason="FLOOD detectado")

                embed = discord.Embed(
                    title="🚨 FLOOD Detectado",
                    description=f"{message.author.mention}, estás enviando mensajes demasiado rápido.",
                    color=discord.Color.red()
                )
                embed.add_field(name="⏱️ Duración", value=f"**{duracion_mute//60} minutos**", inline=True)

                await message.channel.send(embed=embed, delete_after=8)

                if config["canal_logs"]:
                    try:
                        canal_logs = bot.get_channel(config["canal_logs"])
                        if canal_logs:
                            log_embed = discord.Embed(title="🚨 FLOOD", color=discord.Color.red(), timestamp=datetime.now(timezone.utc))
                            log_embed.add_field(name="👤 Usuario", value=f"{message.author.mention}", inline=False)
                            log_embed.add_field(name="📍 Canal", value=message.channel.mention, inline=True)
                            await canal_logs.send(embed=log_embed)
                    except:
                        pass

                bot.anti_spam.limpiar_historial(guild_id_str, user_id_str)
                return
            except discord.errors.Forbidden:
                pass
            except Exception as e:
                print(f"Error FLOOD: {e}")
            return

        # 2. VERIFICAR CADENA
        usuarios_spammers = bot.anti_spam.detectar_cadena_spam(guild_id_str, user_id_str, mensaje_contenido, ventana_segundos=8)

        if usuarios_spammers:
            usuarios_muteados = []

            for spammer_id in usuarios_spammers:
                try:
                    member = message.guild.get_member(int(spammer_id))
                    if member and not member.guild_permissions.administrator:
                        duracion_mute = config.get("anti_spam_mute_duracion", 300)
                        timeout_hasta = discord.utils.utcnow() + timedelta(seconds=duracion_mute)

                        await member.timeout(timeout_hasta, reason="CADENA DE SPAM")
                        usuarios_muteados.append(member.mention)
                        bot.anti_spam.limpiar_historial(guild_id_str, spammer_id)
                except Exception as e:
                    print(f"Error muteando {spammer_id}: {e}")

            try:
                await message.delete()
            except:
                pass

            if usuarios_muteados:
                embed = discord.Embed(
                    title="🔥 CADENA DE SPAM",
                    description=f"**{len(usuarios_muteados)} usuarios** muteados por spam coordinado.",
                    color=discord.Color.red()
                )
                embed.add_field(name="👥 Usuarios", value=", ".join(usuarios_muteados[:10]), inline=False)

                await message.channel.send(embed=embed, delete_after=10)

                if config["canal_logs"]:
                    try:
                        canal_logs = bot.get_channel(config["canal_logs"])
                        if canal_logs:
                            log_embed = discord.Embed(title="🔥 CADENA SPAM", color=discord.Color.red(), timestamp=datetime.now(timezone.utc))
                            log_embed.add_field(name="👥 Participantes", value=f"{len(usuarios_muteados)} usuarios", inline=False)
                            await canal_logs.send(embed=log_embed)
                    except:
                        pass

            bot.anti_spam.limpiar_cadena(guild_id_str, mensaje_contenido)
            return

        # 3. VERIFICAR SPAM INDIVIDUAL
        es_spam = bot.anti_spam.verificar_spam(
            guild_id_str,
            user_id_str,
            mensaje_contenido,
            config.get("anti_spam_mensajes", 5),
            config.get("anti_spam_tiempo", 10)
        )

        if es_spam:
            try:
                await message.delete()

                duracion_mute = config.get("anti_spam_mute_duracion", 300)
                timeout_hasta = discord.utils.utcnow() + timedelta(seconds=duracion_mute)
                await message.author.timeout(timeout_hasta, reason="Spam detectado")

                embed = discord.Embed(
                    title="🚫 Anti-Spam",
                    description=f"{message.author.mention}, spam detectado. Muteado temporalmente.",
                    color=discord.Color.orange()
                )
                embed.add_field(name="⏱️ Duración", value=f"**{duracion_mute//60} minutos**", inline=True)

                await message.channel.send(embed=embed, delete_after=10)

                if config["canal_logs"]:
                    try:
                        canal_logs = bot.get_channel(config["canal_logs"])
                        if canal_logs:
                            log_embed = discord.Embed(title="🚫 Spam", color=discord.Color.orange(), timestamp=datetime.now(timezone.utc))
                            log_embed.add_field(name="👤 Usuario", value=f"{message.author.mention}", inline=False)
                            await canal_logs.send(embed=log_embed)
                    except:
                        pass

                bot.anti_spam.limpiar_historial(guild_id_str, user_id_str)
                return
            except discord.errors.Forbidden:
                pass
            except Exception as e:
                print(f"Error SPAM: {e}")
            return

    # ============ DETECCIÓN DE ENLACES ============
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
        if config["detectar_maliciosos"]:
            todos_sitios = bot.sitios_bloqueados.copy()
            if str(message.guild.id) in bot.sitios_personalizados:
                todos_sitios.update(bot.sitios_personalizados[str(message.guild.id)])

            for url, tipo in urls_filtradas:
                if bot.link_detector.verificar_url_maliciosa(url, todos_sitios):
                    es_maliciosa = True
                    break

        try:
            await message.delete()
        except:
            await bot.process_commands(message)
            return

        user_id = str(message.author.id)
        guild_id = str(message.guild.id)

        if guild_id not in bot.infracciones:
            bot.infracciones[guild_id] = {}

        if user_id not in bot.infracciones[guild_id]:
            bot.infracciones[guild_id][user_id] = {"count": 0, "muteos": 0, "ultimo_muteo": None}

        bot.infracciones[guild_id][user_id]["count"] += 1
        infracciones_total = bot.infracciones[guild_id][user_id]["count"]

        duracion = config["tiempo_muteo"]
        if infracciones_total > 3:
            duracion = min(duracion * infracciones_total // 2, SecurityConfig.MAX_MUTEO)

        timeout_hasta = discord.utils.utcnow() + timedelta(seconds=duracion)

        try:
            await message.author.timeout(timeout_hasta, reason="Enlace no autorizado")
            bot.infracciones[guild_id][user_id]["muteos"] += 1
            bot.infracciones[guild_id][user_id]["ultimo_muteo"] = datetime.now(timezone.utc)

            embed = discord.Embed(
                title="🛡️ AEC Anti-links",
                description=f"{message.author.mention}, enlaces no permitidos.",
                color=discord.Color.red() if es_maliciosa else discord.Color.orange()
            )
            embed.add_field(name="🚨 Tipo", value=f"**{'MALICIOSO' if es_maliciosa else 'NO AUTORIZADO'}**", inline=True)
            embed.add_field(name="📊 Infracción", value=f"**#{infracciones_total}**", inline=True)
            embed.add_field(name="⏱️ Mute", value=f"**{duracion//60} min**", inline=True)

            await message.channel.send(embed=embed, delete_after=15)

            if config["canal_logs"]:
                try:
                    canal_logs = bot.get_channel(config["canal_logs"])
                    if canal_logs:
                        log_embed = discord.Embed(title="📋 Enlace Bloqueado", color=discord.Color.red() if es_maliciosa else discord.Color.orange(), timestamp=datetime.now(timezone.utc))
                        log_embed.add_field(name="👤 Usuario", value=f"{message.author.mention}", inline=False)
                        log_embed.add_field(name="📊 Infracción #", value=infracciones_total, inline=True)
                        await canal_logs.send(embed=log_embed)
                except:
                    pass
        except discord.errors.Forbidden:
            pass
        except Exception as e:
            print(f"Error enlaces: {e}")

    await bot.process_commands(message)

# ============ COMANDOS SLASH ============

@bot.tree.command(name="ayuda_antilinks", description="Información del bot")
async def ayuda_antilinks(interaction: discord.Interaction):
    embed = discord.Embed(
        title="🛡️ AEC Anti-Links Dashboard",
        description=f"**Panel Web:** http://tu-dominio:{SecurityConfig.WEB_PORT}\n\n"
                    "**Protección Activa:**\n"
                    "✓ Detección avanzada de enlaces\n"
                    "✓ Sistema anti-spam balanceado\n"
                    "✓ Detección de FLOOD\n"
                    "✓ Detección de CADENAS de spam\n"
                    "✓ Dashboard web moderno\n",
        color=discord.Color.blue()
    )
    embed.add_field(
        name="📊 Estadísticas",
        value=f"Servidores: **{len(bot.guilds)}**\n"
              f"Sitios bloqueados: **{len(bot.sitios_bloqueados)}**",
        inline=False
    )
    embed.set_footer(text="AEC Anti-Links v3.2 | Sistema balanceado y efectivo")
    await interaction.response.send_message(embed=embed)

# ============ EJECUTAR BOT ============

if __name__ == "__main__":
    print("=" * 70)
    print("🛡️  AEC ANTI-LINKS BOT v3.2 - SISTEMA BALANCEADO")
    print("=" * 70)
    print(f"🌐 Puerto Web: {SecurityConfig.WEB_PORT}")
    print("⚖️ Modo: BALANCEADO - Detecta spam real sin falsos positivos")
    print("=" * 70)

    flask_thread = Thread(target=run_flask, daemon=True)
    flask_thread.start()

    print("✅ Dashboard web iniciado")
    print("🚀 Iniciando bot...")

    try:
        bot.run(SecurityConfig.TOKEN)
    except KeyboardInterrupt:
        print("\n⚠️ Bot detenido por el usuario")
    except Exception as e:
        print(f"\n❌ Error crítico: {e}")
