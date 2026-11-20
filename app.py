import hmac
import json
import urllib.error
import urllib.request
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from zoneinfo import ZoneInfo

from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_NAME = BASE_DIR / 'incidentes.db'
TZ = ZoneInfo('America/Bogota')
ESTADOS = ('Registrado', 'En atención', 'Resuelto')
PRIORIDADES = ('Baja', 'Media', 'Alta', 'Crítica')
CATEGORIAS = ('Infraestructura / Aula', 'Equipos / Audiovisuales', 'Conectividad / Red', 'Convivencia / Operación', 'Seguridad de la Información')

app = Flask(__name__, template_folder='plantillas')
secret_key = os.getenv('SECRET_KEY', '')
if len(secret_key) < 32:
    raise RuntimeError('Define SECRET_KEY con al menos 32 caracteres aleatorios antes de iniciar Flask.')
app.config.update(
    SECRET_KEY=secret_key,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.getenv('COOKIE_SECURE', '0') == '1',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    MAX_CONTENT_LENGTH=1024 * 1024,
)


def enviar_alerta_admin(asunto, contenido):
    """Envía correo transaccional al administrador usando Resend por HTTPS.

    Los fallos de correo NO interrumpen el registro de incidentes ni las
    solicitudes de recuperación. Nunca envía contraseñas ni claves API.
    """
    api_key = os.getenv('RESEND_API_KEY', '').strip()
    destinatario = os.getenv('ADMIN_EMAIL', '').strip()
    remitente = os.getenv('MAIL_FROM', 'onboarding@resend.dev').strip()
    if not api_key or not destinatario or not remitente:
        app.logger.warning('Notificación de correo omitida: configuración incompleta.')
        return False
    if '\r' in destinatario or '\n' in destinatario:
        app.logger.warning('ADMIN_EMAIL no es válido.')
        return False

    cuerpo = json.dumps({
        'from': remitente,
        'to': [destinatario],
        'subject': asunto,
        'text': contenido,
    }, ensure_ascii=False).encode('utf-8')
    solicitud = urllib.request.Request(
        'https://api.resend.com/emails',
        data=cuerpo,
        headers={
            'Authorization': 'Bearer ' + api_key,
            'Content-Type': 'application/json',
            'User-Agent': 'gestion-incidentes-educativos/1.0',
        },
        method='POST',
    )
    try:
        with urllib.request.urlopen(solicitud, timeout=8) as respuesta:
            return 200 <= respuesta.status < 300
    except urllib.error.HTTPError as error:
        app.logger.warning('Resend no aceptó el envío (HTTP %s).', error.code)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        app.logger.warning('No se pudo entregar aviso a Resend (%s).', type(error).__name__)
    return False


def ahora():
    return datetime.now(TZ).strftime('%Y-%m-%d %H:%M:%S')


@contextmanager
def db():
    conn = sqlite3.connect(DB_NAME, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    conn.execute('PRAGMA busy_timeout = 10000')
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with db() as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                nombre TEXT NOT NULL,
                rol TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                cambiar_clave INTEGER NOT NULL DEFAULT 0,
                version_sesion INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS incidentes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                codigo TEXT UNIQUE,
                titulo TEXT NOT NULL,
                categoria TEXT NOT NULL,
                espacio TEXT NOT NULL,
                prioridad TEXT NOT NULL,
                estado TEXT NOT NULL DEFAULT 'Registrado',
                asignado_a TEXT NOT NULL,
                reportado_por TEXT NOT NULL,
                descripcion TEXT NOT NULL,
                observaciones TEXT DEFAULT '',
                fecha_registro TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS auditoria (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incidente_id INTEGER NOT NULL,
                usuario_id INTEGER NOT NULL,
                accion TEXT NOT NULL,
                detalle TEXT NOT NULL,
                fecha TEXT NOT NULL,
                FOREIGN KEY(incidente_id) REFERENCES incidentes(id),
                FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
            );
            CREATE TABLE IF NOT EXISTS solicitudes_clave (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario_id INTEGER NOT NULL,
                fecha_solicitud TEXT NOT NULL,
                estado TEXT NOT NULL DEFAULT 'Pendiente',
                fecha_resolucion TEXT,
                FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
            );
            CREATE INDEX IF NOT EXISTS idx_solicitudes_usuario ON solicitudes_clave(usuario_id, estado);
            CREATE INDEX IF NOT EXISTS idx_incidentes_estado ON incidentes(estado, prioridad);
            CREATE INDEX IF NOT EXISTS idx_auditoria_incidente ON auditoria(incidente_id, id);
        ''')
        # Migración compatible con bases de datos ya existentes.
        columnas = {fila['name'] for fila in conn.execute('PRAGMA table_info(usuarios)')}
        if 'cambiar_clave' not in columnas:
            conn.execute('ALTER TABLE usuarios ADD COLUMN cambiar_clave INTEGER NOT NULL DEFAULT 0')
        if 'version_sesion' not in columnas:
            conn.execute('ALTER TABLE usuarios ADD COLUMN version_sesion INTEGER NOT NULL DEFAULT 0')
        existe = conn.execute("SELECT id FROM usuarios WHERE username='admin'").fetchone()
        clave_admin = os.getenv('ADMIN_PASSWORD', '')
        if not existe:
            if len(clave_admin) < 12:
                raise RuntimeError('Para crear el usuario inicial, define ADMIN_PASSWORD con 12 caracteres o más.')
            conn.execute('INSERT INTO usuarios(username, nombre, rol, password_hash) VALUES (?, ?, ?, ?)',
                         ('admin', 'Administrador', 'Rol Administrador', generate_password_hash(clave_admin)))

        # Dos cuentas independientes para evaluación: consulta y registro.
        # Se crean únicamente si existe su variable de entorno y aún no existen.
        for numero in (1, 2):
            nombre_usuario = f'evaluador{numero}'
            password = os.getenv(f'EVALUADOR{numero}_PASSWORD', '')
            if not password:
                continue
            if len(password) < 12:
                raise RuntimeError(f'EVALUADOR{numero}_PASSWORD debe tener al menos 12 caracteres.')
            registrado = conn.execute('SELECT id FROM usuarios WHERE username=?', (nombre_usuario,)).fetchone()
            if not registrado:
                conn.execute(
                    'INSERT INTO usuarios(username, nombre, rol, password_hash) VALUES (?, ?, ?, ?)',
                    (nombre_usuario, f'Evaluador {numero}', 'Registrador', generate_password_hash(password))
                )


def login_required(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        usuario_id = session.get('user_id')
        if not usuario_id:
            flash('Inicia sesión para continuar.', 'warning')
            return redirect(url_for('login'))
        with db() as conn:
            usuario_actual = conn.execute(
                'SELECT id, cambiar_clave, version_sesion FROM usuarios WHERE id=?',
                (usuario_id,)
            ).fetchone()
        if not usuario_actual or session.get('version_sesion') != usuario_actual['version_sesion']:
            session.clear()
            flash('Tu sesión ya no es válida. Inicia sesión nuevamente.', 'warning')
            return redirect(url_for('login'))
        if usuario_actual['cambiar_clave'] and request.endpoint not in ('cambiar_clave', 'logout'):
            return redirect(url_for('cambiar_clave'))
        return func(*args, **kwargs)
    return wrapped


def es_administrador():
    """Obtiene el rol efectivo desde SQLite, no desde datos enviados por el navegador."""
    usuario_id = session.get('user_id')
    if not usuario_id:
        return False
    with db() as conn:
        usuario_actual = conn.execute('SELECT username, rol FROM usuarios WHERE id=?', (usuario_id,)).fetchone()
    return bool(usuario_actual and usuario_actual['username'] == 'admin'
                and usuario_actual['rol'] == 'Rol Administrador')


def requiere_administrador_para_modificar():
    if not es_administrador():
        abort(403, 'Solo el administrador puede modificar o cerrar incidentes.')


def csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_urlsafe(32)
    return session['_csrf_token']


@app.context_processor
def globales():
    return {'csrf_token': csrf_token, 'usuario': session.get('usuario'), 'rol': session.get('rol'),
            'anio_actual': datetime.now(TZ).year}


@app.before_request
def verificar_csrf():
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        token = request.form.get('csrf_token', '') or request.headers.get('X-CSRFToken', '')
        esperado = session.get('_csrf_token', '')
        if not token or not esperado or not hmac.compare_digest(token, esperado):
            abort(400, 'Formulario inválido o expirado. Recarga la página.')


@app.after_request
def seguridad_respuesta(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        with db() as conn:
            user = conn.execute('SELECT * FROM usuarios WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session.permanent = True
            session.update(user_id=user['id'], username=user['username'], usuario=user['nombre'], rol=user['rol'], version_sesion=user['version_sesion'])
            if user['cambiar_clave']:
                return redirect(url_for('cambiar_clave'))
            flash('Sesión iniciada correctamente.', 'success')
            return redirect(url_for('dashboard'))
        flash('Usuario o contraseña incorrectos.', 'danger')
    return render_template('login.html')


@app.route('/restablecer-clave', methods=['POST'])
def restablecer_clave():
    """Solo solicita recuperación; nunca cambia contraseñas anónimamente."""
    username = request.form.get('reset_username', '').strip().lower()[:100]
    solicitud_nueva = False
    if username in ('evaluador1', 'evaluador2'):
        with db() as conn:
            user = conn.execute('SELECT id FROM usuarios WHERE username=?', (username,)).fetchone()
            if user:
                abierta = conn.execute(
                    "SELECT id, fecha_solicitud FROM solicitudes_clave WHERE usuario_id=? AND estado='Pendiente' ORDER BY id DESC LIMIT 1",
                    (user['id'],)
                ).fetchone()
                if not abierta:
                    conn.execute(
                        'INSERT INTO solicitudes_clave(usuario_id, fecha_solicitud) VALUES (?, ?)',
                        (user['id'], ahora())
                    )
                    solicitud_nueva = True
    if solicitud_nueva:
        enviar_alerta_admin(
            'Solicitud de recuperación de acceso - Gestión de Incidentes',
            f'El usuario {username} solicitó recuperar su acceso.\n'
            f'Fecha: {ahora()} (Colombia).\n'
            'Ingresa al sistema y verifica su identidad antes de restablecer.\n'
            'Panel: ' + url_for('administrar_recuperaciones', _external=True) + '\n'
            'No envíes contraseñas por correo.',
        )
    # Mismo mensaje para usuarios inexistentes, sin revelar su existencia.
    flash('Si la cuenta está habilitada, la solicitud quedó registrada. Contacta al administrador por un canal conocido para verificar tu identidad.', 'info')
    return redirect(url_for('login'))


@app.route('/administrar/recuperaciones', methods=['GET', 'POST'])
@login_required
def administrar_recuperaciones():
    if not es_administrador():
        abort(403)
    temporal = None
    usuario_modificado = None
    if request.method == 'POST':
        solicitud_id = request.form.get('solicitud_id', type=int)
        clave_admin_actual = request.form.get('password_admin', '')
        if not solicitud_id or not clave_admin_actual:
            flash('Verifica los datos antes de continuar.', 'danger')
        else:
            with db() as conn:
                admin = conn.execute('SELECT password_hash FROM usuarios WHERE id=?', (session['user_id'],)).fetchone()
                if not admin or not check_password_hash(admin['password_hash'], clave_admin_actual):
                    flash('La contraseña del administrador no es correcta.', 'danger')
                else:
                    solicitud = conn.execute("""
                        SELECT s.id, u.id AS usuario_id, u.username
                        FROM solicitudes_clave s JOIN usuarios u ON u.id=s.usuario_id
                        WHERE s.id=? AND s.estado='Pendiente'
                    """, (solicitud_id,)).fetchone()
                    if not solicitud or solicitud['username'] not in ('evaluador1', 'evaluador2'):
                        flash('La solicitud no está disponible.', 'warning')
                    else:
                        # Contraseña temporal aleatoria: mostrada una sola vez.
                        temporal = secrets.token_urlsafe(20)
                        usuario_modificado = solicitud['username']
                        conn.execute("""UPDATE usuarios
                            SET password_hash=?, cambiar_clave=1, version_sesion=version_sesion+1
                            WHERE id=?""", (generate_password_hash(temporal), solicitud['usuario_id']))
                        conn.execute("""UPDATE solicitudes_clave SET estado='Atendida', fecha_resolucion=?
                            WHERE id=?""", (ahora(), solicitud['id']))
    with db() as conn:
        pendientes = conn.execute("""SELECT s.id, s.fecha_solicitud, u.username
            FROM solicitudes_clave s JOIN usuarios u ON u.id=s.usuario_id
            WHERE s.estado='Pendiente' ORDER BY s.id DESC LIMIT 50""").fetchall()
    return render_template('administrar_recuperaciones.html', pendientes=pendientes,
                           temporal=temporal, usuario_modificado=usuario_modificado)


@app.route('/cambiar-clave', methods=['GET', 'POST'])
@login_required
def cambiar_clave():
    if request.method == 'POST':
        actual = request.form.get('clave_actual', '')
        nueva = request.form.get('nueva_clave', '')
        confirmar = request.form.get('confirmar_clave', '')
        if len(nueva) < 12 or nueva != confirmar or nueva == actual:
            flash('La nueva contraseña debe tener al menos 12 caracteres, coincidir y ser diferente de la anterior.', 'danger')
        else:
            with db() as conn:
                usuario_actual = conn.execute('SELECT password_hash FROM usuarios WHERE id=?', (session['user_id'],)).fetchone()
                if not usuario_actual or not check_password_hash(usuario_actual['password_hash'], actual):
                    flash('La contraseña actual o temporal no es correcta.', 'danger')
                else:
                    conn.execute("""UPDATE usuarios SET password_hash=?, cambiar_clave=0,
                                   version_sesion=version_sesion+1 WHERE id=?""",
                                 (generate_password_hash(nueva), session['user_id']))
                    version = conn.execute('SELECT version_sesion FROM usuarios WHERE id=?', (session['user_id'],)).fetchone()['version_sesion']
                    session['version_sesion'] = version
                    flash('Contraseña actualizada correctamente.', 'success')
                    return redirect(url_for('dashboard'))
    return render_template('cambiar_clave.html')


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))


CONSULTA = '''SELECT id, codigo, titulo, categoria, espacio, espacio AS sede_o_espacio,
                    prioridad, estado, asignado_a, reportado_por, descripcion, observaciones,
                    fecha_registro, fecha_registro AS fecha_creacion FROM incidentes'''


@app.route('/')
@login_required
def dashboard():
    estado = request.args.get('estado', 'Todos')
    prioridad = request.args.get('prioridad', 'Todas')
    if estado not in (*ESTADOS, 'Todos'):
        estado = 'Todos'
    if prioridad not in (*PRIORIDADES, 'Todas'):
        prioridad = 'Todas'
    with db() as conn:
        row = conn.execute('''SELECT COUNT(*) total,
          SUM(CASE WHEN estado='Registrado' THEN 1 ELSE 0 END) registrados,
          SUM(CASE WHEN estado='En atención' THEN 1 ELSE 0 END) en_atencion,
          SUM(CASE WHEN estado='Resuelto' THEN 1 ELSE 0 END) resueltos FROM incidentes''').fetchone()
        totales = {key: row[key] or 0 for key in ('total', 'registrados', 'en_atencion', 'resueltos')}
        consulta, params = CONSULTA + ' WHERE 1=1', []
        if estado != 'Todos':
            consulta += ' AND estado=?'
            params.append(estado)
        if prioridad != 'Todas':
            consulta += ' AND prioridad=?'
            params.append(prioridad)
        incidentes = conn.execute(consulta + ' ORDER BY id DESC', params).fetchall()
    # Titulares publicos; no equivalen a ciberataques confirmados.
    noticias, errores_noticias = noticias_universitarias()
    noticias_unad = [n for n in noticias if n['categoria'] == 'UNAD']
    noticias_otras = [n for n in noticias if n['categoria'] != 'UNAD']
    return render_template(
        'dashboard.html', incidentes=incidentes, totales=totales,
        estado_filtro=estado, prioridad_filtro=prioridad,
        noticias=noticias, noticias_unad=noticias_unad,
        noticias_otras=noticias_otras, errores_noticias=errores_noticias,
        noticias_actualizado=_CACHE_NOTICIAS.get('fecha_consulta', ''),
    )


@app.route('/registrar', methods=['GET', 'POST'])
@login_required
def registrar():
    if request.method == 'POST':
        titulo = request.form.get('titulo', '').strip()
        categoria = request.form.get('categoria', '').strip()
        espacio = (request.form.get('sede_o_espacio') or request.form.get('espacio') or '').strip()
        prioridad = request.form.get('prioridad', '')
        asignado = request.form.get('asignado_a', '').strip() or 'Sin asignar'
        descripcion = request.form.get('descripcion', '').strip()
        if not (1 <= len(titulo) <= 200 and 1 <= len(descripcion) <= 5000):
            flash('Completa el título y la descripción (máximo 200 y 5000 caracteres).', 'danger')
            return render_template('registrar.html', categorias=CATEGORIAS), 400
        if categoria not in CATEGORIAS or prioridad not in PRIORIDADES or len(espacio) > 150 or len(asignado) > 120:
            abort(400)
        with db() as conn:
            cur = conn.execute('''INSERT INTO incidentes
                (titulo, categoria, espacio, prioridad, estado, asignado_a, reportado_por, descripcion, fecha_registro)
                VALUES (?, ?, ?, ?, 'Registrado', ?, ?, ?, ?)''',
                (titulo, categoria, espacio or 'General', prioridad, asignado, session['usuario'], descripcion, ahora()))
            codigo = f'INC-{cur.lastrowid:03d}'
            conn.execute('UPDATE incidentes SET codigo=? WHERE id=?', (codigo, cur.lastrowid))
            conn.execute('''INSERT INTO auditoria(incidente_id, usuario_id, accion, detalle, fecha)
                VALUES (?, ?, ?, ?, ?)''', (cur.lastrowid, session['user_id'], 'CREACIÓN', 'Registro inicial', ahora()))
        # El incidente ya fue confirmado en SQLite antes del intento de envío.
        enviar_alerta_admin(
            ('[PRIORIDAD CRÍTICA] ' if prioridad == 'Crítica' else '')
            + f'Nuevo incidente registrado: {codigo}',
            f'Código: {codigo}\nTítulo: {titulo}\n'
            f'Prioridad: {prioridad}\nRegistrado por: {session["usuario"]}\n'
            f'Fecha: {ahora()} (Colombia).\n'
            'Ingresa al tablero para revisar los detalles: '
            + url_for('dashboard', _external=True),
        )
        flash(f'{codigo} registrado correctamente.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('registrar.html', categorias=CATEGORIAS)


@app.route('/incidente/<int:incidente_id>', methods=['GET', 'POST'])
@login_required
def detalle(incidente_id):
    with db() as conn:
        incidente = conn.execute(CONSULTA + ' WHERE id=?', (incidente_id,)).fetchone()
        if not incidente:
            abort(404)
        if request.method == 'POST':
            requiere_administrador_para_modificar()
            estado = request.form.get('estado', '')
            prioridad = request.form.get('prioridad', '')
            asignado = request.form.get('asignado_a', '').strip() or 'Sin asignar'
            observaciones = request.form.get('observaciones', '').strip()
            if estado not in ESTADOS or prioridad not in PRIORIDADES or len(asignado) > 120 or len(observaciones) > 5000:
                abort(400)
            if estado == 'Resuelto' and len(observaciones) < 15:
                flash('Para resolverlo, describe la solución en al menos 15 caracteres.', 'danger')
                return redirect(url_for('detalle', incidente_id=incidente_id))
            cambios = (f"Estado: {incidente['estado']} → {estado}; prioridad: {incidente['prioridad']} → {prioridad}; "
                       f"responsable: {incidente['asignado_a']} → {asignado}; observaciones actualizadas")
            conn.execute('''UPDATE incidentes SET estado=?, prioridad=?, asignado_a=?, observaciones=? WHERE id=?''',
                         (estado, prioridad, asignado, observaciones, incidente_id))
            conn.execute('''INSERT INTO auditoria(incidente_id, usuario_id, accion, detalle, fecha)
                VALUES (?, ?, ?, ?, ?)''', (incidente_id, session['user_id'], 'ACTUALIZACIÓN', cambios, ahora()))
        else:
            historial = conn.execute('''SELECT a.*, u.nombre AS usuario FROM auditoria a
                JOIN usuarios u ON u.id=a.usuario_id WHERE a.incidente_id=? ORDER BY a.id DESC''',
                (incidente_id,)).fetchall()
    if request.method == 'POST':
        flash('Seguimiento actualizado correctamente.', 'success')
        return redirect(url_for('detalle', incidente_id=incidente_id))
    return render_template('detalle.html', incidente=incidente, historial=historial, puede_editar=es_administrador())


@app.errorhandler(400)
def error_400(error):
    return 'Solicitud inválida o formulario expirado. Regresa y recarga la página.', 400


@app.errorhandler(403)
def error_403(error):
    return 'Acceso no autorizado.', 403


@app.errorhandler(404)
def error_404(error):
    return 'Página o incidente no encontrado.', 404




# ==========================================
# MONITOR DE NOTICIAS DE CIBERSEGURIDAD
# Prioridad: UNAD / sector universitario colombiano
# ==========================================
import time
import threading
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import timezone
from email.utils import parsedate_to_datetime

CONSULTAS_NOTICIAS = {
    "UNAD": '"UNAD" (ciberataque OR hackeo OR filtración OR ransomware OR ciberseguridad) when:30d',
    "Universidades de Colombia": '(universidad OR universidades) Colombia (ciberataque OR ransomware OR filtración OR phishing) when:30d',
}

_CADUCIDAD_NOTICIAS = 1800  # 30 minutos por proceso; no es una tarea en segundo plano.
_CACHE_NOTICIAS = {"actualizado": 0.0, "noticias": [], "errores": [], "fecha_consulta": ""}
_CERROJO_NOTICIAS = threading.Lock()


def consultar_rss(categoria, consulta):
    """Lee titulares del RSS público de Google News. No implica confirmar un ataque."""
    parametros = urllib.parse.urlencode({
        "q": consulta, "hl": "es-419", "gl": "CO", "ceid": "CO:es-419"
    })
    url = "https://news.google.com/rss/search?" + parametros
    peticion = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (AcademicThreatMonitor/1.0)"}
    )
    with urllib.request.urlopen(peticion, timeout=8) as respuesta:
        xml = respuesta.read(1024 * 1024)
    raiz = ET.fromstring(xml)
    noticias = []
    for item in raiz.findall("./channel/item")[:15]:
        titulo = (item.findtext("title") or "").strip()
        enlace = (item.findtext("link") or "").strip()
        publicada = (item.findtext("pubDate") or "").strip()
        origen = item.find("source")
        fuente = (origen.text or "").strip() if origen is not None else "Fuente sin identificar"
        if not titulo or not enlace.startswith("https://news.google.com/"):
            continue
        orden = 0.0
        fecha = "Fecha no disponible"
        try:
            parsed = parsedate_to_datetime(publicada)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            orden = parsed.timestamp()
            fecha = parsed.astimezone(TZ).strftime("%d/%m/%Y %H:%M")
        except (ValueError, TypeError, OverflowError):
            pass
        noticias.append({
            "categoria": categoria,
            "titulo": titulo[:320],
            "enlace": enlace,
            "fuente": fuente[:100],
            "fecha": fecha,
            "orden": orden,
        })
    return noticias


def noticias_universitarias():
    """Actualiza bajo demanda cada 30 min y conserva cache si falla una fuente."""
    with _CERROJO_NOTICIAS:
        momento = time.monotonic()
        if momento - _CACHE_NOTICIAS["actualizado"] < _CADUCIDAD_NOTICIAS:
            return _CACHE_NOTICIAS["noticias"], _CACHE_NOTICIAS["errores"]
        unicas = {}
        fallos = []
        for categoria, consulta in CONSULTAS_NOTICIAS.items():
            try:
                for noticia in consultar_rss(categoria, consulta):
                    clave = noticia["titulo"].casefold()
                    if clave not in unicas:
                        unicas[clave] = noticia
            except (OSError, ValueError, ET.ParseError) as ex:
                app.logger.warning("Error consultando titulares (%s): %s", categoria, ex)
                fallos.append(categoria)
        noticias = sorted(
            unicas.values(),
            key=lambda n: (n["categoria"] != "UNAD", -n["orden"])
        )[:20]
        if noticias:
            _CACHE_NOTICIAS["noticias"] = noticias
        _CACHE_NOTICIAS["errores"] = fallos
        _CACHE_NOTICIAS["actualizado"] = momento
        _CACHE_NOTICIAS["fecha_consulta"] = ahora()
        return _CACHE_NOTICIAS["noticias"], fallos


@app.route('/amenazas-universitarias')
@login_required
def amenazas_universitarias():
    noticias, errores = noticias_universitarias()
    return render_template('amenazas_universitarias.html', noticias=noticias, errores=errores)

# Se inicializa tanto con python app.py como con un servidor WSGI.
init_db()


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
