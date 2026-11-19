import hmac
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
                password_hash TEXT NOT NULL
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
            CREATE INDEX IF NOT EXISTS idx_incidentes_estado ON incidentes(estado, prioridad);
            CREATE INDEX IF NOT EXISTS idx_auditoria_incidente ON auditoria(incidente_id, id);
        ''')
        existe = conn.execute("SELECT id FROM usuarios WHERE username='admin'").fetchone()
        clave_admin = os.getenv('ADMIN_PASSWORD', '')
        if not existe:
            if len(clave_admin) < 12:
                raise RuntimeError('Para crear el usuario inicial, define ADMIN_PASSWORD con 12 caracteres o más.')
            conn.execute('INSERT INTO usuarios(username, nombre, rol, password_hash) VALUES (?, ?, ?, ?)',
                         ('admin', 'Administrador', 'Rol Administrador', generate_password_hash(clave_admin)))


def login_required(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            flash('Inicia sesión para continuar.', 'warning')
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return wrapped


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
            session.update(user_id=user['id'], username=user['username'], usuario=user['nombre'], rol=user['rol'])
            flash('Sesión iniciada correctamente.', 'success')
            return redirect(url_for('dashboard'))
        flash('Usuario o contraseña incorrectos.', 'danger')
    return render_template('login.html')


@app.route('/restablecer-clave', methods=['POST'])
def restablecer_clave():
    # No permitir restablecimientos anónimos sin verificación de identidad.
    flash('El restablecimiento requiere verificación por un administrador autorizado.', 'warning')
    return redirect(url_for('login'))


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
    return render_template('dashboard.html', incidentes=incidentes, totales=totales,
                           estado_filtro=estado, prioridad_filtro=prioridad)


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
    return render_template('detalle.html', incidente=incidente, historial=historial)


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
_CACHE_NOTICIAS = {"actualizado": 0.0, "noticias": [], "errores": []}
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
