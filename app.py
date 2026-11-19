
import os
import sqlite3
import secrets
import hmac
from pathlib import Path
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from functools import wraps
from contextlib import contextmanager

from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash,
    abort
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


# ==========================================
# CONFIGURACIÓN GENERAL
# ==========================================

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DB_NAME = BASE_DIR / "incidentes.db"

SECRET_KEY = os.environ.get("SECRET_KEY")

if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise RuntimeError(
        "Configura SECRET_KEY con al menos "
        "32 caracteres aleatorios."
    )

app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.getenv("COOKIE_SECURE", "0") == "1"
    ),
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    MAX_CONTENT_LENGTH=1024 * 1024
)

ZONA_HORARIA = ZoneInfo("America/Bogota")

ESTADOS = {
    "Registrado",
    "En atención",
    "Resuelto"
}

PRIORIDADES = {
    "Baja",
    "Media",
    "Alta",
    "Crítica"
}

CATEGORIAS = {
    "Infraestructura / Aula",
    "Equipos / Audiovisuales",
    "Conectividad / Red",
    "Convivencia / Operación"
}


# ==========================================
# BASE DE DATOS
# ==========================================

def get_db_connection():
    conn = sqlite3.connect(
        DB_NAME,
        timeout=10
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


@contextmanager
def database():
    conn = get_db_connection()

    try:
        yield conn
        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def fecha_actual():
    return datetime.now(
        ZONA_HORARIA
    ).strftime("%Y-%m-%d %H:%M:%S")


def init_db():

    with database() as conn:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                nombre TEXT NOT NULL,
                rol TEXT NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)

        conn.execute("""
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
            )
        """)

        # Tabla independiente para trazabilidad

        conn.execute("""
            CREATE TABLE IF NOT EXISTS auditoria (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incidente_id INTEGER NOT NULL,
                usuario_id INTEGER NOT NULL,
                accion TEXT NOT NULL,
                detalle TEXT NOT NULL,
                fecha TEXT NOT NULL,

                FOREIGN KEY (incidente_id)
                    REFERENCES incidentes(id),

                FOREIGN KEY (usuario_id)
                    REFERENCES usuarios(id)
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_incidentes_estado_prioridad
            ON incidentes(estado, prioridad)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_auditoria_incidente
            ON auditoria(incidente_id, fecha)
        """)

        # Crear administrador inicial únicamente
        # cuando se suministre una clave segura.

        admin_password = os.getenv("ADMIN_PASSWORD")

        existe_admin = conn.execute(
            "SELECT id FROM usuarios WHERE username = ?",
            ("admin",)
        ).fetchone()

        if not existe_admin and admin_password:

            if len(admin_password) < 12:
                raise RuntimeError(
                    "ADMIN_PASSWORD debe tener "
                    "al menos 12 caracteres."
                )

            conn.execute("""
                INSERT INTO usuarios
                (username, nombre, rol, password_hash)
                VALUES (?, ?, ?, ?)
            """, (
                "admin",
                "Administrador",
                "Rol Administrador",
                generate_password_hash(admin_password)
            ))


# ==========================================
# PROTECCIÓN CSRF
# ==========================================

def csrf_token():
    token = session.get("_csrf_token")

    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token

    return token


@app.context_processor
def variables_globales():
    return {
        "csrf_token": csrf_token,
        "usuario": session.get("usuario"),
        "rol": session.get("rol"),
        "anio_actual": datetime.now(
            ZONA_HORARIA
        ).year
    }


@app.before_request
def proteger_formularios():

    if request.method in {
        "POST", "PUT", "PATCH", "DELETE"
    }:

        esperado = session.get("_csrf_token", "")
        recibido = (
            request.form.get("csrf_token", "")
            or request.headers.get("X-CSRFToken", "")
        )

        if (
            not esperado
            or not recibido
            or not hmac.compare_digest(
                esperado, recibido
            )
        ):
            abort(400, description="Token CSRF inválido.")


@app.after_request
def encabezados_seguridad(response):

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = (
        "strict-origin-when-cross-origin"
    )

    response.headers["Cache-Control"] = (
        "no-store"
    )

    return response


# ==========================================
# AUTENTICACIÓN Y PERMISOS
# ==========================================

def login_required(func):

    @wraps(func)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:
            flash(
                "Debes iniciar sesión para continuar.",
                "warning"
            )
            return redirect(url_for("login"))

        return func(*args, **kwargs)

    return wrapper


def admin_required(func):

    @wraps(func)
    @login_required
    def wrapper(*args, **kwargs):

        if session.get("rol") != "Rol Administrador":
            abort(403)

        return func(*args, **kwargs)

    return wrapper


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get(
            "username", ""
        ).strip().lower()

        password = request.form.get(
            "password", ""
        )

        with database() as conn:
            user = conn.execute("""
                SELECT *
                FROM usuarios
                WHERE username = ?
            """, (username,)).fetchone()

        if user and check_password_hash(
            user["password_hash"], password
        ):

            # Renovar sesión tras autenticación

            session.clear()
            session.permanent = True

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["usuario"] = user["nombre"]
            session["rol"] = user["rol"]

            flash(
                "Inicio de sesión exitoso.",
                "success"
            )

            return redirect(url_for("dashboard"))

        flash(
            "Usuario o contraseña incorrectos.",
            "danger"
        )

    return render_template("login.html")


# ==========================================
# RECUPERACIÓN DE CONTRASEÑA
# ==========================================

@app.route(
    "/restablecer-clave",
    methods=["POST"]
)
def restablecer_clave():

    # No aceptar cambios anónimos basados
    # únicamente en el nombre de usuario.
    #
    # Para producción, implementar tokens
    # temporales de un solo uso enviados a
    # una dirección verificada.

    flash(
        "El restablecimiento automático está "
        "deshabilitado. Contacta al administrador "
        "autorizado del sistema.",
        "warning"
    )

    return redirect(url_for("login"))


@app.route("/logout")
def logout():

    session.clear()

    flash(
        "Sesión finalizada correctamente.",
        "info"
    )

    return redirect(url_for("login"))


# ==========================================
# CONSULTA DE INCIDENTES
# ==========================================

CONSULTA_INCIDENTES = """
    SELECT
        id,
        codigo,
        titulo,
        categoria,
        espacio,
        espacio AS sede_o_espacio,
        prioridad,
        estado,
        asignado_a,
        reportado_por,
        descripcion,
        observaciones,
        fecha_registro,
        fecha_registro AS fecha_creacion
    FROM incidentes
"""


# ==========================================
# TABLERO PRINCIPAL
# ==========================================

@app.route("/")
@login_required
def dashboard():

    estado_filtro = request.args.get(
        "estado", "Todos"
    )

    prioridad_filtro = request.args.get(
        "prioridad", "Todas"
    )

    if estado_filtro not in ESTADOS | {"Todos"}:
        estado_filtro = "Todos"

    if prioridad_filtro not in PRIORIDADES | {"Todas"}:
        prioridad_filtro = "Todas"

    with database() as conn:

        resumen = conn.execute("""
            SELECT
                COUNT(*) AS total,

                SUM(
                    CASE WHEN estado = 'Registrado'
                    THEN 1 ELSE 0 END
                ) AS registrados,

                SUM(
                    CASE WHEN estado = 'En atención'
                    THEN 1 ELSE 0 END
                ) AS en_atencion,

                SUM(
                    CASE WHEN estado = 'Resuelto'
                    THEN 1 ELSE 0 END
                ) AS resueltos

            FROM incidentes
        """).fetchone()

        totales = {
            "total": resumen["total"] or 0,
            "registrados": resumen["registrados"] or 0,
            "en_atencion": resumen["en_atencion"] or 0,
            "resueltos": resumen["resueltos"] or 0
        }

        consulta = CONSULTA_INCIDENTES + " WHERE 1=1"
        parametros = []

        if estado_filtro != "Todos":

            consulta += " AND estado = ?"
            parametros.append(estado_filtro)

        if prioridad_filtro != "Todas":

            consulta += " AND prioridad = ?"
            parametros.append(prioridad_filtro)

        consulta += " ORDER BY id DESC"

        incidentes = conn.execute(
            consulta,
            parametros
        ).fetchall()

    return render_template(
        "dashboard.html",
        incidentes=incidentes,
        totales=totales,
        total=totales["total"],
        registrados=totales["registrados"],
        en_atencion=totales["en_atencion"],
        resueltos=totales["resueltos"],
        estado_filtro=estado_filtro,
        prioridad_filtro=prioridad_filtro
    )


# ==========================================
# REGISTRAR INCIDENTE
# ==========================================

@app.route("/registrar", methods=["GET", "POST"])
@login_required
def registrar():

    if request.method == "POST":

        titulo = request.form.get(
            "titulo", ""
        ).strip()

        categoria = request.form.get(
            "categoria", ""
        ).strip()

        # Compatibilidad con ambos nombres
        espacio = (
            request.form.get("sede_o_espacio")
            or request.form.get("espacio")
            or ""
        ).strip()

        prioridad = request.form.get(
            "prioridad", "Media"
        )

        asignado_a = request.form.get(
            "asignado_a", ""
        ).strip()

        # El servidor identifica al reportante
        reportado_por = session["usuario"]

        descripcion = request.form.get(
            "descripcion", ""
        ).strip()

        if not titulo or not descripcion:

            return render_template(
                "registrar.html",
                error=(
                    "Completa el título y "
                    "la descripción del incidente."
                )
            ), 400

        if len(titulo) > 200 or len(descripcion) > 5000:
            abort(400)

        if len(espacio) > 150 or len(asignado_a) > 120:
            abort(400)

        if categoria not in CATEGORIAS:
            abort(400)

        if prioridad not in PRIORIDADES:
            abort(400)

        with database() as conn:

            cursor = conn.execute("""
                INSERT INTO incidentes (
                    titulo,
                    categoria,
                    espacio,
                    prioridad,
                    estado,
                    asignado_a,
                    reportado_por,
                    descripcion,
                    fecha_registro
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                titulo,
                categoria,
                espacio or "General",
                prioridad,
                "Registrado",
                asignado_a or "Sin asignar",
                reportado_por,
                descripcion,
                fecha_actual()
            ))

            nuevo_id = cursor.lastrowid
            codigo = f"INC-{nuevo_id:03d}"

            conn.execute("""
                UPDATE incidentes
                SET codigo = ?
                WHERE id = ?
            """, (
                codigo,
                nuevo_id
            ))

            conn.execute("""
                INSERT INTO auditoria (
                    incidente_id,
                    usuario_id,
                    accion,
                    detalle,
                    fecha
                )
                VALUES (?, ?, ?, ?, ?)
            """, (
                nuevo_id,
                session["user_id"],
                "CREACIÓN",
                "Registro inicial del incidente",
                fecha_actual()
            ))

        flash(
            f"Incidente {codigo} registrado correctamente.",
            "success"
        )

        return redirect(url_for("dashboard"))

    return render_template("registrar.html")


# ==========================================
# DETALLE Y SEGUIMIENTO
# ==========================================

@app.route(
    "/incidente/<int:incidente_id>",
    methods=["GET", "POST"]
)
@login_required
def detalle(incidente_id):

    with database() as conn:

        incidente = conn.execute(
            CONSULTA_INCIDENTES + " WHERE id = ?",
            (incidente_id,)
        ).fetchone()

        if incidente is None:
            abort(404)

        if request.method == "POST":

            nuevo_estado = request.form.get(
                "estado", incidente["estado"]
            )

            nueva_prioridad = request.form.get(
                "prioridad", incidente["prioridad"]
            )

            nuevo_asignado = request.form.get(
                "asignado_a", ""
            ).strip()

            observaciones = request.form.get(
                "observaciones", ""
            ).strip()

            if nuevo_estado not in ESTADOS:
                abort(400)

            if nueva_prioridad not in PRIORIDADES:
                abort(400)

            if len(nuevo_asignado) > 120:
                abort(400)

            if len(observaciones) > 5000:
                abort(400)

            # Validación real en el servidor
            if (
                nuevo_estado == "Resuelto"
                and len(observaciones) < 15
            ):
                flash(
                    "Para resolver el incidente debes "
                    "registrar una solución de al menos "
                    "15 caracteres.",
                    "danger"
                )

                return redirect(url_for(
                    "detalle",
                    incidente_id=incidente_id
                ))

            anterior_estado = incidente["estado"]
            anterior_prioridad = incidente["prioridad"]
            anterior_asignado = incidente["asignado_a"]

            conn.execute("""
                UPDATE incidentes
                SET
                    estado = ?,
                    prioridad = ?,
                    asignado_a = ?,
                    observaciones = ?
                WHERE id = ?
            """, (
                nuevo_estado,
                nueva_prioridad,
                nuevo_asignado or "Sin asignar",
                observaciones,
                incidente_id
            ))

            detalle_cambio = (
                f"Estado: {anterior_estado} -> {nuevo_estado}; "
                f"Prioridad: {anterior_prioridad} -> "
                f"{nueva_prioridad}; "
                f"Responsable: {anterior_asignado} -> "
                f"{nuevo_asignado or 'Sin asignar'}; "
                f"Observaciones actualizadas."
            )

            conn.execute("""
                INSERT INTO auditoria (
                    incidente_id,
                    usuario_id,
                    accion,
                    detalle,
                    fecha
                )
                VALUES (?, ?, ?, ?, ?)
            """, (
                incidente_id,
                session["user_id"],
                "ACTUALIZACIÓN",
                detalle_cambio,
                fecha_actual()
            ))

        else:
            historial = conn.execute("""
                SELECT
                    a.accion,
                    a.detalle,
                    a.fecha,
                    u.nombre AS usuario
                FROM auditoria a
                JOIN usuarios u
                    ON u.id = a.usuario_id
                WHERE a.incidente_id = ?
                ORDER BY a.id DESC
            """, (incidente_id,)).fetchall()

    if request.method == "POST":

        flash(
            "Seguimiento actualizado correctamente.",
            "success"
        )

        return redirect(url_for(
            "detalle",
            incidente_id=incidente_id
        ))

    return render_template(
        "detalle.html",
        incidente=incidente,
        historial=historial
    )


# ==========================================
# MANEJO DE ERRORES
# ==========================================

@app.errorhandler(400)
def error_400(error):
    return (
        "Solicitud inválida o token de seguridad incorrecto.",
        400
    )


@app.errorhandler(403)
def error_403(error):
    return (
        "No tienes autorización para realizar esta acción.",
        403
    )


@app.errorhandler(404)
def error_404(error):
    return (
        "El recurso solicitado no existe.",
        404
    )


# ==========================================
# INICIALIZACIÓN
# ==========================================

if __name__ == "__main__":

    init_db()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
