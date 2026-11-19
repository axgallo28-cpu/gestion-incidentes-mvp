# Gestión de Incidentes Educativos — TRL 5

Sistema Flask + SQLite con inicio de sesión, seguimiento, bitácora y mapa mundial de Kaspersky integrado en el tablero.

## Instalación (Windows PowerShell)

```powershell
python -m pip install -r requirements.txt
python -c "import secrets; print(secrets.token_hex(32))"
$env:SECRET_KEY = 'PEGA_AQUI_LA_CLAVE_ALEATORIA_GENERADA'
$env:ADMIN_PASSWORD = 'UNA_CONTRASENA_SEGURA_DE_AL_MENOS_12_CARACTERES'
python app.py
```

Abre http://127.0.0.1:5000/login e ingresa con `admin` y la contraseña que definiste. `ADMIN_PASSWORD` solo se usa para crear el usuario inicial si no existe.

**Si ya tienes `incidentes.db`, haz copia de seguridad antes de actualizar.** No subas bases de datos reales ni secretos a GitHub. Para publicar con HTTPS configura `COOKIE_SECURE=1`. El mapa necesita acceso a internet y depende del servicio de Kaspersky.

## Estructura

- `app.py`: servidor Flask, autenticación, CSRF, incidentes y auditoría.
- `plantillas/`: vistas Jinja2; se configura con `template_folder='plantillas'`.
- `static/css/cyber.css`: diseño compartido.
- `static/images/cyber-escudo.svg`: ilustración local original del fondo.
- `requirements.txt`: Flask.

## Seguridad pendiente antes de producción

Agregar límites de intentos de acceso, administración de cuentas con autorización, recuperación de contraseña con verificación, permisos por acción, pruebas automatizadas, migraciones controladas y despliegue HTTPS/WSGI. El visor externo no detecta incidentes locales. No representa todos los ataques del mundo.

## Importante

- El paquete incluye una ilustración SVG local de ciberseguridad: no es una captura de pantalla ni contiene textos de formulario.
- El visor de Kaspersky se carga por iframe dentro del tablero; si el proveedor restringe la inserción, usa el enlace «Abrir mapa completo».
- `tzdata` permite utilizar la zona horaria America/Bogota también en Windows.
- Las cuentas heredadas conservan sus contraseñas; no publiques el proyecto con claves de prueba.
