# remind2keep

Notas y organización rápida para auditorías de pentesting y CTFs, con una interfaz nativa de Linux pensada para no romper el ritmo durante una auditoría real.

Nada de pestañas del navegador, nada de apps web con login: un único archivo `.r2k.json` por proyecto, en tu disco, que puedes cifrar, llevarte, archivar o subir a tu propio repo privado.

## Características

- **Vista jerárquica Red → Target → Escenario.** Organiza el engagement como lo piensas: redes para escenarios de pivoting (`10.0.3.0/24`), targets dentro de cada red, y varios escenarios por target si necesitas separar hipótesis o fases de ataque.
- **Plantilla de campos para cada escenario:** posibles usuarios, tecnologías y versiones, hallazgos principales y pendientes — todo visible a la vez, sin cambiar de pestaña.
- **Tabla de credenciales con acciones rápidas:** copia usuario o contraseña con un clic, y genera al instante el comando de `hydra`, `netexec`, `evil-winrm`, `impacket`, etc. según el servicio indicado.
- **Checklist de pendientes real:** casillas de verificación, no texto suelto con `[ ]` a mano.
- **Cifrado local del proyecto:** derivación de clave con **Scrypt** (parámetros recomendados por OWASP) y cifrado autenticado con **Fernet** (AES-128-CBC + HMAC-SHA256). La contraseña nunca se escribe a disco; solo vive en memoria mientras la app está abierta.
- **Mapa de pivoting.** Marca qué targets dan acceso a qué otras redes y visualízalo como un grafo — de un vistazo ves la ruta de pivoting del engagement.
- **Búsqueda global (`Ctrl+K`)** sobre redes, targets, escenarios, credenciales (sin incluir contraseñas, por seguridad), hallazgos y pendientes.
- **Exportación a Markdown** del proyecto completo, lista para pegar en un informe o writeup.
- **Tema claro/oscuro**, persistido entre sesiones.
- **Guardado automático** con escritura atómica (nunca te deja un archivo a medias si la app se cierra de golpe).
- **Ligera y nativa:** PyQt6 + `cryptography`, sin Electron, sin base de datos, sin servidor local.

## Capturas

*(añade aquí un par de capturas de pantalla del árbol de redes, la tabla de credenciales y el mapa de pivoting una vez las tengas — ayuda mucho en el README del repo)*

## Instalación rápida

Requisitos: Linux, Python 3.9+, y el paquete `python3-venv` de tu distro (en Debian/Ubuntu/Kali: `sudo apt install python3-venv`).

```bash
git clone https://github.com/tu-usuario/remind2keep.git
cd remind2keep
chmod +x install.sh
./install.sh
```

El instalador:
1. Crea un entorno virtual aislado en `.venv/` (no toca tu Python de sistema).
2. Instala `PyQt6` y `cryptography` dentro de ese entorno.
3. Deja un lanzador ejecutable en `~/.local/bin/remind2keep`.
4. Añade una entrada en el menú de aplicaciones de tu escritorio.

Después, desde cualquier sitio:

```bash
remind2keep                       # proyecto por defecto (~/.local/share/remind2keep/)
remind2keep ~/ctf/htb-box.r2k.json  # proyecto concreto
```

### Instalación manual (sin `install.sh`)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 remind2keep.py
```

## Atajos de teclado

| Atajo | Acción |
|---|---|
| `Ctrl+N` | Nueva red |
| `Ctrl+T` | Nuevo target |
| `Ctrl+E` | Nuevo escenario |
| `F2` | Renombrar el elemento seleccionado |
| `Supr` | Borrar el elemento seleccionado |
| `Ctrl+K` | Búsqueda global |
| `Ctrl+S` | Guardar |
| `Ctrl+Shift+S` | Guardar como... |
| `Ctrl+Shift+N` | Nuevo proyecto |
| `Ctrl+O` | Abrir proyecto |
| `Ctrl+M` | Exportar a Markdown |
| `Ctrl+Q` | Salir |

## Estructura del proyecto

```
remind2keep/
├── remind2keep.py      # Aplicación completa: modelo de datos, cifrado y GUI (PyQt6)
├── requirements.txt    # Dependencias: PyQt6, cryptography
├── install.sh           # Instalador: venv aislado + lanzador en PATH + entrada de menú
└── README.md
```

Es una app de un solo archivo a propósito: para un proyecto de este tamaño, dividir en módulos solo añade indirección sin beneficio real. Si crece mucho más, los candidatos naturales a separar serían el modelo de datos/cifrado (`Store`, `derive_key`, migraciones) y los widgets de la GUI.

## Formato del archivo de proyecto (`.r2k.json`)

Es JSON plano por defecto, o JSON con un único campo cifrado (`ciphertext`) cuando activas la protección con contraseña desde **Seguridad → Cifrar proyecto…**. El resto de metadatos del cifrado (salt, parámetros de Scrypt) quedan en claro porque hacen falta para volver a derivar la clave — no son secretos.

> ⚠️ **No hay recuperación de contraseña.** Si cifras un proyecto y olvidas la contraseña, los datos no son recuperables por diseño. Guarda tus contraseñas de proyecto en tu gestor de contraseñas habitual.

## Seguridad: qué cubre el cifrado y qué no

- Cubre: el archivo en reposo en disco. Si pierdes el portátil o alguien copia el `.r2k.json`, sin la contraseña no puede leer nada.
- No cubre: la memoria del proceso mientras la app está abierta (el JSON vive descifrado en RAM), ni backups automáticos de tu editor/sistema de archivos que pudieran haber guardado una versión sin cifrar antes de activar la protección.

## Licencia

Este proyecto está bajo la [Licencia MIT](LICENSE). Consulta el archivo `LICENSE` para más detalles.
