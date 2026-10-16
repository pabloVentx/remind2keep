#!/usr/bin/env bash
# install.sh — instala remind2keep en un entorno virtual aislado y deja
# un lanzador `remind2keep` disponible en el PATH del usuario.
#
# Uso:
#   chmod +x install.sh
#   ./install.sh
#
# No requiere sudo: todo se instala bajo $HOME. Para desinstalar, basta con
# borrar "$APP_DIR/.venv", "$HOME/.local/bin/remind2keep" y, si lo creaste,
# "$HOME/.local/share/applications/remind2keep.desktop".

set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$APP_DIR/.venv"
BIN_DIR="$HOME/.local/bin"
LAUNCHER="$BIN_DIR/remind2keep"
DESKTOP_DIR="$HOME/.local/share/applications"
DESKTOP_FILE="$DESKTOP_DIR/remind2keep.desktop"

info()  { printf '\033[1;34m[*]\033[0m %s\n' "$1"; }
ok()    { printf '\033[1;32m[✓]\033[0m %s\n' "$1"; }
fail()  { printf '\033[1;31m[✗]\033[0m %s\n' "$1" >&2; exit 1; }

# ---------- 1. Comprobaciones previas ----------
command -v python3 >/dev/null 2>&1 || fail "No se encuentra python3. Instálalo con tu gestor de paquetes."

PY_VERSION="$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
info "Python detectado: $PY_VERSION"

[[ -f "$APP_DIR/remind2keep.py" ]] || fail "No encuentro remind2keep.py junto a este script."
[[ -f "$APP_DIR/requirements.txt" ]] || fail "No encuentro requirements.txt junto a este script."

# ---------- 2. Entorno virtual ----------
if [[ -d "$VENV_DIR" ]]; then
    info "Ya existe un entorno virtual en $VENV_DIR, se reutiliza."
else
    info "Creando entorno virtual en $VENV_DIR..."
    if ! python3 -m venv "$VENV_DIR" 2>/tmp/r2k_venv_err; then
        echo "---"
        cat /tmp/r2k_venv_err
        echo "---"
        fail "No se pudo crear el venv. En Debian/Ubuntu prueba:  sudo apt install python3-venv"
    fi
fi

info "Instalando dependencias (PyQt6, cryptography)..."
"$VENV_DIR/bin/pip" install --upgrade pip --quiet
"$VENV_DIR/bin/pip" install -r "$APP_DIR/requirements.txt" --quiet
ok "Dependencias instaladas."

# ---------- 3. Lanzador en $HOME/.local/bin ----------
mkdir -p "$BIN_DIR"
cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
# Generado por install.sh — no editar a mano, se sobrescribe en cada instalación.
exec "$VENV_DIR/bin/python3" "$APP_DIR/remind2keep.py" "\$@"
EOF
chmod +x "$LAUNCHER"
ok "Lanzador creado en $LAUNCHER"

if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo
    printf '\033[1;33m[!]\033[0m %s\n' "$BIN_DIR no está en tu PATH. Añade esto a tu ~/.bashrc o ~/.zshrc:"
    echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

# ---------- 4. Entrada en el menú de aplicaciones (opcional, no bloqueante) ----------
mkdir -p "$DESKTOP_DIR"
cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Name=remind2keep
Comment=Notas y organización para pentesters y CTFs
Exec=$LAUNCHER %f
Terminal=false
Categories=Development;Security;Utility;
EOF
ok "Entrada de menú creada en $DESKTOP_FILE"

echo
ok "Instalación completa."
echo "   Ejecuta:  remind2keep                     (proyecto por defecto)"
echo "   o bien:   remind2keep ~/ctf/htb.r2k.json   (proyecto concreto)"
