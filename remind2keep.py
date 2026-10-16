#!/usr/bin/env python3
"""remind2keep - notas rápidas para pentesters y CTFs.

Estructura: Red -> Target -> Escenario -> campos (usuarios, creds, tech, hallazgos, todo)
Persistencia: JSON local con guardado automático (atómico).
Dependencia: pip install PyQt6
"""
import base64
import ipaddress
import json
import os
import sys
import tempfile
import uuid
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from PyQt6.QtCore import Qt, QSettings, QTimer
from PyQt6.QtGui import QAction, QBrush, QColor, QFont, QKeySequence, QPainter, QPalette, QPen
from PyQt6.QtWidgets import (
    QAbstractItemView, QApplication, QDialog, QFileDialog, QGraphicsScene,
    QGraphicsView, QGridLayout, QHBoxLayout, QHeaderView, QInputDialog,
    QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMenu,
    QMessageBox, QPlainTextEdit, QSplitter, QStackedWidget, QStyle, QTableWidget,
    QTableWidgetItem, QToolBar, QToolButton, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)

APP = "remind2keep"
DEFAULT_PATH = Path.home() / ".local/share/remind2keep/default.r2k.json"
ROLE_NODE = Qt.ItemDataRole.UserRole
ROLE_KIND = Qt.ItemDataRole.UserRole + 1
NET, TARGET, SCEN = "network", "target", "scenario"


def apply_dark_palette(app: QApplication):
    """Paleta oscura estándar para el estilo Fusion (sin hojas de estilo manuales)."""
    p = QPalette()
    p.setColor(QPalette.ColorRole.Window, QColor(37, 37, 38))
    p.setColor(QPalette.ColorRole.WindowText, QColor(220, 220, 220))
    p.setColor(QPalette.ColorRole.Base, QColor(30, 30, 30))
    p.setColor(QPalette.ColorRole.AlternateBase, QColor(45, 45, 48))
    p.setColor(QPalette.ColorRole.ToolTipBase, QColor(220, 220, 220))
    p.setColor(QPalette.ColorRole.ToolTipText, QColor(45, 45, 48))
    p.setColor(QPalette.ColorRole.Text, QColor(220, 220, 220))
    p.setColor(QPalette.ColorRole.Button, QColor(45, 45, 48))
    p.setColor(QPalette.ColorRole.ButtonText, QColor(220, 220, 220))
    p.setColor(QPalette.ColorRole.BrightText, QColor(255, 90, 90))
    p.setColor(QPalette.ColorRole.Link, QColor(96, 165, 250))
    p.setColor(QPalette.ColorRole.Highlight, QColor(55, 100, 170))
    p.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
    p.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(120, 120, 120))
    p.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(120, 120, 120))
    app.setPalette(p)


def apply_light_palette(app: QApplication):
    app.setPalette(app.style().standardPalette())


class Section(QWidget):
    """Reemplaza a QGroupBox.

    El estilo Fusion mide el ancho del título de QGroupBox con la fuente
    normal pero lo PINTA en negrita (más ancha), así que siempre recorta el
    último carácter o dos — no es un problema de padding, es un bug de
    medición del estilo, y ningún stylesheet sobre QGroupBox lo arregla.
    Esta clase dibuja el título como un QLabel normal (que sí mide bien su
    propio texto) encima de un marco con borde, y expone `content_layout`
    para añadir el contenido tal como se haría con el layout de un QGroupBox.
    """

    def __init__(self, title: str):
        super().__init__()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(4)

        label = QLabel(title)
        f = label.font()
        f.setBold(True)
        label.setFont(f)
        outer.addWidget(label)

        body = QWidget()
        body.setObjectName("sectionBody")
        body.setStyleSheet(
            "#sectionBody { border: 1px solid rgba(127, 127, 127, 110); border-radius: 6px; }")
        outer.addWidget(body, 1)

        self.content_layout = QVBoxLayout(body)
        self.content_layout.setContentsMargins(6, 6, 6, 6)

# clave, título, placeholder, monoespaciado
# (creds -> tabla, todo -> checklist; ambos se gestionan con widgets dedicados)
FIELDS = [
    ("users", "👤 Posibles usuarios", "admin\nsvc_backup\njdoe", True),
    ("tech", "🧩 Tecnologías y versiones", "Apache 2.4.49\nOpenSSH 8.2p1\nWordPress 5.8", True),
    ("findings", "🎯 Hallazgos principales", "LFI en /index.php?page=\n...", False),
]

# Columnas de la tabla de credenciales: (clave interna, título de columna)
CRED_COLUMNS = [
    ("user", "Usuario"), ("password", "Contraseña"),
    ("service", "Servicio"), ("host", "Host"), ("notes", "Notas"),
]

# Plantillas de comandos por servicio: se elige la lista cuya clave aparece
# como substring en el campo "Servicio" de la credencial (ssh, smb, winrm...).
# {user} {password} {host} se sustituyen por los valores de la fila.
CRED_COMMANDS = {
    "ssh": [
        ("hydra", "hydra -l {user} -p '{password}' ssh://{host}"),
        ("netexec", "nxc ssh {host} -u {user} -p '{password}'"),
    ],
    "smb": [
        ("netexec", "nxc smb {host} -u {user} -p '{password}'"),
        ("hydra", "hydra -l {user} -p '{password}' smb://{host}"),
        ("smbclient", "smbclient -L //{host}/ -U '{user}%{password}'"),
    ],
    "winrm": [
        ("evil-winrm", "evil-winrm -i {host} -u {user} -p '{password}'"),
        ("netexec", "nxc winrm {host} -u {user} -p '{password}'"),
    ],
    "rdp": [
        ("netexec", "nxc rdp {host} -u {user} -p '{password}'"),
        ("xfreerdp", "xfreerdp /v:{host} /u:{user} /p:'{password}'"),
    ],
    "ftp": [("hydra", "hydra -l {user} -p '{password}' ftp://{host}")],
    "mysql": [
        ("hydra", "hydra -l {user} -p '{password}' mysql://{host}"),
        ("mysql-cli", "mysql -h {host} -u {user} -p'{password}'"),
    ],
    "mssql": [
        ("netexec", "nxc mssql {host} -u {user} -p '{password}'"),
        ("impacket", "mssqlclient.py {user}:'{password}'@{host}"),
    ],
    "postgres": [("hydra", "hydra -l {user} -p '{password}' postgres://{host}")],
    "vnc": [("hydra", "hydra -p '{password}' vnc://{host}")],
    "ldap": [("netexec", "nxc ldap {host} -u {user} -p '{password}'")],
    "winexe": [("psexec", "psexec.py {user}:'{password}'@{host}")],
}
DEFAULT_COMMANDS = [
    ("netexec smb", "nxc smb {host} -u {user} -p '{password}'"),
    ("hydra genérico", "hydra -l {user} -p '{password}' <protocolo>://{host}"),
]


def generate_commands(cred: dict) -> list:
    """Devuelve [(etiqueta, comando)] según el servicio indicado en la credencial."""
    service = (cred.get("service") or "").strip().lower()
    templates = DEFAULT_COMMANDS
    for key, cmds in CRED_COMMANDS.items():
        if key in service:
            templates = cmds
            break
    user = cred.get("user") or "USER"
    password = cred.get("password") or "PASS"
    host = cred.get("host") or "HOST"
    return [(label, tpl.format(user=user, password=password, host=host))
            for label, tpl in templates]


# ---------- Cifrado del proyecto (Scrypt + Fernet/AES128-CBC+HMAC) ----------
# Scrypt: parámetros recomendados (OWASP) para derivar una clave a partir de
# una contraseña humana sin depender de hardware especializado del atacante.
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1
SCRYPT_SALT_LEN = 16


class NeedsPassword(Exception):
    """El archivo está cifrado y aún no se ha proporcionado contraseña."""


class WrongPassword(Exception):
    """La contraseña proporcionada no descifra el archivo."""


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def new_id() -> str:
    return uuid.uuid4().hex[:8]


def new_scenario(name="General") -> dict:
    fields = {k: "" for k, *_ in FIELDS}
    fields["creds"] = []
    fields["todo"] = []
    return {"id": new_id(), "name": name, "fields": fields}


class Store:
    """Carga y guarda el proyecto en JSON de forma atómica.

    Si `encrypted` es True, el contenido se cifra en disco con Fernet usando
    una clave derivada de `password` vía Scrypt. El archivo sigue siendo JSON
    válido: solo el campo "ciphertext" es opaco, el resto (salt, parámetros
    del KDF) es necesario en claro para poder volver a derivar la clave.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self.data = {"version": 1, "networks": []}
        self.encrypted = False
        self.password = None  # nunca se escribe a disco

    def load(self, password: str = None):
        """Lanza NeedsPassword si el archivo está cifrado y no hay contraseña,
        o WrongPassword si la proporcionada no es correcta."""
        if not self.path.exists():
            return
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if raw.get("r2k_encrypted"):
            self.encrypted = True
            password = password or self.password
            if password is None:
                raise NeedsPassword()
            self.data = self._decrypt(raw, password)
            self.password = password
        else:
            self.encrypted = False
            self.data = raw
        self._migrate()

    def _decrypt(self, raw: dict, password: str) -> dict:
        salt = base64.b64decode(raw["salt"])
        key = derive_key(password, salt)
        try:
            plaintext = Fernet(key).decrypt(raw["ciphertext"].encode("ascii"))
        except InvalidToken:
            raise WrongPassword()
        return json.loads(plaintext.decode("utf-8"))

    def _encrypt(self, password: str) -> dict:
        salt = os.urandom(SCRYPT_SALT_LEN)
        key = derive_key(password, salt)
        token = Fernet(key).encrypt(json.dumps(self.data, ensure_ascii=False).encode("utf-8"))
        return {
            "r2k_encrypted": True,
            "kdf": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
            "salt": base64.b64encode(salt).decode("ascii"),
            "ciphertext": token.decode("ascii"),
        }

    def _migrate(self):
        """Compatibilidad con proyectos de versiones anteriores:
        creds pasa de texto libre a lista, y todo de texto a checklist."""
        for net in self.data.get("networks", []):
            for tgt in net.get("targets", []):
                tgt.setdefault("pivots", [])
                tgt.setdefault("pivot_notes", "")
                for scn in tgt.get("scenarios", []):
                    fields = scn.setdefault("fields", {})
                    if not isinstance(fields.get("creds"), list):
                        fields["creds"] = []
                    if not isinstance(fields.get("todo"), list):
                        fields["todo"] = self._migrate_todo_text(fields.get("todo") or "")

    @staticmethod
    def _migrate_todo_text(text: str) -> list:
        items = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            done = False
            if line[:3].lower() == "[x]":
                done, line = True, line[3:].strip()
            elif line[:3] == "[ ]":
                line = line[3:].strip()
            items.append({"text": line, "done": done})
        return items

    def save(self):
        if self.encrypted and not self.password:
            raise RuntimeError("Proyecto marcado como cifrado pero sin contraseña en memoria")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = self._encrypt(self.password) if self.encrypted else self.data
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        os.replace(tmp, self.path)


def _md_escape(text: str) -> str:
    """Escapa una celda de tabla Markdown (pipes y saltos de línea)."""
    return (text or "").replace("|", "\\|").replace("\n", "<br>")


def build_markdown(data: dict, project_name: str) -> str:
    """Vuelca todo el proyecto (redes > targets > escenarios) a Markdown."""
    lines = [f"# {project_name} — remind2keep", ""]
    networks = data.get("networks", [])
    if not networks:
        return "\n".join(lines + ["_Sin redes registradas todavía._"])

    for net in networks:
        lines += [f"## 🌐 Red: {net['name']}", ""]
        for tgt in net.get("targets", []):
            lines += [f"### 🎯 Target: {tgt['name']}", ""]
            for scn in tgt.get("scenarios", []):
                lines += [f"#### 📁 Escenario: {scn['name']}", ""]
                fields = scn.get("fields", {})

                users = (fields.get("users") or "").strip()
                if users:
                    lines += ["**👤 Posibles usuarios**", "", "```", users, "```", ""]

                creds = fields.get("creds") or []
                if creds:
                    lines.append("**🔑 Credenciales encontradas**")
                    lines.append("")
                    lines.append("| Usuario | Contraseña | Servicio | Host | Notas |")
                    lines.append("|---|---|---|---|---|")
                    for c in creds:
                        lines.append(
                            f"| {_md_escape(c.get('user',''))} | {_md_escape(c.get('password',''))} "
                            f"| {_md_escape(c.get('service',''))} | {_md_escape(c.get('host',''))} "
                            f"| {_md_escape(c.get('notes',''))} |"
                        )
                    lines.append("")

                tech = (fields.get("tech") or "").strip()
                if tech:
                    lines += ["**🧩 Tecnologías y versiones**", "", "```", tech, "```", ""]

                findings = (fields.get("findings") or "").strip()
                if findings:
                    lines += ["**🎯 Hallazgos principales**", "", findings, ""]

                todo = fields.get("todo") or []
                if todo:
                    lines.append("**📝 Pendientes / Cosas a mirar**")
                    lines.append("")
                    for t in todo:
                        mark = "x" if t.get("done") else " "
                        lines.append(f"- [{mark}] {t.get('text', '')}")
                    lines.append("")

                lines += ["---", ""]
    return "\n".join(lines)


class CredentialsWidget(QWidget):
    """Tabla de credenciales con copiado rápido (usuario/contraseña)
    y generador de comandos (hydra, netexec, evil-winrm, ...)."""

    def __init__(self, on_change, on_status):
        super().__init__()
        self.on_change = on_change
        self.on_status = on_status
        self.scenario = None
        self._loading = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        bar = QHBoxLayout()
        add_btn = QToolButton(text="＋ Añadir")
        add_btn.setToolTip("Añadir credencial")
        add_btn.clicked.connect(self.add_row)
        del_btn = QToolButton(text="🗑 Eliminar fila")
        del_btn.setToolTip("Eliminar la(s) fila(s) seleccionada(s)")
        del_btn.clicked.connect(self.delete_row)
        bar.addWidget(add_btn)
        bar.addWidget(del_btn)
        bar.addStretch()
        layout.addLayout(bar)

        headers = [t for _, t in CRED_COLUMNS] + [""]
        self.table = QTableWidget(0, len(headers))
        self.table.setHorizontalHeaderLabels(headers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(
            len(headers) - 1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.itemChanged.connect(self._item_changed)
        layout.addWidget(self.table)

    # ---------- carga / sincronización con el modelo ----------
    def set_scenario(self, scenario: dict):
        self._loading = True
        self.scenario = scenario
        creds = scenario["fields"].setdefault("creds", [])
        self.table.setRowCount(0)
        for cred in creds:
            self._append_row(cred)
        self._loading = False

    def _append_row(self, cred: dict):
        row = self.table.rowCount()
        self.table.insertRow(row)
        for col, (key, _title) in enumerate(CRED_COLUMNS):
            self.table.setItem(row, col, QTableWidgetItem(cred.get(key, "")))
        self.table.setCellWidget(row, len(CRED_COLUMNS), self._make_actions())

    def _make_actions(self) -> QWidget:
        box = QWidget()
        lay = QHBoxLayout(box)
        lay.setContentsMargins(2, 0, 2, 0)
        lay.setSpacing(2)

        b_user = QToolButton(text="👤")
        b_user.setToolTip("Copiar usuario")
        b_user.clicked.connect(lambda: self._copy_field(box, "user", "Usuario"))
        b_pass = QToolButton(text="🔑")
        b_pass.setToolTip("Copiar contraseña")
        b_pass.clicked.connect(lambda: self._copy_field(box, "password", "Contraseña"))
        b_cmd = QToolButton(text="⚡")
        b_cmd.setToolTip("Generar comando (hydra / netexec / ...)")
        b_cmd.clicked.connect(lambda: self._show_commands(box, b_cmd))
        for b in (b_user, b_pass, b_cmd):
            lay.addWidget(b)
        return box

    def _row_of(self, widget: QWidget) -> int:
        for r in range(self.table.rowCount()):
            if self.table.cellWidget(r, len(CRED_COLUMNS)) is widget:
                return r
        return -1

    def _cred_at(self, row: int) -> dict:
        return {key: (self.table.item(row, i).text() if self.table.item(row, i) else "")
                for i, (key, _t) in enumerate(CRED_COLUMNS)}

    def _copy_field(self, box: QWidget, key: str, label: str):
        row = self._row_of(box)
        if row < 0:
            return
        self._copy(self._cred_at(row).get(key, ""), label)

    def _copy(self, text: str, label: str):
        QApplication.clipboard().setText(text)
        self.on_status(f"{label} copiado al portapapeles" if text else f"{label} está vacío")

    def _show_commands(self, box: QWidget, anchor: QToolButton):
        row = self._row_of(box)
        if row < 0:
            return
        cred = self._cred_at(row)
        menu = QMenu(self)
        for label, cmd in generate_commands(cred):
            action = menu.addAction(f"{label}:  {cmd}")
            action.triggered.connect(lambda _checked=False, c=cmd, l=label: self._copy(c, f"Comando {l}"))
        menu.exec(anchor.mapToGlobal(anchor.rect().bottomLeft()))

    # ---------- edición ----------
    def _item_changed(self, item: QTableWidgetItem):
        if self._loading or self.scenario is None:
            return
        row, col = item.row(), item.column()
        if col >= len(CRED_COLUMNS):
            return
        key = CRED_COLUMNS[col][0]
        creds = self.scenario["fields"]["creds"]
        while len(creds) <= row:
            creds.append({k: "" for k, _t in CRED_COLUMNS})
        creds[row][key] = item.text()
        self.on_change()

    def add_row(self):
        if self.scenario is None:
            return
        cred = {k: "" for k, _t in CRED_COLUMNS}
        self.scenario["fields"]["creds"].append(cred)
        self._append_row(cred)
        self.on_change()

    def delete_row(self):
        if self.scenario is None:
            return
        rows = sorted({i.row() for i in self.table.selectedIndexes()}, reverse=True)
        if not rows:
            self.on_status("Selecciona una fila para eliminar")
            return
        creds = self.scenario["fields"]["creds"]
        for r in rows:
            if r < len(creds):
                del creds[r]
            self.table.removeRow(r)
        for r in range(self.table.rowCount()):
            self.table.setCellWidget(r, len(CRED_COLUMNS), self._make_actions())
        self.on_change()


class TodoWidget(QWidget):
    """Checklist de pendientes: checkbox real, texto editable y tachado al completar."""

    def __init__(self, on_change):
        super().__init__()
        self.on_change = on_change
        self.scenario = None
        self._loading = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.list = QListWidget()
        self.list.itemChanged.connect(self._item_changed)
        layout.addWidget(self.list)

        bar = QHBoxLayout()
        self.input = QLineEdit()
        self.input.setPlaceholderText("Nueva tarea… (Enter para añadir)")
        self.input.returnPressed.connect(self.add_item)
        add_btn = QToolButton(text="＋")
        add_btn.setToolTip("Añadir tarea")
        add_btn.clicked.connect(self.add_item)
        del_btn = QToolButton(text="🗑")
        del_btn.setToolTip("Eliminar tarea(s) seleccionada(s)")
        del_btn.clicked.connect(self.delete_selected)
        bar.addWidget(self.input)
        bar.addWidget(add_btn)
        bar.addWidget(del_btn)
        layout.addLayout(bar)

    def set_scenario(self, scenario: dict):
        self._loading = True
        self.scenario = scenario
        todo = scenario["fields"].setdefault("todo", [])
        self.list.clear()
        for t in todo:
            self._append(t)
        self._loading = False

    def _append(self, t: dict):
        item = QListWidgetItem(t.get("text", ""))
        item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEditable)
        item.setCheckState(Qt.CheckState.Checked if t.get("done") else Qt.CheckState.Unchecked)
        self._style(item)
        self.list.addItem(item)

    @staticmethod
    def _style(item: QListWidgetItem):
        font = item.font()
        font.setStrikeOut(item.checkState() == Qt.CheckState.Checked)
        item.setFont(font)

    def add_item(self):
        text = self.input.text().strip()
        if not text or self.scenario is None:
            return
        t = {"text": text, "done": False}
        self.scenario["fields"]["todo"].append(t)
        self._append(t)
        self.input.clear()
        self.on_change()

    def delete_selected(self):
        rows = sorted({self.list.row(i) for i in self.list.selectedItems()}, reverse=True)
        if not rows or self.scenario is None:
            return
        todo = self.scenario["fields"]["todo"]
        for r in rows:
            if r < len(todo):
                del todo[r]
            self.list.takeItem(r)
        self.on_change()

    def _item_changed(self, item: QListWidgetItem):
        if self._loading or self.scenario is None:
            return
        self._style(item)
        row = self.list.row(item)
        todo = self.scenario["fields"]["todo"]
        while len(todo) <= row:
            todo.append({"text": "", "done": False})
        todo[row]["text"] = item.text()
        todo[row]["done"] = item.checkState() == Qt.CheckState.Checked
        self.on_change()


class ScenarioEditor(QWidget):
    """Panel con los campos estructurados del escenario activo."""

    def __init__(self, on_change, on_status):
        super().__init__()
        self.on_change = on_change
        self.scenario = None
        self._loading = False
        self.edits = {}

        grid = QGridLayout(self)
        grid.setContentsMargins(6, 6, 6, 6)
        mono = QFont("monospace")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        positions = {"users": (0, 0), "tech": (1, 0), "findings": (1, 1)}
        for key, title, hint, use_mono in FIELDS:
            box = Section(title)
            edit = QPlainTextEdit()
            edit.setPlaceholderText(hint)
            edit.setTabChangesFocus(True)
            if use_mono:
                edit.setFont(mono)
            edit.textChanged.connect(lambda k=key: self._changed(k))
            box.content_layout.addWidget(edit)
            self.edits[key] = edit
            grid.addWidget(box, *positions[key])

        creds_box = Section("🔑 Credenciales encontradas")
        self.creds_widget = CredentialsWidget(self._creds_changed, on_status)
        creds_box.content_layout.addWidget(self.creds_widget)
        grid.addWidget(creds_box, 0, 1)

        todo_box = Section("📝 Pendientes / Cosas a mirar")
        self.todo_widget = TodoWidget(self._todo_changed)
        todo_box.content_layout.addWidget(self.todo_widget)
        grid.addWidget(todo_box, 2, 0, 1, 2)

        for r in range(3):
            grid.setRowStretch(r, 1)

    def load(self, scenario: dict):
        self._loading = True
        self.scenario = scenario
        for key, edit in self.edits.items():
            edit.setPlainText(scenario["fields"].get(key, ""))
        self.creds_widget.set_scenario(scenario)
        self.todo_widget.set_scenario(scenario)
        self._loading = False

    def _changed(self, key):
        if self._loading or self.scenario is None:
            return
        self.scenario["fields"][key] = self.edits[key].toPlainText()
        self.on_change()

    def _creds_changed(self):
        if self._loading:
            return
        self.on_change()

    def _todo_changed(self):
        if self._loading:
            return
        self.on_change()


class SearchDialog(QDialog):
    """Búsqueda global (Ctrl+K): filtra en vivo sobre redes, targets, escenarios,
    credenciales (usuario/servicio/host/notas, nunca contraseñas), hallazgos y
    pendientes. Flechas para moverse, Enter para saltar al escenario."""

    def __init__(self, parent, store: "Store", on_pick):
        super().__init__(parent)
        self.setWindowTitle("Búsqueda global")
        self.resize(640, 420)
        self.store = store
        self.on_pick = on_pick

        layout = QVBoxLayout(self)
        self.input = QLineEdit()
        self.input.setPlaceholderText(
            "Buscar en redes, targets, escenarios, credenciales, hallazgos, pendientes…")
        self.input.textChanged.connect(self.refresh)
        layout.addWidget(self.input)

        self.list = QListWidget()
        self.list.itemActivated.connect(self._activate)
        layout.addWidget(self.list)

        self.input.setFocus()
        self.refresh("")

    def refresh(self, text):
        self.list.clear()
        query = text.strip().lower()
        for net in self.store.data.get("networks", []):
            for tgt in net.get("targets", []):
                for scn in tgt.get("scenarios", []):
                    ok, snippet = self._match(net, tgt, scn, query)
                    if not ok:
                        continue
                    label = f"{net['name']} › {tgt['name']} › {scn['name']}"
                    if snippet:
                        label += f"   —   {snippet}"
                    item = QListWidgetItem(label)
                    item.setData(Qt.ItemDataRole.UserRole, scn["id"])
                    self.list.addItem(item)
        if self.list.count():
            self.list.setCurrentRow(0)

    @staticmethod
    def _match(net, tgt, scn, query):
        if not query:
            return True, ""
        fields = scn.get("fields", {})
        haystacks = [net["name"], tgt["name"], scn["name"],
                     fields.get("users", ""), fields.get("tech", ""), fields.get("findings", "")]
        for c in fields.get("creds", []):
            # Deliberadamente SIN password: una búsqueda rápida no debe listar secretos en claro.
            haystacks += [c.get("user", ""), c.get("service", ""), c.get("host", ""), c.get("notes", "")]
        for t in fields.get("todo", []):
            haystacks.append(t.get("text", ""))
        for h in haystacks:
            if h and query in h.lower():
                snippet = h if h not in (scn["name"],) else ""
                return True, snippet[:70]
        return False, ""

    def keyPressEvent(self, event):
        key = event.key()
        if key == Qt.Key.Key_Down:
            self.list.setCurrentRow(min(self.list.currentRow() + 1, self.list.count() - 1))
        elif key == Qt.Key.Key_Up:
            self.list.setCurrentRow(max(self.list.currentRow() - 1, 0))
        elif key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            item = self.list.currentItem()
            if item:
                self._activate(item)
        elif key == Qt.Key.Key_Escape:
            self.reject()
        else:
            super().keyPressEvent(event)

    def _activate(self, item):
        scn_id = item.data(Qt.ItemDataRole.UserRole)
        self.accept()
        self.on_pick(scn_id)


class PivotMapDialog(QDialog):
    """Vista rápida del grafo de pivoting: redes como nodos, targets como aristas
    hacia las redes a las que dan acceso."""

    def __init__(self, parent, data: dict):
        super().__init__(parent)
        self.setWindowTitle("🗺 Mapa de pivoting")
        self.resize(820, 620)
        layout = QVBoxLayout(self)
        self.view = QGraphicsView()
        self.view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.scene = QGraphicsScene()
        self.view.setScene(self.scene)
        layout.addWidget(self.view)
        self._build(data)

    def _build(self, data: dict):
        import math
        networks = data.get("networks", [])
        if not networks:
            self.scene.addText("Sin redes registradas todavía.")
            return

        node_r = 46
        radius = max(170, 90 * len(networks))
        cx = cy = radius + node_r + 20
        pen_node = QPen(QColor("#5b8def"))
        pen_node.setWidth(2)
        brush_node = QBrush(QColor("#223355"))
        pen_edge = QPen(QColor("#f2a13a"))
        pen_edge.setWidth(2)

        positions = {}
        for i, net in enumerate(networks):
            angle = 2 * math.pi * i / len(networks)
            x = cx + radius * math.cos(angle)
            y = cy + radius * math.sin(angle)
            positions[net["id"]] = (x, y)

        # Aristas primero, para que los nodos queden por encima.
        for net in networks:
            x1, y1 = positions[net["id"]]
            for tgt in net.get("targets", []):
                for pivot_id in tgt.get("pivots", []):
                    if pivot_id == net["id"] or pivot_id not in positions:
                        continue
                    x2, y2 = positions[pivot_id]
                    self.scene.addLine(x1, y1, x2, y2, pen_edge)
                    mx, my = (x1 + x2) / 2, (y1 + y2) / 2
                    label = self.scene.addText(f"🔀 {tgt['name']}")
                    label.setDefaultTextColor(QColor("#f2a13a"))
                    lb = label.boundingRect()
                    label.setPos(mx - lb.width() / 2, my - lb.height() / 2)

        for net in networks:
            x, y = positions[net["id"]]
            self.scene.addEllipse(x - node_r, y - node_r, node_r * 2, node_r * 2, pen_node, brush_node)
            label = self.scene.addText(net["name"])
            label.setDefaultTextColor(QColor("#e6e6e6"))
            lb = label.boundingRect()
            label.setPos(x - lb.width() / 2, y - lb.height() / 2)

        self.scene.setSceneRect(self.scene.itemsBoundingRect().adjusted(-40, -40, 40, 40))


class TargetPanel(QWidget):
    """Panel mostrado al seleccionar un Target: hacia qué otras redes pivota
    y los comandos/notas del túnel (chisel, ligolo-ng, sshuttle...)."""

    def __init__(self, on_change):
        super().__init__()
        self.on_change = on_change
        self.target = None
        self._loading = False

        layout = QVBoxLayout(self)
        self.title = QLabel()
        f = self.title.font()
        f.setPointSize(f.pointSize() + 2)
        f.setBold(True)
        self.title.setFont(f)
        layout.addWidget(self.title)

        pivot_box = Section("🔀 Pivoting: este target da acceso a…")
        self.pivot_list = QListWidget()
        self.pivot_list.itemChanged.connect(self._pivot_changed)
        pivot_box.content_layout.addWidget(self.pivot_list)
        layout.addWidget(pivot_box)

        notes_box = Section("📒 Comandos / notas de pivoting")
        self.notes = QPlainTextEdit()
        self.notes.setPlaceholderText(
            "chisel server -p 8080 --reverse\n"
            "chisel client ATACANTE:8080 R:1080:socks\n"
            "proxychains nmap -sT -Pn 10.0.4.0/24")
        mono = QFont("monospace")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self.notes.setFont(mono)
        self.notes.textChanged.connect(self._notes_changed)
        notes_box.content_layout.addWidget(self.notes)
        layout.addWidget(notes_box, 1)

    def set_context(self, target: dict, all_networks: list, own_network_id: str):
        self._loading = True
        self.target = target
        self.title.setText(f"🎯 {target['name']}")

        self.pivot_list.clear()
        pivots = set(target.setdefault("pivots", []))
        others = [n for n in all_networks if n["id"] != own_network_id]
        if not others:
            self.pivot_list.addItem("No hay otras redes creadas todavía.")
            self.pivot_list.item(0).setFlags(Qt.ItemFlag.NoItemFlags)
        for net in others:
            item = QListWidgetItem(net["name"])
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked if net["id"] in pivots else Qt.CheckState.Unchecked)
            item.setData(Qt.ItemDataRole.UserRole, net["id"])
            self.pivot_list.addItem(item)

        self.notes.setPlainText(target.get("pivot_notes", ""))
        self._loading = False

    def _pivot_changed(self, item: QListWidgetItem):
        if self._loading or self.target is None:
            return
        net_id = item.data(Qt.ItemDataRole.UserRole)
        if net_id is None:
            return
        pivots = set(self.target.setdefault("pivots", []))
        if item.checkState() == Qt.CheckState.Checked:
            pivots.add(net_id)
        else:
            pivots.discard(net_id)
        self.target["pivots"] = sorted(pivots)
        self.on_change()

    def _notes_changed(self):
        if self._loading or self.target is None:
            return
        self.target["pivot_notes"] = self.notes.toPlainText()
        self.on_change()


class StartupCancelled(Exception):
    """El usuario canceló el diálogo de contraseña al arrancar la aplicación."""


class MainWindow(QMainWindow):
    def __init__(self, path: Path):
        super().__init__()
        self.resize(1200, 750)
        store = self.load_store(path)
        if store is None:
            raise StartupCancelled()
        self.store = store
        self._save_failed = False
        self._nodes = {}  # id -> dict real de store.data (ver node())

        self.settings = QSettings("remind2keep", "remind2keep")
        self.dark_mode = self.settings.value("dark_theme", False, type=bool)

        self.save_timer = QTimer(self, singleShot=True, interval=800)
        self.save_timer.timeout.connect(self.save_now)

        # Árbol
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.context_menu)
        self.tree.itemChanged.connect(self.item_renamed)
        self.tree.currentItemChanged.connect(self.selection_changed)

        # Panel derecho
        self.hint = QLabel(
            "Selecciona o crea un escenario\n\n"
            "Ctrl+N red · Ctrl+T target · Ctrl+E escenario · Ctrl+K buscar")
        self.hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.editor = ScenarioEditor(self.schedule_save, self.status_message)
        self.target_panel = TargetPanel(self.schedule_save)
        self.stack = QStackedWidget()
        self.stack.addWidget(self.hint)
        self.stack.addWidget(self.editor)
        self.stack.addWidget(self.target_panel)

        split = QSplitter()
        split.addWidget(self.tree)
        split.addWidget(self.stack)
        split.setStretchFactor(1, 1)
        split.setSizes([300, 900])
        self.setCentralWidget(split)

        self.build_actions()
        self.populate()
        self.update_title()

    # ---------- UI ----------
    def build_actions(self):
        st = self.style()
        def act(text, shortcut, slot, icon=None):
            a = QAction(text, self)
            if shortcut:
                a.setShortcut(QKeySequence(shortcut))
            if icon:
                a.setIcon(st.standardIcon(icon))
            a.triggered.connect(slot)
            return a

        self.a_net = act("Red", "Ctrl+N", self.add_network, QStyle.StandardPixmap.SP_DriveNetIcon)
        self.a_tgt = act("Target", "Ctrl+T", self.add_target, QStyle.StandardPixmap.SP_ComputerIcon)
        self.a_scn = act("Escenario", "Ctrl+E", self.add_scenario, QStyle.StandardPixmap.SP_FileIcon)
        self.a_del = act("Borrar", "Delete", self.delete_current, QStyle.StandardPixmap.SP_TrashIcon)
        self.a_ren = act("Renombrar", "F2", lambda: self.tree.editItem(self.tree.currentItem()))

        tb = QToolBar("Acciones")
        tb.setMovable(False)
        tb.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        for a in (self.a_net, self.a_tgt, self.a_scn, self.a_del):
            tb.addAction(a)
        self.addToolBar(tb)

        m = self.menuBar().addMenu("&Proyecto")
        m.addAction(act("Nuevo…", "Ctrl+Shift+N", self.new_project))
        m.addAction(act("Abrir…", "Ctrl+O", self.open_project))
        m.addAction(act("Guardar", "Ctrl+S", self.save_now))
        m.addAction(act("Guardar como…", "Ctrl+Shift+S", self.save_as))
        m.addSeparator()
        m.addAction(act("Exportar a Markdown…", "Ctrl+M", self.export_markdown))
        m.addSeparator()
        m.addAction(act("Salir", "Ctrl+Q", self.close))
        self.addAction(self.a_del)
        self.addAction(self.a_ren)

        sec = self.menuBar().addMenu("&Seguridad")
        sec.addAction(act("🔒 Cifrar proyecto…", None, self.encrypt_project))
        sec.addAction(act("🔑 Cambiar contraseña…", None, self.change_password))
        sec.addAction(act("🔓 Quitar cifrado…", None, self.decrypt_project))
        sec.addSeparator()
        sec.addAction(act("🩺 Verificar estructura del proyecto…", None, self.verify_structure))

        red = self.menuBar().addMenu("&Red")
        self.a_search = act("🔎 Búsqueda global…", "Ctrl+K", self.open_search)
        red.addAction(self.a_search)
        red.addAction(act("🗺 Mapa de pivoting…", None, self.open_pivot_map))
        self.addAction(self.a_search)  # el atajo funciona aunque el árbol tenga el foco

        view = self.menuBar().addMenu("&Ver")
        self.a_dark = act("🌙 Tema oscuro", None, self.toggle_theme)
        self.a_dark.setCheckable(True)
        self.a_dark.setChecked(self.dark_mode)
        view.addAction(self.a_dark)

    def toggle_theme(self):
        self.dark_mode = self.a_dark.isChecked()
        app = QApplication.instance()
        (apply_dark_palette if self.dark_mode else apply_light_palette)(app)
        self.settings.setValue("dark_theme", self.dark_mode)

    def open_search(self):
        SearchDialog(self, self.store, self.jump_to_scenario).exec()

    def jump_to_scenario(self, scn_id: str):
        item = self._find_item(lambda it: it.data(0, ROLE_KIND) == SCEN
                                 and self.node(it).get("id") == scn_id)
        if item:
            self.tree.setCurrentItem(item)
            self.tree.scrollToItem(item)

    def _find_item(self, predicate):
        def walk(it):
            if predicate(it):
                return it
            for i in range(it.childCount()):
                found = walk(it.child(i))
                if found:
                    return found
            return None
        for i in range(self.tree.topLevelItemCount()):
            found = walk(self.tree.topLevelItem(i))
            if found:
                return found
        return None

    def open_pivot_map(self):
        PivotMapDialog(self, self.store.data).exec()

    def verify_structure(self):
        """Cuenta la jerarquía tal como está AHORA en self.store.data (lo que
        hay realmente en memoria/en el archivo), al margen de lo que muestre
        el árbol. Sirve para distinguir un bug de guardado (el archivo no
        tiene los datos) de un bug de visualización (los tiene pero no se
        pintan)."""
        networks = self.store.data.get("networks", [])
        n_targets = sum(len(net.get("targets", [])) for net in networks)
        n_scenarios = sum(len(tgt.get("scenarios", []))
                           for net in networks for tgt in net.get("targets", []))
        detalle = "\n".join(
            f"  • {net.get('name', '?')}: {len(net.get('targets', []))} target(s)"
            for net in networks
        ) or "  (sin redes)"
        QMessageBox.information(
            self, APP,
            f"Archivo: {self.store.path}\n"
            f"Cifrado: {'sí' if self.store.encrypted else 'no'}\n\n"
            f"Redes: {len(networks)}\n"
            f"Targets (total): {n_targets}\n"
            f"Escenarios (total): {n_scenarios}\n\n"
            f"Detalle por red:\n{detalle}"
        )

    def update_title(self):
        lock = " 🔒" if self.store.encrypted else ""
        self.setWindowTitle(f"{APP} — {self.store.path.name}{lock}")

    # ---------- Contraseña / cifrado ----------
    def ask_password(self, title: str, label: str):
        text, ok = QInputDialog.getText(self, title, label, echo=QLineEdit.EchoMode.Password)
        return text if ok else None

    def load_store(self, path: Path):
        """Carga un Store en `path`, pidiendo contraseña si está cifrado.
        Devuelve None si el usuario cancela el diálogo de contraseña."""
        store = Store(path)
        while True:
            try:
                store.load()
                return store
            except NeedsPassword:
                pwd = self.ask_password(f"Proyecto cifrado — {path.name}", "Contraseña:")
                if pwd is None:
                    return None
                store.password = pwd
            except WrongPassword:
                QMessageBox.warning(self, APP, "Contraseña incorrecta.")
                store.password = None

    def encrypt_project(self):
        if self.store.encrypted:
            QMessageBox.information(self, APP, "Este proyecto ya está cifrado.")
            return
        pwd1 = self.ask_password("Cifrar proyecto", "Nueva contraseña:")
        if not pwd1:
            return
        pwd2 = self.ask_password("Cifrar proyecto", "Repite la contraseña:")
        if pwd1 != pwd2:
            QMessageBox.warning(self, APP, "Las contraseñas no coinciden.")
            return
        self.store.encrypted = True
        self.store.password = pwd1
        self.save_now()
        self.update_title()
        QMessageBox.information(self, APP, "Proyecto cifrado correctamente.")

    def decrypt_project(self):
        if not self.store.encrypted:
            QMessageBox.information(self, APP, "Este proyecto no está cifrado.")
            return
        if QMessageBox.question(
                self, APP,
                "El archivo se guardará en texto plano a partir de ahora, "
                "incluidas las credenciales. ¿Continuar?"
        ) != QMessageBox.StandardButton.Yes:
            return
        self.store.encrypted = False
        self.store.password = None
        self.save_now()
        self.update_title()

    def change_password(self):
        if not self.store.encrypted:
            QMessageBox.information(self, APP, "Primero cifra el proyecto.")
            return
        current = self.ask_password("Cambiar contraseña", "Contraseña actual:")
        if current != self.store.password:
            QMessageBox.warning(self, APP, "Contraseña actual incorrecta.")
            return
        new1 = self.ask_password("Cambiar contraseña", "Nueva contraseña:")
        if not new1:
            return
        new2 = self.ask_password("Cambiar contraseña", "Repite la nueva contraseña:")
        if new1 != new2:
            QMessageBox.warning(self, APP, "Las contraseñas no coinciden.")
            return
        self.store.password = new1
        self.save_now()
        QMessageBox.information(self, APP, "Contraseña actualizada.")

    # ---------- Árbol ----------
    def make_item(self, kind, node, parent=None):
        item = QTreeWidgetItem(parent or self.tree, [node["name"]])
        self._nodes[node["id"]] = node  # referencia al dict REAL de store.data
        item.setData(0, ROLE_NODE, node["id"])  # solo el id: Qt copiaría un dict
        item.setData(0, ROLE_KIND, kind)
        item.setFlags(item.flags() | Qt.ItemFlag.ItemIsEditable)
        icon = {NET: QStyle.StandardPixmap.SP_DriveNetIcon,
                TARGET: QStyle.StandardPixmap.SP_ComputerIcon,
                SCEN: QStyle.StandardPixmap.SP_FileIcon}[kind]
        item.setIcon(0, self.style().standardIcon(icon))
        return item

    def node(self, item) -> dict:
        """Devuelve el dict REAL (el que vive en self.store.data) de un item.
        No se puede guardar el dict dentro del QTreeWidgetItem: PyQt lo
        convierte a QVariantMap y data() devolvería una copia, de modo que
        todo lo añadido/editado 'dentro' del nodo se perdería al guardar."""
        return self._nodes[item.data(0, ROLE_NODE)]

    def populate(self):
        self._nodes = {}
        self.tree.blockSignals(True)
        self.tree.clear()
        for net in self.store.data["networks"]:
            ni = self.make_item(NET, net)
            for tgt in net["targets"]:
                ti = self.make_item(TARGET, tgt, ni)
                for scn in tgt["scenarios"]:
                    self.make_item(SCEN, scn, ti)
        self.tree.expandAll()
        self.tree.blockSignals(False)
        self.stack.setCurrentWidget(self.hint)

    def current(self):
        item = self.tree.currentItem()
        if not item:
            return None, None, None
        return item, item.data(0, ROLE_KIND), self.node(item)

    def selection_changed(self, item, _prev):
        if not item:
            self.stack.setCurrentWidget(self.hint)
            return
        kind = item.data(0, ROLE_KIND)
        if kind == SCEN:
            self.editor.load(self.node(item))
            self.stack.setCurrentWidget(self.editor)
        elif kind == TARGET:
            net_node = self.node(item.parent())
            self.target_panel.set_context(self.node(item), self.store.data["networks"], net_node["id"])
            self.stack.setCurrentWidget(self.target_panel)
        else:
            self.editor.scenario = None
            self.stack.setCurrentWidget(self.hint)

    def item_renamed(self, item, _col):
        self.node(item)["name"] = item.text(0)
        self.schedule_save()

    # ---------- Altas / bajas ----------
    def ask(self, title, label, default=""):
        text, ok = QInputDialog.getText(self, title, label, text=default)
        return text.strip() if ok and text.strip() else None

    def add_network(self):
        name = self.ask("Nueva red", "CIDR o nombre (ej. 10.0.3.0/24):")
        if not name:
            return
        try:
            ipaddress.ip_network(name, strict=False)
        except ValueError:
            pass  # se permite cualquier nombre (ej. "DMZ")
        net = {"id": new_id(), "name": name, "targets": []}
        self.store.data["networks"].append(net)
        item = self.make_item(NET, net)
        self.tree.setCurrentItem(item)
        self.schedule_save()

    def add_target(self):
        item, kind, _ = self.current()
        if kind is None:
            return QMessageBox.information(self, APP, "Primero crea o selecciona una red.")
        net_item = item if kind == NET else (item.parent() if kind == TARGET else item.parent().parent())
        host = self.ask("Nuevo target", "IP o hostname:")
        if not host:
            return
        scn = new_scenario()
        tgt = {"id": new_id(), "name": host, "scenarios": [scn], "pivots": [], "pivot_notes": ""}
        self.node(net_item)["targets"].append(tgt)
        ti = self.make_item(TARGET, tgt, net_item)
        si = self.make_item(SCEN, scn, ti)
        net_item.setExpanded(True)
        ti.setExpanded(True)
        self.tree.setCurrentItem(si)
        self.schedule_save()

    def add_scenario(self):
        item, kind, _ = self.current()
        if kind not in (TARGET, SCEN):
            return QMessageBox.information(self, APP, "Selecciona un target.")
        tgt_item = item if kind == TARGET else item.parent()
        name = self.ask("Nuevo escenario", "Nombre del escenario:", "Escenario")
        if not name:
            return
        scn = new_scenario(name)
        self.node(tgt_item)["scenarios"].append(scn)
        si = self.make_item(SCEN, scn, tgt_item)
        tgt_item.setExpanded(True)
        self.tree.setCurrentItem(si)
        self.schedule_save()

    def delete_current(self):
        item, kind, node = self.current()
        if not item or not self.tree.hasFocus():
            return
        if QMessageBox.question(self, APP, f"¿Borrar «{node['name']}» y todo su contenido?") \
                != QMessageBox.StandardButton.Yes:
            return
        parent = item.parent()
        if kind == NET:
            self.store.data["networks"].remove(node)
            self.tree.takeTopLevelItem(self.tree.indexOfTopLevelItem(item))
        else:
            key = "targets" if kind == TARGET else "scenarios"
            self.node(parent)[key].remove(node)
            parent.removeChild(item)
        self.schedule_save()

    def context_menu(self, pos):
        item = self.tree.itemAt(pos)
        if item:
            self.tree.setCurrentItem(item)
        menu = QMenu(self)
        menu.addAction(self.a_net)
        if item:
            kind = item.data(0, ROLE_KIND)
            if kind in (NET, TARGET, SCEN):
                menu.addAction(self.a_tgt)
            if kind in (TARGET, SCEN):
                menu.addAction(self.a_scn)
            menu.addSeparator()
            menu.addAction(self.a_ren)
            menu.addAction(self.a_del)
        menu.exec(self.tree.viewport().mapToGlobal(pos))

    def status_message(self, text: str, timeout=2500):
        self.statusBar().showMessage(text, timeout)

    def export_markdown(self):
        self.save_now()
        default = self.store.path.with_suffix(".md")
        path, _ = QFileDialog.getSaveFileName(self, "Exportar a Markdown", str(default), "Markdown (*.md)")
        if not path:
            return
        md = build_markdown(self.store.data, self.store.path.stem)
        Path(path).write_text(md, encoding="utf-8")
        self.statusBar().showMessage(f"Exportado a {path}", 4000)

    # ---------- Persistencia ----------
    def schedule_save(self):
        self.statusBar().showMessage("Cambios sin guardar…")
        self.save_timer.start()

    def save_now(self):
        try:
            self.store.save()
            self.statusBar().showMessage(f"Guardado en {self.store.path}", 3000)
            self._save_failed = False
        except Exception as e:
            # Antes solo se capturaba OSError: cualquier otro fallo durante el
            # cifrado/serialización se escapaba en silencio desde el QTimer
            # del autoguardado, sin avisar y sin escribir nada — el archivo se
            # quedaba "congelado" en el último guardado que sí había
            # funcionado. Ahora se captura todo, se muestra y queda marcado
            # como fallo para poder avisar también al cerrar la aplicación.
            self._save_failed = True
            print(f"[remind2keep] ERROR al guardar: {e!r}", file=sys.stderr)
            self.statusBar().showMessage(f"⚠ ERROR al guardar (ver terminal): {e}")

    def switch_project(self, path: Path):
        self.save_now()
        store = self.load_store(path)
        if store is None:
            return  # contraseña cancelada: se mantiene el proyecto actual
        self.store = store
        self.populate()
        self.update_title()

    def new_project(self):
        path, _ = QFileDialog.getSaveFileName(self, "Nuevo proyecto", str(Path.home() / "nuevo.r2k.json"),
                                              "remind2keep (*.r2k.json)")
        if not path:
            return
        self.save_now()
        self.store = Store(Path(path))
        if QMessageBox.question(
                self, APP, "¿Proteger este proyecto con contraseña desde el principio?"
        ) == QMessageBox.StandardButton.Yes:
            pwd1 = self.ask_password("Cifrar proyecto", "Nueva contraseña:")
            pwd2 = self.ask_password("Cifrar proyecto", "Repite la contraseña:") if pwd1 else None
            if pwd1 and pwd1 == pwd2:
                self.store.encrypted = True
                self.store.password = pwd1
            elif pwd1:
                QMessageBox.warning(self, APP, "Las contraseñas no coinciden; proyecto creado sin cifrar.")
        self.populate()
        self.update_title()
        self.save_now()

    def open_project(self):
        path, _ = QFileDialog.getOpenFileName(self, "Abrir proyecto", str(Path.home()),
                                              "remind2keep (*.r2k.json *.json)")
        if path:
            self.switch_project(Path(path))

    def save_as(self):
        path, _ = QFileDialog.getSaveFileName(self, "Guardar como", str(self.store.path),
                                              "remind2keep (*.r2k.json)")
        if path:
            self.store.path = Path(path)
            self.save_now()
            self.update_title()

    def closeEvent(self, event):
        self.save_now()
        if self._save_failed:
            if QMessageBox.question(
                    self, APP,
                    "El último guardado ha fallado (ver mensaje en la barra de estado "
                    "o en la terminal). Si cierras ahora podrías perder los cambios "
                    "más recientes.\n\n¿Cerrar de todas formas?"
            ) != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    if QSettings("remind2keep", "remind2keep").value("dark_theme", False, type=bool):
        apply_dark_palette(app)
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PATH
    try:
        win = MainWindow(path)
    except StartupCancelled:
        sys.exit(0)
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
