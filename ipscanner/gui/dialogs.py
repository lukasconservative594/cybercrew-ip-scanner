"""Preferences, fetcher selection, host details, favourites and about."""

from __future__ import annotations

from typing import Any, Sequence

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QGuiApplication
from PyQt6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
    QFormLayout, QGridLayout, QGroupBox, QHBoxLayout, QInputDialog, QLabel,
    QLineEdit, QListWidget, QListWidgetItem, QMessageBox, QPlainTextEdit,
    QPushButton, QSpinBox, QTabWidget, QVBoxLayout, QWidget,
)

from .. import APP_NAME, APP_URL, __version__
from ..core import oui, pingers
from ..core.config import Config, DEFAULTS
from ..core.ranges import RangeError, parse_ports
from ..core.subject import ScanResult
from .. import fetchers as fetchers_pkg


class PreferencesDialog(QDialog):
    """Everything that changes how a scan behaves."""

    def __init__(self, config: Config, parent=None):
        super().__init__(parent)
        self.config = config
        self.setWindowTitle("Preferences")
        self.setMinimumWidth(480)

        tabs = QTabWidget(self)
        tabs.addTab(self._scanning_tab(), "Scanning")
        tabs.addTab(self._ports_tab(), "Ports")
        tabs.addTab(self._display_tab(), "Display")

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
            | QDialogButtonBox.StandardButton.RestoreDefaults
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        buttons.button(QDialogButtonBox.StandardButton.RestoreDefaults).clicked.connect(
            self._restore_defaults
        )

        layout = QVBoxLayout(self)
        layout.addWidget(tabs)
        layout.addWidget(buttons)

    # -- tabs --------------------------------------------------------------
    def _scanning_tab(self) -> QWidget:
        page = QWidget()
        form = QFormLayout(page)

        self.threads = QSpinBox()
        self.threads.setRange(1, 1024)
        self.threads.setValue(self.config.int_of("max_threads", 1, 1024))
        self.threads.setToolTip(
            "Hosts probed at the same time. Higher is faster, but very high "
            "values can overwhelm a slow link or trip rate limiting."
        )
        form.addRow("Maximum threads:", self.threads)

        self.delay = QSpinBox()
        self.delay.setRange(0, 10000)
        self.delay.setSuffix(" ms")
        self.delay.setValue(self.config.int_of("thread_delay_ms", 0, 10000))
        self.delay.setToolTip("Pause between launching each host. Use to scan quietly.")
        form.addRow("Delay between hosts:", self.delay)

        self.method = QComboBox()
        for key in ("combined", "icmp", "tcp", "udp", "arp"):
            cls = pingers.PINGERS[key]
            self.method.addItem(cls.name, key)
        current = str(self.config.get("ping_method", "combined"))
        index = self.method.findData(current)
        self.method.setCurrentIndex(index if index >= 0 else 0)
        self.method.setToolTip(
            "Combined tries ICMP, then ARP on the local subnet, then TCP. "
            "It finds hosts that block ping."
        )
        form.addRow("Liveness probe:", self.method)

        self.ping_timeout = QSpinBox()
        self.ping_timeout.setRange(50, 60000)
        self.ping_timeout.setSuffix(" ms")
        self.ping_timeout.setValue(self.config.int_of("ping_timeout_ms", 50, 60000))
        form.addRow("Ping timeout:", self.ping_timeout)

        self.ping_count = QSpinBox()
        self.ping_count.setRange(1, 20)
        self.ping_count.setValue(self.config.int_of("ping_count", 1, 20))
        form.addRow("Probes per host:", self.ping_count)

        self.scan_dead = QCheckBox("Run every fetcher even on hosts that did not answer")
        self.scan_dead.setChecked(self.config.bool_of("scan_dead_hosts"))
        form.addRow("", self.scan_dead)

        self.skip_broadcast = QCheckBox("Skip addresses ending in .0 and .255")
        self.skip_broadcast.setChecked(self.config.bool_of("skip_broadcast"))
        form.addRow("", self.skip_broadcast)
        return page

    def _ports_tab(self) -> QWidget:
        page = QWidget()
        form = QFormLayout(page)

        self.ports = QLineEdit(str(self.config.get("ports", "")))
        self.ports.setToolTip("Comma separated, ranges allowed: 22,80,443,8000-8100")
        form.addRow("Ports to scan:", self.ports)

        presets = QHBoxLayout()
        for label, value in (
            ("Top 20", "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,"
                       "1723,3306,3389,5900,8080"),
            ("Web", "80,443,8000,8008,8080,8081,8443,8888,9000,9090"),
            ("Windows", "88,135,139,389,445,464,593,636,3268,3389,5985,5986"),
            ("Databases", "1433,1521,3306,5432,6379,9042,11211,27017,27018"),
            ("1-1024", "1-1024"),
        ):
            button = QPushButton(label)
            button.setToolTip(value)
            button.clicked.connect(lambda _, v=value: self.ports.setText(v))
            presets.addWidget(button)
        holder = QWidget()
        holder.setLayout(presets)
        form.addRow("Presets:", holder)

        self.port_timeout = QSpinBox()
        self.port_timeout.setRange(50, 60000)
        self.port_timeout.setSuffix(" ms")
        self.port_timeout.setValue(self.config.int_of("port_timeout_ms", 50, 60000))
        form.addRow("Port timeout:", self.port_timeout)

        self.port_batch = QSpinBox()
        self.port_batch.setRange(1, 400)
        self.port_batch.setValue(self.config.int_of("port_batch", 1, 400))
        self.port_batch.setToolTip(
            "Ports probed simultaneously per host. Scanning 128 ports at once "
            "costs about as much time as scanning one."
        )
        form.addRow("Ports in parallel:", self.port_batch)

        self.detect_filtered = QCheckBox(
            "Report filtered ports (slower - waits for the full timeout)"
        )
        self.detect_filtered.setChecked(self.config.bool_of("detect_filtered_ports"))
        form.addRow("", self.detect_filtered)

        self.grab_banners = QCheckBox("Grab service banners from open ports")
        self.grab_banners.setChecked(self.config.bool_of("grab_banners"))
        form.addRow("", self.grab_banners)
        return page

    def _display_tab(self) -> QWidget:
        page = QWidget()
        form = QFormLayout(page)

        self.display = QComboBox()
        self.display.addItem("Alive hosts only", "alive")
        self.display.addItem("Hosts with open ports only", "ports")
        self.display.addItem("All scanned hosts", "all")
        index = self.display.findData(str(self.config.get("display", "alive")))
        self.display.setCurrentIndex(index if index >= 0 else 0)
        form.addRow("Show in list:", self.display)

        self.na_text = QLineEdit(str(self.config.get("not_available_text", "[n/a]")))
        form.addRow("Text when not found:", self.na_text)

        self.ns_text = QLineEdit(str(self.config.get("not_scanned_text", "[n/s]")))
        form.addRow("Text when not scanned:", self.ns_text)

        self.hostname_timeout = QSpinBox()
        self.hostname_timeout.setRange(200, 30000)
        self.hostname_timeout.setSuffix(" ms")
        self.hostname_timeout.setValue(self.config.int_of("hostname_timeout_ms", 200, 30000))
        form.addRow("Reverse DNS timeout:", self.hostname_timeout)

        self.web_ports = QLineEdit(
            ",".join(str(p) for p in (self.config.get("web_detect_ports") or []))
        )
        self.web_ports.setToolTip("Ports the web server fetcher will try.")
        form.addRow("Web detection ports:", self.web_ports)
        return page

    # -- actions -----------------------------------------------------------
    def _restore_defaults(self) -> None:
        if QMessageBox.question(
            self, "Restore defaults",
            "Reset every preference on all three tabs to its default value?"
        ) != QMessageBox.StandardButton.Yes:
            return
        self.threads.setValue(DEFAULTS["max_threads"])
        self.delay.setValue(DEFAULTS["thread_delay_ms"])
        self.method.setCurrentIndex(max(0, self.method.findData(DEFAULTS["ping_method"])))
        self.ping_timeout.setValue(DEFAULTS["ping_timeout_ms"])
        self.ping_count.setValue(DEFAULTS["ping_count"])
        self.scan_dead.setChecked(DEFAULTS["scan_dead_hosts"])
        self.skip_broadcast.setChecked(DEFAULTS["skip_broadcast"])
        self.ports.setText(DEFAULTS["ports"])
        self.port_timeout.setValue(DEFAULTS["port_timeout_ms"])
        self.port_batch.setValue(DEFAULTS["port_batch"])
        self.detect_filtered.setChecked(DEFAULTS["detect_filtered_ports"])
        self.grab_banners.setChecked(DEFAULTS["grab_banners"])
        self.display.setCurrentIndex(max(0, self.display.findData(DEFAULTS["display"])))
        self.na_text.setText(DEFAULTS["not_available_text"])
        self.ns_text.setText(DEFAULTS["not_scanned_text"])
        self.hostname_timeout.setValue(DEFAULTS["hostname_timeout_ms"])
        self.web_ports.setText(",".join(str(p) for p in DEFAULTS["web_detect_ports"]))

    def accept(self) -> None:
        try:
            parse_ports(self.ports.text())
        except RangeError as exc:
            QMessageBox.warning(self, "Invalid ports", str(exc))
            return

        web_ports: list[int] = []
        for chunk in self.web_ports.text().replace(" ", "").split(","):
            if chunk.isdigit() and 1 <= int(chunk) <= 65535:
                web_ports.append(int(chunk))

        self.config.update({
            "max_threads": self.threads.value(),
            "thread_delay_ms": self.delay.value(),
            "ping_method": self.method.currentData(),
            "ping_timeout_ms": self.ping_timeout.value(),
            "ping_count": self.ping_count.value(),
            "scan_dead_hosts": self.scan_dead.isChecked(),
            "skip_broadcast": self.skip_broadcast.isChecked(),
            "ports": self.ports.text().strip(),
            "port_timeout_ms": self.port_timeout.value(),
            "port_batch": self.port_batch.value(),
            "detect_filtered_ports": self.detect_filtered.isChecked(),
            "grab_banners": self.grab_banners.isChecked(),
            "display": self.display.currentData(),
            "not_available_text": self.na_text.text(),
            "not_scanned_text": self.ns_text.text(),
            "hostname_timeout_ms": self.hostname_timeout.value(),
            "web_detect_ports": web_ports or DEFAULTS["web_detect_ports"],
        })
        self.config.save()
        super().accept()


class FetchersDialog(QDialog):
    """Choose which columns to gather, and in what order."""

    def __init__(self, config: Config, parent=None):
        super().__init__(parent)
        self.config = config
        self.setWindowTitle("Select fetchers")
        self.setMinimumSize(460, 460)

        self.list = QListWidget()
        self.list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)

        selected = list(config.get("selected_fetchers") or fetchers_pkg.default_ids())
        classes = {cls.id: cls for cls in fetchers_pkg.available()}

        for fetcher_id in selected:
            if fetcher_id in classes:
                self._add_item(classes[fetcher_id], True)
        for cls in fetchers_pkg.available():
            if cls.id not in selected:
                self._add_item(cls, False)

        up = QPushButton("Move up")
        down = QPushButton("Move down")
        up.clicked.connect(lambda: self._move(-1))
        down.clicked.connect(lambda: self._move(1))

        side = QVBoxLayout()
        side.addWidget(up)
        side.addWidget(down)
        side.addStretch(1)

        row = QHBoxLayout()
        row.addWidget(self.list, 1)
        row.addLayout(side)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        hint = QLabel(
            "Ticked fetchers become columns. Each one costs time, so pick what "
            "you need - IP and Ping are always worth having."
        )
        hint.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.addWidget(hint)
        layout.addLayout(row)
        layout.addWidget(buttons)

    def _add_item(self, cls, checked: bool) -> None:
        item = QListWidgetItem(f"{cls.name}  -  {cls.description}")
        item.setData(Qt.ItemDataRole.UserRole, cls.id)
        item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
        item.setCheckState(Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)
        if cls.id == "ip":
            item.setCheckState(Qt.CheckState.Checked)
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsUserCheckable)
            item.setToolTip("The address column is always shown.")
        self.list.addItem(item)

    def _move(self, offset: int) -> None:
        row = self.list.currentRow()
        target = row + offset
        if row < 0 or not 0 <= target < self.list.count():
            return
        item = self.list.takeItem(row)
        self.list.insertItem(target, item)
        self.list.setCurrentRow(target)

    def selected_ids(self) -> list[str]:
        ids = []
        for index in range(self.list.count()):
            item = self.list.item(index)
            if item.checkState() == Qt.CheckState.Checked:
                ids.append(item.data(Qt.ItemDataRole.UserRole))
        if "ip" not in ids:
            ids.insert(0, "ip")
        return ids

    def accept(self) -> None:
        self.config.set("selected_fetchers", self.selected_ids())
        self.config.save()
        super().accept()


class HostDetailsDialog(QDialog):
    """Everything gathered about one host, in a copyable block."""

    def __init__(self, result: ScanResult, fetchers: Sequence, config: Config, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Details - {result.ip}")
        self.setMinimumSize(560, 420)

        not_available = str(config.get("not_available_text", "[n/a]"))
        not_scanned = str(config.get("not_scanned_text", "[n/s]"))

        lines = [f"{'Address':<18}{result.ip}", f"{'Status':<18}{result.state.label}", ""]
        for fetcher in fetchers:
            if fetcher.id == "ip":
                continue
            value = result.display(fetcher.id, not_available, not_scanned)
            lines.append(f"{fetcher.name + ':':<18}{value}")

        self.text = QPlainTextEdit("\n".join(lines))
        self.text.setReadOnly(True)
        self.text.setFont(QFont("Consolas" if hasattr(QFont, "Monospace") else "monospace", 10))

        copy = QPushButton("Copy to clipboard")
        copy.clicked.connect(self._copy)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)

        row = QHBoxLayout()
        row.addWidget(copy)
        row.addStretch(1)
        row.addWidget(buttons)

        layout = QVBoxLayout(self)
        layout.addWidget(self.text)
        layout.addLayout(row)

    def _copy(self) -> None:
        QGuiApplication.clipboard().setText(self.text.toPlainText())


class FavoritesDialog(QDialog):
    """Named ranges you scan often."""

    def __init__(self, config: Config, parent=None):
        super().__init__(parent)
        self.config = config
        self.setWindowTitle("Manage favourites")
        self.setMinimumSize(440, 340)

        self.favorites: dict[str, Any] = dict(config.get("favorites") or {})
        self.list = QListWidget()
        self._reload()

        rename = QPushButton("Rename")
        edit = QPushButton("Edit range")
        remove = QPushButton("Remove")
        rename.clicked.connect(self._rename)
        edit.clicked.connect(self._edit)
        remove.clicked.connect(self._remove)

        side = QVBoxLayout()
        for button in (rename, edit, remove):
            side.addWidget(button)
        side.addStretch(1)

        row = QHBoxLayout()
        row.addWidget(self.list, 1)
        row.addLayout(side)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(row)
        layout.addWidget(buttons)

    def _reload(self) -> None:
        self.list.clear()
        for name in sorted(self.favorites):
            entry = self.favorites[name]
            item = QListWidgetItem(f"{name}  -  {entry.get('from', '')} to {entry.get('to', '')}")
            item.setData(Qt.ItemDataRole.UserRole, name)
            self.list.addItem(item)

    def _current(self) -> str | None:
        item = self.list.currentItem()
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def _rename(self) -> None:
        name = self._current()
        if not name:
            return
        new_name, ok = QInputDialog.getText(self, "Rename favourite", "Name:", text=name)
        if ok and new_name.strip() and new_name != name:
            self.favorites[new_name.strip()] = self.favorites.pop(name)
            self._reload()

    def _edit(self) -> None:
        name = self._current()
        if not name:
            return
        entry = self.favorites[name]
        start, ok = QInputDialog.getText(self, "Edit range", "From:", text=entry.get("from", ""))
        if not ok:
            return
        end, ok = QInputDialog.getText(self, "Edit range", "To:", text=entry.get("to", ""))
        if not ok:
            return
        self.favorites[name] = {"from": start.strip(), "to": end.strip()}
        self._reload()

    def _remove(self) -> None:
        name = self._current()
        if not name:
            return
        if QMessageBox.question(self, "Remove favourite",
                                f"Remove '{name}'?") == QMessageBox.StandardButton.Yes:
            self.favorites.pop(name, None)
            self._reload()

    def accept(self) -> None:
        self.config.set("favorites", self.favorites)
        self.config.save()
        super().accept()


class AboutDialog(QDialog):
    def __init__(self, config: Config, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"About {APP_NAME}")
        self.setMinimumWidth(460)

        title = QLabel(f"<h2>{APP_NAME}</h2>")
        version = QLabel(f"Version {__version__}")
        blurb = QLabel(
            "A fast IP and port scanner built by CyberCrew for vulnerability "
            "assessment and penetration testing work.<br><br>"
            "Scans any range, resolves hostnames and MAC vendors, fingerprints "
            "services and exports to CSV, TXT, XML, JSON, IP:Port and HTML.<br><br>"
            f'<a href="{APP_URL}">{APP_URL}</a>'
        )
        blurb.setWordWrap(True)
        blurb.setOpenExternalLinks(True)

        details = QGroupBox("Environment")
        grid = QGridLayout(details)
        rows = [
            ("MAC vendor database", oui.source_description()),
            ("Settings file", str(config.path)),
            ("Mode", "Portable" if config.is_portable else "Installed"),
        ]
        for index, (label, value) in enumerate(rows):
            name = QLabel(f"{label}:")
            name.setStyleSheet("color: palette(mid);")
            grid.addWidget(name, index, 0)
            field = QLabel(value)
            field.setWordWrap(True)
            field.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            grid.addWidget(field, index, 1)

        legal = QLabel(
            "<b>Use responsibly.</b> Only scan networks you own or have written "
            "authorisation to test."
        )
        legal.setWordWrap(True)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)

        layout = QVBoxLayout(self)
        for widget in (title, version, blurb, details, legal, buttons):
            layout.addWidget(widget)
