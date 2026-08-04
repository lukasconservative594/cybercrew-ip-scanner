"""The main application window.

Deliberately plain: one row of controls, one table, one status bar. Anything
that is not needed to start a scan lives in a menu.
"""

from __future__ import annotations

import collections
import threading
from pathlib import Path
from typing import Any

from PyQt6.QtCore import QPoint, Qt, QTimer, QUrl
from PyQt6.QtGui import (
    QAction, QActionGroup, QColor, QDesktopServices, QFont, QGuiApplication,
    QIcon, QKeySequence, QPainter, QPixmap,
)
from PyQt6.QtWidgets import (
    QAbstractItemView, QApplication, QComboBox, QFileDialog, QHeaderView,
    QInputDialog, QLabel, QLineEdit, QMainWindow, QMenu, QMessageBox,
    QProgressBar, QPushButton, QSizePolicy, QStatusBar, QTableView, QToolBar,
    QWidget,
)

from .. import APP_NAME, APP_URL, __version__
from .. import fetchers as fetchers_pkg
from ..core import net, oui
from ..core.config import Config
from ..core.ranges import (
    FileFeeder, RandomFeeder, RangeError, RangeFeeder, netmask_to_prefix,
    parse_ip, parse_ports,
)
from ..core.scanner import ScanStats, Scanner
from ..core.subject import HostState, ScanResult
from ..exporters import FORMATS, ExportError, export
from . import openers as openers_mod
from .dialogs import (
    AboutDialog, FavoritesDialog, FetchersDialog, HostDetailsDialog,
    PreferencesDialog,
)
from .model import ResultsModel, ResultsProxy, state_icon

_DISPLAY_STATES = {
    "all": HostState.UNKNOWN,
    "alive": HostState.ALIVE,
    "ports": HostState.WITH_PORTS,
}


def app_icon() -> QIcon:
    """Draw the application icon so there is no binary asset to ship."""
    icon = QIcon()
    for size in (16, 32, 48, 64, 256):
        pixmap = QPixmap(size, size)
        pixmap.fill(QColor(0, 0, 0, 0))
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        unit = size / 64.0
        painter.setBrush(QColor("#0b7285"))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(0, 0, size, size, 12 * unit, 12 * unit)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        for index, radius in enumerate((10, 18, 26)):
            painter.setPen(QColor(255, 255, 255, 210 - index * 55))
            r = radius * unit
            painter.drawEllipse(
                int(size / 2 - r), int(size / 2 - r), int(r * 2), int(r * 2)
            )
        painter.setBrush(QColor("#4dd4c4"))
        painter.setPen(Qt.PenStyle.NoPen)
        dot = max(3.0, 5 * unit)
        painter.drawEllipse(
            int(size / 2 - dot / 2), int(size / 2 - dot / 2), int(dot), int(dot)
        )
        painter.end()
        icon.addPixmap(pixmap)
    return icon


class MainWindow(QMainWindow):
    def __init__(self, config: Config):
        super().__init__()
        self.config = config
        self.scanner: Scanner | None = None
        self.active_fetchers: list = []
        self.feeder_info = ""
        self.last_stats: ScanStats | None = None

        self._incoming: collections.deque = collections.deque()
        self._latest_stats: ScanStats | None = None
        self._finished_stats: ScanStats | None = None
        self._errors: list[str] = []

        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(app_icon())
        self.resize(1180, 680)

        self._build_table()
        self._build_toolbar()
        self._build_status_bar()
        self._build_menus()
        self._restore_geometry()

        self._timer = QTimer(self)
        self._timer.setInterval(60)
        self._timer.timeout.connect(self._drain)

        self._load_last_range()
        self._apply_display_filter()
        self._update_actions()

    # ------------------------------------------------------------------
    # construction
    # ------------------------------------------------------------------
    def _build_table(self) -> None:
        self.model = ResultsModel(self.config, self)
        self.proxy = ResultsProxy(self)
        self.proxy.setSourceModel(self.model)

        self.table = QTableView(self)
        self.table.setModel(self.proxy)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        self.table.doubleClicked.connect(lambda _: self.show_details())
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(22)
        self.table.horizontalHeader().setSectionsMovable(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.setCentralWidget(self.table)

        self._rebuild_columns()
        # Address order is the sane default; the IP column sorts numerically,
        # so 192.168.1.9 comes before 192.168.1.10 rather than after it.
        self.table.sortByColumn(0, Qt.SortOrder.AscendingOrder)

    def _build_toolbar(self) -> None:
        bar = QToolBar("Scan", self)
        bar.setMovable(False)
        bar.setFloatable(False)
        self.addToolBar(bar)

        bar.addWidget(QLabel("  Range: "))
        self.range_from = QLineEdit()
        self.range_from.setPlaceholderText("192.168.1.1")
        self.range_from.setMinimumWidth(150)
        self.range_from.returnPressed.connect(self.start_scan)
        bar.addWidget(self.range_from)

        self.to_label = QLabel("  to  ")
        bar.addWidget(self.to_label)
        self.range_to = QLineEdit()
        self.range_to.setPlaceholderText("192.168.1.254")
        self.range_to.setMinimumWidth(150)
        self.range_to.returnPressed.connect(self.start_scan)
        bar.addWidget(self.range_to)

        self.range_button = QPushButton("Fill  ")
        self.range_button.setToolTip("Fill the range from a local interface or a netmask")
        self.range_button.setMenu(self._build_range_menu())
        bar.addWidget(self.range_button)

        bar.addSeparator()
        bar.addWidget(QLabel("  Ports: "))
        self.ports_edit = QLineEdit(str(self.config.get("ports", "")))
        self.ports_edit.setMinimumWidth(220)
        self.ports_edit.setToolTip("Comma separated, ranges allowed: 22,80,443,8000-8100")
        self.ports_edit.returnPressed.connect(self.start_scan)
        self.ports_edit.setCursorPosition(0)
        bar.addWidget(self.ports_edit)

        bar.addSeparator()
        self.start_button = QPushButton("  Start  ")
        self.start_button.setDefault(True)
        self.start_button.clicked.connect(self.toggle_scan)
        bar.addWidget(self.start_button)

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        bar.addWidget(spacer)

        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter results...")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.setMaximumWidth(220)
        self.filter_edit.textChanged.connect(self.proxy.set_text_filter)
        bar.addWidget(self.filter_edit)
        bar.addWidget(QLabel("  "))

    def _build_range_menu(self) -> QMenu:
        menu = QMenu(self)
        for iface in net.local_interfaces():
            network = iface.network
            if network is None or network.num_addresses <= 2:
                continue
            action = menu.addAction(
                f"{iface.name}: {network.network_address}/{network.prefixlen}"
            )
            action.triggered.connect(
                lambda _, n=network: self._set_range(
                    str(n.network_address), str(n.broadcast_address)
                )
            )
        menu.addSeparator()
        for prefix in (24, 23, 22, 20, 16):
            action = menu.addAction(f"Expand the address on the left to /{prefix}")
            action.triggered.connect(lambda _, p=prefix: self._expand_to_prefix(p))
        return menu

    def _build_status_bar(self) -> None:
        status = QStatusBar(self)
        self.setStatusBar(status)

        self.progress = QProgressBar()
        self.progress.setMaximumWidth(240)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(True)
        status.addPermanentWidget(self.progress)

        self.count_label = QLabel("")
        status.addPermanentWidget(self.count_label)

        self.status_label = QLabel("Ready")
        status.addWidget(self.status_label)

    def _build_menus(self) -> None:
        bar = self.menuBar()

        # --- Scan ------------------------------------------------------
        scan_menu = bar.addMenu("&Scan")
        self.action_start = QAction("&Start scan", self)
        self.action_start.setShortcut(QKeySequence("F5"))
        self.action_start.triggered.connect(self.start_scan)
        scan_menu.addAction(self.action_start)

        self.action_stop = QAction("S&top scan", self)
        self.action_stop.setShortcut(QKeySequence("Esc"))
        self.action_stop.triggered.connect(self.stop_scan)
        scan_menu.addAction(self.action_stop)

        scan_menu.addSeparator()
        self.action_export = QAction("&Export results...", self)
        self.action_export.setShortcut(QKeySequence.StandardKey.Save)
        self.action_export.triggered.connect(lambda: self.export_results(False))
        scan_menu.addAction(self.action_export)

        self.action_export_selection = QAction("Export se&lection...", self)
        self.action_export_selection.triggered.connect(lambda: self.export_results(True))
        scan_menu.addAction(self.action_export_selection)

        scan_menu.addSeparator()
        load = QAction("Load targets from &file...", self)
        load.triggered.connect(self.load_target_file)
        scan_menu.addAction(load)

        clear = QAction("&Clear results", self)
        clear.triggered.connect(self.clear_results)
        scan_menu.addAction(clear)

        scan_menu.addSeparator()
        quit_action = QAction("&Quit", self)
        quit_action.setShortcut(QKeySequence.StandardKey.Quit)
        quit_action.triggered.connect(self.close)
        scan_menu.addAction(quit_action)

        # --- View ------------------------------------------------------
        view_menu = bar.addMenu("&View")
        self.display_group = QActionGroup(self)
        self.display_group.setExclusive(True)
        current = str(self.config.get("display", "alive"))
        for key, label in (
            ("alive", "Alive hosts only"),
            ("ports", "Hosts with open ports only"),
            ("all", "All scanned hosts"),
        ):
            action = QAction(label, self, checkable=True)
            action.setData(key)
            action.setChecked(key == current)
            action.triggered.connect(lambda _, k=key: self._set_display(k))
            self.display_group.addAction(action)
            view_menu.addAction(action)

        view_menu.addSeparator()
        fit = QAction("Resize columns to content", self)
        fit.triggered.connect(self._fit_columns)
        view_menu.addAction(fit)

        # --- Go --------------------------------------------------------
        go_menu = bar.addMenu("&Go")
        find = QAction("&Find address...", self)
        find.setShortcut(QKeySequence("Ctrl+G"))
        find.triggered.connect(self.goto_address)
        go_menu.addAction(find)

        next_alive = QAction("Next alive host", self)
        next_alive.setShortcut(QKeySequence("Ctrl+D"))
        next_alive.triggered.connect(lambda: self._goto_state(HostState.ALIVE))
        go_menu.addAction(next_alive)

        next_ports = QAction("Next host with open ports", self)
        next_ports.setShortcut(QKeySequence("Ctrl+P"))
        next_ports.triggered.connect(lambda: self._goto_state(HostState.WITH_PORTS))
        go_menu.addAction(next_ports)

        # --- Commands --------------------------------------------------
        self.commands_menu = bar.addMenu("&Commands")
        self.commands_menu.aboutToShow.connect(self._rebuild_commands_menu)

        # --- Favourites ------------------------------------------------
        self.favorites_menu = bar.addMenu("Fa&vourites")
        self.favorites_menu.aboutToShow.connect(self._rebuild_favorites_menu)

        # --- Tools -----------------------------------------------------
        tools_menu = bar.addMenu("&Tools")
        prefs = QAction("&Preferences...", self)
        prefs.setShortcut(QKeySequence("Ctrl+,"))
        prefs.triggered.connect(self.show_preferences)
        tools_menu.addAction(prefs)

        pick = QAction("Select &fetchers...", self)
        pick.setShortcut(QKeySequence("Ctrl+F"))
        pick.triggered.connect(self.show_fetchers)
        tools_menu.addAction(pick)

        tools_menu.addSeparator()
        stats = QAction("Scan &statistics", self)
        stats.triggered.connect(self.show_statistics)
        tools_menu.addAction(stats)

        update_oui = QAction("&Update MAC vendor database", self)
        update_oui.triggered.connect(self.update_vendor_database)
        tools_menu.addAction(update_oui)

        # --- Help ------------------------------------------------------
        help_menu = bar.addMenu("&Help")
        about = QAction(f"&About {APP_NAME}", self)
        about.triggered.connect(lambda: AboutDialog(self.config, self).exec())
        help_menu.addAction(about)

        site = QAction("Project &website", self)
        site.triggered.connect(lambda: QDesktopServices.openUrl(QUrl(APP_URL)))
        help_menu.addAction(site)

    # ------------------------------------------------------------------
    # scanning
    # ------------------------------------------------------------------
    def toggle_scan(self) -> None:
        if self.scanner and self.scanner.running:
            self.stop_scan()
        else:
            self.start_scan()

    def start_scan(self) -> None:
        if self.scanner and self.scanner.running:
            return

        try:
            parse_ports(self.ports_edit.text())
        except RangeError as exc:
            QMessageBox.warning(self, "Invalid ports", str(exc))
            return
        self.config.set("ports", self.ports_edit.text().strip())

        try:
            feeder = self._build_feeder()
        except (RangeError, OSError) as exc:
            QMessageBox.warning(self, "Invalid range", str(exc))
            return

        if len(feeder) > 100000:
            answer = QMessageBox.question(
                self, "Large scan",
                f"This range covers {len(feeder):,} addresses and may take a "
                "long time.\n\nStart anyway?",
            )
            if answer != QMessageBox.StandardButton.Yes:
                return

        ids = list(self.config.get("selected_fetchers") or fetchers_pkg.default_ids())
        self.active_fetchers = fetchers_pkg.create(ids)
        if not self.active_fetchers:
            QMessageBox.warning(self, "No fetchers", "Select at least one fetcher first.")
            return

        self._rebuild_columns()
        self.model.clear()
        self._incoming.clear()
        self._errors.clear()
        self._latest_stats = None
        self._finished_stats = None

        self.feeder_info = feeder.info
        self.config.set("last_range", {"from": self.range_from.text().strip(),
                                       "to": self.range_to.text().strip()})
        self.config.save()

        self.progress.setValue(0)
        self.status_label.setText(f"Scanning {feeder.info}...")
        self.setWindowTitle(f"{feeder.info} - {APP_NAME}")

        # The engine emits every host; the view filters. That way switching
        # between "alive only" and "all" afterwards costs nothing.
        self.scanner = Scanner(
            feeder, self.active_fetchers, self.config,
            on_result=self._incoming.append,
            on_progress=self._on_progress,
            on_finished=self._on_finished,
            on_error=self._on_error,
            display="all",
        )
        self.scanner.start()
        self._timer.start()
        self._update_actions()

    def stop_scan(self) -> None:
        if self.scanner and self.scanner.running:
            self.scanner.abort()
            self.status_label.setText("Stopping...")
            self._update_actions()

    def _build_feeder(self):
        skip = self.config.bool_of("skip_broadcast")
        start = self.range_from.text().strip()
        end = self.range_to.text().strip()

        if not start:
            raise RangeError("Enter a starting address, range or CIDR.")
        if not end:
            # A single field may itself be a range, CIDR or wildcard.
            return RangeFeeder.from_text(start, skip)
        return RangeFeeder(parse_ip(start), parse_ip(end), skip)

    # -- engine callbacks (worker threads) ---------------------------------
    def _on_progress(self, stats: ScanStats) -> None:
        self._latest_stats = stats

    def _on_finished(self, stats: ScanStats) -> None:
        self._finished_stats = stats

    def _on_error(self, where: str, exc: Exception) -> None:
        if len(self._errors) < 50:
            self._errors.append(f"{where}: {exc}")

    # -- GUI thread drain --------------------------------------------------
    def _drain(self) -> None:
        batch: list[ScanResult] = []
        while self._incoming and len(batch) < 2000:
            batch.append(self._incoming.popleft())
        if batch:
            self.model.add_results(batch)

        stats = self._latest_stats
        if stats is not None:
            self.progress.setValue(stats.percent)
            self.count_label.setText(
                f"  {stats.scanned}/{stats.total}   alive {stats.alive}   "
                f"ports {stats.with_ports}   {stats.rate:.0f}/s  "
            )

        finished = self._finished_stats
        if finished is not None and not self._incoming:
            self._timer.stop()
            self._finished_stats = None
            self.last_stats = finished
            self.progress.setValue(100 if not finished.aborted else finished.percent)
            verb = "Aborted" if finished.aborted else "Finished"
            self.status_label.setText(f"{verb}: {finished.summary()}")
            self.setWindowTitle(f"{self.feeder_info} - {APP_NAME}")
            self._fit_columns()
            self._update_actions()

    def _update_actions(self) -> None:
        running = bool(self.scanner and self.scanner.running)
        self.start_button.setText("  Stop  " if running else "  Start  ")
        self.action_start.setEnabled(not running)
        self.action_stop.setEnabled(running)
        self.range_from.setEnabled(not running)
        self.range_to.setEnabled(not running)
        self.ports_edit.setEnabled(not running)
        self.range_button.setEnabled(not running)

    # ------------------------------------------------------------------
    # columns and display
    # ------------------------------------------------------------------
    def _rebuild_columns(self) -> None:
        if not self.active_fetchers:
            ids = list(self.config.get("selected_fetchers") or fetchers_pkg.default_ids())
            self.active_fetchers = fetchers_pkg.create(ids)
        self.model.set_fetchers(self.active_fetchers)
        header = self.table.horizontalHeader()
        for index, fetcher in enumerate(self.active_fetchers):
            self.table.setColumnWidth(index, getattr(fetcher, "width", 120))
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)

    def _fit_columns(self) -> None:
        self.table.resizeColumnsToContents()
        for index in range(self.model.columnCount()):
            if self.table.columnWidth(index) > 340:
                self.table.setColumnWidth(index, 340)

    def _set_display(self, key: str) -> None:
        self.config.set("display", key)
        self.config.save()
        self._apply_display_filter()

    def _apply_display_filter(self) -> None:
        key = str(self.config.get("display", "alive"))
        self.proxy.set_minimum_state(_DISPLAY_STATES.get(key, HostState.ALIVE))

    # ------------------------------------------------------------------
    # range helpers
    # ------------------------------------------------------------------
    def _set_range(self, start: str, end: str) -> None:
        self.range_from.setText(start)
        self.range_to.setText(end)

    def _expand_to_prefix(self, prefix: int) -> None:
        text = self.range_from.text().strip()
        if not text:
            QMessageBox.information(self, "No address",
                                    "Type an address in the first box first.")
            return
        try:
            from ..core.ranges import range_of_network

            start, end = range_of_network(parse_ip(text.split("/")[0]), prefix)
        except RangeError as exc:
            QMessageBox.warning(self, "Invalid address", str(exc))
            return
        self._set_range(str(start), str(end))

    def _load_last_range(self) -> None:
        last = self.config.get("last_range") or {}
        start, end = str(last.get("from", "")), str(last.get("to", ""))
        if not start:
            iface = net.primary_interface()
            network = iface.network if iface else None
            if network is not None and network.num_addresses > 2:
                start = str(network.network_address)
                end = str(network.broadcast_address)
        self._set_range(start, end)

    def load_target_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Load targets", "", "Text files (*.txt *.lst);;All files (*)"
        )
        if not path:
            return
        try:
            feeder = FileFeeder(path, self.config.bool_of("skip_broadcast"))
        except OSError as exc:
            QMessageBox.warning(self, "Could not read file", str(exc))
            return
        if not len(feeder):
            QMessageBox.warning(self, "Nothing to scan",
                                "That file contained no usable addresses.")
            return
        addresses = list(feeder)
        self._set_range(str(addresses[0]), str(addresses[-1]))
        QMessageBox.information(
            self, "Targets loaded",
            f"{len(addresses)} addresses found. The range boxes now span the "
            "first and last entry - press Start to scan it."
        )

    # ------------------------------------------------------------------
    # selection actions
    # ------------------------------------------------------------------
    def selected_results(self) -> list[ScanResult]:
        rows = {index.row() for index in self.table.selectionModel().selectedRows()}
        if not rows:
            rows = {index.row() for index in self.table.selectionModel().selectedIndexes()}
        results = []
        for row in sorted(rows):
            source = self.proxy.mapToSource(self.proxy.index(row, 0))
            result = self.model.result_at(source.row())
            if result is not None:
                results.append(result)
        return results

    def show_details(self) -> None:
        results = self.selected_results()
        if not results:
            return
        HostDetailsDialog(results[0], self.model.fetchers(), self.config, self).exec()

    def copy_selection(self, ip_only: bool = False) -> None:
        results = self.selected_results()
        if not results:
            return
        na = str(self.config.get("not_available_text", ""))
        ns = str(self.config.get("not_scanned_text", ""))
        if ip_only:
            text = "\n".join(r.ip for r in results)
        else:
            ids = [f.id for f in self.model.fetchers()]
            headers = [f.name for f in self.model.fetchers()]
            lines = ["\t".join(headers)]
            lines += ["\t".join(r.display(i, na, ns) for i in ids) for r in results]
            text = "\n".join(lines)
        QGuiApplication.clipboard().setText(text)
        self.status_label.setText(f"Copied {len(results)} row(s) to the clipboard.")

    def add_comment(self) -> None:
        results = self.selected_results()
        if not results:
            return
        comments = dict(self.config.get("comments") or {})
        current = comments.get(results[0].ip, "")
        text, ok = QInputDialog.getText(
            self, "Comment", f"Note for {results[0].ip}:", text=current
        )
        if not ok:
            return
        for result in results:
            if text.strip():
                comments[result.ip] = text.strip()
                result.values["comment"] = text.strip()
            else:
                comments.pop(result.ip, None)
                result.values["comment"] = None
        self.config.set("comments", comments)
        self.config.save()
        self.model.refresh_texts()

    def goto_address(self) -> None:
        text, ok = QInputDialog.getText(self, "Find address", "Address:")
        if not ok or not text.strip():
            return
        row = self.model.row_of_ip(text.strip())
        if row < 0:
            QMessageBox.information(self, "Not found",
                                    f"{text.strip()} is not in the current results.")
            return
        self._select_source_row(row)

    def _goto_state(self, minimum: HostState) -> None:
        selection = self.table.selectionModel().selectedRows()
        start = selection[0].row() + 1 if selection else 0
        for row in range(start, self.proxy.rowCount()):
            source = self.proxy.mapToSource(self.proxy.index(row, 0))
            result = self.model.result_at(source.row())
            if result and result.state >= minimum:
                self.table.selectRow(row)
                self.table.scrollTo(self.proxy.index(row, 0))
                return
        self.status_label.setText("No further matching host below the selection.")

    def _select_source_row(self, source_row: int) -> None:
        proxy_index = self.proxy.mapFromSource(self.model.index(source_row, 0))
        if not proxy_index.isValid():
            QMessageBox.information(
                self, "Hidden by filter",
                "That host is in the results but the current view filters it out."
            )
            return
        self.table.selectRow(proxy_index.row())
        self.table.scrollTo(proxy_index)

    # ------------------------------------------------------------------
    # menus that rebuild on demand
    # ------------------------------------------------------------------
    def _rebuild_commands_menu(self) -> None:
        self.commands_menu.clear()
        has_selection = bool(self.table.selectionModel().selectedIndexes())

        details = self.commands_menu.addAction("Show &details")
        details.setEnabled(has_selection)
        details.triggered.connect(self.show_details)

        copy_ip = self.commands_menu.addAction("Copy &address")
        copy_ip.setEnabled(has_selection)
        copy_ip.triggered.connect(lambda: self.copy_selection(True))

        copy_row = self.commands_menu.addAction("&Copy row")
        copy_row.setShortcut(QKeySequence.StandardKey.Copy)
        copy_row.setEnabled(has_selection)
        copy_row.triggered.connect(lambda: self.copy_selection(False))

        comment = self.commands_menu.addAction("Add co&mment...")
        comment.setEnabled(has_selection)
        comment.triggered.connect(self.add_comment)

        self.commands_menu.addSeparator()
        for opener in self._openers():
            action = self.commands_menu.addAction(opener.get("name", "Opener"))
            action.setEnabled(has_selection)
            action.triggered.connect(lambda _, o=opener: self._run_opener(o))

        self.commands_menu.addSeparator()
        edit = self.commands_menu.addAction("&Edit openers...")
        edit.triggered.connect(self.edit_openers)

    def _openers(self) -> list[dict[str, Any]]:
        stored = self.config.get("openers")
        if not stored:
            stored = openers_mod.default_openers()
            self.config.set("openers", stored)
        return list(stored)

    def _run_opener(self, opener: dict[str, Any]) -> None:
        results = self.selected_results()
        if not results:
            return
        for result in results[:10]:
            ok, message = openers_mod.launch(opener, result)
            if not ok:
                QMessageBox.warning(self, "Could not run opener", message)
                return
        self.status_label.setText(f"Ran '{opener.get('name')}' on {len(results[:10])} host(s).")

    def edit_openers(self) -> None:
        lines = []
        for opener in self._openers():
            kind = "url" if opener.get("url") else "cmd"
            lines.append(f"{opener.get('name','')} | {kind} | {opener.get('command','')}")
        text, ok = QInputDialog.getMultiLineText(
            self, "Edit openers",
            "One per line:  Name | url or cmd | command\n"
            "Placeholders: ${ip} ${hostname} ${port} ${ports} ${mac}",
            "\n".join(lines),
        )
        if not ok:
            return
        parsed = []
        for line in text.splitlines():
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 3 and parts[0] and parts[2]:
                parsed.append({
                    "name": parts[0],
                    "url": parts[1].lower().startswith("url"),
                    "command": parts[2],
                })
        self.config.set("openers", parsed or openers_mod.default_openers())
        self.config.save()

    def _rebuild_favorites_menu(self) -> None:
        self.favorites_menu.clear()
        add = self.favorites_menu.addAction("&Add current range...")
        add.triggered.connect(self.add_favorite)
        manage = self.favorites_menu.addAction("&Manage favourites...")
        manage.triggered.connect(lambda: FavoritesDialog(self.config, self).exec())

        favorites = self.config.get("favorites") or {}
        if favorites:
            self.favorites_menu.addSeparator()
        for name in sorted(favorites):
            entry = favorites[name]
            action = self.favorites_menu.addAction(name)
            action.triggered.connect(
                lambda _, e=entry: self._set_range(str(e.get("from", "")),
                                                   str(e.get("to", "")))
            )

    def add_favorite(self) -> None:
        start = self.range_from.text().strip()
        if not start:
            QMessageBox.information(self, "Nothing to save", "Enter a range first.")
            return
        end = self.range_to.text().strip()
        default = f"{start} - {end}" if end else start
        name, ok = QInputDialog.getText(self, "Add favourite", "Name:", text=default)
        if not ok or not name.strip():
            return
        favorites = dict(self.config.get("favorites") or {})
        favorites[name.strip()] = {"from": start, "to": end}
        self.config.set("favorites", favorites)
        self.config.save()
        self.status_label.setText(f"Saved favourite '{name.strip()}'.")

    def _show_context_menu(self, position: QPoint) -> None:
        menu = QMenu(self)
        has_selection = bool(self.table.selectionModel().selectedIndexes())

        details = menu.addAction("Show details")
        details.setEnabled(has_selection)
        details.triggered.connect(self.show_details)

        copy_ip = menu.addAction("Copy address")
        copy_ip.setEnabled(has_selection)
        copy_ip.triggered.connect(lambda: self.copy_selection(True))

        copy_row = menu.addAction("Copy row")
        copy_row.setEnabled(has_selection)
        copy_row.triggered.connect(lambda: self.copy_selection(False))

        comment = menu.addAction("Add comment...")
        comment.setEnabled(has_selection)
        comment.triggered.connect(self.add_comment)

        menu.addSeparator()
        for opener in self._openers():
            action = menu.addAction(opener.get("name", "Opener"))
            action.setEnabled(has_selection)
            action.triggered.connect(lambda _, o=opener: self._run_opener(o))

        menu.exec(self.table.viewport().mapToGlobal(position))

    # ------------------------------------------------------------------
    # tools
    # ------------------------------------------------------------------
    def show_preferences(self) -> None:
        dialog = PreferencesDialog(self.config, self)
        if dialog.exec():
            self.ports_edit.setText(str(self.config.get("ports", "")))
            self.model.refresh_texts()
            for action in self.display_group.actions():
                action.setChecked(action.data() == str(self.config.get("display")))
            self._apply_display_filter()

    def show_fetchers(self) -> None:
        dialog = FetchersDialog(self.config, self)
        if dialog.exec():
            if self.model.rowCount():
                answer = QMessageBox.question(
                    self, "Clear results?",
                    "Changing columns clears the current results.\n\nContinue?",
                )
                if answer != QMessageBox.StandardButton.Yes:
                    return
            self.active_fetchers = fetchers_pkg.create(dialog.selected_ids())
            self._rebuild_columns()

    def show_statistics(self) -> None:
        stats = self.last_stats
        if stats is None:
            QMessageBox.information(self, "Scan statistics", "No scan has finished yet.")
            return
        lines = [
            f"Range:              {self.feeder_info}",
            f"Addresses scanned:  {stats.scanned} of {stats.total}",
            f"Alive hosts:        {stats.alive}",
            f"Hosts with ports:   {stats.with_ports}",
            f"Open ports found:   {stats.open_ports}",
            f"Dead / no reply:    {stats.dead}",
            f"Elapsed:            {stats.elapsed:.1f} s",
            f"Rate:               {stats.rate:.0f} hosts/s",
        ]
        if stats.aborted:
            lines.append("\nThe scan was stopped before it finished.")
        if self._errors:
            lines.append(f"\n{len(self._errors)} non-fatal error(s):")
            lines.extend(f"  {message}" for message in self._errors[:10])
        QMessageBox.information(self, "Scan statistics", "\n".join(lines))

    def update_vendor_database(self) -> None:
        self.status_label.setText("Downloading the IEEE MAC vendor registry...")
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        QApplication.processEvents()
        try:
            ok, message = oui.update_from_ieee()
        finally:
            QApplication.restoreOverrideCursor()
        self.status_label.setText(message)
        if ok:
            QMessageBox.information(self, "Vendor database", message)
        else:
            QMessageBox.warning(self, "Vendor database", message)

    # ------------------------------------------------------------------
    # export
    # ------------------------------------------------------------------
    def export_results(self, selection_only: bool = False) -> None:
        results = self.selected_results() if selection_only else self._visible_results()
        if not results:
            QMessageBox.information(
                self, "Nothing to export",
                "There are no results to save." if not selection_only
                else "Select some rows first."
            )
            return

        filters = ";;".join(FORMATS[key] for key in ("csv", "txt", "xml", "json", "lst", "html"))
        path, chosen = QFileDialog.getSaveFileName(
            self, "Export results", "scan-results.csv", filters
        )
        if not path:
            return

        fmt = None
        for key, label in FORMATS.items():
            if label == chosen:
                fmt = key
                break
        if fmt == "lst" and Path(path).suffix.lower() != ".txt":
            path = str(Path(path).with_suffix(".txt"))

        try:
            written = export(
                results, path, self.model.fetchers(), fmt,
                not_available=str(self.config.get("not_available_text", "")),
                not_scanned=str(self.config.get("not_scanned_text", "")),
                feeder_info=self.feeder_info,
            )
        except ExportError as exc:
            QMessageBox.warning(self, "Export failed", str(exc))
            return

        self.status_label.setText(f"Exported {written} row(s) to {path}")
        if QMessageBox.question(
            self, "Export complete",
            f"Wrote {written} row(s) to:\n{path}\n\nOpen the containing folder?",
        ) == QMessageBox.StandardButton.Yes:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(path).parent)))

    def _visible_results(self) -> list[ScanResult]:
        results = []
        for row in range(self.proxy.rowCount()):
            source = self.proxy.mapToSource(self.proxy.index(row, 0))
            result = self.model.result_at(source.row())
            if result is not None:
                results.append(result)
        return results

    def clear_results(self) -> None:
        self.model.clear()
        self.progress.setValue(0)
        self.count_label.setText("")
        self.status_label.setText("Ready")
        self.setWindowTitle(APP_NAME)

    # ------------------------------------------------------------------
    # geometry
    # ------------------------------------------------------------------
    def _restore_geometry(self) -> None:
        stored = self.config.get("window_geometry")
        if isinstance(stored, str) and stored:
            try:
                from PyQt6.QtCore import QByteArray

                self.restoreGeometry(QByteArray.fromBase64(stored.encode("ascii")))
            except Exception:
                pass

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt naming
        if self.scanner and self.scanner.running:
            answer = QMessageBox.question(
                self, "Scan in progress",
                "A scan is still running. Stop it and quit?",
            )
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self.scanner.abort()
            self.scanner.join(3)

        try:
            geometry = bytes(self.saveGeometry().toBase64()).decode("ascii")
            self.config.set("window_geometry", geometry)
        except Exception:
            pass
        self.config.set("ports", self.ports_edit.text().strip())
        self.config.save()
        event.accept()
