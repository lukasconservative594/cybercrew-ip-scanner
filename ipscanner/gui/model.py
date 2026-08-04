"""Table model for scan results.

Results arrive from many worker threads at once. Rather than touching the
model from those threads, the window drops them into a queue and a timer
flushes the queue on the GUI thread in batches - one ``beginInsertRows`` per
batch instead of one per host, which is the difference between a responsive
table and a frozen one during a /16.
"""

from __future__ import annotations

from typing import Any, Sequence

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PyQt6.QtGui import QBrush, QColor, QIcon, QPainter, QPixmap

from ..core.subject import HostState, ScanResult

SORT_ROLE = Qt.ItemDataRole.UserRole + 1
STATE_ROLE = Qt.ItemDataRole.UserRole + 2

STATE_COLOURS: dict[HostState, str] = {
    HostState.WITH_PORTS: "#2f9e44",
    HostState.ALIVE: "#1c7ed6",
    HostState.DEAD: "#e03131",
    HostState.UNKNOWN: "#868e96",
}

_ICON_CACHE: dict[str, QIcon] = {}


def state_icon(state: HostState) -> QIcon:
    """A small coloured dot, drawn rather than shipped as an asset."""
    colour = STATE_COLOURS.get(state, "#868e96")
    if colour not in _ICON_CACHE:
        pixmap = QPixmap(12, 12)
        pixmap.fill(QColor(0, 0, 0, 0))
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setBrush(QColor(colour))
        painter.setPen(QColor(0, 0, 0, 60))
        painter.drawEllipse(1, 1, 9, 9)
        painter.end()
        _ICON_CACHE[colour] = QIcon(pixmap)
    return _ICON_CACHE[colour]


class ResultsModel(QAbstractTableModel):
    """Holds every result row; one column per active fetcher."""

    def __init__(self, config, parent=None):
        super().__init__(parent)
        self.config = config
        self._results: list[ScanResult] = []
        self._fetchers: list = []
        self._headers: list[str] = []
        self._ids: list[str] = []
        self._numeric: list[bool] = []
        self.not_available = str(config.get("not_available_text", "[n/a]"))
        self.not_scanned = str(config.get("not_scanned_text", "[n/s]"))

    # -- structure ---------------------------------------------------------
    def set_fetchers(self, fetchers: Sequence) -> None:
        self.beginResetModel()
        self._fetchers = list(fetchers)
        self._headers = [f.name for f in self._fetchers]
        self._ids = [f.id for f in self._fetchers]
        self._numeric = [bool(getattr(f, "numeric", False)) for f in self._fetchers]
        self._results.clear()
        self.endResetModel()

    def refresh_texts(self) -> None:
        self.not_available = str(self.config.get("not_available_text", "[n/a]"))
        self.not_scanned = str(self.config.get("not_scanned_text", "[n/s]"))
        if self._results:
            top = self.index(0, 0)
            bottom = self.index(len(self._results) - 1, max(0, len(self._ids) - 1))
            self.dataChanged.emit(top, bottom)

    # -- content -----------------------------------------------------------
    def add_results(self, results: Sequence[ScanResult]) -> None:
        if not results:
            return
        start = len(self._results)
        self.beginInsertRows(QModelIndex(), start, start + len(results) - 1)
        self._results.extend(results)
        self.endInsertRows()

    def clear(self) -> None:
        self.beginResetModel()
        self._results.clear()
        self.endResetModel()

    def results(self) -> list[ScanResult]:
        return list(self._results)

    def result_at(self, row: int) -> ScanResult | None:
        if 0 <= row < len(self._results):
            return self._results[row]
        return None

    def fetchers(self) -> list:
        return list(self._fetchers)

    def row_of_ip(self, ip: str) -> int:
        for index, result in enumerate(self._results):
            if result.ip == ip:
                return index
        return -1

    # -- Qt interface ------------------------------------------------------
    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._results)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._headers)

    def headerData(self, section: int, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            if 0 <= section < len(self._headers):
                return self._headers[section]
            return None
        return section + 1

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        row, column = index.row(), index.column()
        if row >= len(self._results) or column >= len(self._ids):
            return None
        result = self._results[row]
        fetcher_id = self._ids[column]

        if role == Qt.ItemDataRole.DisplayRole:
            return result.display(fetcher_id, self.not_available, self.not_scanned)

        if role == Qt.ItemDataRole.DecorationRole and column == 0:
            return state_icon(result.state)

        if role == Qt.ItemDataRole.ForegroundRole and result.state == HostState.DEAD:
            return QBrush(QColor("#9aa3ad"))

        if role == Qt.ItemDataRole.TextAlignmentRole and self._numeric[column]:
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        if role == Qt.ItemDataRole.ToolTipRole:
            text = result.display(fetcher_id, self.not_available, self.not_scanned)
            return text if len(text) > 28 else None

        if role == STATE_ROLE:
            return int(result.state)

        if role == SORT_ROLE:
            return self._sort_value(result, column, fetcher_id)

        return None

    def _sort_value(self, result: ScanResult, column: int, fetcher_id: str):
        """Sort addresses numerically and empty cells last."""
        if fetcher_id == "ip":
            return int(result.address)
        value = result.value(fetcher_id)
        if value is None or value == "":
            return float("inf") if self._numeric[column] else "￿"
        if self._numeric[column]:
            try:
                return float(value)
            except (TypeError, ValueError):
                return float("inf")
        if isinstance(value, (list, tuple)):
            return ", ".join(str(v) for v in value).lower()
        return str(value).lower()


class ResultsProxy(QSortFilterProxyModel):
    """Sorting plus the alive/open-ports display filter."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setSortRole(SORT_ROLE)
        # Keep incoming rows in sorted position as they stream in, so the list
        # never shows a half-sorted jumble mid-scan.
        self.setDynamicSortFilter(True)
        self.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._min_state = HostState.UNKNOWN
        self._text = ""

    def set_minimum_state(self, state: HostState) -> None:
        self._min_state = state
        self.invalidateFilter()

    def set_text_filter(self, text: str) -> None:
        self._text = (text or "").strip().lower()
        self.invalidateFilter()

    def filterAcceptsRow(self, row: int, parent: QModelIndex) -> bool:
        model = self.sourceModel()
        if model is None:
            return True
        result = model.result_at(row)
        if result is None:
            return True
        if result.state < self._min_state:
            return False
        if not self._text:
            return True
        for column in range(model.columnCount()):
            index = model.index(row, column)
            value = model.data(index, Qt.ItemDataRole.DisplayRole)
            if value and self._text in str(value).lower():
                return True
        return False
