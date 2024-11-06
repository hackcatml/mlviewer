import platform

from PyQt6 import QtCore
from PyQt6.QtCore import Qt, QObject, pyqtSlot, QPoint
from PyQt6.QtWidgets import QTableWidgetItem, QWidget

import history_ui


class EscapableWidget(QWidget):
    @pyqtSlot()
    def key_escape_pressed_sig_func(self):
        self.close()


class HistoryViewClass(QObject):
    history_addr_signal = QtCore.pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.history_window = EscapableWidget()
        self.history_ui = history_ui.Ui_Form()
        self.history_ui.setupUi(self.history_window)

        self.history_ui.historyTableWidget.key_escape_pressed_signal.connect(self.history_window.key_escape_pressed_sig_func)
        self.history_ui.historyTableWidget.history_remove_row_signal.connect(self.history_remove_row_sig_func)
        self.history_ui.historyTableWidget.itemClicked.connect(self.addr_clicked)

        self.historyBtnClickedCount = 0

    def show_history(self):
        self.historyBtnClickedCount += 1
        self.history_window.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint)
        self.history_window.show()
        if self.historyBtnClickedCount == 1:
            curr_pos = self.history_window.pos()
            new_pos = (curr_pos + QPoint(480, -350)) if platform.system() == "Darwin" else (
                    curr_pos + QPoint(490, -360))
            self.history_window.move(new_pos)

    def add_row(self, addr):
        for row in range(self.history_ui.historyTableWidget.rowCount()):
            item = self.history_ui.historyTableWidget.item(row, 0)
            if item is not None and item.text() == addr:
                return

        row_position = self.history_ui.historyTableWidget.rowCount()
        self.history_ui.historyTableWidget.insertRow(row_position)

        # Address column (non-editable)
        address_item = QTableWidgetItem(f"{addr}")
        address_item.setFlags(address_item.flags() & ~Qt.ItemFlag.ItemIsEditable)  # Make it non-editable
        self.history_ui.historyTableWidget.setItem(row_position, 0, address_item)

        # Description column (editable)
        description_item = QTableWidgetItem("Description")
        self.history_ui.historyTableWidget.setItem(row_position, 1, description_item)

        # Stat column (non-editable)
        stat_item = QTableWidgetItem("")
        self.history_ui.historyTableWidget.setItem(row_position, 2, stat_item)

    def addr_clicked(self, item):
        if item.column() == 0:
            self.history_addr_signal.emit(item.text())

    def clear_table(self):
        self.history_ui.historyTableWidget.clearContents()
        while self.history_ui.historyTableWidget.rowCount() > 0:
            self.history_ui.historyTableWidget.removeRow(0)

    @pyqtSlot(str)
    def history_remove_row_sig_func(self, sig: str):
        selected_items = self.history_ui.historyTableWidget.selectedItems()
        if selected_items:
            selected_row = selected_items[0].row()
            self.history_ui.historyTableWidget.removeRow(selected_row)
