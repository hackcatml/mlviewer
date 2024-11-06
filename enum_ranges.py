import platform

from PyQt6 import QtCore
from PyQt6.QtCore import QObject, pyqtSlot, Qt, QPoint
from PyQt6.QtWidgets import QWidget, QTableWidgetItem

import enum_ranges_ui
import gvar


class EscapableWidget(QWidget):
    @pyqtSlot()
    def key_escape_pressed_sig_func(self):
        self.close()


class EnumRangesViewClass(QObject):
    refresh_enum_ranges_signal = QtCore.pyqtSignal(str)
    enum_ranges_item_clicked_signal = QtCore.pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self.enum_ranges_window = EscapableWidget()
        self.enum_ranges_ui = enum_ranges_ui.Ui_Form()
        self.enum_ranges_ui.setupUi(self.enum_ranges_window)

        self.table_filled = False

        self.enum_ranges_ui.refreshEnumRangesBtn.clicked.connect(self.refresh_enum_ranges)
        self.enum_ranges_ui.enumRangesTableWidget.key_escape_pressed_signal.connect(self.enum_ranges_window.key_escape_pressed_sig_func)
        self.enum_ranges_ui.enumRangesFilter.textChanged.connect(self.enum_ranges_filter)
        self.enum_ranges_ui.enumRangesTableWidget.itemClicked.connect(self.item_clicked)

        self.showEnumRangesBtnClickedCount = 0

    def show_enum_ranges(self):
        self.showEnumRangesBtnClickedCount += 1
        self.enum_ranges_window.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint)
        self.enum_ranges_window.show()
        if self.showEnumRangesBtnClickedCount == 1:
            curr_pos = self.enum_ranges_window.pos()
            new_pos = (curr_pos + QPoint(350, -150)) if platform.system() == "Darwin" else (
                    curr_pos + QPoint(360, -160))
            self.enum_ranges_window.move(new_pos)
        if gvar.enumerate_ranges and not self.table_filled:
            self.add_row(gvar.enumerate_ranges)

    def refresh_enum_ranges(self):
        if gvar.is_frida_attached and gvar.frida_instrument is not None:
            self.refresh_enum_ranges_signal.emit('r--')
            self.enum_ranges_ui.enumRangesTableWidget.setRowCount(0)
            self.add_row(gvar.enumerate_ranges)

    def add_row(self, ranges):
        for i in range(len(ranges)):
            row_position = self.enum_ranges_ui.enumRangesTableWidget.rowCount()
            self.enum_ranges_ui.enumRangesTableWidget.insertRow(row_position)

            # Base column (non-editable)
            base_addr_item = QTableWidgetItem(f"{ranges[i][0]}")
            base_addr_item.setFlags(base_addr_item.flags() & ~Qt.ItemFlag.ItemIsEditable)  # Make it non-editable
            self.enum_ranges_ui.enumRangesTableWidget.setItem(row_position, 0, base_addr_item)

            # End column (non-editable)
            end_addr_item = QTableWidgetItem(f"{ranges[i][1]}")
            end_addr_item.setFlags(end_addr_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.enum_ranges_ui.enumRangesTableWidget.setItem(row_position, 1, end_addr_item)

            # Prot column (non-editable)
            prot_item = QTableWidgetItem(f"{ranges[i][2]}")
            prot_item.setFlags(prot_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.enum_ranges_ui.enumRangesTableWidget.setItem(row_position, 2, prot_item)

            # Prot column (non-editable)
            path_column = QTableWidgetItem(f"{ranges[i][4]}")
            path_column.setFlags(path_column.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.enum_ranges_ui.enumRangesTableWidget.setItem(row_position, 3, path_column)

        self.table_filled = True

    def enum_ranges_filter(self):
        filter_text = self.enum_ranges_ui.enumRangesFilter.toPlainText().lower()  # Get filter text (or use `text()` if it's a QLineEdit)
        for row in range(self.enum_ranges_ui.enumRangesTableWidget.rowCount()):
            row_match = False
            for column in range(self.enum_ranges_ui.enumRangesTableWidget.columnCount()):
                item = self.enum_ranges_ui.enumRangesTableWidget.item(row, column)
                if item and filter_text in item.text().lower():
                    row_match = True
                    break  # If one column matches, no need to check the rest

            # Hide the row if it doesn't match the filter
            self.enum_ranges_ui.enumRangesTableWidget.setRowHidden(row, not row_match)

    def item_clicked(self, item):
        self.enum_ranges_item_clicked_signal.emit([item.column(), item.text()])
