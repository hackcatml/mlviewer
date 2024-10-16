import platform

from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtCore import Qt, QObject, pyqtSlot
from PyQt6.QtWidgets import QTableWidgetItem, QWidget


class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(450, 170)
        font = QtGui.QFont()
        font.setFamily("Courier New")
        font_size = 13 if platform.system() == "Darwin" else 9
        font.setPointSize(font_size)
        Form.setFont(font)
        self.gridLayout = QtWidgets.QGridLayout(Form)
        self.gridLayout.setObjectName("gridLayout")
        self.historyTableWidget = QtWidgets.QTableWidget(Form)
        font = QtGui.QFont()
        font.setFamily("Courier New")
        self.historyTableWidget.setFont(font)
        self.historyTableWidget.setColumnCount(2)
        self.historyTableWidget.setColumnWidth(0, 130)
        self.historyTableWidget.setColumnWidth(1, 250)
        self.historyTableWidget.setHorizontalHeaderLabels(['Address', 'Description'])
        self.historyTableWidget.setObjectName("historyTableWidget")
        self.gridLayout.addWidget(self.historyTableWidget, 0, 0, 1, 1)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "History"))


class EscapableWidget(QWidget):
    history_remove_row_signal = QtCore.pyqtSignal()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            self.close()
        elif event.key() == Qt.Key.Key_Delete:
            self.history_remove_row_signal.emit()
        else:
            super().keyPressEvent(event)


class HistoryViewClass(QObject):
    history_addr_signal = QtCore.pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.history_window = EscapableWidget()
        self.history_window.history_remove_row_signal.connect(self.remove_row)
        self.history_ui = Ui_Form()
        self.history_ui.setupUi(self.history_window)

        self.history_ui.historyTableWidget.itemClicked.connect(self.addr_clicked)

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

    def addr_clicked(self, item):
        if item.column() == 0:
            self.history_addr_signal.emit(item.text())

    def clear_table(self):
        self.history_ui.historyTableWidget.clearContents()
        while self.history_ui.historyTableWidget.rowCount() > 0:
            self.history_ui.historyTableWidget.removeRow(0)

    @pyqtSlot()
    def remove_row(self):
        selected_items = self.history_ui.historyTableWidget.selectedItems()
        if selected_items:
            selected_row = selected_items[0].row()
            self.history_ui.historyTableWidget.removeRow(selected_row)
