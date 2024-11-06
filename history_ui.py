import platform

from PyQt6 import QtGui, QtCore, QtWidgets
from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtWidgets import QTableWidgetItem, QTableWidget, QMenu


class HistoryTableWidget(QTableWidget):
    key_escape_pressed_signal = QtCore.pyqtSignal()
    history_remove_row_signal = QtCore.pyqtSignal(str)
    set_watch_func_signal = QtCore.pyqtSignal(str)
    set_watch_regs_signal = QtCore.pyqtSignal(str)

    def __init__(self, args):
        super(HistoryTableWidget, self).__init__(args)

    def keyPressEvent(self, e: QtGui.QKeyEvent) -> None:
        if e.key() == Qt.Key.Key_Escape:
            self.key_escape_pressed_signal.emit()
        if e.key() == Qt.Key.Key_Delete:
            item = self.item(self.selectedItems()[0].row(), 0)
            self.history_remove_row_signal.emit(item.text())

    def contextMenuEvent(self, event: QtGui.QContextMenuEvent):
        item = self.itemAt(event.pos())
        if item is not None and len(self.selectedItems()) == 1 and item.column() == 0:
            context_menu = QMenu(self)
            action1 = context_menu.addAction("Set Watch Func")
            action2 = context_menu.addAction("Set Watch Regs")
            action = context_menu.exec(event.globalPos())
            if action == action1:
                self.set_watch_func_signal.emit(item.text())
            elif action == action2:
                self.set_watch_regs_signal.emit(item.text())

    @pyqtSlot(list)
    def watch_list_sig_func(self, sig: list):
        if not sig:
            for row in range(self.rowCount()):
                item = self.item(row, 2)
                if item.text() == "Watch func" or "Watch regs":
                    self.setItem(row, 2, QTableWidgetItem(""))
        else:
            for row in range(self.rowCount()):
                item = self.item(row, 0)
                for watch_item in sig:
                    if watch_item[0] in item.text():
                        self.setItem(item.row(), 2, QTableWidgetItem("Watch func" if watch_item[1] is False else "Watch regs"))
                        break


class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(530, 170)
        font = QtGui.QFont()
        font.setFamily("Courier New")
        font_size = 13 if platform.system() == "Darwin" else 9
        font.setPointSize(font_size)
        Form.setFont(font)
        self.gridLayout = QtWidgets.QGridLayout(Form)
        self.gridLayout.setObjectName("gridLayout")
        # self.historyTableWidget = QtWidgets.QTableWidget(Form)
        self.historyTableWidget = HistoryTableWidget(Form)
        font = QtGui.QFont()
        font.setFamily("Courier New")
        self.historyTableWidget.setFont(font)
        self.historyTableWidget.setColumnCount(3)
        self.historyTableWidget.setColumnWidth(0, 130)
        self.historyTableWidget.setColumnWidth(1, 250)
        self.historyTableWidget.setColumnWidth(2, 100)
        self.historyTableWidget.setHorizontalHeaderLabels(['Address', 'Description', 'Stat'])
        self.historyTableWidget.setObjectName("historyTableWidget")
        self.gridLayout.addWidget(self.historyTableWidget, 0, 0, 1, 1)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "History"))