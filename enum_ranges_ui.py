# Form implementation generated from reading ui file 'enum_ranges.ui'
#
# Created by: PyQt6 UI code generator 6.4.0
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.

from PyQt6 import QtCore, QtWidgets, QtGui
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QShortcut, QKeySequence
from PyQt6.QtWidgets import QTableWidget, QApplication


class EnumRangesTableWidget(QTableWidget):
    key_escape_pressed_signal = QtCore.pyqtSignal()

    def __init__(self, args):
        super(EnumRangesTableWidget, self).__init__(args)

        # Set up the shortcut for Cmd+C or Ctrl+C
        copy_shortcut = QShortcut(QKeySequence("Ctrl+C"), self)
        copy_shortcut.activated.connect(self.copy_selected_items)

    def keyPressEvent(self, e: QtGui.QKeyEvent) -> None:
        if e.key() == Qt.Key.Key_Escape:
            self.key_escape_pressed_signal.emit()

    def copy_selected_items(self):
        # Get selected items
        selected_items = self.selectedItems()

        # Group items by row for copying in table format
        rows = {}
        for item in selected_items:
            row = item.row()
            if row not in rows:
                rows[row] = []
            rows[row].append(item.text())

        # Sort rows by their keys (row number) and create formatted text
        copied_text = "\n".join(
            "\t".join(rows[row]) for row in sorted(rows.keys())
        )

        # Copy to clipboard
        clipboard = QApplication.clipboard()
        clipboard.setText(copied_text)


class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(644, 269)
        self.gridLayout = QtWidgets.QGridLayout(Form)
        self.gridLayout.setObjectName("gridLayout")
        # self.enumRangesTableWidget = QtWidgets.QTableWidget(Form)
        self.enumRangesTableWidget = EnumRangesTableWidget(Form)
        self.enumRangesTableWidget.setObjectName("enumRangesTableWidget")
        self.enumRangesTableWidget.setColumnCount(4)
        self.enumRangesTableWidget.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.enumRangesTableWidget.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.enumRangesTableWidget.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.enumRangesTableWidget.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.enumRangesTableWidget.setHorizontalHeaderItem(3, item)
        self.enumRangesTableWidget.horizontalHeader().setVisible(True)
        self.enumRangesTableWidget.setColumnWidth(3, 300)
        self.gridLayout.addWidget(self.enumRangesTableWidget, 1, 0, 1, 1)
        self.enumRangesFilter = QtWidgets.QTextEdit(Form)
        self.enumRangesFilter.setMinimumSize(QtCore.QSize(0, 0))
        self.enumRangesFilter.setMaximumSize(QtCore.QSize(16777215, 27))
        self.enumRangesFilter.setObjectName("enumRangesFilter")
        self.gridLayout.addWidget(self.enumRangesFilter, 2, 0, 1, 1)
        self.refreshEnumRangesBtn = QtWidgets.QPushButton(Form)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.refreshEnumRangesBtn.sizePolicy().hasHeightForWidth())
        self.refreshEnumRangesBtn.setSizePolicy(sizePolicy)
        self.refreshEnumRangesBtn.setMinimumSize(QtCore.QSize(0, 0))
        self.refreshEnumRangesBtn.setMaximumSize(QtCore.QSize(200, 16777215))
        self.refreshEnumRangesBtn.setObjectName("refreshEnumRangesBtn")
        self.gridLayout.addWidget(self.refreshEnumRangesBtn, 0, 0, 1, 1)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Enum Ranges"))
        item = self.enumRangesTableWidget.horizontalHeaderItem(0)
        item.setText(_translate("Form", "Base"))
        item = self.enumRangesTableWidget.horizontalHeaderItem(1)
        item.setText(_translate("Form", "End"))
        item = self.enumRangesTableWidget.horizontalHeaderItem(2)
        item.setText(_translate("Form", "Protection"))
        item = self.enumRangesTableWidget.horizontalHeaderItem(3)
        item.setText(_translate("Form", "Path"))
        self.refreshEnumRangesBtn.setText(_translate("Form", "Refresh Enum Ranges"))