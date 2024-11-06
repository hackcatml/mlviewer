import platform

from PyQt6 import QtWidgets, QtCore, QtGui


class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(550, 300)
        self.gridLayout = QtWidgets.QGridLayout(Form)
        self.gridLayout.setObjectName("gridLayout")
        self.disasmBrowser = QtWidgets.QTextEdit(Form)
        self.disasmBrowser.setReadOnly(True)
        font = QtGui.QFont()
        font.setFamily("Courier New")
        fontsize = 13 if platform.system() == 'Darwin' else 10
        font.setPointSize(fontsize)
        self.disasmBrowser.setFont(font)
        self.disasmBrowser.setObjectName("disasmBrowser")
        self.gridLayout.addWidget(self.disasmBrowser, 0, 0, 1, 1)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Disassemble"))