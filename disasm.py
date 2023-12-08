import re
import platform

from PyQt6.QtCore import QObject, Qt
from PyQt6 import QtCore, QtGui, QtWidgets
from capstone import *


class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(550, 300)
        self.gridLayout = QtWidgets.QGridLayout(Form)
        self.gridLayout.setObjectName("gridLayout")
        self.disasmBrowser = QtWidgets.QTextBrowser(Form)
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


class DisassembleWorker(QObject):
    def __init__(self):
        super().__init__()
        self.disasm_window = QtWidgets.QWidget()
        self.disasm_window.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint)
        self.disasmui = Ui_Form()
        self.disasmui.setupUi(self.disasm_window)

        self.disasm_result = None

    def disassemble(self, arch: str, addr: str, hex_dump_result: str):
        hex_dump_result = hex_dump_result.replace('\u2029', '\n')
        lines = hex_dump_result.strip().split('\n')

        hex_data = []
        for line in lines:
            # Calculate hex start and end positions
            hex_start = len(line) - 65
            hex_end = len(line) - 16

            # Extract hex part
            hex_part = line[hex_start:hex_end]

            # Extract two-digit hex numbers from the part
            matches = re.findall(r'\b[0-9a-fA-F]{2}\b', hex_part)
            hex_data.append(' '.join(matches))

        hex_string = ' '.join(hex_data).split()
        disasm_target = b''.join(bytes([int(hex_value, 16)]) for hex_value in hex_string)

        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM) if arch == "arm64" else Cs(CS_ARCH_ARM, CS_MODE_ARM)
        disasm_lines = []
        for (address, size, mnemonic, op_str) in md.disasm_lite(disasm_target, int(addr, 16)):
            # print("0x%x\t%s\t%s" % (address, mnemonic, op_str))
            disasm_lines.append("%x \t%s\t%s" % (address, mnemonic, op_str))

        self.disasm_result = '\n'.join(disasm_lines)
        self.disasmui.disasmBrowser.setText(self.disasm_result)
