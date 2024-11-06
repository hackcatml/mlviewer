import re

from PyQt6.QtCore import QObject, Qt, pyqtSlot
from PyQt6.QtWidgets import QWidget
from capstone import *

import disasm_ui


class EscapableWidget(QWidget):
    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            self.close()
        else:
            super().keyPressEvent(event)


class DisassembleWorker(QObject):
    def __init__(self):
        super().__init__()
        self.disasm_window = EscapableWidget()
        self.disasm_window.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint)
        self.disasm_ui = disasm_ui.Ui_Form()
        self.disasm_ui.setupUi(self.disasm_window)

        self.hex_viewer = None

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

        if arch == "arm64":
            md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        elif arch == "arm":
            md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        disasm_lines = []
        for (address, size, mnemonic, op_str) in md.disasm_lite(disasm_target, int(addr, 16)):
            # print("0x%x\t%s\t%s" % (address, mnemonic, op_str))
            disasm_lines.append("%x \t%s\t%s" % (address, mnemonic, op_str))

        self.disasm_result = '\n'.join(disasm_lines)
        self.disasm_ui.disasmBrowser.setText(self.disasm_result)

    @pyqtSlot(str)
    def hex_viewer_wheel_sig_func(self, sig: str):
        if not re.search(r"0x[0-9a-f]+", sig) or re.search(r"\d+\. 0x[0-9a-f]+, module:", sig):
            return

        tc = self.disasm_ui.disasmBrowser.textCursor()
        if not re.search(r"[0-9a-f]+", tc.block().text().split('\t')[0]):
            return

        # calculate scrollbar position
        wheel_gap = int(sig, 16) - int(tc.block().text().split('\t')[0], 16)
        if wheel_gap < 0:
            return
        wheel_count = round(wheel_gap / 64)
        gap = (wheel_gap + 16 * wheel_count) * 3
        scrollbar = self.disasm_ui.disasmBrowser.verticalScrollBar()
        scrollbar.setValue(gap)

    @pyqtSlot(int)
    def hex_viewer_scroll_sig_func(self, scroll_signal: int):
        # sync the scrollbar position with hexviewer's one approximately
        scrollbar = self.disasm_ui.disasmBrowser.verticalScrollBar()
        scrollbar.setValue(4 * scroll_signal - 5)
