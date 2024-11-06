import inspect
import re

from PyQt6 import QtGui
from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QColor, QPalette, QTextCursor
from PyQt6.QtWidgets import QWidget, QLabel
from capstone import *

import gvar
import watchpoint_ui


class WatchPointWidget(QWidget):
    def __init__(self):
        super(WatchPointWidget, self).__init__()
        self.watch_point_ui = watchpoint_ui.Ui_Form()
        self.watch_point_ui.setupUi(self)
        self.watch_point_ui.watchpointResult.setReadOnly(True)
        self.watch_point_ui.disassemResult.setReadOnly(True)
        self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint)

        self.watch_point_ui.watchpointSetButton.clicked.connect(lambda: self.set_watchpoint(
            self.watch_point_ui.watchpointSetButton.text()))

        self.watchpoint_addr = None
        self.watchpoint_signal_connected = False
        self.disasm_result = None

    @pyqtSlot(tuple)
    def watchpoint_sig_func(self, sig: tuple):  # sig --> (addr, stat) or (what, how, where, what_hexdump, thread_id, thread_name)
        if len(sig) == 2 and sig[1] == 1:
            result_text = f"HardwareWatchpoint set at {sig[0]}"
            self.watch_point_ui.watchpointSetButton.setText('Unset')
            self.watch_point_ui.disassemResult.clear()
        else:
            result_text = f"{sig[0]} tried to \"{'write' if sig[1] == 'w' else 'read'}\" at {sig[2]} ({sig[4]} {sig[5]})"
            hex_dump_result = sig[3]
            hex_dump_result = hex_dump_result[hex_dump_result.find('\n') + 1:]
            addr = hex_dump_result[:hex_dump_result.find(' ')]
            self.disassemble(gvar.arch, addr, hex_dump_result)
        self.watch_point_ui.watchpointResult.setText(result_text)

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        if self.watch_point_ui.watchpointSetButton.text() == 'Unset':
            self.unset_watchpoint()
        super().closeEvent(event)

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
        self.watch_point_ui.disassemResult.clear()
        for (address, size, mnemonic, op_str) in md.disasm_lite(disasm_target, int(addr, 16)):
            _addr = f"%x" % address
            _mnemonic = f"%s" % mnemonic
            _op_str = f"%s" % op_str
            if int(_addr, 16) == (int(addr, 16) + 16):
                # print("0x%x\t%s\t%s" % (address, mnemonic, op_str))
                color = QColor("red")
                mnemonic_space = "&nbsp;" * (8 - len(_mnemonic))
                formatted_text = f'<span style="color: {color.name()};">' \
                                 f'{_addr}{"&nbsp;" * 4}{_mnemonic}{mnemonic_space}{_op_str}</span>'
                self.watch_point_ui.disassemResult.append(formatted_text)
            else:
                mnemonic_space = "&nbsp;" * (8 - len(_mnemonic))
                formatted_text = f'<span>{_addr}{"&nbsp;" * 4}{_mnemonic}{mnemonic_space}{_op_str}</span>'
                self.watch_point_ui.disassemResult.append(formatted_text)

        self.watch_point_ui.disassemResult.moveCursor(QTextCursor.MoveOperation.Start)

    def set_watchpoint(self, button_text: str):
        if button_text == 'Set':
            self.watchpoint_addr = self.watch_point_ui.watchpointAddrInput.text()
            if self.watchpoint_addr != '' and '0x' not in self.watchpoint_addr:
                self.watchpoint_addr = ''.join(('0x', self.watchpoint_addr))
            hex_regex_pattern = r'(\b0x[a-fA-F0-9]+\b)'
            hex_regex = re.compile(hex_regex_pattern)
            if not hex_regex.match(self.watchpoint_addr):
                print(f"[watchpoint][set_watchpoint] invalid address")
                return
            watchpoint_size_text = self.watch_point_ui.watchpointSizeComboBox.currentText()
            if watchpoint_size_text == 'Size':
                return
            watchpoint_size: int = int(watchpoint_size_text)
            watchpoint_type_text = self.watch_point_ui.watchpointTypeComboBox.currentText()
            if watchpoint_size == 'Size' or watchpoint_type_text == 'Type':
                return
            watchpoint_type = 'w' if watchpoint_type_text == 'Write' else 'r'
            try:
                threads_list = gvar.frida_instrument.get_process_threads()
                gvar.enum_threads = threads_list
            except Exception as e:
                print(f"[watchpoint]{inspect.currentframe().f_code.co_name}: {e}")
                return
            if not threads_list:
                self.watch_point_ui.watchpointResult.setText("Process threads are protected. Cannot set watchpoint")
            else:
                try:
                    if self.watchpoint_signal_connected is False:
                        gvar.frida_instrument.watchpoint_signal.connect(self.watchpoint_sig_func)
                        self.watchpoint_signal_connected = True
                    gvar.frida_instrument.set_watchpoint(self.watchpoint_addr, watchpoint_size, watchpoint_type)
                except Exception as e:
                    print(f"[watchpoint]{inspect.currentframe().f_code.co_name}: {e}")
                    return
            self.watch_point_ui.watchpointSetButton.setText('Unset')
        else:
            self.unset_watchpoint()

    def unset_watchpoint(self):
        try:
            gvar.frida_instrument.stop_watchpoint()
            gvar.frida_instrument.watchpoint_signal.disconnect()
        except Exception as e:
            print(f"[watchpoint]{inspect.currentframe().f_code.co_name}: {e}")
        result_text = f"{self.watchpoint_addr} Watchpoint stopped"
        self.watchpoint_signal_connected = False
        self.watch_point_ui.watchpointResult.setText(result_text)
        self.watch_point_ui.watchpointSetButton.setText('Set')




