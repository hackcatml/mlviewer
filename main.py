import collections
import inspect
import os
import platform
import re

from PyQt6 import QtCore, QtGui
from PyQt6.QtCore import QThread, pyqtSlot, Qt, QEvent, QPoint
from PyQt6.QtGui import QPixmap, QTextCursor, QShortcut, QKeySequence, QColor, QIcon, QPalette
from PyQt6.QtWidgets import QLabel, QMainWindow, QMessageBox, QApplication, QInputDialog

import code
import gadget
import gvar
import spawn
import ui
import ui_win
from disasm import DisassembleWorker
from history import HistoryViewClass


def is_readable_addr(addr):
    for i in range(len(gvar.enumerate_ranges)):
        if int(gvar.enumerate_ranges[i][0], 16) <= int(addr, 16) <= int(gvar.enumerate_ranges[i][1], 16):
            return True
    return False


def size_to_read(addr):
    for i in range(len(gvar.enumerate_ranges)):
        if int(gvar.enumerate_ranges[i][0], 16) <= int(addr, 16) <= int(gvar.enumerate_ranges[i][1], 16):
            return int(gvar.enumerate_ranges[i][1], 16) - int(addr, 16)


def set_mem_range(prot):
    try:
        result = gvar.frida_instrument.mem_enumerate_ranges(prot)
        # print("[hackcatml] mem_enumerate_ranges result: ", result)
    except Exception as e:
        print(e)
        return
    # enumerateRanges --> [(base, base + size - 1, prot, size), ... ]
    gvar.enumerate_ranges.clear()
    for i in range(len(result)):
        gvar.enumerate_ranges.append(
            (result[i]['base'], hex(int(result[i]['base'], 16) + result[i]['size'] - 1), result[i]['protection'],
             result[i]['size']))
    # print("[hackcatml] gvar.enumerate_ranges: ", gvar.enumerate_ranges)


def hex_calculator(s):
    """ https://leetcode.com/problems/basic-calculator-ii/solutions/658480/Python-Basic-Calculator-I-II-III-easy
    -solution-detailed-explanation/comments/881191/"""

    def twos_complement(input_value: int, num_bits: int) -> int:
        mask = 2 ** num_bits - 1
        return ((input_value ^ mask) + 1) & mask

    def replace(match):
        num = int(match.group(0), 16)
        return "- " + hex(twos_complement(num, 64))

    # multiply, divide op are not supported
    if re.search(r"[*/]", s):
        return False

    # find negative hex value which starts with ffffffff and replace it with "- 2's complement"
    pattern = re.compile(r'[fF]{8}\w*')
    s = pattern.sub(replace, s)
    s = s.replace('0x', '')

    num, op, arr, stack = '', "+", collections.deque(s + "+"), []
    while sym := arr.popleft() if arr else None:
        if str.isdigit(sym):
            num += sym
        elif re.search(r"[a-zA-F]", sym):
            num += sym
        elif sym in ('+', '-'):
            if num == '':
                num = '0'
            stack += int(op + num, 16),
            op, num = sym, ''

    return hex(sum(stack))


def process_read_mem_result(result: str) -> str:
    remove_target = '0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF\n'
    result = result.replace(result[result.find('\n') + 1:result.find(remove_target)], '')
    result = result.replace(remove_target, '')
    # remove any residual whitespace
    for i in range(5):
        result = result.replace(' ' * (14 - i), '')
    return result


class MemScanWorker(QThread):
    mem_scan_signal = QtCore.pyqtSignal(int)

    def __init__(self):
        super(MemScanWorker, self).__init__()

    def run(self) -> None:
        while True:
            self.mem_scan_signal.emit(0)
            if type(code.MESSAGE) is str and code.MESSAGE.find('[!] Memory Scan Done') != -1:
                # print(code.MESSAGE)
                self.mem_scan_signal.emit(1)
                break
            self.msleep(100)


class Il2CppDumpWorker(QThread):
    il2cpp_dump_signal = QtCore.pyqtSignal(str)

    def __init__(self, il2cpp_frida_instrument, statusBar):
        super(Il2CppDumpWorker, self).__init__()
        self.il2cpp_frida_instrument = il2cpp_frida_instrument
        self.statusBar = statusBar

    def run(self) -> None:
        self.statusBar.showMessage("il2cpp dumping...stay")
        try:
            result = self.il2cpp_frida_instrument.il2cpp_dump()
            if result is not None:
                self.il2cpp_dump_signal.emit(result)
        except Exception as e:
            if str(e) == gvar.ERROR_SCRIPT_DESTROYED:
                self.statusBar.showMessage(f"{e}...try again")
                self.il2cpp_frida_instrument.sessions.clear()
            return


class MemRefreshWorker(QThread):
    update_signal = QtCore.pyqtSignal()

    def __init__(self):
        super().__init__()
        self.status_current = None
        self.addrInput = None
        self.watchMemorySpinBox = None
        self.interval = None

    def run(self) -> None:
        while True:
            self.interval = int(self.watchMemorySpinBox.value() * 1000)
            s = self.status_current.toPlainText()
            match = re.search(r'(0x[a-fA-F0-9]+)', s)
            if match:
                addr = match.group(1)
                self.addrInput.setText(addr)
                self.update_signal.emit()
            self.msleep(100) if self.interval == 0 else self.msleep(self.interval)


class WindowClass(QMainWindow, ui.Ui_MainWindow if (platform.system() == 'Darwin') else ui_win.Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.spawn_dialog = None
        self.gadgetBtn.clicked.connect(self.prepare_gadget)
        self.prepare_gadget_dialog = None
        self.statusBar()
        self.status_light = QLabel()
        self.set_status_light()
        self.mem_scan_worker = MemScanWorker()
        self.mem_scan_worker.mem_scan_signal.connect(self.mem_scan_sig)
        self.is_il2cpp_checked = None
        self.il2cpp_dump_worker = None
        self.il2cpp_frida_instrument = None
        self.hex_edit_shortcut = QShortcut(QKeySequence(Qt.Key.Key_F2), self)
        self.is_mem_scan_str_checked = False
        self.is_remote_attach_checked = False
        self.is_mem_search_replace_checked = False
        self.is_spawn_checked = False
        self.is_mem_search_with_img_checked = False
        self.memReplaceBtn.setEnabled(False)
        self.memReplacePattern.setEnabled(False)
        self.hexViewer.wheel_up_signal.connect(self.wheel_up_sig_func)
        self.hexViewer.move_signal.connect(self.move_sig_func)
        self.hexViewer.refresh_signal.connect(self.refresh_sig_func)
        self.hexViewer.statusBar = self.statusBar()
        self.default_color = QLabel().palette().color(QPalette.ColorRole.WindowText)
        self.listImgViewer.module_name_signal.connect(lambda sig: self.module_name_sig_func(sig, "listImgViewer"))
        self.parseImgListImgViewer.module_name_signal.connect(
            lambda sig: self.module_name_sig_func(sig, "parseImgListImgViewer"))
        self.memSearchResult.search_result_addr_signal.connect(self.search_result_addr_sig_func)
        self.arrangedresult = None
        self.arrangedresult2 = None
        self.platform = None
        self.is_list_pid_checked = False
        self.attach_target_name = None  # name to attach. need to provide on the AppList widget
        self.attach_target_name_reserved = None
        self.attached_name = None  # main module name after frida attached successfully
        self.spawn_target_id = None  # target identifier to do frida spawn. need to provide on the AppList widget
        self.remote_addr = ''
        self.mem_refresh_worker = None
        self.refresh_curr_addr_shortcut = QShortcut(QKeySequence(Qt.Key.Key_F3), self)
        self.refresh_curr_addr_shortcut.activated.connect(self.refresh_curr_addr)
        self.is_palera1n = False

        self.attachBtn.clicked.connect(lambda: self.attach_frida("attachBtnClicked"))
        self.detachBtn.clicked.connect(self.detach_frida)
        self.offsetInput.returnPressed.connect(lambda: self.offset_ok_btn_pressed_func("returnPressed"))
        self.offsetOkbtn.pressed.connect(lambda: self.offset_ok_btn_pressed_func("pressed"))
        self.offsetOkbtn.clicked.connect(self.offset_ok_btn_func)
        self.status_img_name.returnPressed.connect(lambda: self.offset_ok_btn_pressed_func("returnPressed"))
        self.addrInput.returnPressed.connect(lambda: self.addr_btn_pressed_func("returnPressed"))
        self.addrBtn.pressed.connect(lambda: self.addr_btn_pressed_func("pressed"))
        self.addrBtn.clicked.connect(self.addr_btn_func)
        self.tabWidget.tabBarClicked.connect(self.util_tab_bar_click_func)
        self.tabWidget2.tabBarClicked.connect(self.status_tab_bar_click_func)

        self.hexEditBtn.clicked.connect(self.hex_edit)
        self.hexEditDoneBtn.clicked.connect(self.hex_edit)
        self.hex_edit_shortcut.activated.connect(self.hex_edit)

        self.memSearchBtn.clicked.connect(self.mem_search_func)
        self.memReplaceBtn.clicked.connect(self.mem_search_replace_func)
        self.memSearchTargetImgCheckBox.stateChanged.connect(self.mem_search_with_img_checkbox)
        self.memScanPatternTypeCheckBox.stateChanged.connect(self.mem_scan_pattern_checkbox)
        self.listPIDCheckBox.stateChanged.connect(self.list_pid)
        self.attachTypeCheckBox.stateChanged.connect(self.remote_attach)
        self.spawnModeCheckBox.stateChanged.connect(self.spawn_mode)
        self.memSearchReplaceCheckBox.stateChanged.connect(self.mem_search_replace_checkbox)
        self.memDumpBtn.clicked.connect(self.dump_module)
        self.memDumpModuleName.returnPressed.connect(self.dump_module)
        self.memDumpModuleName.textChanged.connect(lambda: self.search_img("memDumpModuleName"))
        self.parseImgName.textChanged.connect(lambda: self.search_img("parseImgName"))
        self.searchMemSearchResult.textChanged.connect(self.search_mem_search_result)
        self.unityCheckBox.stateChanged.connect(self.il2cpp_checkbox)
        self.watchMemoryCheckBox.stateChanged.connect(self.watch_mem_checkbox)
        self.refreshBtn.clicked.connect(self.refresh_curr_addr)
        self.moveBackwardBtn.clicked.connect(self.move_backward)
        self.moveForwardBtn.clicked.connect(self.move_forward)

        self.disasm_thread = QThread()
        self.disasm_worker = DisassembleWorker()
        self.disasm_worker.hex_viewer = self.hexViewer
        self.disasm_worker.hex_viewer.wheel_signal.connect(self.disasm_worker.hex_viewer_wheel_sig_func)
        self.disasm_worker.hex_viewer.scroll_signal.connect(self.disasm_worker.hex_viewer_scroll_sig_func)
        self.disasm_worker.moveToThread(self.disasm_thread)
        self.disasm_thread.start()
        self.disassemBtnClickedCount = 0
        self.disassemBtn.clicked.connect(self.show_disassemble_result)

        self.history_view = HistoryViewClass()
        self.history_view.history_addr_signal.connect(self.history_addr_sig_func)
        self.historyBtn.clicked.connect(self.show_history)
        self.historyBtnClickedCount = 0

        self.utilViewer.parse_img_name = self.parse_img_name
        self.utilViewer.parse_img_base = self.parse_img_base
        self.utilViewer.parse_img_path = self.parse_img_path
        self.utilViewer.parseImgName = self.parseImgName
        self.utilViewer.statusBar = self.statusBar()
        self.parseImgTabWidget.tabBarClicked.connect(self.parseimg_tab_bar_click_func)
        self.parse_img_name.returnPressed.connect(lambda: self.utilViewer.parse("parse_img_name"))
        self.parseBtn.clicked.connect(lambda: self.utilViewer.parse("parseBtn"))
        self.parseImgName.returnPressed.connect(lambda: self.utilViewer.parse("parseImgName"))

        self.utilViewer.app_info_btn = self.appInfoBtn
        self.utilViewer.app_info_btn.clicked.connect(self.utilViewer.app_info)

        self.utilViewer.pull_package_btn = self.pullPackageBtn
        self.utilViewer.pull_package_btn.clicked.connect(self.utilViewer.pull_package)

        self.utilViewer.full_memory_dump_btn = self.fullMemoryDumpBtn
        self.utilViewer.full_memory_dump_btn.clicked.connect(self.utilViewer.full_memory_dump)

        self.utilViewer.binary_diff_btn = self.binaryDiffBtn
        self.utilViewer.binary_diff_btn.clicked.connect(self.utilViewer.binary_diff)

        self.utilViewer.dex_dump_btn = self.dexDumpBtn
        self.utilViewer.dex_dump_btn.clicked.connect(self.utilViewer.dex_dump)
        self.utilViewer.dex_dump_check_box = self.dexDumpCheckBox
        self.utilViewer.dex_dump_check_box.stateChanged.connect(self.utilViewer.dex_dump_checkbox)

        # install event filter to use tab and move to some input fields
        self.interested_widgets = []
        QApplication.instance().installEventFilter(self)

    @pyqtSlot(int)
    def mem_scan_sig(self, sig: int):
        # mem scan progressing...
        if sig == 0:
            self.progressBar.setValue(gvar.scan_progress_ratio)
        # mem scan completed
        if sig == 1:
            self.mem_scan_retrieve_result()
            self.memSearchBtn.setText("GO")

    @pyqtSlot(str)
    def wheel_up_sig_func(self, sig: str):
        # print(sig)
        if self.status_img_base.toPlainText() == hex_calculator(f"{sig}"):
            return
        addr = hex_calculator(f"{sig} - 10")
        # print(addr)
        self.addrInput.setText(addr)
        self.addr_btn_func()

    @pyqtSlot(int)
    def move_sig_func(self, sig: int):
        self.move_backward() if sig == 0 else self.move_forward()

    @pyqtSlot(int)
    def refresh_sig_func(self, sig: int):
        if sig:
            self.refresh_curr_addr()

    @pyqtSlot(str)
    def module_name_sig_func(self, sig: str, caller):
        if caller == "listImgViewer":
            self.memDumpModuleName.setText(sig)
        elif caller == "parseImgListImgViewer":
            self.parseImgName.setText(sig)

    @pyqtSlot(str)
    def search_result_addr_sig_func(self, sig: str):
        self.addrInput.setText(sig)
        self.addr_btn_func()

    @pyqtSlot(str)
    def target_sig_func(self, sig: str):
        if self.is_spawn_checked:
            self.spawn_target_id = sig
        else:
            self.attach_target_name = sig
            self.attach_target_name_reserved = sig
        if self.is_remote_attach_checked is True:
            if re.search(r"^\d+\.\d+\.\d+\.\d+:\d+$", self.spawn_dialog.spawn_ui.remoteAddrInput.text()) is None:
                QMessageBox.information(self, "info", "Enter IP:PORT")
                self.spawn_target_id = None
                self.attach_target_name = None
                return
            self.remote_addr = self.spawn_dialog.spawn_ui.remoteAddrInput.text()
        self.attach_frida("target_sig_func")
        self.spawn_dialog = None
        self.spawn_target_id = None
        self.attach_target_name = None
        self.remote_addr = ''

    @pyqtSlot(str)
    def il2cpp_dump_sig_func(self, sig: str):
        if sig is not None:
            QThread.msleep(100)
            self.statusBar().showMessage("il2cpp Dump Done!", 5000)
            self.listImgViewer.moveCursor(QTextCursor.MoveOperation.Start, QTextCursor.MoveMode.MoveAnchor)
            self.listImgViewer.setTextColor(QColor("Red"))
            dir_to_save = os.getcwd() + "\\dump\\" if platform.system() == "Windows" else os.getcwd() + "/dump/"
            if self.is_remote_attach_checked:
                os.system(
                    f"frida-pull -H {self.il2cpp_frida_instrument.remote_addr} \"{sig}\" {dir_to_save}")
            else:
                os.system(f"frida-pull -U \"{sig}\" {dir_to_save}")
            self.listImgViewer.insertPlainText(f"Dumped file at: {dir_to_save}{sig.split('/')[-1]}\n\n")
            self.listImgViewer.setTextColor(self.default_color)
            # after il2cpp dump some android apps crash
            self.il2cpp_dump_worker.terminate()
            self.memDumpBtn.setEnabled(True)

    @pyqtSlot(int)
    def frida_attach_sig_func(self, sig: int):
        if sig:
            gvar.is_frida_attached = True
            if self.is_remote_attach_checked:
                gvar.remote = True
        else:
            gvar.is_frida_attached = False
            self.detach_frida()
        self.set_status_light()

    @pyqtSlot(list)
    def frida_portal_node_info_sig_func(self, sig: list):  # node info signal
        if sig:
            self.remote_addr = "localhost"
            self.attach_target_name = sig[0]
            self.attach_frida("frida_portal_node_info_sig_func")

    @pyqtSlot(str)
    def history_addr_sig_func(self, sig: str):
        self.addrInput.setText(sig)
        self.addr_btn_func()

    def adjust_label_pos(self):
        tc = self.hexViewer.textCursor()
        text_length = len(tc.block().text())
        current_height = self.height()
        self.resize(text_length * 13, current_height)
        if text_length >= 77:
            self.label_3.setIndent(28 + (text_length - 77) * 8)
        else:
            self.label_3.setIndent(28 - (77 - text_length) * 7)

    def list_pid(self, state):
        self.is_list_pid_checked = state == Qt.CheckState.Checked.value

    def remote_attach(self, state):
        self.is_remote_attach_checked = state == Qt.CheckState.Checked.value

    def spawn_mode(self, state):
        self.is_spawn_checked = state == Qt.CheckState.Checked.value

    def prepare_gadget(self):
        try:
            self.prepare_gadget_dialog = gadget.GadgetDialogClass()
            self.prepare_gadget_dialog.frida_portal_node_info_signal.connect(self.frida_portal_node_info_sig_func)
        except Exception as e:
            self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
            return

    def attach_frida(self, caller: str):
        if gvar.is_frida_attached is True:
            try:
                # check if script is still alive. if not exception will occur
                gvar.frida_instrument.dummy_script()
                QMessageBox.information(self, "info", "Already attached")
            except Exception as e:
                self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
                gvar.frida_instrument.sessions.clear()
            return

        try:
            if not caller == "frida_portal_node_info_sig_func":
                if (self.is_list_pid_checked and not self.is_spawn_checked and self.attach_target_name is None) or \
                        (self.is_spawn_checked and self.spawn_target_id is None):
                    self.spawn_dialog = spawn.SpawnDialogClass()
                    if self.is_list_pid_checked and not self.is_spawn_checked:
                        self.spawn_dialog.is_pid_list_checked = True
                        self.spawn_dialog.spawn_ui.spawnTargetIdInput.setPlaceholderText("AppStore")
                        self.spawn_dialog.spawn_ui.appListLabel.setText("PID           Name")
                        self.spawn_dialog.spawn_ui.spawnBtn.setText("Attach")
                        self.spawn_dialog.attach_target_name_signal.connect(self.target_sig_func)

                    self.spawn_dialog.spawn_target_id_signal.connect(self.target_sig_func)

                    if self.is_remote_attach_checked is False:
                        self.spawn_dialog.spawn_ui.remoteAddrInput.setEnabled(False)
                        self.spawn_dialog.spawn_ui.spawnTargetIdInput.setFocus()
                    else:
                        self.spawn_dialog.spawn_ui.remoteAddrInput.setFocus()
                    return

                if self.is_remote_attach_checked and self.remote_addr == '':
                    self.remote_addr, ok = QInputDialog.getText(self, 'Remote Attach', 'Enter IP:PORT')
                    if ok is False:
                        return

                gvar.frida_instrument = code.Instrument("scripts/default.js",
                                                        self.is_remote_attach_checked,
                                                        self.remote_addr,
                                                        self.attach_target_name if (
                                                                    self.is_list_pid_checked and not self.is_spawn_checked) else self.spawn_target_id,
                                                        self.is_spawn_checked)
                # connect frida attach signal function
                gvar.frida_instrument.attach_signal.connect(self.frida_attach_sig_func)
                msg = gvar.frida_instrument.instrument(caller)
            elif caller == "frida_portal_node_info_sig_func":
                gvar.frida_instrument = code.Instrument("scripts/default.js",
                                                        True,
                                                        self.remote_addr,
                                                        self.attach_target_name,
                                                        False)
                # connect frida attach signal function
                gvar.frida_instrument.attach_signal.connect(self.frida_attach_sig_func)
                msg = gvar.frida_instrument.instrument(caller)

            self.remote_addr = ''
        except Exception as e:
            print(e)
            self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
            return

        if msg is not None:
            QMessageBox.information(self, "info", msg)
            self.offsetInput.clear()
            return

        set_mem_range('r--')

        try:
            self.platform = gvar.frida_instrument.platform()
            if self.platform == 'darwin':
                self.is_palera1n = gvar.frida_instrument.is_palera1n()
            self.utilViewer.platform = self.platform
            gvar.arch = gvar.frida_instrument.arch()
            name = gvar.frida_instrument.list_modules()[0]['name']
            self.attached_name = name
            self.set_status(name)
        except Exception as e:
            print(e)
            return

    def detach_frida(self):
        if gvar.frida_instrument is None:
            pass
        else:
            try:
                for session in gvar.frida_instrument.sessions:
                    session.detach()
                gvar.frida_instrument.sessions.clear()
                gvar.enumerate_ranges.clear()
                gvar.hex_edited.clear()
                gvar.list_modules.clear()
                gvar.arch = None
                gvar.is_frida_attached = False
                gvar.frida_instrument = None
                gvar.visited_address.clear()
                gvar.frida_portal_mode = False
                self.remote_addr = ''
                self.il2cpp_frida_instrument = None
                if self.hexViewer.new_watch_widget is not None:
                    self.hexViewer.new_watch_widget.close()
                if self.utilViewer.pull_ipa_worker is not None:
                    self.utilViewer.pull_ipa_worker.quit()
                if self.history_view is not None:
                    self.history_view.history_window.close()
                    self.history_view.clear_table()
                self.memDumpBtn.setEnabled(True)
                self.statusBar().showMessage("")
            except Exception as e:
                self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 5000)

    def is_addr_in_mem_range_for_palera1n(self, result):
        # if the hexdump result is dict and has 'palera1n', it means mem addr not in the mem range
        return not (isinstance(result, dict) and 'palera1n' in result)

    def offset_ok_btn_pressed_func(self, caller):
        self.is_cmd_pressed = QApplication.instance().keyboardModifiers() & (
                Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.MetaModifier)
        if self.is_cmd_pressed in (Qt.KeyboardModifier.ControlModifier, Qt.KeyboardModifier.MetaModifier):
            if gvar.is_frida_attached: gvar.frida_instrument.force_read_mem_addr(True)
        else:
            if gvar.is_frida_attached: gvar.frida_instrument.force_read_mem_addr(False)

        if caller == "returnPressed":
            self.offset_ok_btn_func()

    def offset_ok_btn_func(self):
        if gvar.is_frida_attached is False:
            QMessageBox.information(self, "info", "Attach first")
            self.offsetInput.clear()
            return

        offset = self.offsetInput.text()
        try:
            offset = hex_calculator(offset)
        except Exception as e:
            self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
            return

        if offset is False:
            self.statusBar().showMessage("can't operate *, /", 3000)
            return

        self.offsetInput.setText(offset)

        name = self.status_img_name.text().strip()
        # print(f'name: {name}')
        try:
            if self.status_img_base.toPlainText() == '':
                result = gvar.frida_instrument.read_mem_offset(name, offset, 8192)
            else:
                addr = hex_calculator(f"{self.status_img_base.toPlainText()} + {offset} + 2000")
                # check addr in mem regions
                if is_readable_addr(addr):
                    result = gvar.frida_instrument.read_mem_offset(name, offset, 8192)
                else:
                    # not in mem regions. but check module existence
                    if gvar.frida_instrument.get_module_name_by_addr(addr) != '':
                        # there is a module
                        size = int(gvar.frida_instrument.get_module_name_by_addr(addr)['base'], 16) + \
                               gvar.frida_instrument.get_module_name_by_addr(addr)['size'] - 1 - int(addr, 16)
                        if size < 8192:
                            result = gvar.frida_instrument.read_mem_offset(name, offset, size)
                        else:
                            result = gvar.frida_instrument.read_mem_offset(name, offset, 8192)
                    else:
                        # there is no module. just try to read
                        size = size_to_read(hex_calculator(f"{self.status_img_base.toPlainText()} + {offset}"))
                        if size is not None:
                            result = gvar.frida_instrument.read_mem_offset(name, offset, size)
                        else:
                            result = gvar.frida_instrument.read_mem_offset(name, offset, 4096)
        except Exception as e:
            self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
            if str(e) == gvar.ERROR_SCRIPT_DESTROYED:
                gvar.frida_instrument.sessions.clear()
            return

        if self.is_palera1n and not self.is_cmd_pressed and not self.is_addr_in_mem_range_for_palera1n(result):
            self.statusBar().showMessage(f"{result['palera1n']}", 3000)
            return

        self.show_mem_result_on_viewer(name, None, result)

    def addr_btn_pressed_func(self, caller):
        self.is_cmd_pressed = QApplication.instance().keyboardModifiers() & (
                Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.MetaModifier)
        if self.is_cmd_pressed in (Qt.KeyboardModifier.ControlModifier, Qt.KeyboardModifier.MetaModifier):
            if gvar.is_frida_attached: gvar.frida_instrument.force_read_mem_addr(True)
        else:
            if gvar.is_frida_attached: gvar.frida_instrument.force_read_mem_addr(False)

        if caller == "returnPressed":
            self.addr_btn_func()

    def addr_btn_func(self):
        if gvar.is_frida_attached is False:
            QMessageBox.information(self, "info", "Attach first")
            self.addrInput.clear()
            return

        addr = self.addrInput.text()
        if addr.strip() == '':
            return
        hex_regex = re.compile(r'(\b0x[a-fA-F0-9]+\b|\b[a-fA-F0-9]{6,}\b)')
        match = hex_regex.match(addr)
        # in case it's not a hex expression on addrInput field. for example "fopen", "sysctl", ...
        if match is None:
            try:
                func_addr = gvar.frida_instrument.find_sym_addr_by_name(self.status_img_name.text(), addr)
                if func_addr is None:
                    self.statusBar().showMessage(f"Cannot find address for {addr}", 3000)
                    return
                addr = func_addr
            except Exception as e:
                self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
                return

        try:
            addr = hex_calculator(addr)
        except Exception as e:
            self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
            return

        if addr is False:
            self.statusBar().showMessage("Can't operate *, /")
            return

        self.addrInput.setText(addr)

        if is_readable_addr(addr) is False:
            # refresh memory ranges just in case and if it's still not readable then return
            # set_mem_range('---')
            try:
                # on iOS in case frida's Process.enumerateRangesSync('---') doesn't show up every memory regions
                if gvar.frida_instrument.get_module_name_by_addr(addr) != '':
                    # there is a module
                    name = gvar.frida_instrument.get_module_name_by_addr(addr)['name']
                    size = int(gvar.frida_instrument.get_module_name_by_addr(addr)['base'], 16) + \
                           gvar.frida_instrument.get_module_name_by_addr(addr)['size'] - 1 - int(addr, 16)
                    if size < 8192:
                        result = gvar.frida_instrument.read_mem_addr(addr, size)
                    else:
                        result = gvar.frida_instrument.read_mem_addr(addr, 8192)

                    if self.is_palera1n and not self.is_cmd_pressed and not self.is_addr_in_mem_range_for_palera1n(
                            result):
                        self.statusBar().showMessage(f"{result['palera1n']}", 5000)
                        return

                    self.show_mem_result_on_viewer(name, addr, result)
                    return
                else:
                    # there is no module. but let's try to read small mem regions anyway
                    result = gvar.frida_instrument.read_mem_addr(addr, 4096)

                    if self.is_palera1n and not self.is_cmd_pressed and not self.is_addr_in_mem_range_for_palera1n(
                            result):
                        self.statusBar().showMessage(f"{result['palera1n']}", 5000)
                        return

                    self.show_mem_result_on_viewer(None, addr, result)
                    return
            except Exception as e:
                self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
                if str(e) == gvar.ERROR_SCRIPT_DESTROYED:
                    gvar.frida_instrument.sessions.clear()
                return

        try:
            if is_readable_addr(hex_calculator(f"{addr} + 2000")):
                size = size_to_read(addr)
                if size < 8192:
                    # check there's an empty memory space between from address to (address + 0x2000).
                    # if then read maximum readable size
                    result = gvar.frida_instrument.read_mem_addr(addr, size)
                else:
                    result = gvar.frida_instrument.read_mem_addr(addr, 8192)
            else:
                size = size_to_read(addr)
                result = gvar.frida_instrument.read_mem_addr(addr, size)

            if self.is_palera1n and not self.is_cmd_pressed and not self.is_addr_in_mem_range_for_palera1n(result):
                self.statusBar().showMessage(f"{result['palera1n']}", 5000)
                return

            self.show_mem_result_on_viewer(None, addr, result)
            return

        except Exception as e:
            self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
            if str(e) == gvar.ERROR_SCRIPT_DESTROYED:
                gvar.frida_instrument.sessions.clear()
            return

    def show_mem_result_on_viewer(self, name, addr, result):
        # empty changed hex list before refresh hexviewer
        gvar.hex_edited.clear()
        # show hex dump result
        hex_dump_result = result[result.find('\n') + 1:]
        self.hexViewer.setPlainText(hex_dump_result)
        # adjust label pos
        self.adjust_label_pos()

        if inspect.currentframe().f_back.f_code.co_name != "offset_ok_btn_func" and \
                gvar.frida_instrument.get_module_name_by_addr(addr) == '':
            self.status_img_name.clear()
            self.status_img_base.clear()
            self.status_size.clear()
            self.status_end.clear()
            self.status_path.clear()
            self.status_current.setPlainText(self.addrInput.text())
            self.addrInput.clear()

            gvar.current_frame_block_number = 0
            gvar.current_frame_start_address = "".join(
                ("0x",
                 self.hexViewer.textCursor().block().text()[:self.hexViewer.textCursor().block().text().find(' ')]))
            # print("[hackcatml] currentFrameBlockNumber: ", gvar.current_frame_block_number)
            # print("[hackcatml] currentFrameStartAddress: ", gvar.current_frame_start_address)
            self.visited_addr()
            # disassemble the result of hex dump
            self.disasm_worker.disassemble(gvar.arch, gvar.current_frame_start_address, hex_dump_result)
            return

        if inspect.currentframe().f_back.f_code.co_name != "offset_ok_btn_func":
            self.set_status(gvar.frida_instrument.get_module_name_by_addr(addr)['name'])
            # reset address input area
            self.addrInput.clear()
        else:
            self.set_status(name)
            # reset offset input area
            self.offsetInput.clear()

        # move cursor
        if self.hexViewer.textCursor().positionInBlock() == 0:
            self.hexViewer.moveCursor(QTextCursor.MoveOperation.NextWord)
        # set initial currentFrameStartAddress
        gvar.current_frame_block_number = 0
        gvar.current_frame_start_address = "".join(
            ("0x", self.hexViewer.textCursor().block().text()[:self.hexViewer.textCursor().block().text().find(' ')]))
        # print("[hackcatml] currentFrameBlockNumber: ", gvar.current_frame_block_number)
        # print("[hackcatml] currentFrameStartAddress: ", gvar.current_frame_start_address)
        self.visited_addr()

        self.disasm_worker.disassemble(gvar.arch, gvar.current_frame_start_address, hex_dump_result)

    # remember visited address
    def visited_addr(self):
        if len(inspect.stack()) > 3 and inspect.stack()[3].function == 'wheel_up_sig_func':
            return
        curr_addr = self.status_current.toPlainText()
        match = re.search(r'\(0x[a-fA-F0-9]+\)', curr_addr)
        visited_addr = curr_addr[:match.start()] if match is not None else curr_addr
        if visited_addr != '':
            if len(gvar.visited_address) == 0:
                gvar.visited_address.append(['last', visited_addr])
            else:
                last_visit_index = None
                for item in gvar.visited_address:
                    if item[0] == 'last':
                        last_visit_index = gvar.visited_address.index(item)
                if not any(sublist[1] == visited_addr for sublist in gvar.visited_address):
                    gvar.visited_address.append(['last', visited_addr])
                    if last_visit_index is not None:
                        gvar.visited_address[last_visit_index][0] = 'notlast'
                else:
                    revisit_index = None
                    # Find the index of the sublist to modify
                    for idx, sublist in enumerate(gvar.visited_address):
                        if sublist[1] == visited_addr and sublist[0] == 'notlast':
                            revisit_index = idx
                            break
                    # Modify the sublist if we found a matching index
                    if revisit_index is not None and (inspect.stack()[3].function != 'move_forward' and inspect.stack()[
                        3].function != 'move_backward'):
                        revisit_addr_mark = gvar.visited_address[revisit_index][0]
                        revisit_addr = gvar.visited_address[revisit_index][1]
                        gvar.visited_address.remove([revisit_addr_mark, revisit_addr])
                        gvar.visited_address.append(['last', revisit_addr])
                        for idx, sublist in enumerate(gvar.visited_address):
                            if sublist[1] != revisit_addr and sublist[0] == 'last':
                                gvar.visited_address[idx][0] = 'notlast'
                                break
                    elif revisit_index is not None and (
                            inspect.stack()[3].function == 'move_forward' or inspect.stack()[
                        3].function == 'move_backward'):
                        gvar.visited_address[revisit_index][0] = 'last'
                        if revisit_index != last_visit_index:
                            gvar.visited_address[last_visit_index][0] = 'notlast'
            # add visted_addr to the history table
            self.history_view.add_row(visited_addr)

    def show_disassemble_result(self):
        self.disassemBtnClickedCount += 1
        self.disasm_worker.disasm_window.show()
        if self.disassemBtnClickedCount == 1:
            curr_pos = self.disasm_worker.disasm_window.pos()
            new_pos = curr_pos + QPoint(-270, 150)
            self.disasm_worker.disasm_window.move(new_pos)

    def show_history(self):
        self.historyBtnClickedCount += 1
        self.history_view.history_window.show()
        if self.historyBtnClickedCount == 1:
            curr_pos = self.history_view.history_window.pos()
            new_pos = (curr_pos + QPoint(480, -350)) if platform.system() == "Darwin" else (
                        curr_pos + QPoint(490, -360))
            self.history_view.history_window.move(new_pos)

    def util_tab_bar_click_func(self, index):
        pass

    def parseimg_tab_bar_click_func(self, index):
        # Parse IMG tab
        current_tab_name = self.parseImgTabWidget.tabText(index)
        if current_tab_name == "Parse IMG":
            text = ""
            result = []
            self.parseImgName.setText('')
            if gvar.frida_instrument is not None:
                try:
                    result = gvar.frida_instrument.list_modules()
                    gvar.list_modules = result
                except Exception as e:
                    if str(e) == gvar.ERROR_SCRIPT_DESTROYED or "'NoneType' object has no attribute" in str(e):
                        gvar.frida_instrument.sessions.clear()
                        gvar.frida_instrument = None
                    self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
                    return
            if len(result) > 0:
                for i in range(len(result) - 1):
                    text += result[i]['name'] + '\n'
                text += result[len(result) - 1]['name']
            self.parseImgListImgViewer.setPlainText(text)

    def status_tab_bar_click_func(self, index):
        # status tab
        if index == 0:
            try:
                if gvar.frida_instrument is not None:
                    gvar.frida_instrument.dummy_script()
            except Exception as e:
                if str(e) == gvar.ERROR_SCRIPT_DESTROYED:
                    gvar.frida_instrument.sessions.clear()
                self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
                return
        # list img tab
        elif index == 1:
            text = ""
            result = []
            self.memDumpModuleName.setText('')
            if len(gvar.list_modules) > 0 and self.mem_scan_worker.isRunning():
                result = gvar.list_modules
            elif gvar.frida_instrument is not None:
                try:
                    result = gvar.frida_instrument.list_modules()
                    gvar.list_modules = result
                except Exception as e:
                    if str(e) == gvar.ERROR_SCRIPT_DESTROYED:
                        gvar.frida_instrument.sessions.clear()
                    self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
                    return
            if len(result) > 0:
                for i in range(len(result) - 1):
                    text += result[i]['name'] + '\n'
                text += result[len(result) - 1]['name']
            self.listImgViewer.setTextColor(self.default_color)
            self.listImgViewer.setPlainText(text)

    def is_hex_edited_from_search(self):
        tc = self.hexViewer.textCursor()
        finalposlist = []
        tc.movePosition(QTextCursor.MoveOperation.Start, QTextCursor.MoveMode.MoveAnchor)
        if re.search(r"1\. 0x[a-f0-9]+, module:", tc.block().text()):
            # print("[hackcatml] hex edited from search")
            for arr in gvar.hex_edited:
                origpos = arr[4]
                # print("[hackcatml] origpos: ", origpos)
                tc.setPosition(origpos, QTextCursor.MoveMode.MoveAnchor)
                while True:
                    tc.movePosition(QTextCursor.MoveOperation.Up, QTextCursor.MoveMode.MoveAnchor)
                    if re.search(r"\d+\. 0x[a-f0-9]+, module:", tc.block().text()):
                        tc.movePosition(QTextCursor.MoveOperation.Down, QTextCursor.MoveMode.MoveAnchor)
                        tc.movePosition(QTextCursor.MoveOperation.StartOfBlock, QTextCursor.MoveMode.MoveAnchor)
                        finalposlist.append(tc.position())
                        break
            # remove duplicate items
            finalposlist = list(dict.fromkeys(finalposlist))
            # print("[hackcatml] finalposlist: ", finalposlist)
            return finalposlist
        return False

    def hex_edit(self):
        if self.tabWidget.tabText(self.tabWidget.currentIndex()) == "Util":
            return
        # print(self.sender().__class__.__name__)
        if self.sender().__class__.__name__ == "QShortcut" or \
                (self.sender().__class__.__name__ != "QShortcut" and self.sender().text() == "Done"):
            if gvar.is_hex_edit_mode is True:
                self.hexViewer.setReadOnly(True)
                if len(gvar.hex_edited) == 0:
                    gvar.is_hex_edit_mode = False
                    return
                elif len(gvar.hex_edited) >= 1:
                    try:
                        gvar.frida_instrument.write_mem_addr(gvar.hex_edited)
                    except Exception as e:
                        if str(e) == gvar.ERROR_SCRIPT_DESTROYED:
                            gvar.frida_instrument.sessions.clear()
                            gvar.hex_edited.clear()
                        self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
                        return
                print("[hackcatml] hex edited: ", gvar.hex_edited)
                # refresh mem range. it slows down hex edit func speed :(
                # set_mem_range('r--')

                # if hex edited from search result, refresh hexviewer after patching
                result = self.is_hex_edited_from_search()
                if result is not False:
                    print("[hackcatml] hex edited from search")
                    for finalpos in result:
                        tc = self.hexViewer.textCursor()
                        tc.setPosition(finalpos, QTextCursor.MoveMode.MoveAnchor)
                        # read mem addr after patching
                        result = gvar.frida_instrument.read_mem_addr(
                            "".join(("0x", tc.block().text()[:tc.block().text().find(' ')])), 32)
                        # process read mem result
                        result = process_read_mem_result(result)
                        # replace text
                        tc.movePosition(QTextCursor.MoveOperation.Down, QTextCursor.MoveMode.KeepAnchor)
                        tc.movePosition(QTextCursor.MoveOperation.EndOfBlock, QTextCursor.MoveMode.KeepAnchor)
                        tc.insertText(result)
                        self.hexViewer.moveCursor(QTextCursor.MoveOperation.StartOfBlock,
                                                  QTextCursor.MoveMode.MoveAnchor)
                        self.hexViewer.moveCursor(QTextCursor.MoveOperation.Up, QTextCursor.MoveMode.MoveAnchor)
                        self.hexViewer.moveCursor(QTextCursor.MoveOperation.NextWord, QTextCursor.MoveMode.MoveAnchor)
                    gvar.is_hex_edit_mode = False
                    # empty changed hex list
                    gvar.hex_edited.clear()
                    # reset current frame block number
                    gvar.current_frame_block_number = 0
                    # reset current global mem scan hex view variable
                    gvar.current_mem_scan_hex_view_result = self.hexViewer.toPlainText()
                    return

                # refresh hex viewer after patching
                tc = self.hexViewer.textCursor()
                finalposlist = []
                for arr in gvar.hex_edited:
                    origpos = arr[4]
                    tc.setPosition(origpos, QTextCursor.MoveMode.MoveAnchor)
                    tc.movePosition(QTextCursor.MoveOperation.StartOfBlock, QTextCursor.MoveMode.MoveAnchor)
                    if tc.position() not in finalposlist:
                        finalposlist.append(tc.position())

                for finalpos in finalposlist:
                    tc.setPosition(finalpos, QTextCursor.MoveMode.MoveAnchor)
                    # read mem addr after patching
                    result = gvar.frida_instrument.read_mem_addr(
                        "".join(("0x", tc.block().text()[:tc.block().text().find(' ')])), 16)
                    # process read mem result
                    result = process_read_mem_result(result)
                    # replace text
                    tc.movePosition(QTextCursor.MoveOperation.EndOfBlock, QTextCursor.MoveMode.KeepAnchor)
                    tc.insertText(result)

                self.hexViewer.moveCursor(QTextCursor.MoveOperation.StartOfBlock, QTextCursor.MoveMode.MoveAnchor)
                self.hexViewer.moveCursor(QTextCursor.MoveOperation.NextWord, QTextCursor.MoveMode.MoveAnchor)
                gvar.is_hex_edit_mode = False
                # empty changed hex list
                gvar.hex_edited.clear()
                # reset current frame block number
                # gvar.current_frame_block_number = 0
                return

        if self.sender().__class__.__name__ == "QShortcut" or (
                self.sender().__class__.__name__ != "QShortcut" and self.sender().text() == "HexEdit"):
            if gvar.is_hex_edit_mode is False:
                self.hexViewer.setReadOnly(False)
                self.hexViewer.setTextInteractionFlags(
                    ~Qt.TextInteractionFlag.TextSelectableByKeyboard & ~Qt.TextInteractionFlag.TextSelectableByMouse)
                gvar.is_hex_edit_mode = True

    def hex_pattern_check(self, text: str):
        # memory scan pattern check
        if (pattern := text) == '':
            self.statusBar().showMessage("put some pattern", 3000)
            return None
        if self.is_mem_scan_str_checked:
            pattern = bytes(pattern, 'utf-8').hex()
            return pattern
        else:
            pattern = pattern.replace(' ', '')
            if len(pattern) % 2 != 0 or len(pattern) == 0:
                self.statusBar().showMessage("hex pattern length should be 2, 4, 6...", 3000)
                return None
            # check hex pattern match regex (negative lookahead)
            # support mask for mem search pattern
            elif inspect.currentframe().f_back.f_code.co_name == "mem_search_func" and (
                    re.search(r"(?![0-9a-fA-F?]).", pattern) or re.search(r"^[?]{2}|[?]{2}$", pattern)):
                self.statusBar().showMessage("invalid hex pattern", 3000)
                return None
            elif inspect.currentframe().f_back.f_code.co_name == "mem_search_replace_func" and re.search(
                    r"(?![0-9a-fA-F]).", pattern):
                self.statusBar().showMessage("invalid hex pattern", 3000)
                return None
            return pattern

    def mem_search_func(self, *args):
        # if stop btn clicked, send scan stop signal to the frida script
        if self.memSearchBtn.text() == 'STOP':
            try:
                gvar.frida_instrument.stop_mem_scan()
            except Exception as e:
                self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
                if str(e) == gvar.ERROR_SCRIPT_DESTROYED:
                    gvar.frida_instrument.sessions.clear()
                self.memSearchBtn.setText("GO")
                return
            return
        # memory scan thread start
        self.mem_scan_worker.start()
        self.memSearchFoundCount.setText("")
        # memory scan pattern check
        if inspect.currentframe().f_back.f_code.co_name == "mem_search_replace_func":
            pattern = args[0]
        else:
            pattern = self.hex_pattern_check(self.memSearchPattern.toPlainText())

        # cannot get memory scan result at the first time
        # need to retrieve it later on. don't know why :(
        try:
            if pattern is not None:
                # mem scan on whole images
                if self.is_mem_search_with_img_checked is False:
                    result = gvar.frida_instrument.mem_scan(gvar.enumerate_ranges, pattern)
                    self.memSearchBtn.setText("STOP")
                # mem scan on a specific image
                elif self.is_mem_search_with_img_checked is True:
                    result = gvar.frida_instrument.mem_scan_with_img(self.memSearchTargetImgInput.text(), pattern)
                    self.memSearchBtn.setText("STOP")
                    if result == 'module not found':
                        self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {result}", 3000)
                        self.memSearchBtn.setText("GO")
                        # self.mem_scan_worker.terminate()
                        self.mem_scan_worker.quit()
                        return False
                return True
        except Exception as e:
            self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
            # self.mem_scan_worker.terminate()
            self.mem_scan_worker.quit()
            try:
                gvar.frida_instrument.stop_mem_scan()
            except Exception as err:
                self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {err}", 3000)
                if str(err) == gvar.ERROR_SCRIPT_DESTROYED:
                    gvar.frida_instrument.sessions.clear()
                return False
            if str(e) == gvar.ERROR_SCRIPT_DESTROYED:
                gvar.frida_instrument.sessions.clear()
            return False

    def mem_search_replace_func(self):
        # memory replace pattern check
        replacepattern = self.hex_pattern_check(self.memReplacePattern.toPlainText())
        try:
            if replacepattern is not None:
                replacecode = ["".join(("0x", replacepattern[i:i + 2])) for i, char in enumerate(replacepattern) if
                               i % 2 == 0]
                # memory search pattern check
                searchpattern = self.hex_pattern_check(self.memSearchPattern.toPlainText())
                if searchpattern is not None:
                    gvar.frida_instrument.mem_scan_and_replace(replacecode)
                    result = self.mem_search_func(searchpattern)
                    # refresh mem ranges
                    if result is True:
                        # set_mem_range('r--')
                        pass
        except Exception as e:
            self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
            # self.mem_scan_worker.terminate()
            self.mem_scan_worker.quit()
            if str(e) == gvar.ERROR_SCRIPT_DESTROYED:
                gvar.frida_instrument.sessions.clear()
            return

    # this function retrieve above memory scan result and show it on the hexviewer
    def mem_scan_retrieve_result(self):
        # hmm...mem scan frida script sometimes sends the result multiple times.
        # so when it's empty, nothing to be appeared on the viewer
        tempresult = gvar.frida_instrument.get_mem_scan_result()
        if tempresult == '':
            # print('[hackcatml] memscan result: ', tempresult)
            pass
        else:
            result = tempresult
            # process read mem result
            result = process_read_mem_result(result)
            # sort memory scan result
            indices = [i for i, char in enumerate(result) if char == '\n']
            matchcount = len(indices) // 4

            arr = []
            for i in range(matchcount):
                if i == 0:
                    arr.append((matchcount, result[0: indices[3] + 1]))
                    continue
                arr.append((matchcount - i, result[indices[4 * i - 1] + 1: indices[4 * i - 1 + 3] + 1]))

            arr.sort()
            self.arrangedresult = ''
            self.arrangedresult2 = ''
            for i in arr:
                index = i[1].find('\n')
                self.arrangedresult += f"{str(i[0])}. {i[1]}\n"
                self.arrangedresult2 += f"{i[1][:index]}\n"

            self.hexViewer.setPlainText(self.arrangedresult)
            gvar.current_mem_scan_hex_view_result = self.arrangedresult
            self.memSearchResult.setText(self.arrangedresult2)
            self.memSearchFoundCount.setText(str(matchcount) + ' found')
            # terminate memory scan thread
            code.MESSAGE = ''
            # self.mem_scan_worker.terminate()
            self.mem_scan_worker.quit()

    def search_mem_search_result(self):
        if self.arrangedresult2 != '':
            searchresult = re.findall(fr".*{self.searchMemSearchResult.text()}.*", self.arrangedresult2, re.IGNORECASE)
            searchresult = [result for result in searchresult if result != '']
            finaltext = ''
            for text in searchresult:
                finaltext += text + '\n'
            self.memSearchResult.setText(finaltext)
            self.memSearchFoundCount.setText(str(len(searchresult)) + ' found')

    def mem_search_with_img_checkbox(self, state):
        isChecked = state == Qt.CheckState.Checked.value
        self.is_mem_search_with_img_checked = isChecked
        self.memSearchTargetImgInput.setEnabled(isChecked)

    def mem_scan_pattern_checkbox(self, state):
        self.is_mem_scan_str_checked = state == Qt.CheckState.Checked.value

    def mem_search_replace_checkbox(self, state):
        isChecked = state == Qt.CheckState.Checked.value
        self.memReplaceBtn.setEnabled(isChecked)
        self.memReplacePattern.setEnabled(isChecked)
        self.is_mem_search_replace_checked = isChecked

    def il2cpp_checkbox(self, state):
        isChecked = state == Qt.CheckState.Checked.value
        self.is_il2cpp_checked = isChecked
        self.memDumpModuleName.setEnabled(not isChecked)

    def watch_mem_checkbox(self, state):
        isChecked = state == Qt.CheckState.Checked.value
        if isChecked and gvar.is_frida_attached:
            self.mem_refresh_worker = MemRefreshWorker()
            self.mem_refresh_worker.status_current = self.status_current
            self.mem_refresh_worker.addr_input = self.addrInput
            self.mem_refresh_worker.watch_memory_spin_box = self.watchMemorySpinBox
            self.mem_refresh_worker.update_signal.connect(self.addr_btn_func)
            self.mem_refresh_worker.start()
        else:
            if self.mem_refresh_worker is not None:
                self.mem_refresh_worker.terminate()

    def refresh_curr_addr(self):
        curr_addr = self.status_current.toPlainText()
        if curr_addr == '':
            return
        else:
            match = re.search(r'\(0x[a-fA-F0-9]+\)', curr_addr)
            curr_addr = curr_addr[:match.start()] if match is not None else curr_addr
            self.addrInput.setText(curr_addr)
            self.addr_btn_func()

    def move_backward(self):
        tc = self.hexViewer.textCursor()
        indices = [i for i, x in enumerate(tc.block().text()) if x == " "]
        if len(indices) == 0:
            return
        elif re.search(r"\d+\. 0x[a-f0-9]+, module:", tc.block().text()):
            return

        if len(gvar.visited_address) > 0:
            for idx, sublist in enumerate(gvar.visited_address):
                if sublist[0] == 'last' and idx > 0:
                    addr_to_visit = gvar.visited_address[idx - 1][1]
                    self.addrInput.setText(addr_to_visit)
                    self.addr_btn_func()
                    break

    def move_forward(self):
        tc = self.hexViewer.textCursor()
        indices = [i for i, x in enumerate(tc.block().text()) if x == " "]
        if len(indices) == 0:
            return
        elif re.search(r"\d+\. 0x[a-f0-9]+, module:", tc.block().text()):
            return

        if len(gvar.visited_address) > 0:
            for idx, sublist in enumerate(gvar.visited_address):
                if sublist[0] == 'last' and idx < len(gvar.visited_address) - 1:
                    addr_to_visit = gvar.visited_address[idx + 1][1]
                    self.addrInput.setText(addr_to_visit)
                    self.addr_btn_func()
                    break

    def dump_module(self):
        # il2cpp dump
        if self.is_il2cpp_checked is True:
            if gvar.is_frida_attached is False:
                QMessageBox.information(self, "info", "Attach first")
                return
            elif gvar.is_frida_attached is True:
                try:
                    gvar.frida_instrument.dummy_script()
                except Exception as e:
                    if str(e) == gvar.ERROR_SCRIPT_DESTROYED:
                        gvar.frida_instrument.sessions.clear()
                    self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
                    return

            if self.il2cpp_frida_instrument is None or len(self.il2cpp_frida_instrument.sessions) == 0:
                if self.is_list_pid_checked:
                    target = self.attach_target_name_reserved
                elif gvar.frida_portal_mode:
                    target = self.attach_target_name
                else:
                    target = None
                self.il2cpp_frida_instrument = code.Instrument("scripts/il2cpp-dump.js",
                                                               True if gvar.frida_portal_mode is True else self.is_remote_attach_checked,
                                                               gvar.frida_instrument.remote_addr,
                                                               target,
                                                               False)
                msg = self.il2cpp_frida_instrument.instrument("dump_module")
                if msg is not None:
                    QMessageBox.information(self, "info", msg)
                    return

            # il2cpp dump thread worker start
            self.il2cpp_dump_worker = Il2CppDumpWorker(self.il2cpp_frida_instrument, self.statusBar())
            self.il2cpp_dump_worker.il2cpp_dump_signal.connect(self.il2cpp_dump_sig_func)
            self.il2cpp_dump_worker.start()
            self.memDumpBtn.setEnabled(False)
            return

        # just normal module memory dump
        if self.platform is None:
            self.statusBar().showMessage("Attach first", 3000)
            return

        result = False
        if self.platform == 'darwin':
            code.change_frida_script("scripts/dump-ios-module.js")
            result = gvar.frida_instrument.dump_ios_module(self.memDumpModuleName.text())
        elif self.platform == 'linux':
            code.change_frida_script("scripts/dump-so.js")
            result = gvar.frida_instrument.dump_so(self.memDumpModuleName.text())

        if result is False:
            self.statusBar().showMessage("dump fail. try again", 3000)
        else:
            self.listImgViewer.moveCursor(QTextCursor.MoveOperation.Start, QTextCursor.MoveMode.MoveAnchor)
            self.listImgViewer.setTextColor(QColor("Red"))
            dir_to_save = os.getcwd() + "\\dump\\" if platform.system() == "Windows" else os.getcwd() + "/dump/"
            if self.platform == 'darwin':
                if self.is_remote_attach_checked:
                    os.system(f"frida-pull -H {gvar.frida_instrument.remote_addr} \"{result}\" {dir_to_save}")
                else:
                    os.system(f"frida-pull -U \"{result}\" {dir_to_save}")
                self.listImgViewer.insertPlainText(f"Dumped file at: {dir_to_save}{result.split('/')[-1]}\n\n")
            elif self.platform == 'linux':
                self.listImgViewer.insertPlainText(
                    'Dumped file at: ' + result + "\n\nYou need to fix so file using SoFixer\n\n")
            self.listImgViewer.setTextColor(self.default_color)  # Revert to the default color
        code.revert_frida_script()

    def search_img(self, caller):
        # print(self.memDumpModuleName.text())
        text_to_find = ''
        viewer = None
        if caller == "memDumpModuleName":
            text_to_find = self.memDumpModuleName.text().lower()
            viewer = self.listImgViewer
        elif caller == "parseImgName":
            text_to_find = self.parseImgName.text().lower()
            viewer = self.parseImgListImgViewer

        matched = ''
        if len(gvar.list_modules) > 0:
            for module in gvar.list_modules:
                if module['name'].lower().find(text_to_find) != -1:
                    # print(module['name'])
                    matched += module['name'] + '\n'
        viewer.setText(matched)

    def set_status(self, name):
        # print(inspect.currentframe().f_back.f_code.co_name)
        # print(inspect.stack()[0][3] + ':', name)
        result = gvar.frida_instrument.module_status(name)
        if result is None: return

        self.status_img_name.setText(result['name'])
        self.status_img_base.setPlainText(result['base'])

        input = self.offsetInput.text()
        if inspect.stack()[2].function == "addr_btn_func":
            input = self.addrInput.text()

        if input.startswith('0x') is False:
            input = "".join(("0x0", input))

        addr = ""
        current_addr = ""
        try:
            if inspect.stack()[2].function == "offset_ok_btn_func":
                addr = hex(int(result['base'], 16) + int(input, 16))
                current_addr = addr + f"({input})"
            elif inspect.stack()[2].function == "addr_btn_func":
                addr = hex(int(input, 16))
                current_addr = addr + f"({hex(int(input, 16) - int(result['base'], 16))})"
            # caller function 찾기. https://stackoverflow.com/questions/900392/getting-the-caller-function-name-inside-another-function-in-python
            elif inspect.currentframe().f_back.f_code.co_name == "attach_frida":
                self.offsetInput.clear()
                self.addrInput.clear()
            # show the function name if it can be found
            if name is not None and current_addr != "" and gvar.is_frida_attached:
                if (sym_name := gvar.frida_instrument.find_sym_name_by_addr(name, addr)) is not None:
                    current_addr += f"({sym_name})"
        except Exception as e:
            print(e)
            pass

        self.status_current.setPlainText(current_addr)

        self.status_size.setPlainText(str(result['size']))
        self.status_end.setPlainText(hex(int(result['base'], 16) + result['size']))

        self.status_path.setPlainText(result['path'])

    def set_status_light(self):
        onicon = QPixmap("icon/greenlight.png").scaledToHeight(13)
        officon = QPixmap("icon/redlight.png").scaledToHeight(13)

        self.status_light.setPixmap(officon)
        if gvar.is_frida_attached is True:
            self.status_light.setPixmap(onicon)

        self.statusBar().removeWidget(self.status_light)
        self.statusBar().addPermanentWidget(self.status_light)
        self.status_light.show()

    def eventFilter(self, obj, event):
        self.interested_widgets = [self.offsetInput, self.addrInput]
        if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Tab:
            try:
                if self.tabWidget.tabText(
                        self.tabWidget.currentIndex()) == "Viewer" and self.tabWidget2.currentIndex() == 0:
                    self.interested_widgets.append(self.status_img_name)
                elif self.tabWidget.tabText(
                        self.tabWidget.currentIndex()) == "Viewer" and self.tabWidget2.currentIndex() == 2:
                    self.interested_widgets.append(self.memSearchPattern)
                elif self.tabWidget.tabText(self.tabWidget.currentIndex()) == "Util":
                    self.interested_widgets = [self.parse_img_name, self.parseImgName]
                # Get the index of the currently focused widget in our list
                index = self.interested_widgets.index(self.focusWidget())

                # Try to focus the next widget in the list
                self.interested_widgets[(index + 1) % len(self.interested_widgets)].setFocus()
            except ValueError:
                # The currently focused widget is not in our list, so we focus the first one
                self.interested_widgets[0].setFocus()

            # We've handled the event ourselves, so we don't pass it on
            return True

        # For other events, we let them be handled normally
        return super().eventFilter(obj, event)

    def closeEvent(self, a0: QtGui.QCloseEvent) -> None:
        if self.prepare_gadget_dialog is not None:
            self.prepare_gadget_dialog.gadget_dialog.close()
        if self.disasm_worker is not None:
            self.disasm_worker.disasm_window.close()
        if self.utilViewer.dex_dump_worker is not None:
            self.utilViewer.dex_dump_worker.quit()


if __name__ == "__main__":
    import sys

    # for windows taskbar icon. https://stackoverflow.com/a/1552105
    if platform.system() == "Windows":
        import ctypes

        myappid = 'com.hackcatml.mlviewer.1.0.0'  # arbitrary string
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)

    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon('icon/mlviewerico.png'))
    myWindow = WindowClass()
    myWindow.show()
    sys.exit(app.exec())
