import collections
import inspect
import os
import platform
import re

from PyQt6 import QtCore, QtGui
from PyQt6.QtCore import QThread, pyqtSlot, Qt, QEvent, QPoint, QMutex, QWaitCondition
from PyQt6.QtGui import QPixmap, QTextCursor, QShortcut, QKeySequence, QColor, QIcon, QPalette
from PyQt6.QtWidgets import QLabel, QMainWindow, QMessageBox, QApplication, QInputDialog, QTableWidgetItem

import frida_code
import gadget
import gvar
import hex_viewer
import misc
import parse_unity_dump
import scan_result
import spawn
import ui
import ui_win
from disasm import DisassembleWorker
from enum_ranges import EnumRangesViewClass
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
        # print("[main][set_mem_range] mem_enumerate_ranges result: ", result)
    except Exception as e:
        print(e)
        return
    # enumerateRanges --> [(base, base + size - 1, prot, size, path), ... ]
    gvar.enumerate_ranges.clear()
    for i in range(len(result)):
        gvar.enumerate_ranges.append(
            (result[i]['base'], hex(int(result[i]['base'], 16) + result[i]['size'] - 1), result[i]['protection'],
             result[i]['size'], result[i]['file']['path'] if result[i].get('file') is not None else ""))
    # print("[main][set_mem_range] gvar.enumerate_ranges: ", gvar.enumerate_ranges)


def hex_calculator(s):
    """ https://leetcode.com/problems/basic-calculator-ii/solutions/658480/Python-Basic-Calculator-I-II-III-easy
    -solution-detailed-explanation/comments/881191/"""

    def twos_complement(input_value: int, num_bits: int) -> int:
        mask = 2 ** num_bits - 1
        return ((input_value ^ mask) + 1) & mask

    def replace(match):
        num = int(match.group(0), 16)
        return "- " + hex(twos_complement(num, 64))

    # Multiply, divide op are not supported
    if re.search(r"[*/]", s):
        return False

    # Find negative hex value which starts with ffffffff and replace it with "- 2's complement"
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
    # Remove any residual whitespace
    for i in range(5):
        result = result.replace(' ' * (14 - i), '')
    return result


class GetFileFromDeviceWorker(QThread):
    get_file_from_device_finished_signal = QtCore.pyqtSignal()

    def __init__(self, file_path, output_path):
        super(GetFileFromDeviceWorker, self).__init__()
        self.file_path = file_path
        self.output_path = output_path
        if os.path.exists(self.output_path):
            os.remove(self.output_path)

    def run(self) -> None:
        try:
            gvar.frida_instrument.get_file_from_device(self.file_path)
        except Exception as e:
            print(f"[main][GetFileFromDeviceWorker] {e}")
            self.get_file_from_device_finished_signal.emit()
            return

    @pyqtSlot(bytes)
    def get_file_from_device_sig_func(self, sig: bytes):
        if len(sig) > 0:
            with open(self.output_path, 'ab') as f:
                f.write(sig)
        else:
            self.get_file_from_device_finished_signal.emit()


class Il2CppDumpWorker(QThread):
    il2cpp_dump_signal = QtCore.pyqtSignal(str)

    def __init__(self, il2cpp_frida_instrument, statusBar):
        super(Il2CppDumpWorker, self).__init__()
        self.il2cpp_frida_instrument = il2cpp_frida_instrument
        self.statusBar = statusBar

    def run(self) -> None:
        self.statusBar.showMessage("\tIl2cpp dumping...stay")
        try:
            result = self.il2cpp_frida_instrument.il2cpp_dump()
            if result is not None:
                self.il2cpp_dump_signal.emit(result)
        except Exception as e:
            if str(e) == gvar.ERROR_SCRIPT_DESTROYED:
                self.statusBar.showMessage(f"\t{e}...try again")
                self.il2cpp_frida_instrument.sessions.clear()
            return


class MemRefreshWorker(QThread):
    update_hexdump_result_signal = QtCore.pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.watch_memory_spin_box = None
        self.interval = None
        self.hex_dump_result = None
        self.hex_dump_result_start_address = None

        self.paused = False
        self.mutex = QMutex()
        self.pause_condition = QWaitCondition()

    def run(self) -> None:
        if gvar.frida_instrument is not None:
            gvar.frida_instrument.start_mem_refresh()
        while True:
            # Check for pause
            self.mutex.lock()
            if self.paused:
                self.pause_condition.wait(self.mutex)  # Pause until resumed
            self.mutex.unlock()

            self.interval = int(self.watch_memory_spin_box.value() * 1000)
            if gvar.frida_instrument is not None:
                try:
                    gvar.frida_instrument.get_mem_refresh(100 if self.interval == 0 else self.interval,
                                                      gvar.current_frame_start_address)
                except Exception as e:
                    print(f"[main]{inspect.currentframe().f_code.co_name}: {e}")
            self.msleep(100) if self.interval == 0 else self.msleep(self.interval)

            if self.hex_dump_result_start_address == gvar.current_frame_start_address:
                self.update_hexdump_result_signal.emit(self.hex_dump_result)

    @pyqtSlot(str)
    def refresh_hexdump_result_sig_func(self, sig: str):
        self.hex_dump_result = sig[sig.find('\n') + 1:]
        self.hex_dump_result_start_address = "".join(("0x", self.hex_dump_result[:self.hex_dump_result.find(' ')]))

    def pause(self):
        self.mutex.lock()
        self.paused = True
        self.mutex.unlock()

    def resume(self):
        self.mutex.lock()
        self.paused = False
        self.pause_condition.wakeAll()
        self.mutex.unlock()


class WindowClass(QMainWindow, ui.Ui_MainWindow if (platform.system() == 'Darwin') else ui_win.Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.spawn_dialog = None
        self.statusBar()
        self.status_light = QLabel()
        self.set_status_light()
        self.text_length = None

        self.is_il2cpp_checked = None
        self.il2cpp_dump_worker = None
        self.il2cpp_frida_instrument = None
        self.parse_unity_dump_dialog = None
        self.parse_result_table_created_signal_connected = False
        self.method_clicked_signal_connected = False
        self.get_file_from_device_worker = None

        self.hex_edit_shortcut = QShortcut(QKeySequence(Qt.Key.Key_F2), self)
        self.is_remote_attach_checked = False
        self.is_spawn_checked = False

        gvar.hex_viewer_signal_manager = hex_viewer.HexViewerSignalManager()
        gvar.hex_viewer_signal_manager.backtrace_text_edit_backtrace_addr_clicked_signal.connect(
            self.backtrace_text_edit_backtrace_addr_clicked_sig_func)
        self.hexViewer.wheel_up_signal.connect(self.wheel_up_sig_func)
        self.hexViewer.move_signal.connect(self.move_sig_func)
        self.hexViewer.refresh_signal.connect(self.refresh_sig_func)
        self.hexViewer.mem_patch_addr_signal.connect(self.mem_patch_addr_sig_func)
        self.hexViewer.set_watchpoint_addr_signal.connect(self.set_watchpoint_addr_sig_func)
        self.hexViewer.statusBar = self.statusBar()

        self.default_color = QLabel().palette().color(QPalette.ColorRole.WindowText)
        self.listImgViewer.module_name_signal.connect(lambda sig: self.module_name_sig_func(sig, "listImgViewer"))
        self.parseImgListImgViewer.module_name_signal.connect(
            lambda sig: self.module_name_sig_func(sig, "parseImgListImgViewer"))

        self.prepare_gadget_dialog = gadget.GadgetDialogClass()
        self.prepare_gadget_dialog.frida_portal_node_info_signal.connect(self.frida_portal_node_info_sig_func)
        self.prepare_gadget_dialog.gadget_ui.fridaPortalModeCheckBox.setChecked(True)
        self.gadgetBtn.clicked.connect(self.prepare_gadget)
        self.statusBar().showMessage(f"\tWelcome! frida-portal is listening on {gadget.get_local_ip()}:{gvar.frida_portal_cluster_port}", 10000)

        self.platform = None
        self.is_list_pid_checked = False
        self.attach_target_name = None  # Name to attach. need to provide on the AppList widget
        self.attach_target_name_reserved = None
        self.attached_name = None  # Main module name after frida attached successfully
        self.spawn_target_id = None  # Target identifier to do frida spawn. need to provide on the AppList widget
        self.remote_addr = ''

        self.mem_refresh_worker = None
        self.mem_refresh_interval = 0
        self.refresh_hexdump_result_signal_connected = False

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

        self.memScanHexCheckBox.stateChanged.connect(self.mem_scan_hex_checkbox)
        self.memScanTypeComboBox.currentTextChanged.connect(self.mem_scan_type_combobox)
        self.floatDoubleRoundedScanOptionRadioButton.toggled.connect(self.float_double_rounded_scan_option)
        self.floatDoubleExactScanOptionRadioButton.toggled.connect(self.float_double_rounded_scan_option)
        self.memScanTargetImg.setEnabled(False)
        self.memScanTargetImg.returnPressed.connect(self.mem_scan_target_img_pressed_func)
        self.memScanTargetImgCheckBox.stateChanged.connect(self.mem_scan_target_img_checkbox)
        self.enum_ranges_view = EnumRangesViewClass()
        self.enum_ranges_view.refresh_enum_ranges_signal.connect(self.refresh_enum_ranges_sig_func)
        self.enum_ranges_view.enum_ranges_item_clicked_signal.connect(self.enum_ranges_item_clicked_sig_func)
        self.showEnumRangesBtn.clicked.connect(self.enum_ranges_view.show_enum_ranges)

        self.scan_result_view_thread = QThread()
        self.scan_result_view_worker = scan_result.ScanResultViewWorker()
        self.scan_result_view_worker.set_scan_options_signal.connect(self.set_scan_options_sig_func)
        self.scan_result_view_worker.notify_mem_scan_to_main_signal.connect(self.notify_mem_scan_to_main_sig_func)
        self.scan_result_view_worker.scan_result_addr_signal.connect(self.scan_result_addr_sig_func)
        self.scan_result_view_worker.scan_result_view_ui.memScanResultTableWidget.\
            watch_point_widget.watch_point_ui.\
            disassemResult.watchpoint_addr_clicked_signal.connect(self.watchpoint_addr_clicked_sig_func)
        self.scan_result_view_worker.moveToThread(self.scan_result_view_thread)
        self.scan_result_view_thread.start()

        self.memDumpBtn.clicked.connect(self.dump_module)
        self.memDumpModuleName.returnPressed.connect(self.dump_module)
        self.memDumpModuleName.textChanged.connect(lambda: self.search_img("memDumpModuleName"))
        self.parseImgName.textChanged.connect(lambda: self.search_img("parseImgName"))

        self.listPIDCheckBox.stateChanged.connect(self.list_pid)
        self.attachTypeCheckBox.stateChanged.connect(self.remote_attach)
        self.spawnModeCheckBox.stateChanged.connect(self.spawn_mode)
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
        self.history_view.history_ui.historyTableWidget.set_watch_func_signal.connect(
            self.hexViewer.set_watch_func_sig_func)
        self.history_view.history_ui.historyTableWidget.set_watch_regs_signal.connect(
            self.hexViewer.set_watch_regs_sig_func)
        self.history_view.history_ui.historyTableWidget.history_remove_row_signal.connect(
            self.hexViewer.history_remove_row_sig_func)
        self.hexViewer.watch_list_signal.connect(self.history_view.history_ui.historyTableWidget.watch_list_sig_func)
        self.hexViewer.add_address_to_history_signal.connect(self.history_view.add_address_to_history_sig_func)
        self.historyBtn.clicked.connect(self.history_view.show_history)

        self.utilViewer.parse_img_name = self.parse_img_name
        self.utilViewer.parse_img_base = self.parse_img_base
        self.utilViewer.parse_img_path = self.parse_img_path
        self.utilViewer.parseImgName = self.parseImgName
        self.utilViewer.statusBar = self.statusBar()
        self.parseImgTabWidget.tabBarClicked.connect(self.parse_img_tab_bar_click_func)
        self.parse_img_name.returnPressed.connect(lambda: self.utilViewer.parse("parse_img_name"))
        self.parseBtn.clicked.connect(lambda: self.utilViewer.parse("parseBtn"))
        self.parseImgName.returnPressed.connect(lambda: self.utilViewer.parse("parseImgName"))
        self.utilViewer.search_input = self.utilViewerSearchInput
        self.utilViewer.search_input.returnPressed.connect(self.utilViewer.search_text)
        self.utilViewer.search_button = self.utilViewerSearchBtn
        self.utilViewer.search_button.clicked.connect(self.utilViewer.search_text)

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

        self.utilViewer.show_proc_self_maps_btn = self.showMapsBtn
        self.utilViewer.show_proc_self_maps_btn.clicked.connect(self.utilViewer.show_maps)

        # Install event filter to use tab and move to some input fields
        self.interested_widgets = []
        QApplication.instance().installEventFilter(self)

    @pyqtSlot(str)
    def set_scan_options_sig_func(self, sig: str):
        scan_value = self.memScanPattern.toPlainText()
        is_hex_checked = self.memScanHexCheckBox.isChecked()
        if scan_value.strip() == '':
            return
        hex_regex = re.compile(r'(\b0x[a-fA-F0-9]+\b)')
        match = hex_regex.match(scan_value)
        if match is not None:   # Pointer scan
            try:
                scan_value = hex_calculator(scan_value)
            except Exception as e:
                self.statusBar().showMessage(f"\t[main]{inspect.currentframe().f_code.co_name}: {e}", 5000)
                return
            if scan_value is False:
                self.statusBar().showMessage("\tCan't operate *, /", 5000)
                return
            byte_pairs = misc.hex_value_byte_pairs(scan_value.replace('0x', ''))
            if gvar.arch == 'arm64' and (8 - len(byte_pairs) < 0):
                self.statusBar().showMessage("\tWrong pointer size", 5000)
                return
            elif gvar.arch == 'arm64' and (8 - len(byte_pairs) > 0):
                byte_pairs = ['00' for _ in range(8 - len(byte_pairs))] + byte_pairs
            elif gvar.arch == 'arm' and (4 - len(byte_pairs) < 0):
                self.statusBar().showMessage("\tWrong pointer size", 5000)
                return
            else:
                byte_pairs = ['00' for _ in range(4 - len(byte_pairs))] + byte_pairs
            reversed_bytes = "".join(reversed(byte_pairs))
            scan_value = reversed_bytes
            scan_type = "Pointer"
            scan_module = self.memScanTargetImgCheckBox.isChecked()
            if scan_module:
                scan_module_name = self.memScanTargetImg.text()
            else:
                scan_module_name = ''
            scan_start = self.memScanStartAddress.toPlainText()
            scan_end = self.memScanEndAddress.toPlainText()
            scan_prot = 'r--'
            if not self.memProtWritableCheckBox.isChecked() and not self.memProtExecutableCheckBox.isChecked():
                scan_prot = 'r--'
            elif self.memProtWritableCheckBox.isChecked() and not self.memProtExecutableCheckBox.isChecked():
                scan_prot = 'rw-'
            elif not self.memProtWritableCheckBox.isChecked() and self.memProtExecutableCheckBox.isChecked():
                scan_prot = 'r-x'
            elif self.memProtWritableCheckBox.isChecked() and self.memProtExecutableCheckBox.isChecked():
                scan_prot = 'rwx'
            scan_options = [scan_value, is_hex_checked, scan_type, scan_module_name, scan_start, scan_end, scan_prot]
        else:
            if sig == 'First Scan':  # Set the options for the first scan
                scan_type = self.memScanTypeComboBox.itemText(self.memScanTypeComboBox.currentIndex())
                if not is_hex_checked:
                    if scan_type == '1 Byte' or scan_type == '2 Bytes' or \
                        scan_type == '4 Bytes' or scan_type == '8 Bytes' or \
                            scan_type == 'Int' or scan_type == 'String':
                        scan_value = misc.change_value_to_little_endian_hex(scan_value, scan_type, 10)
                        if 'Error' in scan_value:
                            self.statusBar().showMessage(scan_value, 3000)
                            return
                        if 'Error' in (result := misc.hex_pattern_check(scan_value)):
                            self.statusBar().showMessage(result, 3000)
                            return
                    elif scan_type == 'Float' or scan_type == 'Double':
                        if self.floatDoubleExactScanOptionRadioButton.isChecked():
                            scan_value = misc.change_value_to_little_endian_hex(scan_value, scan_type, 10)
                            if 'Error' in scan_value:
                                self.statusBar().showMessage(scan_value, 3000)
                                return
                            if 'Error' in (result := misc.hex_pattern_check(scan_value)):
                                self.statusBar().showMessage(result, 3000)
                                return
                        elif self.floatDoubleRoundedScanOptionRadioButton.isChecked():
                            try:
                                rounded_value = round(float(scan_value))
                            except Exception as e:
                                self.statusBar().showMessage(f"\t{inspect.currentframe().f_code.co_name}: {e}", 3000)
                                print(f"[main][set_scan_options_sig_func] {e}")
                                return
                            float_double_scan_value_hex_pattern = misc.generate_hex_pattern_for_rounded_float_double(rounded_value, scan_type)
                            print(f"[main][set_scan_options_sig_func] float_double_scan_value_hex_pattern: {float_double_scan_value_hex_pattern}")
                            float_double_scan_value_byte_pairs = misc.hex_value_byte_pairs(float_double_scan_value_hex_pattern.replace("??", "").strip())
                            print(f"[main][set_scan_options_sig_func] float_double_scan_value_byte_pairs: {float_double_scan_value_byte_pairs}")
                            scan_value = {"scan_type": scan_type,
                                          "rounded_value": rounded_value,
                                          "scan_value_length": len(float_double_scan_value_byte_pairs),
                                          "scan_value": float_double_scan_value_hex_pattern}
                            # print(f"[main][set_scan_options_sig_func] scan_value: {scan_value}")
                if scan_type == 'String':
                    scan_value_string = misc.change_little_endian_hex_to_value(scan_value, scan_type)
                    print(f"[main][set_scan_options_sig_func] scan_value_string: {scan_value_string}")
                    if 'Error' in scan_value_string:
                        self.statusBar().showMessage(scan_value_string, 3000)
                        return
                    pattern_length = len(scan_value_string)
                    scan_type = {'String': pattern_length}
                if scan_type == 'Array of Bytes':
                    if 'Error' in (result := misc.hex_pattern_check(scan_value)):
                        self.statusBar().showMessage(result, 3000)
                        return
                    pattern_length = len(scan_value.replace(' ', '')) / 2
                    scan_type = {'Array of Bytes': pattern_length}
                scan_module = self.memScanTargetImgCheckBox.isChecked()
                if scan_module:
                    scan_module_name = self.memScanTargetImg.text()
                else:
                    scan_module_name = ''
                scan_start = self.memScanStartAddress.toPlainText()
                scan_end = self.memScanEndAddress.toPlainText()
                scan_prot = 'r--'
                if not self.memProtWritableCheckBox.isChecked() and not self.memProtExecutableCheckBox.isChecked():
                    scan_prot = 'r--'
                elif self.memProtWritableCheckBox.isChecked() and not self.memProtExecutableCheckBox.isChecked():
                    scan_prot = 'rw-'
                elif not self.memProtWritableCheckBox.isChecked() and self.memProtExecutableCheckBox.isChecked():
                    scan_prot = 'r-x'
                elif self.memProtWritableCheckBox.isChecked() and self.memProtExecutableCheckBox.isChecked():
                    scan_prot = 'rwx'
                # For the first scan, scan_value should be in hexadecimal byte format
                scan_options = [scan_value, is_hex_checked, scan_type, scan_module_name, scan_start, scan_end, scan_prot]
            else:   # Set the options for the next scan
                scan_type = self.memScanTypeComboBox.itemText(self.memScanTypeComboBox.currentIndex())
                if scan_type == '1 Byte' or scan_type == '2 Bytes' or \
                    scan_type == '4 Bytes' or scan_type == '8 Bytes' or \
                        scan_type == 'Int':
                    if is_hex_checked:
                        # Scan_value should not be in hexadecimal byte format
                        scan_value = misc.change_little_endian_hex_to_value(scan_value, scan_type)
                        if type(scan_value) is str and 'Error' in scan_value:
                            self.statusBar().showMessage(scan_value, 3000)
                            return
                    else:
                        integer_regex = re.compile(r'^-?\d+$')
                        if integer_regex.match(scan_value) is None:
                            self.statusBar().showMessage("\tWrong value", 3000)
                            return
                if scan_type == 'Float' or scan_type == 'Double':
                    if self.floatDoubleExactScanOptionRadioButton.isChecked():
                        if is_hex_checked:
                            # Scan_value should not be in hexadecimal byte format
                            scan_value = misc.change_little_endian_hex_to_value(scan_value, scan_type)
                            if type(scan_value) is str and 'Error' in scan_value:
                                self.statusBar().showMessage(scan_value, 3000)
                                return
                    elif self.floatDoubleRoundedScanOptionRadioButton.isChecked():
                        try:
                            rounded_value = round(float(scan_value))
                        except Exception as e:
                            self.statusBar().showMessage(f"\t{inspect.currentframe().f_code.co_name}: {e}", 3000)
                            print(f"[main][set_scan_options_sig_func] {e}")
                            return
                        scan_value = {"rounded_value": rounded_value}
                if scan_type == 'String':
                    if not is_hex_checked:
                        pattern_length = len(scan_value)
                        scan_value = misc.change_value_to_little_endian_hex(scan_value, scan_type, 10)
                    else:
                        scan_value_string = misc.change_little_endian_hex_to_value(scan_value, scan_type)
                        print(f"[main][set_scan_options_sig_func] scan_value_string: {scan_value_string}")
                        if 'Error' in scan_value_string:
                            self.statusBar().showMessage(scan_value_string, 3000)
                            return
                        pattern_length = len(scan_value_string)
                    scan_type = {'String': pattern_length}
                if scan_type == 'Array of Bytes':
                    if 'Error' in (result := misc.hex_pattern_check(scan_value)):
                        self.statusBar().showMessage(result, 3000)
                        return
                    pattern_length = len(scan_value.replace(' ', '')) / 2
                    scan_type = {'Array of Bytes': pattern_length}
                scan_options = [scan_value, is_hex_checked, scan_type, "", "", "", ""]

        print(f"[main][set_scan_options_sig_func] scan_options: {scan_options}")
        self.scan_result_view_worker.get_scan_options_signal.emit(scan_options)

        if sig == "First Scan":
            self.memScanTypeComboBox.setEnabled(False)
            if self.memScanTypeComboBox.currentText() == "Float" or self.memScanTypeComboBox.currentText() == "Double":
                self.floatDoubleExactScanOptionRadioButton.setEnabled(False)
                self.floatDoubleRoundedScanOptionRadioButton.setEnabled(False)
            self.memScanTargetImgCheckBox.setEnabled(False)
            if self.memScanTargetImgCheckBox.isChecked():
                self.memScanTargetImg.setEnabled(False)
            self.memScanStartAddress.setEnabled(False)
            self.memScanEndAddress.setEnabled(False)
            self.memProtWritableCheckBox.setEnabled(False)
            self.memProtExecutableCheckBox.setEnabled(False)

    @pyqtSlot(list)
    def notify_mem_scan_to_main_sig_func(self, sig: list):
        # sig --> ["Scan", 0] or ["First Scan", 1]...
        # Memory scan started
        if sig[0] == "Scan" and sig[1] == 0:
            self.stop_or_restart_mem_refresh(0)     # Stop refreshing memory
            self.watchMemoryCheckBox.setEnabled(False)

        # New scan
        if sig[0] == "New Scan" and sig[1] == 1:
            self.memScanTypeComboBox.setEnabled(True)
            if self.memScanTypeComboBox.currentText() == "Float" or self.memScanTypeComboBox.currentText() == "Double":
                self.floatDoubleExactScanOptionRadioButton.setEnabled(True)
                self.floatDoubleRoundedScanOptionRadioButton.setEnabled(True)
            self.memScanTargetImgCheckBox.setEnabled(True)
            if self.memScanTargetImgCheckBox.isChecked():
                self.memScanTargetImg.setEnabled(True)
            self.memScanStartAddress.setEnabled(True)
            self.memScanEndAddress.setEnabled(True)
            self.memProtWritableCheckBox.setEnabled(True)
            self.memProtExecutableCheckBox.setEnabled(True)
        # Memory scan completed
        if sig[1] == 1:
            self.stop_or_restart_mem_refresh(1)     # Restart refreshing memory
            self.watchMemoryCheckBox.setEnabled(True)

    @pyqtSlot(str)
    def scan_result_addr_sig_func(self, sig: str):
        self.addrInput.setText(sig)
        self.addr_btn_func()

    @pyqtSlot(str)
    def watchpoint_addr_clicked_sig_func(self, sig: str):
        self.addrInput.setText(sig)
        self.addr_btn_func()

    @pyqtSlot(str)
    def wheel_up_sig_func(self, sig: str):
        # If memory refresh worker is running, update gvar.current_frame_start_address and return
        if self.watchMemoryCheckBox.isChecked() and self.mem_refresh_worker.isRunning():
            if self.status_img_base.toPlainText() == hex_calculator(f"{sig}"):
                return
            else:
                gvar.current_frame_start_address = hex_calculator(f"{sig} - 10")
                return

        self.pause_or_resume_mem_refresh(0)
        # print(f"[main][wheel_up_sig_func] {sig}")
        if self.status_img_base.toPlainText() == hex_calculator(f"{sig}"):
            self.pause_or_resume_mem_refresh(1)
            return
        addr = hex_calculator(f"{sig} - 10")
        # print(f"[main][wheel_up_sig_func] {addr}")
        self.addrInput.setText(addr)
        self.addr_btn_func()
        self.pause_or_resume_mem_refresh(1)

    @pyqtSlot(int)
    def move_sig_func(self, sig: int):
        self.move_backward() if sig == 0 else self.move_forward()

    @pyqtSlot(int)
    def refresh_sig_func(self, sig: int):
        if sig:
            self.refresh_curr_addr()

    @pyqtSlot(str)
    def mem_patch_addr_sig_func(self, sig: str):
        if sig and self.scan_result_view_worker is not None:
            self.scan_result_view_worker.scan_result_view_ui.memScanResultTableWidget.\
                mem_patch_widget.add_row([sig])
            self.scan_result_view_worker.scan_result_view_ui.memScanResultTableWidget.\
                mem_patch_widget.show()

    @pyqtSlot(str)
    def set_watchpoint_addr_sig_func(self, sig: str):
        if sig and self.scan_result_view_worker is not None:
            self.scan_result_view_worker.scan_result_view_ui.memScanResultTableWidget.\
                watch_point_widget.watch_point_ui.watchpointAddrInput.setText(sig)
            self.scan_result_view_worker.scan_result_view_ui.memScanResultTableWidget. \
                watch_point_widget.show()

    @pyqtSlot(str)
    def module_name_sig_func(self, sig: str, caller):
        if caller == "listImgViewer":
            self.memDumpModuleName.setText(sig)
        elif caller == "parseImgListImgViewer":
            self.parseImgName.setText(sig)

    @pyqtSlot(str)
    def spawn_target_id_sig_func(self, sig: str):
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
        self.attach_frida("spawn_target_id_sig_func")
        self.spawn_dialog = None
        self.spawn_target_id = None
        self.attach_target_name = None
        self.remote_addr = ''

    @pyqtSlot(str)
    def il2cpp_dump_sig_func(self, sig: str):   # sig --> dumped il2cpp file path in the device
        if sig is not None:
            QThread.msleep(100)
            self.statusBar().showMessage("\tIl2cpp Dump Done!", 5000)
            self.listImgViewer.moveCursor(QTextCursor.MoveOperation.Start, QTextCursor.MoveMode.MoveAnchor)
            self.listImgViewer.setTextColor(QColor("Red"))
            dir_to_save = os.getcwd() + "\\dump\\" if platform.system() == "Windows" else os.getcwd() + "/dump/"
            dump_file_name = sig.split('/')[-1]
            output_path = None
            if self.is_remote_attach_checked and gvar.frida_portal_mode is False:
                os.system(
                    f"frida-pull -H {self.il2cpp_frida_instrument.remote_addr} \"{sig}\" {dir_to_save}")
            elif self.is_remote_attach_checked is False and gvar.frida_portal_mode is False:
                os.system(f"frida-pull -U \"{sig}\" {dir_to_save}")
            elif gvar.frida_portal_mode is True:
                output_path = dir_to_save + dump_file_name
            else:
                dir_to_save = ""
                dump_file_name = sig
            self.listImgViewer.insertPlainText(f"Dumped file at: {dir_to_save}{dump_file_name}\n\n")
            self.listImgViewer.setTextColor(self.default_color)
            # After il2cpp dump some android apps crash
            self.il2cpp_dump_worker.terminate()
            self.memDumpBtn.setEnabled(True)
            if output_path is not None:
                self.get_file_from_device(sig, output_path)

    @pyqtSlot(int)
    def frida_attach_sig_func(self, sig: int):
        if sig:     # sig == 1
            gvar.is_frida_attached = True
            if self.is_remote_attach_checked:
                gvar.remote = True
        else:   # sig == 0
            gvar.is_frida_attached = False
            self.detach_frida()
        self.set_status_light()

    @pyqtSlot(str)
    def change_frida_script_sig_func(self, sig: str):
        if sig != 'scripts/default.js':
            self.stop_or_restart_mem_refresh(0)
        else:
            self.stop_or_restart_mem_refresh(1)

    @pyqtSlot(list)
    def frida_portal_node_info_sig_func(self, sig: list):  # Node info signal
        if sig:
            self.remote_addr = "localhost"
            self.attach_target_name = sig[0]
            self.attach_frida("frida_portal_node_info_sig_func")

    @pyqtSlot(str)
    def history_addr_sig_func(self, sig: str):
        self.addrInput.setText(sig)
        self.addr_btn_func()

    @pyqtSlot(str)
    def refresh_enum_ranges_sig_func(self, sig: str):
        set_mem_range(sig)

    @pyqtSlot(list)
    def enum_ranges_item_clicked_sig_func(self, sig: list):
        if sig[0] == 0:
            self.memScanStartAddress.setText(sig[1])
        if sig[0] == 1:
            self.memScanEndAddress.setText(sig[1])
        if sig[0] == 2:
            self.memProtWritableCheckBox.setChecked(False)
            self.memProtExecutableCheckBox.setChecked(False)
            if sig[1] == 'rw-':
                self.memProtWritableCheckBox.setChecked(True)
            if sig[1] == 'rwx':
                self.memProtWritableCheckBox.setChecked(True)
                self.memProtExecutableCheckBox.setChecked(True)
            if sig[1] == 'r-x':
                self.memProtExecutableCheckBox.setChecked(True)
        if sig[0] == 3:
            if self.memScanTargetImgCheckBox.isChecked():
                try:
                    module = gvar.frida_instrument.get_module_by_name(sig[1])
                except Exception as e:
                    self.statusBar().showMessage(f"\t{inspect.currentframe().f_code.co_name}: {e}", 3000)
                    return

                if module != '':
                    self.memScanTargetImg.setText(sig[1])
                    self.memScanStartAddress.setText(module['base'])
                    self.memScanEndAddress.setText(hex(int(module['base'], 16) + module['size'] - 1))
                else:
                    self.memScanTargetImg.setText('')
                    self.memScanStartAddress.setText('0000000000000000')
                    self.memScanEndAddress.setText('00007fffffffffff')

    @pyqtSlot(str)
    def backtrace_text_edit_backtrace_addr_clicked_sig_func(self, sig: str):
        self.addrInput.setText(sig)
        self.addr_btn_func()

    @pyqtSlot(str)
    def update_hexdump_result_sig_func(self, sig: str):
        if self.watchMemoryCheckBox.isChecked() and sig == "":
            print(f"[main][update_hexdump_result_sig_func] signal is not received")
        self.hexViewer.setPlainText(sig)
        curr_addr = int(sig[:sig.find(' ')], 16)
        if (base_addr := self.status_img_base.toPlainText()) != '' and (curr_addr >= int(base_addr, 16)):
            current_addr = hex(curr_addr) + f"({hex(curr_addr - int(base_addr, 16))})"
        else:
            current_addr = hex(curr_addr)
        self.status_current.setPlainText(current_addr)
        gvar.current_frame_block_number = 0
        self.disasm_worker.disassemble(gvar.arch, gvar.current_frame_start_address, sig)

    @pyqtSlot(int)
    def parse_result_table_create_sig_func(self, sig: int):
        if sig == 0:
            pass
        elif sig == 1:  # New tableview
            try:
                self.parse_unity_dump_dialog.parse_result.method_clicked_signal.disconnect()
                self.method_clicked_signal_connected = False
            except Exception as e:
                self.method_clicked_signal_connected = False
            if self.method_clicked_signal_connected is False:
                self.parse_unity_dump_dialog.parse_result.method_clicked_signal.connect(self.method_clicked_sig_func)
                self.method_clicked_signal_connected = True

    @pyqtSlot(str)
    def method_clicked_sig_func(self, sig: str):
        if sig:
            self.addrInput.setText(sig)
            self.addr_btn_func()

    @pyqtSlot()
    def get_file_from_device_finished_sig_func(self):
        if self.get_file_from_device_worker is not None and self.get_file_from_device_worker.isRunning():
            gvar.frida_instrument.get_file_from_device_signal.disconnect()
            self.get_file_from_device_worker.get_file_from_device_finished_signal.disconnect()
            self.get_file_from_device_worker.quit()

    def closeEvent(self, a0: QtGui.QCloseEvent) -> None:
        if self.prepare_gadget_dialog is not None:
            self.prepare_gadget_dialog.gadget_dialog.close()
        if self.disasm_worker is not None:
            self.disasm_worker.disasm_window.close()
        if self.utilViewer.dex_dump_worker is not None:
            self.utilViewer.dex_dump_worker.quit()

    def eventFilter(self, obj, event):
        self.interested_widgets = [self.offsetInput, self.addrInput]
        if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Tab:
            try:
                if self.tabWidget.tabText(
                        self.tabWidget.currentIndex()) == "Viewer" and self.tabWidget2.currentIndex() == 0:
                    self.interested_widgets.append(self.status_img_name)
                elif self.tabWidget.tabText(
                        self.tabWidget.currentIndex()) == "Viewer" and self.tabWidget2.currentIndex() == 2:
                    self.interested_widgets.append(self.memScanPattern)
                    if self.memScanTargetImgCheckBox.isChecked():
                        self.interested_widgets.append(self.memScanTargetImg)
                    self.interested_widgets.append(self.memScanStartAddress)
                    self.interested_widgets.append(self.memScanEndAddress)
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

    def adjust_label_pos(self):
        tc = self.hexViewer.textCursor()
        text_length = len(tc.block().text())
        if self.text_length == text_length:
            return
        else:
            self.text_length = text_length
        current_height = self.height()
        if text_length >= 83:
            resize_width = text_length * 14 + round(text_length / 10)
        else:
            resize_width = text_length * 13
        self.resize(resize_width, current_height)
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
            # if self.prepare_gadget_dialog is None:
            #     self.prepare_gadget_dialog = gadget.GadgetDialogClass()
            #     self.prepare_gadget_dialog.frida_portal_node_info_signal.connect(self.frida_portal_node_info_sig_func)
            self.prepare_gadget_dialog.gadget_dialog.show()
        except Exception as e:
            self.statusBar().showMessage(f"\t{inspect.currentframe().f_code.co_name}: {e}", 3000)
            return

    def attach_frida(self, caller: str):
        if gvar.is_frida_attached is True:
            try:
                # Check if script is still alive. if not exception will occur
                gvar.frida_instrument.dummy_script()
                QMessageBox.information(self, "info", "Already attached")
            except Exception as e:
                self.statusBar().showMessage(f"\t{inspect.currentframe().f_code.co_name}: {e}", 3000)
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
                        self.spawn_dialog.attach_target_name_signal.connect(self.spawn_target_id_sig_func)

                    self.spawn_dialog.spawn_target_id_signal.connect(self.spawn_target_id_sig_func)

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

                gvar.frida_instrument = frida_code.Instrument("scripts/default.js",
                                                        self.is_remote_attach_checked,
                                                        self.remote_addr,
                                                        self.attach_target_name if (
                                                                self.is_list_pid_checked and not self.is_spawn_checked) else self.spawn_target_id,
                                                        self.is_spawn_checked)
                # Connect frida attach signal function
                gvar.frida_instrument.attach_signal.connect(self.frida_attach_sig_func)
                gvar.frida_instrument.change_frida_script_signal.connect(self.change_frida_script_sig_func)
                msg = gvar.frida_instrument.instrument(caller)
            elif caller == "frida_portal_node_info_sig_func":
                gvar.frida_instrument = frida_code.Instrument("scripts/default.js",
                                                        True,
                                                        self.remote_addr,
                                                        self.attach_target_name,
                                                        False)
                # Connect frida attach signal function
                gvar.frida_instrument.attach_signal.connect(self.frida_attach_sig_func)
                gvar.frida_instrument.change_frida_script_signal.connect(self.change_frida_script_sig_func)
                msg = gvar.frida_instrument.instrument(caller)

            self.remote_addr = ''
        except Exception as e:
            print(e)
            self.statusBar().showMessage(f"\t{inspect.currentframe().f_code.co_name}: {e}", 3000)
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
            modules = gvar.frida_instrument.list_modules()
            name = modules[0]['name']
            for module in modules:
                if module['name'] == 'libil2cpp.so' or module['name'] == 'UnityFramework' or \
                        module['name'] == 'libUnreal.so' or module['name'] == 'libUE4.so':
                    name = module['name']
                    break
            self.attached_name = name
            self.set_status(name)

            for module in modules:
                if module['name'] == 'libpairipcore.so':
                    gvar.frida_instrument.set_exception()
                    break
        except Exception as e:
            print(e)
            return

    def is_addr_in_mem_range_for_palera1n(self, result):
        # If the hexdump result is dict and has 'palera1n', it means mem addr not in the mem range
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
            self.statusBar().showMessage(f"\t{inspect.currentframe().f_code.co_name}: {e}", 3000)
            return

        if offset is False:
            self.statusBar().showMessage("\tCan't operate *, /", 3000)
            return

        self.offsetInput.setText(offset)

        name = self.status_img_name.text().strip()
        # print(f'name: {name}')
        try:
            if self.status_img_base.toPlainText() == '':
                result = gvar.frida_instrument.read_mem_offset(name, offset, gvar.READ_MEM_SIZE)
            else:
                addr = hex_calculator(f"{self.status_img_base.toPlainText()} + {offset} + 1000")
                # Check the address in the memory regions
                if is_readable_addr(addr):
                    result = gvar.frida_instrument.read_mem_offset(name, offset, gvar.READ_MEM_SIZE)
                else:
                    # Not in the memory regions. but check module existence
                    if gvar.frida_instrument.get_module_by_addr(addr) != '':
                        # There is a module
                        size = int(gvar.frida_instrument.get_module_by_addr(addr)['base'], 16) + \
                               gvar.frida_instrument.get_module_by_addr(addr)['size'] - 1 - int(addr, 16)
                        if size < gvar.READ_MEM_SIZE:
                            result = gvar.frida_instrument.read_mem_offset(name, offset, size)
                        else:
                            result = gvar.frida_instrument.read_mem_offset(name, offset, gvar.READ_MEM_SIZE)
                    else:
                        # There is no module. But just try to read.
                        size = size_to_read(hex_calculator(f"{self.status_img_base.toPlainText()} + {offset}"))
                        if size is not None:
                            result = gvar.frida_instrument.read_mem_offset(name, offset, size)
                        else:
                            result = gvar.frida_instrument.read_mem_offset(name, offset, gvar.READ_MEM_SIZE / 2)
        except Exception as e:
            self.statusBar().showMessage(f"\t{inspect.currentframe().f_code.co_name}: {e}", 3000)
            if str(e) == gvar.ERROR_SCRIPT_DESTROYED:
                gvar.frida_instrument.sessions.clear()
            return

        if self.is_palera1n and not self.is_cmd_pressed and not self.is_addr_in_mem_range_for_palera1n(result):
            self.statusBar().showMessage(f"\t{result['palera1n']}", 3000)
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
        # In case it's not a hex expression on addrInput field. for example "fopen", "sysctl", ...
        if match is None:
            try:
                func_addr = gvar.frida_instrument.find_sym_addr_by_name(self.status_img_name.text(), addr)
                if func_addr is None:
                    self.statusBar().showMessage(f"\tCannot find address for {addr}", 3000)
                    return
                addr = func_addr
            except Exception as e:
                self.statusBar().showMessage(f"\t{inspect.currentframe().f_code.co_name}: {e}", 3000)
                return

        try:
            addr = hex_calculator(addr)
        except Exception as e:
            self.statusBar().showMessage(f"\t{inspect.currentframe().f_code.co_name}: {e}", 3000)
            return

        if addr is False:
            self.statusBar().showMessage("\tCan't operate *, /")
            return

        self.addrInput.setText(addr)

        if is_readable_addr(addr) is False:
            # Refresh memory ranges just in case and if it's still not readable then return
            # set_mem_range('---')
            try:
                # On iOS in case frida's Process.enumerateRangesSync('---') doesn't show up every memory regions
                if gvar.frida_instrument.get_module_by_addr(addr) != '':
                    # There is a module
                    name = gvar.frida_instrument.get_module_by_addr(addr)['name']
                    size = int(gvar.frida_instrument.get_module_by_addr(addr)['base'], 16) + \
                           gvar.frida_instrument.get_module_by_addr(addr)['size'] - 1 - int(addr, 16)
                    if size < gvar.READ_MEM_SIZE:
                        result = gvar.frida_instrument.read_mem_addr(addr, size)
                    else:
                        result = gvar.frida_instrument.read_mem_addr(addr, gvar.READ_MEM_SIZE)

                    if self.is_palera1n and not self.is_cmd_pressed and not self.is_addr_in_mem_range_for_palera1n(
                            result):
                        self.statusBar().showMessage(f"\t{result['palera1n']}", 5000)
                        return

                    self.show_mem_result_on_viewer(name, addr, result)
                    return
                else:
                    # There is no module. but let's try to read small mem regions anyway
                    result = gvar.frida_instrument.read_mem_addr(addr, gvar.READ_MEM_SIZE / 2)

                    if self.is_palera1n and not self.is_cmd_pressed and not self.is_addr_in_mem_range_for_palera1n(
                            result):
                        self.statusBar().showMessage(f"\t{result['palera1n']}", 5000)
                        return

                    self.show_mem_result_on_viewer(None, addr, result)
                    return
            except Exception as e:
                self.statusBar().showMessage(f"\t{inspect.currentframe().f_code.co_name}: {e}", 3000)
                if str(e) == gvar.ERROR_SCRIPT_DESTROYED:
                    gvar.frida_instrument.sessions.clear()
                return

        try:
            if is_readable_addr(hex_calculator(f"{addr} + 1000")):
                size = size_to_read(addr)
                if size < gvar.READ_MEM_SIZE:
                    # Check there's an empty memory space between from address to (address + 0x2000).
                    # If then read maximum readable size
                    result = gvar.frida_instrument.read_mem_addr(addr, size)
                else:
                    result = gvar.frida_instrument.read_mem_addr(addr, gvar.READ_MEM_SIZE)
            else:
                size = size_to_read(addr)
                result = gvar.frida_instrument.read_mem_addr(addr, size)

            if self.is_palera1n and not self.is_cmd_pressed and not self.is_addr_in_mem_range_for_palera1n(result):
                self.statusBar().showMessage(f"\t{result['palera1n']}", 5000)
                return

            self.show_mem_result_on_viewer(None, addr, result)
            return

        except Exception as e:
            self.statusBar().showMessage(f"\t{inspect.currentframe().f_code.co_name}: {e}", 3000)
            if str(e) == gvar.ERROR_SCRIPT_DESTROYED:
                gvar.frida_instrument.sessions.clear()
            return

    def show_mem_result_on_viewer(self, name, addr, result):
        self.stop_or_restart_mem_refresh(0)

        # Empty the changed hex list before refreshing hexviewer
        gvar.hex_edited.clear()
        # Show the hex dump result
        hex_dump_result = result[result.find('\n') + 1:]
        self.hexViewer.setPlainText(hex_dump_result)
        # Adjust the label pos
        self.adjust_label_pos()

        if inspect.currentframe().f_back.f_code.co_name != "offset_ok_btn_func" and \
                gvar.frida_instrument.get_module_by_addr(addr) == '':
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
            # print("[main][show_mem_result_on_viewer] currentFrameBlockNumber: ", gvar.current_frame_block_number)
            # print("[main][show_mem_result_on_viewer] currentFrameStartAddress: ", gvar.current_frame_start_address)
            self.visited_addr()
            # Disassemble the result of hex dump
            self.disasm_worker.disassemble(gvar.arch, gvar.current_frame_start_address, hex_dump_result)
            # Restart refreshing memory
            self.stop_or_restart_mem_refresh(1)

            return

        if inspect.currentframe().f_back.f_code.co_name != "offset_ok_btn_func":
            self.set_status(gvar.frida_instrument.get_module_by_addr(addr)['name'])
            # Reset the address input area
            self.addrInput.clear()
        else:
            self.set_status(name)
            # Reset the offset input area
            self.offsetInput.clear()

        # Move the cursor
        if self.hexViewer.textCursor().positionInBlock() == 0:
            self.hexViewer.moveCursor(QTextCursor.MoveOperation.NextWord)
        # Set the initial currentFrameStartAddress
        gvar.current_frame_block_number = 0
        gvar.current_frame_start_address = "".join(
            ("0x", self.hexViewer.textCursor().block().text()[:self.hexViewer.textCursor().block().text().find(' ')]))
        # print("[main][show_mem_result_on_viewer] currentFrameBlockNumber: ", gvar.current_frame_block_number)
        # print("[main][show_mem_result_on_viewer] currentFrameStartAddress: ", gvar.current_frame_start_address)
        self.visited_addr()

        self.disasm_worker.disassemble(gvar.arch, gvar.current_frame_start_address, hex_dump_result)
        # Restart refreshing memory
        self.stop_or_restart_mem_refresh(1)

    # Remember the visited address
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

    def util_tab_bar_click_func(self, index):
        pass

    def parse_img_tab_bar_click_func(self, index):
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
                    self.statusBar().showMessage(f"\t{inspect.currentframe().f_code.co_name}: {e}", 3000)
                    return
            if len(result) > 0:
                for i in range(len(result) - 1):
                    text += result[i]['name'] + '\n'
                text += result[len(result) - 1]['name']
            self.parseImgListImgViewer.setPlainText(text)

    def status_tab_bar_click_func(self, index):
        # Status tab
        if index == 0:
            try:
                if gvar.frida_instrument is not None and not self.scan_result_view_worker.mem_scan_worker.isRunning():
                    gvar.frida_instrument.dummy_script()
            except Exception as e:
                if str(e) == gvar.ERROR_SCRIPT_DESTROYED:
                    gvar.frida_instrument.sessions.clear()
                self.statusBar().showMessage(f"\t{inspect.currentframe().f_code.co_name}: {e}", 3000)
                return
        # List img tab
        elif index == 1:
            text = ""
            result = []
            self.memDumpModuleName.setText('')
            if len(gvar.list_modules) > 0 and self.scan_result_view_worker.mem_scan_worker.isRunning():
                result = gvar.list_modules
            elif gvar.frida_instrument is not None and not self.scan_result_view_worker.mem_scan_worker.isRunning():
                try:
                    result = gvar.frida_instrument.list_modules()
                    gvar.list_modules = result
                except Exception as e:
                    if str(e) == gvar.ERROR_SCRIPT_DESTROYED:
                        gvar.frida_instrument.sessions.clear()
                    self.statusBar().showMessage(f"\t{inspect.currentframe().f_code.co_name}: {e}", 3000)
                    return
            if len(result) > 0:
                for i in range(len(result) - 1):
                    text += result[i]['name'] + '\n'
                text += result[len(result) - 1]['name']
            self.listImgViewer.setTextColor(self.default_color)
            self.listImgViewer.setPlainText(text)
        # Memory scan tab
        elif index == 2:
            self.scan_result_view_worker.show_scan_result_view()
            self.memScanPattern.setFocus()

    def hex_edit(self):
        if self.tabWidget.tabText(self.tabWidget.currentIndex()) == "Util":
            return
        # print(self.sender().__class__.__name__)
        if self.sender().__class__.__name__ == "QShortcut" or \
                (self.sender().__class__.__name__ != "QShortcut" and self.sender().text() == "Done"):
            if gvar.is_hex_edit_mode is True:
                # Resume mem refresh worker after hex edit done
                self.pause_or_resume_mem_refresh(1)

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
                        self.statusBar().showMessage(f"\t{inspect.currentframe().f_code.co_name}: {e}", 3000)
                        return
                print("[main][hex_edit] hex edited: ", gvar.hex_edited)

                # refresh mem range. it slows down hex edit func speed :(
                # set_mem_range('r--')

                # refresh hex viewer after patching
                tc = self.hexViewer.textCursor()
                final_pos_list = []
                for arr in gvar.hex_edited:
                    orig_pos = arr[4]
                    tc.setPosition(orig_pos, QTextCursor.MoveMode.MoveAnchor)
                    tc.movePosition(QTextCursor.MoveOperation.StartOfBlock, QTextCursor.MoveMode.MoveAnchor)
                    if tc.position() not in final_pos_list:
                        final_pos_list.append(tc.position())

                for final_pos in final_pos_list:
                    tc.setPosition(final_pos, QTextCursor.MoveMode.MoveAnchor)
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
                # If mem refresh worker is running, then pause it
                self.pause_or_resume_mem_refresh(0)

                self.hexViewer.setReadOnly(False)
                self.hexViewer.setTextInteractionFlags(
                    ~Qt.TextInteractionFlag.TextSelectableByKeyboard & ~Qt.TextInteractionFlag.TextSelectableByMouse)
                gvar.is_hex_edit_mode = True

    # Value <--> hex conversion
    def mem_scan_hex_checkbox(self, state):
        if (value := self.memScanPattern.toPlainText()) != '' and state == Qt.CheckState.Checked.value:
            value_regex = re.compile(r'^-?\d+(\.\d+)?$')
            scan_type = self.memScanTypeComboBox.currentText()
            if value_regex.match(value.replace(' ', '')) and scan_type != 'Array of Bytes' and \
                    scan_type != 'String':
                value = value.replace(' ', '')
                hex_value = misc.change_value_to_little_endian_hex(value, scan_type, 10)
                if 'Error' in hex_value:
                    self.statusBar().showMessage(hex_value, 3000)
                    print(f"[main][mem_scan_hex_checkbox] {hex_value}")
                    return
            elif scan_type == 'String':
                hex_value = misc.change_value_to_little_endian_hex(value, scan_type, 10)
            elif scan_type == 'Array of Bytes':
                hex_value = misc.hex_pattern_check(value)
                if 'Error' in hex_value:
                    self.statusBar().showMessage(hex_value, 3000)
                    print(f"[main][mem_scan_hex_checkbox] {hex_value}")
                    return
            else:
                self.statusBar().showMessage("\tWrong value", 3000)
                print(f"[main][mem_scan_hex_checkbox] Wrong value")
                return
            self.memScanPattern.setText(hex_value)
        elif (value := self.memScanPattern.toPlainText()) != '' and state != Qt.CheckState.Checked.value:
            if not re.search(r"(?![0-9a-fA-F?]).", value):
                value = misc.change_little_endian_hex_to_value(value, self.memScanTypeComboBox.currentText())
                if type(value) is str and 'Error' in value:
                    self.statusBar().showMessage(value, 3000)
                    print(f"[main][mem_scan_hex_checkbox] {value}")
                    return
                self.memScanPattern.setText(str(value))

    def mem_scan_type_combobox(self, curr_text):
        value = self.memScanPattern.toPlainText()
        if value != '' and self.memScanHexCheckBox.isChecked():
            if curr_text == 'String':
                value = bytes(value, 'utf-8').hex()
            else:
                value = misc.change_little_endian_hex_to_value(value, curr_text)
                value = misc.change_value_to_little_endian_hex(value, curr_text, 16)
            if type(value) is str and 'Error' in value:
                self.statusBar().showMessage(f"\t{value}", 3000)
                print(f"[main][mem_scan_type_combobox] {value}")
                return
            self.memScanPattern.setText(str(value))
        elif value != '' and not self.memScanHexCheckBox.isChecked():
            pass

        if curr_text == "Float" or curr_text == "Double":
            self.floatDoubleExactScanOptionRadioButton.setEnabled(True)
            self.floatDoubleRoundedScanOptionRadioButton.setEnabled(True)
        else:
            self.floatDoubleExactScanOptionRadioButton.setEnabled(False)
            self.floatDoubleRoundedScanOptionRadioButton.setEnabled(False)
            self.memScanHexCheckBox.setEnabled(True)

    def float_double_rounded_scan_option(self):
        if self.floatDoubleRoundedScanOptionRadioButton.isChecked():
            self.memScanHexCheckBox.setChecked(False)
            self.memScanHexCheckBox.setEnabled(False)
        else:
            self.memScanHexCheckBox.setEnabled(True)

    def mem_scan_target_img_pressed_func(self):
        if (module_name := self.memScanTargetImg.text()) != '':
            try:
                module: dict = gvar.frida_instrument.get_module_by_name(module_name)
            except Exception as e:
                self.statusBar().showMessage(f"\t{inspect.currentframe().f_code.co_name}: {e}", 3000)
                return
        else:
            module = {}

        if module:
            self.memScanTargetImg.setText(module['name'])
            self.memScanStartAddress.setText(module['base'])
            self.memScanEndAddress.setText(hex(int(module['base'], 16) + module['size'] - 1))
        else:
            self.memScanTargetImg.setText('')
            self.memScanStartAddress.setText('0000000000000000')
            self.memScanEndAddress.setText('00007fffffffffff')

    def mem_scan_target_img_checkbox(self, state):
        isChecked = state == Qt.CheckState.Checked.value
        self.memScanTargetImg.setEnabled(isChecked)

    def il2cpp_checkbox(self, state):
        isChecked = state == Qt.CheckState.Checked.value
        self.is_il2cpp_checked = isChecked
        self.memDumpModuleName.setEnabled(not isChecked)
        if isChecked:
            if self.parse_unity_dump_dialog is None:
                self.parse_unity_dump_dialog = parse_unity_dump.ParseUnityDumpFile()
                self.parse_unity_dump_dialog.platform = self.platform
                if self.parse_result_table_created_signal_connected is False:
                    self.parse_unity_dump_dialog.parse_result_table_created_signal.connect(
                        self.parse_result_table_create_sig_func)
                    self.parse_result_table_created_signal_connected = True
            if self.parse_unity_dump_dialog is not None and self.parse_unity_dump_dialog.parse_result is not None:
                self.parse_unity_dump_dialog.parse_unity_dump_file_dialog_ui.doParseBtn.setText('Show')
            self.parse_unity_dump_dialog.parse_unity_dump_file_dialog.show()

    def watch_mem_checkbox(self, state):
        isChecked = state == Qt.CheckState.Checked.value
        if isChecked and gvar.is_frida_attached:
            self.mem_refresh_worker = MemRefreshWorker()
            self.mem_refresh_worker.watch_memory_spin_box = self.watchMemorySpinBox
            if self.refresh_hexdump_result_signal_connected is False:
                gvar.frida_instrument.refresh_hexdump_result_signal.connect(self.mem_refresh_worker.refresh_hexdump_result_sig_func)
                self.refresh_hexdump_result_signal_connected = True
            self.mem_refresh_worker.update_hexdump_result_signal.connect(self.update_hexdump_result_sig_func)
            self.mem_refresh_worker.start()
        else:
            if self.mem_refresh_worker is not None:
                try:
                    self.mem_refresh_worker.update_hexdump_result_signal.disconnect()
                    self.mem_refresh_worker.quit()
                    gvar.frida_instrument.refresh_hexdump_result_signal.disconnect()
                    self.refresh_hexdump_result_signal_connected = False
                    gvar.frida_instrument.stop_mem_refresh()
                except Exception as e:
                    print(f"[main]{inspect.currentframe().f_code.co_name}: {e}")

    def pause_or_resume_mem_refresh(self, pause_or_resume: int):
        if pause_or_resume == 0:
            if self.watchMemoryCheckBox.isChecked() and self.mem_refresh_worker is not None and \
                    self.mem_refresh_worker.paused is False:
                # print(f"Pause mem refresh")
                self.mem_refresh_worker.pause()
        elif pause_or_resume == 1:
            if self.watchMemoryCheckBox.isChecked() and self.mem_refresh_worker is not None and \
                    self.mem_refresh_worker.paused is True:
                # print(f"Resume mem refresh")
                self.mem_refresh_worker.resume()

    def stop_or_restart_mem_refresh(self, stop_or_restart: int):
        if stop_or_restart == 0:
            if self.watchMemoryCheckBox.isChecked() and self.mem_refresh_worker is not None:
                try:
                    if gvar.frida_instrument.is_mem_refresh_on():
                        # print(f"Stop mem refresh")
                        gvar.frida_instrument.stop_mem_refresh()
                        if self.refresh_hexdump_result_signal_connected is True:
                            gvar.frida_instrument.refresh_hexdump_result_signal.disconnect()
                            self.refresh_hexdump_result_signal_connected = False
                except Exception as e:
                    pass
        elif stop_or_restart == 1:
            if self.watchMemoryCheckBox.isChecked() and self.mem_refresh_worker is not None:
                try:
                    if not gvar.frida_instrument.is_mem_refresh_on():
                        # print(f"Restart mem refresh")
                        gvar.frida_instrument.start_mem_refresh()
                        if self.refresh_hexdump_result_signal_connected is False:
                            gvar.frida_instrument.refresh_hexdump_result_signal.connect(
                                self.mem_refresh_worker.refresh_hexdump_result_sig_func)
                            self.refresh_hexdump_result_signal_connected = True
                except Exception as e:
                    pass

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
        # Il2cpp dump
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
                    self.statusBar().showMessage(f"\t{inspect.currentframe().f_code.co_name}: {e}", 3000)
                    return

            if self.il2cpp_frida_instrument is None or len(self.il2cpp_frida_instrument.sessions) == 0:
                if self.is_list_pid_checked:
                    target = self.attach_target_name_reserved
                elif gvar.frida_portal_mode:
                    target = self.attach_target_name
                else:
                    target = None
                self.il2cpp_frida_instrument = frida_code.Instrument("scripts/il2cpp-dump.js",
                                                               True if gvar.frida_portal_mode is True else self.is_remote_attach_checked,
                                                               gvar.frida_instrument.remote_addr,
                                                               target,
                                                               False)
                msg = self.il2cpp_frida_instrument.instrument("dump_module")
                if msg is not None:
                    QMessageBox.information(self, "info", msg)
                    return

            # Il2cpp dump thread worker start
            self.il2cpp_dump_worker = Il2CppDumpWorker(self.il2cpp_frida_instrument, self.statusBar())
            self.il2cpp_dump_worker.il2cpp_dump_signal.connect(self.il2cpp_dump_sig_func)
            self.il2cpp_dump_worker.start()
            self.memDumpBtn.setEnabled(False)
            return

        # Just normal module memory dump
        if self.platform is None:
            self.statusBar().showMessage("\tAttach first", 3000)
            return

        result = False
        if self.platform == 'darwin':
            frida_code.change_frida_script("scripts/dump-ios-module.js")
            result = gvar.frida_instrument.dump_ios_module(self.memDumpModuleName.text())
        elif self.platform == 'linux':
            frida_code.change_frida_script("scripts/dump-so.js")
            result = gvar.frida_instrument.dump_so(self.memDumpModuleName.text())

        if result is False:
            self.statusBar().showMessage("\tdump fail. try again", 3000)
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
        frida_code.revert_frida_script()

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
        if result is None:
            return

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
            # Caller function 찾기. https://stackoverflow.com/questions/900392/getting-the-caller-function-name-inside-another-function-in-python
            elif inspect.currentframe().f_back.f_code.co_name == "attach_frida":
                self.offsetInput.clear()
                self.addrInput.clear()
            # Show the function name if it can be found
            if name is not None and current_addr != "" and gvar.is_frida_attached:
                if (sym_name := gvar.frida_instrument.find_sym_name_by_addr(name, addr)) is not None:
                    current_addr += f"({sym_name})"
        except Exception as e:
            print(f"[main]{inspect.currentframe().f_code.co_name}: {e}")
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

    def get_file_from_device(self, file_path, output_path):
        self.get_file_from_device_worker = GetFileFromDeviceWorker(file_path, output_path)
        gvar.frida_instrument.get_file_from_device_signal.connect(
            self.get_file_from_device_worker.get_file_from_device_sig_func)
        self.get_file_from_device_worker.get_file_from_device_finished_signal.connect(
            self.get_file_from_device_finished_sig_func)
        self.get_file_from_device_worker.start()
        self.statusBar().showMessage(f"\tGetting the dumped file from the device...", 5000)

    def detach_frida(self):
        if gvar.frida_instrument is None:
            pass
        else:
            try:
                self.remote_addr = ''
                self.il2cpp_frida_instrument = None
                if self.hexViewer.watch_on_addr_widget is not None:
                    # self.hexViewer.watch_on_addr_widget.close()
                    self.hexViewer.watch_on_addr_widget.watch_list.clear()
                if self.utilViewer.pull_ipa_worker is not None:
                    self.utilViewer.pull_ipa_worker.quit()
                if self.history_view is not None:
                    row_count = self.history_view.history_ui.historyTableWidget.rowCount()
                    for i in range(row_count):
                        self.history_view.history_ui.historyTableWidget.setItem(i, 2, QTableWidgetItem(""))
                    # self.history_view.history_window.close()
                    # self.history_view.clear_table()
                if self.enum_ranges_view is not None:
                    self.enum_ranges_view.enum_ranges_window.close()
                    self.enum_ranges_view.enum_ranges_ui.enumRangesTableWidget.setRowCount(0)
                    self.enum_ranges_view.table_filled = False
                if self.mem_refresh_worker is not None and self.mem_refresh_worker.isRunning():
                    self.watchMemoryCheckBox.setChecked(False)
                self.scan_result_view_worker.mem_scan_func("New Scan")
                if self.scan_result_view_worker.mem_scan_worker is not None and \
                        self.scan_result_view_worker.mem_scan_worker.isRunning():
                    self.scan_result_view_worker.mem_scan_worker.quit()
                if self.scan_result_view_worker.mem_scan_signal_emit_worker is not None and \
                        self.scan_result_view_worker.mem_scan_signal_emit_worker.isRunning():
                    self.scan_result_view_worker.mem_scan_signal_emit_worker.quit()
                if self.parse_unity_dump_dialog is not None:
                    self.parse_result_table_created_signal_connected = False
                    self.method_clicked_signal_connected = False
                    if  self.parse_unity_dump_dialog.parse_result is not None:
                        self.parse_unity_dump_dialog.parse_result.il2cpp_base = None
                if self.get_file_from_device_worker is not None and self.get_file_from_device_worker.isRunning():
                    gvar.frida_instrument.get_file_from_device_signal.disconnect()
                    self.get_file_from_device_worker.get_file_from_device_finished_signal.disconnect()
                    self.get_file_from_device_worker.quit()

                self.memDumpBtn.setEnabled(True)
                self.statusBar().showMessage("\t")

                # self.scan_result_view_worker.scan_result_view_ui.\
                #     memScanResultTableWidget.watch_point_widget.unset_watchpoint()

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
                gvar.scan_matches.clear()
                gvar.scanned_value = None
            except Exception as e:
                self.statusBar().showMessage(f"\t{inspect.currentframe().f_code.co_name}: {e}", 5000)


if __name__ == "__main__":
    import sys

    # For windows taskbar icon. https://stackoverflow.com/a/1552105
    if platform.system() == "Windows":
        import ctypes

        myappid = 'com.main.mlviewer.2.0.0'  # arbitrary string
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)

    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon('icon/mlviewerico.png'))
    myWindow = WindowClass()
    myWindow.show()
    sys.exit(app.exec())
