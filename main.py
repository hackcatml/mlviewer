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
import globvar
import spawn
import ui
import ui_win
from disasm import DisassembleWorker
from history import HistoryViewClass


def is_readable_addr(addr):
    for i in range(len(globvar.enumerateRanges)):
        if int(globvar.enumerateRanges[i][0], 16) <= int(addr, 16) <= int(globvar.enumerateRanges[i][1], 16):
            return True
    return False


def size_to_read(addr):
    for i in range(len(globvar.enumerateRanges)):
        if int(globvar.enumerateRanges[i][0], 16) <= int(addr, 16) <= int(globvar.enumerateRanges[i][1], 16):
            return int(globvar.enumerateRanges[i][1], 16) - int(addr, 16)


def set_mem_range(prot):
    try:
        result = globvar.fridaInstrument.mem_enumerate_ranges(prot)
        # print("[hackcatml] mem_enumerate_ranges result: ", result)
    except Exception as e:
        print(e)
        return
    # enumerateRanges --> [(base, base + size - 1, prot, size), ... ]
    globvar.enumerateRanges.clear()
    for i in range(len(result)):
        globvar.enumerateRanges.append(
            (result[i]['base'], hex(int(result[i]['base'], 16) + result[i]['size'] - 1), result[i]['protection'],
             result[i]['size']))
    # print("[hackcatml] globvar.enumerateRanges: ", globvar.enumerateRanges)


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
    memscansig = QtCore.pyqtSignal(int)

    def __init__(self):
        super(MemScanWorker, self).__init__()

    def run(self) -> None:
        while True:
            self.memscansig.emit(0)
            if type(code.MESSAGE) is str and code.MESSAGE.find('[!] Memory Scan Done') != -1:
                # print(code.MESSAGE)
                self.memscansig.emit(1)
                break
            self.msleep(100)


class Il2CppDumpWorker(QThread):
    il2cppdumpsig = QtCore.pyqtSignal(str)

    def __init__(self, il2cppFridaInstrument, statusBar):
        super(Il2CppDumpWorker, self).__init__()
        self.il2cppFridaInstrument = il2cppFridaInstrument
        self.statusBar = statusBar

    def run(self) -> None:
        self.statusBar.showMessage("il2cpp dumping...stay")
        try:
            result = self.il2cppFridaInstrument.il2cpp_dump()
            if result is not None:
                self.il2cppdumpsig.emit(result)
        except Exception as e:
            if str(e) == globvar.errorType1:
                self.statusBar.showMessage(f"{e}...try again")
                self.il2cppFridaInstrument.sessions.clear()
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
        self.spawndialog = None
        self.gadgetBtn.clicked.connect(self.prepare_gadget)
        self.prepareGadgetDialog = None
        self.statusBar()
        self.statusLight = QLabel()
        self.set_status_light()
        self.memscanworker = MemScanWorker()
        self.memscanworker.memscansig.connect(self.memscansig_func)
        self.isil2cppchecked = None
        self.il2cppdumpworker = None
        self.il2cppFridaInstrument = None
        self.hexEditShortcut = QShortcut(QKeySequence(Qt.Key.Key_F2), self)
        self.ismemscanstrchecked = False
        self.isremoteattachchecked = False
        self.ismemsearchreplacechecked = False
        self.isspawnchecked = False
        self.ismemsearchwithimgchecked = False
        self.memReplaceBtn.setEnabled(False)
        self.memReplacePattern.setEnabled(False)
        self.hexViewer.wheelupsig.connect(self.wheelupsig_func)
        self.hexViewer.movesig.connect(self.movesig_func)
        self.hexViewer.refreshsig.connect(self.refreshsig_func)
        self.hexViewer.statusBar = self.statusBar()
        self.defaultcolor = QLabel().palette().color(QPalette.ColorRole.WindowText)
        self.listImgViewer.modulenamesig.connect(lambda sig: self.modulenamesig_func(sig, "listImgViewer"))
        self.parseImgListImgViewer.modulenamesig.connect(lambda sig: self.modulenamesig_func(sig, "parseImgListImgViewer"))
        self.memSearchResult.searchresultaddrsig.connect(self.searchresultaddrsig_func)
        self.arrangedresult = None
        self.arrangedresult2 = None
        self.platform = None
        self.islistpidchecked = False
        self.attachtargetname = None    # name to attach. need to provide on the AppList widget
        self.attachtargetnamereserved = None
        self.attachedname = None    # main module name after frida attached successfully
        self.spawntargetid = None   # target identifier to do frida spawn. need to provide on the AppList widget
        self.remoteaddr = ''
        self.memrefreshworker = None
        self.refreshCurrentAddressShortcut = QShortcut(QKeySequence(Qt.Key.Key_F3), self)
        self.refreshCurrentAddressShortcut.activated.connect(self.refresh_curr_addr)
        self.isPalera1n = False

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
        self.hexEditShortcut.activated.connect(self.hex_edit)

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
        self.disasm_worker.hexviewer = self.hexViewer
        self.disasm_worker.hexviewer.wheelsig.connect(self.disasm_worker.hexviewer_wheelsig_func)
        self.disasm_worker.hexviewer.scrollsig.connect(self.disasm_worker.hexviewer_scrollsig_func)
        self.disasm_worker.moveToThread(self.disasm_thread)
        self.disasm_thread.start()
        self.disassemBtnClickedCount = 0
        self.disassemBtn.clicked.connect(self.show_disassemble_result)

        self.history_view = HistoryViewClass()
        self.history_view.historyaddrsig.connect(self.history_addr_sig_func)
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
    def sig_func(self, onoffsig: int):
        if onoffsig:
            self.set_status_light()

    @pyqtSlot(int)
    def memscansig_func(self, memscansig: int):
        # mem scan progressing...
        if memscansig == 0:
            self.progressBar.setValue(globvar.scanProgressRatio)
        # mem scan completed
        if memscansig == 1:
            self.mem_scan_retrieve_result()
            self.memSearchBtn.setText("GO")

    @pyqtSlot(str)
    def wheelupsig_func(self, wheelupsig: str):
        # print(wheelupsig)
        if self.status_img_base.toPlainText() == hex_calculator(f"{wheelupsig}"):
            return
        addr = hex_calculator(f"{wheelupsig} - 10")
        # print(addr)
        self.addrInput.setText(addr)
        self.addr_btn_func()

    @pyqtSlot(int)
    def movesig_func(self, movesig: int):
        self.move_backward() if movesig == 0 else self.move_forward()

    @pyqtSlot(int)
    def refreshsig_func(self, refreshsig: int):
        if refreshsig:
            self.refresh_curr_addr()

    @pyqtSlot(str)
    def modulenamesig_func(self, modulenamesig: str, caller):
        if caller == "listImgViewer":
            self.memDumpModuleName.setText(modulenamesig)
        elif caller == "parseImgListImgViewer":
            self.parseImgName.setText(modulenamesig)

    @pyqtSlot(str)
    def searchresultaddrsig_func(self, searchresultaddrsig: str):
        self.addrInput.setText(searchresultaddrsig)
        self.addr_btn_func()

    @pyqtSlot(str)
    def targetsig_func(self, targetsig: str):
        if self.isspawnchecked:
            self.spawntargetid = targetsig
        else:
            self.attachtargetname = targetsig
            self.attachtargetnamereserved = targetsig
        if self.isremoteattachchecked is True:
            if re.search(r"^\d+\.\d+\.\d+\.\d+:\d+$", self.spawndialog.spawnui.remoteAddrInput.text()) is None:
                QMessageBox.information(self, "info", "Enter IP:PORT")
                self.spawntargetid = None
                self.attachtargetname = None
                return
            self.remoteaddr = self.spawndialog.spawnui.remoteAddrInput.text()
        self.attach_frida("targetsig_func")
        self.spawndialog = None
        self.spawntargetid = None
        self.attachtargetname = None
        self.remoteaddr = ''

    @pyqtSlot(str)
    def il2cppdumpsig_func(self, il2cppdumpsig: str):
        if il2cppdumpsig is not None:
            QThread.msleep(100)
            self.statusBar().showMessage("il2cpp Dump Done!", 5000)
            self.listImgViewer.moveCursor(QTextCursor.MoveOperation.Start, QTextCursor.MoveMode.MoveAnchor)
            self.listImgViewer.setTextColor(QColor("Red"))
            dir_to_save = os.getcwd() + "\\dump\\" if platform.system() == "Windows" else os.getcwd() + "/dump/"
            if self.isremoteattachchecked:
                os.system(f"frida-pull -H {self.il2cppFridaInstrument.remoteaddr} \"{il2cppdumpsig}\" {dir_to_save}")
            else:
                os.system(f"frida-pull -U \"{il2cppdumpsig}\" {dir_to_save}")
            self.listImgViewer.insertPlainText(f"Dumped file at: {dir_to_save}{il2cppdumpsig.split('/')[-1]}\n\n")
            self.listImgViewer.setTextColor(self.defaultcolor)
            # after il2cpp dump some android apps crash
            self.il2cppdumpworker.terminate()
            self.memDumpBtn.setEnabled(True)

    @pyqtSlot(int)
    def fridaattachsig_func(self, attach_sig: int):
        if attach_sig:
            globvar.isFridaAttached = True
            if self.isremoteattachchecked:
                globvar.remote = True
        else:
            globvar.isFridaAttached = False
            self.detach_frida()
        self.set_status_light()

    @pyqtSlot(list)
    def frida_portal_sig_func(self, nodeinfo: list):
        if nodeinfo:
            self.remoteaddr = "localhost"
            self.attachtargetname = nodeinfo[0]
            self.attach_frida("frida_portal_sig_func")

    @pyqtSlot(str)
    def history_addr_sig_func(self, addr: str):
        self.addrInput.setText(addr)
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
        self.islistpidchecked = state == Qt.CheckState.Checked.value

    def remote_attach(self, state):
        self.isremoteattachchecked = state == Qt.CheckState.Checked.value

    def spawn_mode(self, state):
        self.isspawnchecked = state == Qt.CheckState.Checked.value

    def prepare_gadget(self):
        try:
            self.prepareGadgetDialog = gadget.GadgetDialogClass()
            self.prepareGadgetDialog.fridaportalsig.connect(self.frida_portal_sig_func)
        except Exception as e:
            self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
            return

    def attach_frida(self, caller: str):
        if globvar.isFridaAttached is True:
            try:
                # check if script is still alive. if not exception will occur
                globvar.fridaInstrument.dummy_script()
                QMessageBox.information(self, "info", "Already attached")
            except Exception as e:
                self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
                globvar.fridaInstrument.sessions.clear()
            return

        try:
            if not caller == "frida_portal_sig_func":
                if (self.islistpidchecked and not self.isspawnchecked and self.attachtargetname is None) or \
                        (self.isspawnchecked and self.spawntargetid is None):
                    self.spawndialog = spawn.SpawnDialogClass()
                    if self.islistpidchecked and not self.isspawnchecked:
                        self.spawndialog.ispidlistchecked = True
                        self.spawndialog.spawnui.spawnTargetIdInput.setPlaceholderText("AppStore")
                        self.spawndialog.spawnui.appListLabel.setText("PID           Name")
                        self.spawndialog.spawnui.spawnBtn.setText("Attach")
                        self.spawndialog.attachtargetnamesig.connect(self.targetsig_func)

                    self.spawndialog.spawntargetidsig.connect(self.targetsig_func)

                    if self.isremoteattachchecked is False:
                        self.spawndialog.spawnui.remoteAddrInput.setEnabled(False)
                        self.spawndialog.spawnui.spawnTargetIdInput.setFocus()
                    else:
                        self.spawndialog.spawnui.remoteAddrInput.setFocus()
                    return

                if self.isremoteattachchecked and self.remoteaddr == '':
                    self.remoteaddr, ok = QInputDialog.getText(self, 'Remote Attach', 'Enter IP:PORT')
                    if ok is False:
                        return

                globvar.fridaInstrument = code.Instrument("scripts/default.js",
                                                          self.isremoteattachchecked,
                                                          self.remoteaddr,
                                                          self.attachtargetname if (self.islistpidchecked and not self.isspawnchecked) else self.spawntargetid,
                                                          self.isspawnchecked)
                # connect frida attach signal function
                globvar.fridaInstrument.attachsig.connect(self.fridaattachsig_func)
                msg = globvar.fridaInstrument.instrument(caller)
            elif caller == "frida_portal_sig_func":
                globvar.fridaInstrument = code.Instrument("scripts/default.js",
                                                          True,
                                                          self.remoteaddr,
                                                          self.attachtargetname,
                                                          False)
                # connect frida attach signal function
                globvar.fridaInstrument.attachsig.connect(self.fridaattachsig_func)
                msg = globvar.fridaInstrument.instrument(caller)

            self.remoteaddr = ''
        except Exception as e:
            self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
            return

        if msg is not None:
            QMessageBox.information(self, "info", msg)
            self.offsetInput.clear()
            return

        set_mem_range('r--')

        try:
            self.platform = globvar.fridaInstrument.platform()
            if self.platform == 'darwin':
                self.isPalera1n = globvar.fridaInstrument.is_palera1n()
            self.utilViewer.platform = self.platform
            globvar.arch = globvar.fridaInstrument.arch()
            name = globvar.fridaInstrument.list_modules()[0]['name']
            self.attachedname = name
            self.set_status(name)
        except Exception as e:
            print(e)
            return

    def detach_frida(self):
        if globvar.fridaInstrument is None:
            pass
        else:
            try:
                for session in globvar.fridaInstrument.sessions:
                    session.detach()
                globvar.fridaInstrument.sessions.clear()
                globvar.enumerateRanges.clear()
                globvar.hexEdited.clear()
                globvar.listModules.clear()
                globvar.arch = None
                globvar.isFridaAttached = False
                globvar.fridaInstrument = None
                globvar.visitedAddress.clear()
                globvar.fridaPortalMode = False
                self.remoteaddr = ''
                self.il2cppFridaInstrument = None
                if self.hexViewer.new_watch_widget is not None:
                    self.hexViewer.new_watch_widget.close()
                if self.utilViewer.pullIpaWorker is not None:
                    self.utilViewer.pullIpaWorker.quit()
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
            if globvar.isFridaAttached: globvar.fridaInstrument.force_read_mem_addr(True)
        else:
            if globvar.isFridaAttached: globvar.fridaInstrument.force_read_mem_addr(False)

        if caller == "returnPressed":
            self.offset_ok_btn_func()

    def offset_ok_btn_func(self):
        if globvar.isFridaAttached is False:
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
                result = globvar.fridaInstrument.read_mem_offset(name, offset, 8192)
            else:
                addr = hex_calculator(f"{self.status_img_base.toPlainText()} + {offset} + 2000")
                # check addr in mem regions
                if is_readable_addr(addr):
                    result = globvar.fridaInstrument.read_mem_offset(name, offset, 8192)
                else:
                    # not in mem regions. but check module existence
                    if globvar.fridaInstrument.get_module_name_by_addr(addr) != '':
                        # there is a module
                        size = int(globvar.fridaInstrument.get_module_name_by_addr(addr)['base'], 16) + \
                               globvar.fridaInstrument.get_module_name_by_addr(addr)['size'] - 1 - int(addr, 16)
                        if size < 8192:
                            result = globvar.fridaInstrument.read_mem_offset(name, offset, size)
                        else:
                            result = globvar.fridaInstrument.read_mem_offset(name, offset, 8192)
                    else:
                        # there is no module. just try to read
                        size = size_to_read(hex_calculator(f"{self.status_img_base.toPlainText()} + {offset}"))
                        if size is not None:
                            result = globvar.fridaInstrument.read_mem_offset(name, offset, size)
                        else:
                            result = globvar.fridaInstrument.read_mem_offset(name, offset, 4096)
        except Exception as e:
            self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
            if str(e) == globvar.errorType1:
                globvar.fridaInstrument.sessions.clear()
            return

        if self.isPalera1n and not self.is_cmd_pressed and not self.is_addr_in_mem_range_for_palera1n(result):
            self.statusBar().showMessage(f"{result['palera1n']}", 3000)
            return

        self.show_mem_result_on_viewer(name, None, result)

    def addr_btn_pressed_func(self, caller):
        self.is_cmd_pressed = QApplication.instance().keyboardModifiers() & (
                Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.MetaModifier)
        if self.is_cmd_pressed in (Qt.KeyboardModifier.ControlModifier, Qt.KeyboardModifier.MetaModifier):
            if globvar.isFridaAttached: globvar.fridaInstrument.force_read_mem_addr(True)
        else:
            if globvar.isFridaAttached: globvar.fridaInstrument.force_read_mem_addr(False)

        if caller == "returnPressed":
            self.addr_btn_func()

    def addr_btn_func(self):
        if globvar.isFridaAttached is False:
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
                func_addr = globvar.fridaInstrument.find_sym_addr_by_name(addr)
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
            # if is_readable_addr(addr) is False:
            try:
                # on iOS in case frida's Process.enumerateRangesSync('---') doesn't show up every memory regions
                if globvar.fridaInstrument.get_module_name_by_addr(addr) != '':
                    # there is a module
                    name = globvar.fridaInstrument.get_module_name_by_addr(addr)['name']
                    size = int(globvar.fridaInstrument.get_module_name_by_addr(addr)['base'], 16) + \
                           globvar.fridaInstrument.get_module_name_by_addr(addr)['size'] - 1 - int(addr, 16)
                    if size < 8192:
                        result = globvar.fridaInstrument.read_mem_addr(addr, size)
                    else:
                        result = globvar.fridaInstrument.read_mem_addr(addr, 8192)

                    if self.isPalera1n and not self.is_cmd_pressed and not self.is_addr_in_mem_range_for_palera1n(result):
                        self.statusBar().showMessage(f"{result['palera1n']}", 5000)
                        return

                    self.show_mem_result_on_viewer(name, addr, result)
                    return
                else:
                    # there is no module. but let's try to read small mem regions anyway
                    result = globvar.fridaInstrument.read_mem_addr(addr, 4096)

                    if self.isPalera1n and not self.is_cmd_pressed and not self.is_addr_in_mem_range_for_palera1n(result):
                        self.statusBar().showMessage(f"{result['palera1n']}", 5000)
                        return

                    self.show_mem_result_on_viewer(None, addr, result)
                    return
            except Exception as e:
                self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
                if str(e) == globvar.errorType1:
                    globvar.fridaInstrument.sessions.clear()
                return

        try:
            if is_readable_addr(hex_calculator(f"{addr} + 2000")):
                size = size_to_read(addr)
                if size < 8192:
                    # check there's an empty memory space between from address to (address + 0x2000).
                    # if then read maximum readable size
                    result = globvar.fridaInstrument.read_mem_addr(addr, size)
                else:
                    result = globvar.fridaInstrument.read_mem_addr(addr, 8192)
            else:
                size = size_to_read(addr)
                result = globvar.fridaInstrument.read_mem_addr(addr, size)

            if self.isPalera1n and not self.is_cmd_pressed and not self.is_addr_in_mem_range_for_palera1n(result):
                self.statusBar().showMessage(f"{result['palera1n']}", 5000)
                return

            self.show_mem_result_on_viewer(None, addr, result)
            return

        except Exception as e:
            self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
            if str(e) == globvar.errorType1:
                globvar.fridaInstrument.sessions.clear()
            return

    def show_mem_result_on_viewer(self, name, addr, result):
        # empty changed hex list before refresh hexviewer
        globvar.hexEdited.clear()
        # show hex dump result
        hex_dump_result = result[result.find('\n') + 1:]
        self.hexViewer.setPlainText(hex_dump_result)
        # adjust label pos
        self.adjust_label_pos()

        if inspect.currentframe().f_back.f_code.co_name != "offset_ok_btn_func" and \
                globvar.fridaInstrument.get_module_name_by_addr(addr) == '':
            self.status_img_name.clear()
            self.status_img_base.clear()
            self.status_size.clear()
            self.status_end.clear()
            self.status_path.clear()
            self.status_current.setPlainText(self.addrInput.text())
            self.addrInput.clear()

            globvar.currentFrameBlockNumber = 0
            globvar.currentFrameStartAddress = "".join(
                ("0x",
                 self.hexViewer.textCursor().block().text()[:self.hexViewer.textCursor().block().text().find(' ')]))
            # print("[hackcatml] currentFrameBlockNumber: ", globvar.currentFrameBlockNumber)
            # print("[hackcatml] currentFrameStartAddress: ", globvar.currentFrameStartAddress)
            self.visited_addr()
            # disassemble the result of hex dump
            self.disasm_worker.disassemble(globvar.arch, globvar.currentFrameStartAddress, hex_dump_result)
            return

        if inspect.currentframe().f_back.f_code.co_name != "offset_ok_btn_func":
            self.set_status(globvar.fridaInstrument.get_module_name_by_addr(addr)['name'])
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
        globvar.currentFrameBlockNumber = 0
        globvar.currentFrameStartAddress = "".join(
            ("0x", self.hexViewer.textCursor().block().text()[:self.hexViewer.textCursor().block().text().find(' ')]))
        # print("[hackcatml] currentFrameBlockNumber: ", globvar.currentFrameBlockNumber)
        # print("[hackcatml] currentFrameStartAddress: ", globvar.currentFrameStartAddress)
        self.visited_addr()

        self.disasm_worker.disassemble(globvar.arch, globvar.currentFrameStartAddress, hex_dump_result)

    # remember visited address
    def visited_addr(self):
        if len(inspect.stack()) > 3 and inspect.stack()[3].function == 'wheelupsig_func':
            return
        curr_addr = self.status_current.toPlainText()
        match = re.search(r'\(0x[a-fA-F0-9]+\)', curr_addr)
        visited_addr = curr_addr[:match.start()] if match is not None else curr_addr
        if visited_addr != '':
            if len(globvar.visitedAddress) == 0:
                globvar.visitedAddress.append(['last', visited_addr])
            else:
                last_visit_index = None
                for item in globvar.visitedAddress:
                    if item[0] == 'last':
                        last_visit_index = globvar.visitedAddress.index(item)
                if not any(sublist[1] == visited_addr for sublist in globvar.visitedAddress):
                    globvar.visitedAddress.append(['last', visited_addr])
                    if last_visit_index is not None:
                        globvar.visitedAddress[last_visit_index][0] = 'notlast'
                else:
                    revisit_index = None
                    # Find the index of the sublist to modify
                    for idx, sublist in enumerate(globvar.visitedAddress):
                        if sublist[1] == visited_addr and sublist[0] == 'notlast':
                            revisit_index = idx
                            break
                    # Modify the sublist if we found a matching index
                    if revisit_index is not None and (inspect.stack()[3].function != 'move_forward' and inspect.stack()[3].function != 'move_backward'):
                        revisit_addr_mark = globvar.visitedAddress[revisit_index][0]
                        revisit_addr = globvar.visitedAddress[revisit_index][1]
                        globvar.visitedAddress.remove([revisit_addr_mark, revisit_addr])
                        globvar.visitedAddress.append(['last', revisit_addr])
                        for idx, sublist in enumerate(globvar.visitedAddress):
                            if sublist[1] != revisit_addr and sublist[0] == 'last':
                                globvar.visitedAddress[idx][0] = 'notlast'
                                break
                    elif revisit_index is not None and (inspect.stack()[3].function == 'move_forward' or inspect.stack()[3].function == 'move_backward'):
                        globvar.visitedAddress[revisit_index][0] = 'last'
                        if revisit_index != last_visit_index:
                            globvar.visitedAddress[last_visit_index][0] = 'notlast'
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
            new_pos = (curr_pos + QPoint(480, -350)) if platform.system() == "Darwin" else (curr_pos + QPoint(490, -360))
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
            if globvar.fridaInstrument is not None:
                try:
                    result = globvar.fridaInstrument.list_modules()
                    globvar.listModules = result
                except Exception as e:
                    if str(e) == globvar.errorType1 or "'NoneType' object has no attribute" in str(e):
                        globvar.fridaInstrument.sessions.clear()
                        globvar.fridaInstrument = None
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
                if globvar.fridaInstrument is not None:
                    globvar.fridaInstrument.dummy_script()
            except Exception as e:
                if str(e) == globvar.errorType1:
                    globvar.fridaInstrument.sessions.clear()
                self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
                return
        # list img tab
        elif index == 1:
            text = ""
            result = []
            self.memDumpModuleName.setText('')
            if len(globvar.listModules) > 0 and self.memscanworker.isRunning():
                result = globvar.listModules
            elif globvar.fridaInstrument is not None:
                try:
                    result = globvar.fridaInstrument.list_modules()
                    globvar.listModules = result
                except Exception as e:
                    if str(e) == globvar.errorType1:
                        globvar.fridaInstrument.sessions.clear()
                    self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
                    return
            if len(result) > 0:
                for i in range(len(result) - 1):
                    text += result[i]['name'] + '\n'
                text += result[len(result) - 1]['name']
            self.listImgViewer.setTextColor(self.defaultcolor)
            self.listImgViewer.setPlainText(text)

    def is_hex_edited_from_search(self):
        tc = self.hexViewer.textCursor()
        finalposlist = []
        tc.movePosition(QTextCursor.MoveOperation.Start, QTextCursor.MoveMode.MoveAnchor)
        if re.search(r"1\. 0x[a-f0-9]+, module:", tc.block().text()):
            # print("[hackcatml] hex edited from search")
            for arr in globvar.hexEdited:
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
            if globvar.isHexEditMode is True:
                self.hexViewer.setReadOnly(True)
                if len(globvar.hexEdited) == 0:
                    globvar.isHexEditMode = False
                    return
                elif len(globvar.hexEdited) >= 1:
                    try:
                        globvar.fridaInstrument.write_mem_addr(globvar.hexEdited)
                    except Exception as e:
                        if str(e) == globvar.errorType1:
                            globvar.fridaInstrument.sessions.clear()
                            globvar.hexEdited.clear()
                        self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
                        return
                print("[hackcatml] hex edited: ", globvar.hexEdited)
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
                        result = globvar.fridaInstrument.read_mem_addr(
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
                    globvar.isHexEditMode = False
                    # empty changed hex list
                    globvar.hexEdited.clear()
                    # reset current frame block number
                    globvar.currentFrameBlockNumber = 0
                    # reset current global mem scan hex view variable
                    globvar.currentMemScanHexViewResult = self.hexViewer.toPlainText()
                    return

                # refresh hex viewer after patching
                tc = self.hexViewer.textCursor()
                finalposlist = []
                for arr in globvar.hexEdited:
                    origpos = arr[4]
                    tc.setPosition(origpos, QTextCursor.MoveMode.MoveAnchor)
                    tc.movePosition(QTextCursor.MoveOperation.StartOfBlock, QTextCursor.MoveMode.MoveAnchor)
                    if tc.position() not in finalposlist:
                        finalposlist.append(tc.position())

                for finalpos in finalposlist:
                    tc.setPosition(finalpos, QTextCursor.MoveMode.MoveAnchor)
                    # read mem addr after patching
                    result = globvar.fridaInstrument.read_mem_addr(
                        "".join(("0x", tc.block().text()[:tc.block().text().find(' ')])), 16)
                    # process read mem result
                    result = process_read_mem_result(result)
                    # replace text
                    tc.movePosition(QTextCursor.MoveOperation.EndOfBlock, QTextCursor.MoveMode.KeepAnchor)
                    tc.insertText(result)

                self.hexViewer.moveCursor(QTextCursor.MoveOperation.StartOfBlock, QTextCursor.MoveMode.MoveAnchor)
                self.hexViewer.moveCursor(QTextCursor.MoveOperation.NextWord, QTextCursor.MoveMode.MoveAnchor)
                globvar.isHexEditMode = False
                # empty changed hex list
                globvar.hexEdited.clear()
                # reset current frame block number
                # globvar.currentFrameBlockNumber = 0
                return

        if self.sender().__class__.__name__ == "QShortcut" or (
                self.sender().__class__.__name__ != "QShortcut" and self.sender().text() == "HexEdit"):
            if globvar.isHexEditMode is False:
                self.hexViewer.setReadOnly(False)
                self.hexViewer.setTextInteractionFlags(
                    ~Qt.TextInteractionFlag.TextSelectableByKeyboard & ~Qt.TextInteractionFlag.TextSelectableByMouse)
                globvar.isHexEditMode = True

    def hex_pattern_check(self, text: str):
        # memory scan pattern check
        if (pattern := text) == '':
            self.statusBar().showMessage("put some pattern", 3000)
            return None
        if self.ismemscanstrchecked:
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
                globvar.fridaInstrument.stop_mem_scan()
            except Exception as e:
                self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
                if str(e) == globvar.errorType1:
                    globvar.fridaInstrument.sessions.clear()
                self.memSearchBtn.setText("GO")
                return
            return
        # memory scan thread start
        self.memscanworker.start()
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
                if self.ismemsearchwithimgchecked is False:
                    result = globvar.fridaInstrument.mem_scan(globvar.enumerateRanges, pattern)
                    self.memSearchBtn.setText("STOP")
                # mem scan on a specific image
                elif self.ismemsearchwithimgchecked is True:
                    result = globvar.fridaInstrument.mem_scan_with_img(self.memSearchTargetImgInput.text(), pattern)
                    self.memSearchBtn.setText("STOP")
                    if result == 'module not found':
                        self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {result}", 3000)
                        self.memSearchBtn.setText("GO")
                        # self.memscanworker.terminate()
                        self.memscanworker.quit()
                        return False
                return True
        except Exception as e:
            self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
            # self.memscanworker.terminate()
            self.memscanworker.quit()
            try:
                globvar.fridaInstrument.stop_mem_scan()
            except Exception as err:
                self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {err}", 3000)
                if str(err) == globvar.errorType1:
                    globvar.fridaInstrument.sessions.clear()
                return False
            if str(e) == globvar.errorType1:
                globvar.fridaInstrument.sessions.clear()
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
                    globvar.fridaInstrument.mem_scan_and_replace(replacecode)
                    result = self.mem_search_func(searchpattern)
                    # refresh mem ranges
                    if result is True:
                        # set_mem_range('r--')
                        pass
        except Exception as e:
            self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
            # self.memscanworker.terminate()
            self.memscanworker.quit()
            if str(e) == globvar.errorType1:
                globvar.fridaInstrument.sessions.clear()
            return

    # this function retrieve above memory scan result and show it on the hexviewer
    def mem_scan_retrieve_result(self):
        # hmm...mem scan frida script sometimes sends the result multiple times.
        # so when it's empty, nothing to be appeared on the viewer
        tempresult = globvar.fridaInstrument.get_mem_scan_result()
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
            globvar.currentMemScanHexViewResult = self.arrangedresult
            self.memSearchResult.setText(self.arrangedresult2)
            self.memSearchFoundCount.setText(str(matchcount) + ' found')
            # terminate memory scan thread
            code.MESSAGE = ''
            # self.memscanworker.terminate()
            self.memscanworker.quit()

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
        self.ismemsearchwithimgchecked = isChecked
        self.memSearchTargetImgInput.setEnabled(isChecked)

    def mem_scan_pattern_checkbox(self, state):
        self.ismemscanstrchecked = state == Qt.CheckState.Checked.value

    def mem_search_replace_checkbox(self, state):
        isChecked = state == Qt.CheckState.Checked.value
        self.memReplaceBtn.setEnabled(isChecked)
        self.memReplacePattern.setEnabled(isChecked)
        self.ismemsearchreplacechecked = isChecked

    def il2cpp_checkbox(self, state):
        isChecked = state == Qt.CheckState.Checked.value
        self.isil2cppchecked = isChecked
        self.memDumpModuleName.setEnabled(not isChecked)

    def watch_mem_checkbox(self, state):
        isChecked = state == Qt.CheckState.Checked.value
        if isChecked and globvar.isFridaAttached:
            self.memrefreshworker = MemRefreshWorker()
            self.memrefreshworker.status_current = self.status_current
            self.memrefreshworker.addrInput = self.addrInput
            self.memrefreshworker.watchMemorySpinBox = self.watchMemorySpinBox
            self.memrefreshworker.update_signal.connect(self.addr_btn_func)
            self.memrefreshworker.start()
        else:
            if self.memrefreshworker is not None:
                self.memrefreshworker.terminate()

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

        if len(globvar.visitedAddress) > 0:
            for idx, sublist in enumerate(globvar.visitedAddress):
                if sublist[0] == 'last' and idx > 0:
                    addr_to_visit = globvar.visitedAddress[idx - 1][1]
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

        if len(globvar.visitedAddress) > 0:
            for idx, sublist in enumerate(globvar.visitedAddress):
                if sublist[0] == 'last' and idx < len(globvar.visitedAddress) - 1:
                    addr_to_visit = globvar.visitedAddress[idx + 1][1]
                    self.addrInput.setText(addr_to_visit)
                    self.addr_btn_func()
                    break

    def dump_module(self):
        # il2cpp dump
        if self.isil2cppchecked is True:
            if globvar.isFridaAttached is False:
                QMessageBox.information(self, "info", "Attach first")
                return
            elif globvar.isFridaAttached is True:
                try:
                    globvar.fridaInstrument.dummy_script()
                except Exception as e:
                    if str(e) == globvar.errorType1:
                        globvar.fridaInstrument.sessions.clear()
                    self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
                    return

            # print("[hackcatml] il2cppFridaInstrument: ", self.il2cppFridaInstrument)
            if self.il2cppFridaInstrument is None or len(self.il2cppFridaInstrument.sessions) == 0:
                self.il2cppFridaInstrument = code.Instrument("scripts/il2cppdump.js",
                                                             self.isremoteattachchecked,
                                                             globvar.fridaInstrument.remoteaddr,
                                                             self.attachtargetnamereserved if self.islistpidchecked else None,
                                                             False)
                msg = self.il2cppFridaInstrument.instrument("dump_module")
                if msg is not None:
                    QMessageBox.information(self, "info", msg)
                    return

            # il2cpp dump thread worker start
            self.il2cppdumpworker = Il2CppDumpWorker(self.il2cppFridaInstrument, self.statusBar())
            self.il2cppdumpworker.il2cppdumpsig.connect(self.il2cppdumpsig_func)
            self.il2cppdumpworker.start()
            self.memDumpBtn.setEnabled(False)
            return

        # just normal module memory dump
        if self.platform is None:
            self.statusBar().showMessage("Attach first", 3000)
            return

        result = False
        if self.platform == 'darwin':
            code.change_frida_script("scripts/dump-ios-module.js")
            result = globvar.fridaInstrument.dump_ios_module(self.memDumpModuleName.text())
        elif self.platform == 'linux':
            code.change_frida_script("scripts/dump-so.js")
            result = globvar.fridaInstrument.dump_so(self.memDumpModuleName.text())

        if result is False:
            self.statusBar().showMessage("dump fail. try again", 3000)
        else:
            self.listImgViewer.moveCursor(QTextCursor.MoveOperation.Start, QTextCursor.MoveMode.MoveAnchor)
            self.listImgViewer.setTextColor(QColor("Red"))
            dir_to_save = os.getcwd() + "\\dump\\" if platform.system() == "Windows" else os.getcwd() + "/dump/"
            if self.platform == 'darwin':
                if self.isremoteattachchecked:
                    os.system(f"frida-pull -H {globvar.fridaInstrument.remoteaddr} \"{result}\" {dir_to_save}")
                else:
                    os.system(f"frida-pull -U \"{result}\" {dir_to_save}")
                self.listImgViewer.insertPlainText(f"Dumped file at: {dir_to_save}{result.split('/')[-1]}\n\n")
            elif self.platform == 'linux':
                self.listImgViewer.insertPlainText(
                    'Dumped file at: ' + result + "\n\nYou need to fix so file using SoFixer\n\n")
            self.listImgViewer.setTextColor(self.defaultcolor)  # Revert to the default color
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
        if len(globvar.listModules) > 0:
            for module in globvar.listModules:
                if module['name'].lower().find(text_to_find) != -1:
                    # print(module['name'])
                    matched += module['name'] + '\n'
        viewer.setText(matched)

    def set_status(self, name):
        # print(inspect.currentframe().f_back.f_code.co_name)
        # print(inspect.stack()[0][3] + ':', name)
        result = globvar.fridaInstrument.module_status(name)
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
            if name is not None and current_addr != "" and globvar.isFridaAttached:
                if (sym_name := globvar.fridaInstrument.find_sym_name_by_addr(name, addr)) is not None:
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

        self.statusLight.setPixmap(officon)
        if globvar.isFridaAttached is True:
            self.statusLight.setPixmap(onicon)

        self.statusBar().removeWidget(self.statusLight)
        self.statusBar().addPermanentWidget(self.statusLight)
        self.statusLight.show()

    def eventFilter(self, obj, event):
        self.interested_widgets = [self.offsetInput, self.addrInput]
        if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Tab:
            try:
                if self.tabWidget.tabText(self.tabWidget.currentIndex()) == "Viewer" and self.tabWidget2.currentIndex() == 0:
                    self.interested_widgets.append(self.status_img_name)
                elif self.tabWidget.tabText(self.tabWidget.currentIndex()) == "Viewer" and self.tabWidget2.currentIndex() == 2:
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
        if self.prepareGadgetDialog is not None:
            self.prepareGadgetDialog.gadgetdialog.close()
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
