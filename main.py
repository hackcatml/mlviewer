import collections
import inspect
import platform
import re

from PyQt6 import QtCore
from PyQt6.QtCore import QThread, pyqtSlot, Qt, QEvent
from PyQt6.QtGui import QPixmap, QTextCursor, QShortcut, QKeySequence, QColor, QIcon, QPalette
from PyQt6.QtWidgets import QLabel, QMainWindow, QMessageBox, QApplication, QInputDialog

import code
import globvar
import spawn
import spawn_win
import ui
import ui_win


def change_frida_script(script_text):
    globvar.fridaInstrument.script_text = script_text
    globvar.fridaInstrument.script = globvar.fridaInstrument.sessions[0].create_script(
        globvar.fridaInstrument.read_frida_js_source())
    globvar.fridaInstrument.script.on('message', globvar.fridaInstrument.on_message)
    globvar.fridaInstrument.script.load()


def revert_frida_script():
    change_frida_script("scripts/default.js")


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


class Worker(QThread):
    sig = QtCore.pyqtSignal(int)

    def __init__(self):
        super(Worker, self).__init__()

    def run(self) -> None:
        while True:
            try:
                globvar.isFridaAttached = False
                if globvar.fridaInstrument is not None and len(globvar.fridaInstrument.sessions) != 0:
                    globvar.isFridaAttached = True
                self.sig.emit(1)
                # don't know why but while loop without sleep makes app freeze :(
                self.msleep(2000)
            except Exception as e:
                print(e)


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


class WindowClass(QMainWindow, ui.Ui_MainWindow if (platform.system() == 'Darwin') else ui_win.Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.spawndialog = None
        self.setupUi(self)
        self.statusBar()
        self.statusLight = QLabel()
        self.set_status_light()
        self.worker = Worker()
        self.worker.start()
        self.worker.sig.connect(self.sig_func)
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
        self.defaultcolor = QLabel().palette().color(QPalette.ColorRole.WindowText)
        self.listImgViewer.modulenamesig.connect(self.modulenamesig_func)
        self.memSearchResult.searchresultaddrsig.connect(self.searchresultaddrsig_func)
        self.arrangedresult = None
        self.arrangedresult2 = None
        self.platform = None
        self.spawntargetid = None
        self.remoteaddr = ''

        self.attachBtn.clicked.connect(self.attach_frida)
        self.detachBtn.clicked.connect(self.detach_frida)
        self.offsetOkbtn.clicked.connect(self.offset_ok_btn_func)
        self.offsetInput.returnPressed.connect(self.offset_ok_btn_func)
        self.status_img_name.returnPressed.connect(self.offset_ok_btn_func)
        self.addrInput.returnPressed.connect(self.addr_btn_func)
        self.addrBtn.clicked.connect(self.addr_btn_func)
        self.tabWidget2.tabBarClicked.connect(self.status_tab_bar_click_func)
        # hexviewer text changed event
        self.hexViewer.textChanged.connect(self.text_changed)
        self.hexEditBtn.clicked.connect(self.hex_edit)
        self.hexEditDoneBtn.clicked.connect(self.hex_edit)
        self.hexEditShortcut.activated.connect(self.hex_edit)
        self.memSearchBtn.clicked.connect(self.mem_search_func)
        self.memReplaceBtn.clicked.connect(self.mem_search_replace_func)
        self.memSearchTargetImgCheckBox.stateChanged.connect(self.mem_search_with_img_checkbox)
        self.memScanPatternTypeCheckBox.stateChanged.connect(self.mem_scan_pattern_checkbox)
        self.attachTypeCheckBox.stateChanged.connect(self.remote_attach)
        self.spawnModeCheckBox.stateChanged.connect(self.spawn_mode)
        self.memSearchReplaceCheckBox.stateChanged.connect(self.mem_search_replace_checkbox)
        self.memDumpBtn.clicked.connect(self.dump_module)
        self.memDumpModuleName.returnPressed.connect(self.dump_module)
        self.memDumpModuleName.textChanged.connect(self.search_img)
        self.searchMemSearchResult.textChanged.connect(self.search_mem_search_result)
        self.unityCheckBox.stateChanged.connect(self.il2cpp_checkbox)

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
        addr = hex_calculator(f"{wheelupsig} - 10")
        # print(addr)
        self.addrInput.setText(addr)
        self.addr_btn_func()

    @pyqtSlot(str)
    def modulenamesig_func(self, modulenamesig: str):
        self.memDumpModuleName.setText(modulenamesig)

    @pyqtSlot(str)
    def searchresultaddrsig_func(self, searchresultaddrsig: str):
        self.addrInput.setText(searchresultaddrsig)
        self.addr_btn_func()

    @pyqtSlot(str)
    def spawntargetsig_func(self, spawntargetidsig: str):
        self.spawntargetid = spawntargetidsig
        if self.isremoteattachchecked is True:
            if re.search(r"^\d+\.\d+\.\d+\.\d+:\d+$", self.spawndialog.spawnui.remoteAddrInput.text()) is None:
                QMessageBox.information(self, "info", "Enter IP:PORT")
                self.spawntargetid = None
                return
            self.remoteaddr = self.spawndialog.spawnui.remoteAddrInput.text()
        self.attach_frida()
        self.spawndialog = None
        self.spawntargetid = None
        self.remoteaddr = ''

    @pyqtSlot(str)
    def il2cppdumpsig_func(self, il2cppdumpsig: str):
        if il2cppdumpsig is not None:
            self.statusBar().showMessage("il2cpp Dump Done!", 5000)
            self.listImgViewer.moveCursor(QTextCursor.MoveOperation.Start, QTextCursor.MoveMode.MoveAnchor)
            self.listImgViewer.setTextColor(QColor("Red"))
            self.listImgViewer.insertPlainText("Dumped file at: " + il2cppdumpsig + "\n\n")
            self.listImgViewer.setTextColor(self.defaultcolor)
            # after il2cpp dump some android apps crash
            self.il2cppdumpworker.terminate()

    def adjust_label_pos(self):
        tc = self.hexViewer.textCursor()
        self.label_3.setIndent(28 - (77 - len(tc.block().text())) * 7) if len(
            tc.block().text()) < 77 else self.label_3.setIndent(28)

    def remote_attach(self, state):
        if state == Qt.CheckState.Checked.value:
            self.isremoteattachchecked = True
        else:
            self.isremoteattachchecked = False

    def spawn_mode(self, state):
        if state == Qt.CheckState.Checked.value:
            self.isspawnchecked = True
        else:
            self.isspawnchecked = False

    def attach_frida(self):
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
            if self.isspawnchecked and self.spawntargetid is None:
                self.spawndialog = spawn.SpawnDialogClass() if (
                        platform.system() == 'Darwin') else spawn_win.SpawnDialogClass()
                self.spawndialog.spawntargetidsig.connect(self.spawntargetsig_func)

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

            globvar.fridaInstrument = code.Instrument("scripts/default.js", self.isremoteattachchecked, self.remoteaddr,
                                                      self.spawntargetid)
            msg = globvar.fridaInstrument.instrument()
            self.remoteaddr = ''
        except Exception as e:
            self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
            return

        if msg is not None:
            QMessageBox.information(self, "info", msg)
            self.offsetInput.clear()
            return

        set_mem_range('---')

        self.platform = globvar.fridaInstrument.platform()
        name = globvar.fridaInstrument.list_modules()[0]['name']
        self.set_status(name)

    def detach_frida(self):
        try:
            for session in globvar.fridaInstrument.sessions:
                session.detach()
            globvar.fridaInstrument.sessions.clear()
            globvar.enumerateRanges.clear()
            globvar.hexEdited.clear()
            globvar.listModules.clear()
            self.remoteaddr = ''
            self.il2cppFridaInstrument = None
        except Exception as e:
            self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)

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
                    # check module existence
                    if globvar.fridaInstrument.get_module_name_by_addr(addr) is not None:
                        # there is a module
                        size = int(globvar.fridaInstrument.get_module_name_by_addr(addr)['base'], 16) + \
                               globvar.fridaInstrument.get_module_name_by_addr(addr)['size'] - 1 - int(addr, 16)
                        if size < 8192:
                            result = globvar.fridaInstrument.read_mem_offset(name, offset, size)
                        else:
                            result = globvar.fridaInstrument.read_mem_offset(name, offset, 8192)
                    else:
                        size = size_to_read(hex_calculator(f"{self.status_img_base.toPlainText()} + {offset}"))
                        result = globvar.fridaInstrument.read_mem_offset(name, offset, size)
        except Exception as e:
            self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
            if str(e) == globvar.errorType1:
                globvar.fridaInstrument.sessions.clear()
            return

        self.show_mem_result_on_viewer(name, None, result)

    def addr_btn_func(self):
        if globvar.isFridaAttached is False:
            QMessageBox.information(self, "info", "Attach first")
            self.addrInput.clear()
            return

        addr = self.addrInput.text()
        hex_regex = re.compile(r'(\b0x[a-fA-F0-9]+\b|\b[a-fA-F0-9]{6,}\b)')
        match = hex_regex.match(addr)
        # in case it's not a hex expression on addrInput field. for example "fopen", "sysctl", ...
        if match is None:
            try:
                func_addr = globvar.fridaInstrument.find_sym_addr_by_name(addr)
                if func_addr is None:
                    self.statusBar().showMessage(f"cannot find address for {addr}", 3000)
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
            self.statusBar().showMessage("can't operate *, /")
            return

        self.addrInput.setText(addr)

        if is_readable_addr(addr) is False:
            # refresh memory ranges just in case and if it's still not readable then return
            # set_mem_range('---')
            # if is_readable_addr(addr) is False:
            try:
                # on iOS in case frida's Process.enumerateRangesSync('---') doesn't show up every memory regions
                if globvar.fridaInstrument.get_module_name_by_addr(addr) is not None:
                    # there is a module
                    size = int(globvar.fridaInstrument.get_module_name_by_addr(addr)['base'], 16) + \
                           globvar.fridaInstrument.get_module_name_by_addr(addr)['size'] - 1 - int(addr, 16)
                    if size < 8192:
                        result = globvar.fridaInstrument.read_mem_addr(addr, size)
                    else:
                        result = globvar.fridaInstrument.read_mem_addr(addr, 8192)
                    self.show_mem_result_on_viewer(None, addr, result)
                    return
                else:
                    # there is no module. but let's try to read it anyway
                    result = globvar.fridaInstrument.read_mem_addr(addr, 8192)
                    self.show_mem_result_on_viewer(None, addr, result)
                    return
            except Exception as e:
                self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
                if str(e) == globvar.errorType1:
                    globvar.fridaInstrument.sessions.clear()
                return

            # self.statusBar().showMessage(f"{addr} is not readable. access violation", 3000)
            # return

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
        self.hexViewer.setPlainText(result[result.find('\n') + 1:])
        # adjust label pos
        self.adjust_label_pos()

        if inspect.currentframe().f_back.f_code.co_name != "offset_ok_btn_func" and \
                globvar.fridaInstrument.get_module_name_by_addr(addr) is None:
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

    def status_tab_bar_click_func(self, index):
        # status tab
        if index == 0:
            try:
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
            self.listImgViewer.setPlainText(text)

    def text_changed(self):
        tc = self.hexViewer.textCursor()
        tcx = tc.positionInBlock()
        # print("[hackcatml] text changed: " + tc.block().text())
        # if tc.block().text() == "", index out of error occurs so need to return
        if tc.block().text() == "": return
        indices = [i for i, x in enumerate(tc.block().text()) if x == " "]
        hexstart = indices[1] + 1

        # print("[hackcatml] (tcx - hexstart) // 3 = ", (tcx - hexstart) // 3)
        if (tcx - hexstart) // 3 < 0 or (tcx - hexstart) // 3 > 15: return

        addr = hex(int(tc.block().text()[:tc.block().text().find(" ")], 16) + (tcx - hexstart) // 3)
        # print("[hackcatml] text changed addr: ", addr)

        changed = tc.block().text()[3 * ((tcx - hexstart) // 3) + hexstart: 3 * ((tcx - hexstart) // 3) + hexstart + 2]
        changed = "".join(("0x", changed))
        # print("[hackcatml] changed hex: ", changed)

        pos = tc.position()

        try:
            orig = globvar.fridaInstrument.read_mem_addr(addr, 1)
            index = orig.find("\n")
            index = index + orig[index:].find(' ') + 2
            orig = orig[index: index + 2]
            orig = "".join(("0x", orig))
            if changed == orig or len(changed.replace('0x', '').strip()) == 1 or re.search(r"(?![0-9a-fA-F]).",
                                                                                           changed.replace('0x', '')):
                return
        except Exception as e:
            if str(e) == globvar.errorType1:
                globvar.fridaInstrument.sessions.clear()
            return

        prot = '---'
        for i in range(len(globvar.enumerateRanges)):
            if int(globvar.enumerateRanges[i][0], 16) <= int(addr, 16) <= int(globvar.enumerateRanges[i][1], 16):
                prot = globvar.enumerateRanges[i][2]

        for i in range(len(globvar.hexEdited)):
            if addr in globvar.hexEdited[i]:
                globvar.hexEdited[i][1] = changed
                globvar.hexEdited[i][2] = orig
                globvar.hexEdited[i][3] = prot
                globvar.hexEdited[i][4] = pos
                return

        globvar.hexEdited.append([addr, changed, orig, prot, pos])
        # print(f"text changed pos: {tcx}")

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
        # print(self.sender().__class__.__name__)
        if self.sender().__class__.__name__ == "QShortcut" or (
                self.sender().__class__.__name__ != "QShortcut" and self.sender().text()) == "Done":
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
        if state == Qt.CheckState.Checked.value:
            self.ismemsearchwithimgchecked = True
            self.memSearchTargetImgInput.setEnabled(True)
        else:
            self.ismemsearchwithimgchecked = False
            self.memSearchTargetImgInput.setEnabled(False)

    def mem_scan_pattern_checkbox(self, state):
        if state == Qt.CheckState.Checked.value:
            self.ismemscanstrchecked = True
        else:
            self.ismemscanstrchecked = False

    def mem_search_replace_checkbox(self, state):
        if state == Qt.CheckState.Checked.value:
            self.memReplaceBtn.setEnabled(True)
            self.memReplacePattern.setEnabled(True)
            self.ismemsearchreplacechecked = True
        else:
            self.memReplaceBtn.setEnabled(False)
            self.memReplacePattern.setEnabled(False)
            self.ismemsearchreplacechecked = False

    def il2cpp_checkbox(self, state):
        if state == Qt.CheckState.Checked.value:
            self.isil2cppchecked = True
            self.memDumpModuleName.setEnabled(False)
        else:
            self.isil2cppchecked = False
            self.memDumpModuleName.setEnabled(True)

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
                self.il2cppFridaInstrument = code.Instrument("scripts/il2cppdump.js", self.isremoteattachchecked,
                                                             globvar.fridaInstrument.remoteaddr, None)
                msg = self.il2cppFridaInstrument.instrument()
                if msg is not None:
                    QMessageBox.information(self, "info", msg)
                    return
            # il2cpp dump thread worker start
            self.il2cppdumpworker = Il2CppDumpWorker(self.il2cppFridaInstrument, self.statusBar())
            self.il2cppdumpworker.il2cppdumpsig.connect(self.il2cppdumpsig_func)
            self.il2cppdumpworker.start()
            return

        # just normal module memory dump
        if self.platform is None:
            self.statusBar().showMessage("Attach first", 3000)
            return

        result = False
        if self.platform == 'darwin':
            change_frida_script("scripts/dump-ios-module.js")
            result = globvar.fridaInstrument.dump_ios_module(self.memDumpModuleName.text())
        elif self.platform == 'linux':
            change_frida_script("scripts/dump-so.js")
            result = globvar.fridaInstrument.dump_so(self.memDumpModuleName.text())

        if result is False:
            self.statusBar().showMessage("dump fail. try again", 3000)
        else:
            self.listImgViewer.moveCursor(QTextCursor.MoveOperation.Start, QTextCursor.MoveMode.MoveAnchor)
            self.listImgViewer.setTextColor(QColor("Red"))
            if self.platform == 'darwin':
                self.listImgViewer.insertPlainText('Dumped file at: ' + result + "\n\n")
            elif self.platform == 'linux':
                self.listImgViewer.insertPlainText(
                    'Dumped file at: ' + result + "\n\nYou need to fix so file using SoFixer\n\n")
            self.listImgViewer.setTextColor(self.defaultcolor)  # Revert to the default color
        revert_frida_script()

    def search_img(self):
        # print(self.memDumpModuleName.text())
        matched = ''
        if len(globvar.listModules) > 0:
            for module in globvar.listModules:
                if module['name'].lower().find(self.memDumpModuleName.text().lower()) != -1:
                    # print(module['name'])
                    matched += module['name'] + '\n'
        self.listImgViewer.setText(matched)

    def set_status(self, name):
        # print(inspect.currentframe().f_back.f_code.co_name)
        # print(inspect.stack()[0][3] + ':', name)
        result = globvar.fridaInstrument.module_status(name)
        if result is None: return

        self.status_img_name.setText(result['name'])
        self.status_img_base.setPlainText(result['base'])

        offsetinput = self.offsetInput.text()
        if inspect.stack()[2].function == "addr_btn_func":
            offsetinput = self.addrInput.text()

        if offsetinput.startswith('0x') is False:
            offsetinput = "".join(("0x0", offsetinput))
        current_addr = hex(int(result['base'], 16) + int(offsetinput, 16)) + f"({offsetinput})"
        if inspect.stack()[2].function == "addr_btn_func":
            current_addr = hex(int(offsetinput, 16)) + f"({hex(int(offsetinput, 16) - int(result['base'], 16))})"

        # caller function 찾기. https://stackoverflow.com/questions/900392/getting-the-caller-function-name-inside-another-function-in-python
        if inspect.currentframe().f_back.f_code.co_name == "attach_frida":
            current_addr = ""

        self.status_current.setPlainText(current_addr)

        self.status_size.setPlainText(str(result['size']))
        self.status_end.setPlainText(hex(int(result['base'], 16) + result['size']))

        self.status_path.setPlainText(result['path'])

    def set_status_light(self):
        onicon = QPixmap("icon/greenlight.png").scaledToHeight(round(self.statusBar().height() // 2))
        officon = QPixmap("icon/redlight.png").scaledToHeight(round(self.statusBar().height() // 2))

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
                if self.tabWidget2.currentIndex() == 0:
                    self.interested_widgets.append(self.status_img_name)
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
    app.exec()
