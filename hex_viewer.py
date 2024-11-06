import inspect
import platform
import re

from PyQt6 import QtGui, QtCore
from PyQt6.QtCore import Qt, pyqtSlot, QEvent, QObject
from PyQt6.QtGui import QTextCursor, QAction, QCursor
from PyQt6.QtWidgets import QTextEdit, QApplication, QWidget, QVBoxLayout, QSlider, QLabel, QHBoxLayout, QPushButton, \
    QCheckBox, QWidgetAction, QLineEdit

import gvar
import misc


def get_hex_code(tc, pos, tcx, tcy, block_text, hex_start, caller):
    if caller == "text_changed_event" and pos is not None:
        tc.setPosition(pos, QTextCursor.MoveMode.MoveAnchor)
        tcx = tc.positionInBlock()
        block_text = tc.block().text()
        # addr = hex(int(block_text[:block_text.find(" ")], 16) + (tcx - hex_start) // 3)

    cursor_len_4bytes = 12
    cursor_len_8bytes = 12 * 2
    hex_code = None
    if tcx in [hex_start, hex_start + 1, hex_start + 2]:
        if caller == 'copy_pointer':
            hex_code = block_text[hex_start:hex_start + cursor_len_8bytes - 1] if gvar.arch == "arm64" else \
                    block_text[hex_start:hex_start + cursor_len_4bytes - 1]
        else:
            hex_code = block_text[hex_start:hex_start + cursor_len_8bytes - 1]
    elif tcx in [hex_start + cursor_len_4bytes, hex_start + cursor_len_4bytes + 1, hex_start + cursor_len_4bytes + 2]:
        hex_code = block_text[
                   hex_start + cursor_len_4bytes:hex_start + cursor_len_4bytes + cursor_len_8bytes - 1]
    elif tcx in [hex_start + cursor_len_8bytes, hex_start + cursor_len_8bytes + 1, hex_start + cursor_len_8bytes + 2]:
        if caller == 'copy_pointer':
            hex_code = block_text[hex_start + cursor_len_8bytes:hex_start + 2 * cursor_len_8bytes - 1] if gvar.arch == "arm64" else \
                block_text[hex_start + cursor_len_8bytes:hex_start + 3 * cursor_len_4bytes - 1]
        else:
            hex_code = block_text[hex_start + cursor_len_8bytes:hex_start + 2 * cursor_len_8bytes - 1]
    elif tcx in [hex_start + 3 * cursor_len_4bytes, hex_start + 3 * cursor_len_4bytes + 1,
                 hex_start + 3 * cursor_len_4bytes + 2]:
        hex_code = block_text[hex_start + 3 * cursor_len_4bytes:hex_start + 4 * cursor_len_4bytes - 1]
    addr = hex(int(block_text[:block_text.find(" ")], 16) + (tcx - hex_start) // 3)
    return [addr, hex_code]


# A signal manager for a class that cannot send signals to the main class or other classes
class HexViewerSignalManager(QObject):
    backtrace_text_edit_backtrace_addr_clicked_signal = QtCore.pyqtSignal(str)
    close_backtrace_signal = QtCore.pyqtSignal()


class HexViewerClass(QTextEdit):
    wheel_up_signal = QtCore.pyqtSignal(str)
    wheel_signal = QtCore.pyqtSignal(str)
    scroll_signal = QtCore.pyqtSignal(int)
    move_signal = QtCore.pyqtSignal(int)
    refresh_signal = QtCore.pyqtSignal(int)
    watch_list_signal = QtCore.pyqtSignal(list)
    mem_patch_addr_signal = QtCore.pyqtSignal(str)
    set_watchpoint_addr_signal = QtCore.pyqtSignal(str)

    def __init__(self, args):
        super(HexViewerClass, self).__init__(args)
        self.hit_count = 0
        self.verticalScrollBar().sliderMoved.connect(self.setScrollBarPos)
        self.statusBar = None
        self.watch_on_addr_widget = WatchOnAddrWidget()
        self.watch_on_addr_widget.watch_on_addr_widget_close_event_signal.connect(self.watch_on_addr_widget_close_event_sig_func)
        # Hexviewer text changed event
        self.textChanged.connect(self.text_changed_event)

        self.hex_code_read_widget = None
        self.hex_code_read_tc = None
        self.hex_code_read_pos = None
        self.hex_code_read_tcx = None
        self.hex_code_read_tcy = None
        self.hex_code_read_block_text = None
        self.hex_code_read_hex_start = None

    @pyqtSlot(str)
    def message_sig_func(self, sig: str):
        # print(f"[hex_viewer] watching...{sig}")
        # Append the new message to the text edit
        line_count = self.watch_on_addr_widget.text_edit.document().lineCount()
        if line_count > 1000:
            self.watch_on_addr_widget.text_edit.clear()
        self.watch_on_addr_widget.text_edit.append(sig)

    @pyqtSlot(str)
    def set_watch_func_sig_func(self, sig: str):
        self.set_watch_on_addr("watch_func", sig, "set_watch_func_sig_func")

    @pyqtSlot(str)
    def set_watch_regs_sig_func(self, sig: str):
        self.set_watch_on_addr("watch_regs", sig, "set_watch_regs_sig_func")

    @pyqtSlot(str)
    def history_remove_row_sig_func(self, sig: str):    # sig: item's text
        # Detach All --> re-attach
        try:
            gvar.frida_instrument.detach_all()
            gvar.hex_viewer_signal_manager.close_backtrace_signal.emit()
        except Exception as e:
            print(f"[hex_viewer] {inspect.currentframe().f_code.co_name}: {e}")
            return

        self.watch_on_addr_widget.watch_list = [item for item in self.watch_on_addr_widget.watch_list if item[0] != sig]
        if self.watch_on_addr_widget.watch_list:
            for item in self.watch_on_addr_widget.watch_list:
                self.set_watch_on_addr("watch_func" if item[1] is False else "watch_regs", item[0],
                                       "history_remove_row_sig_func")

    @pyqtSlot()
    def watch_on_addr_widget_close_event_sig_func(self):
        self.watch_list_signal.emit(self.watch_on_addr_widget.watch_list)

    def setScrollBarPos(self, value):
        # print("[hackcatml] slidermoved: ", value)
        self.scroll_signal.emit(value)
        gvar.current_frame_block_number = round(value / 15)

    # Wheelevent https://spec.tistory.com/449
    def wheelEvent(self, e: QtGui.QWheelEvent) -> None:
        delta = e.angleDelta().y()
        # wheel down
        if delta < 0:
            gvar.current_frame_block_number += -1 * delta / 120 * 4
        # wheel up
        elif delta > 0 and gvar.current_frame_block_number > 0:
            gvar.current_frame_block_number -= delta / 120 * 4

        tc = self.textCursor()
        tc.movePosition(QTextCursor.MoveOperation.Start, QTextCursor.MoveMode.MoveAnchor, 1)
        tc.movePosition(QTextCursor.MoveOperation.Down, QTextCursor.MoveMode.MoveAnchor, int(gvar.current_frame_block_number))
        gvar.current_frame_start_address = "".join(("0x", tc.block().text()[:tc.block().text().find(' ')]))

        if tc.blockNumber() == 0 and re.search(r"\d+\. 0x[0-9a-f]+, module:", tc.block().text()) is None:
            self.hit_count += 1
            if self.hit_count > 0 and delta > 0:
                self.wheel_up_signal.emit(gvar.current_frame_start_address)
                self.hit_count = 0
        elif re.search(r"\d+\. 0x[0-9a-f]+, module:", tc.block().text()) is None:
            self.wheel_signal.emit(gvar.current_frame_start_address)
        # print("[hackcatml] gvar.current_frame_block_number: ", gvar.current_frame_block_number)
        # print("[hackcatml] tc.blockNumber(): ", tc.blockNumber())
        # print("[hackcatml] tc.block().text(): ", tc.block().text())
        # print("[hackcatml] gvar.current_frame_start_address: ", gvar.current_frame_start_address)

        return super(HexViewerClass, self).wheelEvent(e)

    def keyReleaseEvent(self, e: QtGui.QKeyEvent) -> None:
        # If key is hexedit shortcut key then just return. if not hexeditor behavior is weird
        if e.key() == Qt.Key.Key_F2:
            return

        tc = self.textCursor()
        tcx = tc.positionInBlock()
        # print("keyrelease pos: ", tcx)
        indices = [i for i, x in enumerate(tc.block().text()) if x == " "]
        if len(indices) == 0:
            return
        if tcx in range(indices[1]):
            return

        # Change color on edited hex as black -> red
        if self.isReadOnly() is False:
            self.moveCursor(QTextCursor.MoveOperation.Left, QTextCursor.MoveMode.KeepAnchor)
            self.setTextColor(QtGui.QColor("Red"))
            self.moveCursor(QTextCursor.MoveOperation.Right)

        if tcx in range(indices[2], indices[len(indices) - 2] + 3, 3) and e.key() != Qt.Key.Key_Left:
            if tcx == indices[len(indices) - 2]:
                self.moveCursor(QTextCursor.MoveOperation.Down)
                self.moveCursor(QTextCursor.MoveOperation.StartOfLine)
                self.moveCursor(QTextCursor.MoveOperation.NextWord)
                return
            self.moveCursor(QTextCursor.MoveOperation.Right)
            return

    def keyPressEvent(self, e: QtGui.QKeyEvent) -> None:
        tc = self.textCursor()
        tcx = tc.positionInBlock()
        tcy = tc.anchor()
        # print("keypress pos: ", tcx, tcy)

        # Backspace, delete, enter, left key and space is not allowed
        if e.key() in (
                QtCore.Qt.Key.Key_Backspace, QtCore.Qt.Key.Key_Delete, QtCore.Qt.Key.Key_Return, Qt.Key.Key_Left, Qt.Key.Key_Space
        ): return

        # Hexedit 모드에서 ctrl + a, cmd + a (select all), ctrl + v, cmd + v (paste) is not allowed
        # if self.isReadOnly() is False:
        if (e.keyCombination().keyboardModifiers() == QtCore.Qt.KeyboardModifier.MetaModifier or e.keyCombination().keyboardModifiers() == QtCore.Qt.KeyboardModifier.ControlModifier) and e.key() == QtCore.Qt.Key.Key_A:
            # print("ctrl + a, cmd + a is not allowed")
            return
        if (e.keyCombination().keyboardModifiers() == QtCore.Qt.KeyboardModifier.MetaModifier or e.keyCombination().keyboardModifiers() == QtCore.Qt.KeyboardModifier.ControlModifier) and e.key() == QtCore.Qt.Key.Key_V:
            # print("ctrl + v, cmd + v is not allowed")
            return

        # Cmd, ctrl, alt, shift + up, right, left, down selection not allowed
        # print(str(e.keyCombination().keyboardModifiers()))
        if str(e.keyCombination().keyboardModifiers()) in ["KeyboardModifier.KeypadModifier|ShiftModifier", "KeyboardModifier.AltModifier", "KeyboardModifier.KeypadModifier|ControlModifier|ShiftModifier", "KeyboardModifier.KeypadModifier|MetaModifier|ShiftModifier","KeyboardModifier.KeypadModifier|AltModifier|ShiftModifier", "KeyboardModifier.KeypadModifier|ControlModifier"]: return

        # Editable only hex area. indices => [9, 10, 13, 16, 19, 22, 25, 28, 31, 34, 37, 40, 43, 46, 49, 52, 55, 58, 59]
        indices = [i for i, x in enumerate(tc.block().text()) if x == " "]
        if (len(indices) > 0) is False:
            return
        if tcx in range(indices[1]) or tcx in range(indices[1] + 3, indices[len(indices) - 2] + 3, 3):
            return

        super(HexViewerClass, self).keyPressEvent(e)

    def mousePressEvent(self, e: QtGui.QMouseEvent) -> None:
        super(HexViewerClass, self).mousePressEvent(e)
        pos = e.pos()
        tc = self.cursorForPosition(pos)
        tcx = tc.positionInBlock()
        line = tc.block().text()
        # print(tc.block().text())
        # print("mousepress pos: ", tcx, tcy)

        indices = [i for i, x in enumerate(line) if x == " "]
        # Memory pattern search 한 결과창에서 마우스 클릭한 경우
        if len(indices) == 0:
            if e.buttons() == QtCore.Qt.MouseButton.XButton1 or e.buttons() == QtCore.Qt.MouseButton.XButton2: return
            for i in range(2): self.moveCursor(QTextCursor.MoveOperation.Up)
            self.moveCursor(QTextCursor.MoveOperation.NextWord)
            return
        # elif line.find(', module:') != -1:
        elif re.search(r"\d+\. 0x[a-f0-9]+, module:", line):
            if e.buttons() == QtCore.Qt.MouseButton.XButton1 or e.buttons() == QtCore.Qt.MouseButton.XButton2: return
            self.moveCursor(QTextCursor.MoveOperation.Down)
            self.moveCursor(QTextCursor.MoveOperation.StartOfBlock)
            self.moveCursor(QTextCursor.MoveOperation.NextWord)
            return

        if e.buttons() == QtCore.Qt.MouseButton.XButton1:
            self.move_signal.emit(0)
        elif e.buttons() == QtCore.Qt.MouseButton.XButton2:
            self.move_signal.emit(1)

        # Select a word with a single click
        if gvar.is_hex_edit_mode is False and e.buttons() == QtCore.Qt.MouseButton.LeftButton:
            cursor = self.cursorForPosition(e.pos())
            cursor.select(QTextCursor.SelectionType.WordUnderCursor)
            self.setTextCursor(cursor)
        # Mouse left click on non hex editable region at normal hexviewer
        elif gvar.is_hex_edit_mode is True and e.buttons() == QtCore.Qt.MouseButton.LeftButton and len(indices) > 0:
            # ADDRESS region
            if tcx in range(indices[1] + 1):
                self.moveCursor(QTextCursor.MoveOperation.NextWord)
                return
            # ASCII String Region
            if tcx in range(len(line) - 16, len(line) + 1):
                self.moveCursor(QTextCursor.MoveOperation.StartOfLine)
                for i in range(16):
                    self.moveCursor(QTextCursor.MoveOperation.NextWord)
                return
            # if (tcx - 9) % 3 == 0 or (tcx - 9) % 3 == 1:
            if tcx in indices or (tcx + 1) in indices:
                self.moveCursor(QTextCursor.MoveOperation.PreviousWord)
                return

    def contextMenuEvent(self, e: QtGui.QContextMenuEvent) -> None:
        # In the hexedit mode, don't create a context menu on right click
        if not self.isReadOnly():
            return

        tc = self.cursorForPosition(e.pos())
        pos = tc.position()
        tcx = tc.positionInBlock()
        tcy = tc.anchor()
        block_text = tc.block().text()

        menu = super(HexViewerClass, self).createStandardContextMenu()  # Get the default context menu
        select_all_action = next((action for action in menu.actions() if "Select All" in action.text()), None)

        if select_all_action:
            # Check if the selected text matches the hex_regex
            hex_regex_pattern = r'(\b0x[a-fA-F0-9]+\b|\b[a-fA-F0-9]{6,}\b)'
            hex_regex = re.compile(hex_regex_pattern)
            match = hex_regex.match(self.textCursor().selectedText())
            is_selected = bool(self.textCursor().selectedText())

            def create_action(text, enabled, func):
                action = QAction(text, self)
                action.setEnabled(enabled)
                action.triggered.connect(func)
                return action

            # Create and insert the actions
            copy_hex_action = None
            disassemble_action = None
            if match is None or len(list(re.finditer(hex_regex_pattern, self.textCursor().selectedText(), re.IGNORECASE))) > 1:
                copy_hex_action = create_action("Copy Hex", is_selected, self.copy_hex)
                disassemble_action = create_action("Hex to Arm", is_selected, self.request_armconverter)

            hex_code_read_action = None
            copy_pointer_action = None
            if gvar.frida_instrument is None:
                self.statusBar.showMessage(f"\tAttach first", 3000)
                return

            addr_match = hex_regex.match(tc.block().text())
            if addr_match is not None:
                addr_length = len(addr_match[0])
                hex_start = addr_length + 2
                cursor_len_4bytes = 12  # '00 00 00 00 '
                cursor_len_8bytes = 2 * 12
                make_hex_code_read_action = False
                make_copy_pointer_action = False
                if (tcx in [hex_start, hex_start + 1, hex_start + 2] or
                    tcx in [hex_start + cursor_len_8bytes, hex_start + cursor_len_8bytes + 1, hex_start + cursor_len_8bytes + 2]):
                    if gvar.arch == "arm64":
                        make_copy_pointer_action = True
                if (tcx in [hex_start, hex_start + 1, hex_start + 2] or
                    tcx in [hex_start + cursor_len_4bytes, hex_start + cursor_len_4bytes + 1, hex_start + cursor_len_4bytes + 2] or
                    tcx in [hex_start + cursor_len_8bytes, hex_start + cursor_len_8bytes + 1, hex_start + cursor_len_8bytes + 2] or
                    tcx in [hex_start + 3 * cursor_len_4bytes, hex_start + 3 * cursor_len_4bytes + 1, hex_start + 3 * cursor_len_4bytes + 2]):
                    make_hex_code_read_action = True
                    if gvar.arch == "arm":
                        make_copy_pointer_action = True

                if make_hex_code_read_action:
                    hex_code_read_action = create_action("Read", match is None,
                                                lambda : self.hex_code_read(tc, pos, tcx, tcy, block_text, hex_start))
                if make_copy_pointer_action:
                    copy_pointer_action = create_action("Copy Pointer", match is None,
                                                        lambda: self.copy_pointer(tc, pos, tcx, tcy, block_text, hex_start))

                if tcx < hex_start:
                    watch_action = create_action("Set Watch Func", True,
                                                 lambda: self.set_watch_on_addr("watch_func", addr_match[0], ""))
                    watch_regs_action = create_action("Set Watch Regs", True,
                                                      lambda: self.set_watch_on_addr("watch_regs", addr_match[0], ""))
                    mem_patch_action = create_action("Memory patch", True, lambda: self.mem_patch(addr_match[0]))
                    set_watchpoint_action = create_action("Set watchpoint", True, lambda: self.set_watchpoint(addr_match[0]))

                    menu.insertAction(select_all_action, watch_action)
                    menu.insertAction(select_all_action, watch_regs_action)
                    menu.insertAction(select_all_action, mem_patch_action)
                    menu.insertAction(select_all_action, set_watchpoint_action)

            if copy_hex_action is not None:
                menu.insertAction(select_all_action, copy_hex_action)
            if disassemble_action is not None:
                menu.insertAction(select_all_action, disassemble_action)
            if hex_code_read_action is not None:
                menu.insertAction(select_all_action, hex_code_read_action)
            if copy_pointer_action is not None:
                menu.insertAction(select_all_action, copy_pointer_action)

        menu.exec(e.globalPos())

    def text_changed_event(self):
        tc = self.textCursor()
        tcx = tc.positionInBlock()
        line = tc.block().text()
        # print("[hackcatml] text changed: " + tc.block().text())

        # Update hex code read when the text change event happens by mem refresh worker
        if self.hex_code_read_widget is not None and self.hex_code_read_widget.isVisible() and \
                gvar.is_hex_edit_mode is False:
            target_addr = int(self.hex_code_read_widget.windowTitle(), 16)
            current_block_text_addr = int(line[:line.find(" ")], 16)
            hex_code = None
            # print(f"[hex_viewer] target_addr: {target_addr}, current_block_text_addr: {current_block_text_addr}")
            if target_addr >= current_block_text_addr:
                # Strip the "0x" prefix
                hex_digits = hex(target_addr - current_block_text_addr)[2:]
                # Separate the last digit and the preceding digits (if any)
                if len(hex_digits) == 1:
                    result = [0, int(hex_digits, 16)]
                else:
                    # Split into the preceding part and the last digit
                    result = [int(hex_digits[:-1], 16), int(hex_digits[-1], 16)]
                y, x = result
                for i in range(y):
                    tc.movePosition(QTextCursor.MoveOperation.Down, QTextCursor.MoveMode.MoveAnchor)
                hex_code_list = tc.block().text()[self.hex_code_read_hex_start + x * 3:].split(' ')
                hex_code_list_length = len(hex_code_list)
                # print(f"[hex_viewer] hex_code_list: {hex_code_list}")
                if hex_code_list_length - 8 > 0:
                    hex_code_list = hex_code_list[:-(hex_code_list_length - 8)]
                    hex_code = " ".join(hex_code_list)
                # print(f"[hex_viewer] hex_code_list_length: {hex_code_list_length}")
                if hex_code_list_length - 6 == 0:
                    hex_code_list = hex_code_list[:-2]
                    hex_code = " ".join(hex_code_list)
                # print(f"[hex_viewer] hex_code: {hex_code}")

            if hex_code is not None:
                self.hex_code_read_widget.hex_code = hex_code
                self.hex_code_read_widget.set_label()
                self.hex_code_read_widget.show()

        # if tc.block().text() == "", index out of error occurs
        if line == "":
            return

        # check if it's the mem scan result view
        if self.toPlainText() is not None and re.search(r"\d+\. 0x[0-9a-f]+, module:", self.toPlainText()):
            is_mem_scan_result_view = True
        else:
            is_mem_scan_result_view = False

        # If changed text is not hex, then refresh the hex viewer
        # print(f"[hex_viewer] text: {line[len(line) - 66:len(line) - 16]}")
        if re.search(r"[^0-9a-f\s]+", line[len(line) - 66:len(line) - 16]) and not re.search(r"\d+\. 0x[0-9a-f]+, module:", line):
            if is_mem_scan_result_view:
                self.setText(gvar.current_mem_scan_hex_view_result)
            else:
                self.refresh_signal.emit(1) if gvar.is_frida_attached else None
            return

        indices = [i for i, x in enumerate(line) if x == " "]
        try:
            hex_start = indices[1] + 1
        except Exception as e:
            print(f"[hex_viewer] {inspect.currentframe().f_code.co_name}: {e}")
            self.clear()
            return

        # print("[hackcatml] (tcx - hex_start) // 3 = ", (tcx - hex_start) // 3)
        if (tcx - hex_start) // 3 < 0 or (tcx - hex_start) // 3 > 15:
            return

        addr = hex(int(line[:line.find(" ")], 16) + (tcx - hex_start) // 3)
        # print("[hackcatml] text changed addr: ", addr)

        changed = line[3 * ((tcx - hex_start) // 3) + hex_start: 3 * ((tcx - hex_start) // 3) + hex_start + 2]
        changed = "".join(("0x", changed))
        # print("[hackcatml] changed hex: ", changed)

        pos = tc.position()

        try:
            orig = gvar.frida_instrument.read_mem_addr(addr, 1)
            index = orig.find("\n")
            index = index + orig[index:].find(' ') + 2
            orig = orig[index: index + 2]
            orig = "".join(("0x", orig))
            if changed == orig or len(changed.replace('0x', '').strip()) == 1 or re.search(r"(?![0-9a-fA-F]).",
                                                                                           changed.replace('0x', '')):
                return
        except Exception as e:
            if str(e) == gvar.ERROR_SCRIPT_DESTROYED:
                gvar.frida_instrument.sessions.clear()
            return

        prot = '---'
        for i in range(len(gvar.enumerate_ranges)):
            if int(gvar.enumerate_ranges[i][0], 16) <= int(addr, 16) <= int(gvar.enumerate_ranges[i][1], 16):
                prot = gvar.enumerate_ranges[i][2]

        for i in range(len(gvar.hex_edited)):
            if addr in gvar.hex_edited[i]:
                gvar.hex_edited[i][1] = changed
                gvar.hex_edited[i][2] = orig
                gvar.hex_edited[i][3] = prot
                gvar.hex_edited[i][4] = pos
                return

        gvar.hex_edited.append([addr, changed, orig, prot, pos])
        # print(f"[hex_viewer] text changed pos: {tcx}")

    def selected_text(self, request_to_armconverter: bool) -> str:
        selected_text = self.textCursor().selectedText()  # gets the currently selected text
        selected_text = selected_text.replace('\u2029', '\n')
        lines = selected_text.strip().split('\n')
        if len(lines) <= 2:
            hex_data = []
            for line in lines:
                matches = re.findall(r'\b[0-9a-fA-F]{2}\b', line)
                hex_data.append(' '.join(matches))
            if request_to_armconverter is False:
                hex_string = '\n'.join(hex_data)
            else:
                hex_string = ''.join(hex_data)
            return hex_string
        elif len(lines) > 2:
            # Determine the length of the second line
            second_line_length = len(lines[1])
            # If the first line is shorter, pad it with spaces at the beginning
            if len(lines[0]) < second_line_length:
                difference = second_line_length - len(lines[0])
                lines[0] = ' ' * difference + lines[0]
            # If the last line is shorter, pad it with spaces at the end
            if len(lines[-1]) < second_line_length:
                difference = second_line_length - len(lines[-1])
                lines[-1] += ' ' * difference
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
            # Join hex data into a single string
            if request_to_armconverter is False:
                hex_string = '\n'.join(hex_data)
            else:
                hex_string = ''.join(hex_data)
            return hex_string

    def copy_hex(self):
        hex_string = self.selected_text(False)
        QApplication.clipboard().setText(hex_string)  # Copies the hex text to the clipboard

    def request_armconverter(self):
        import requests

        url = 'https://armconverter.com/api/convert'
        hex_string = self.selected_text(True)

        payload = {"hex": hex_string, "offset": "", "arch": [gvar.arch]}
        response = requests.post(url, json=payload)
        data = response.json()

        if data['asm'][gvar.arch][0] is True:
            hex_to_arm_result = data['asm'][gvar.arch][1]
            # Show the copied text in a new widget
            self.hex_to_arm_widget = HexToArmWidget(hex_to_arm_result)
            cursor_pos = QCursor.pos()
            # Move the widget to the cursor position
            self.hex_to_arm_widget.move(cursor_pos)
            self.hex_to_arm_widget.show()
        else:
            print("Fail to hex to arm convert")

    def hex_code_read(self, tc, pos, tcx, tcy, block_text, hex_start):
        self.hex_code_read_tc = tc
        self.hex_code_read_pos = pos
        self.hex_code_read_tcx = tcx
        self.hex_code_read_tcy = tcy
        self.hex_code_read_block_text = block_text
        self.hex_code_read_hex_start = hex_start
        addr, hex_code = get_hex_code(tc, pos, tcx, tcy, block_text, hex_start, "hex_code_read")
        if hex_code is None:
            return
        self.hex_code_read_widget = HexCodeReadWidget(hex_code)
        self.hex_code_read_widget.setWindowTitle(addr)
        self.hex_code_read_widget.set_label()
        cursor_pos = QCursor.pos()
        self.hex_code_read_widget.move(cursor_pos)
        self.hex_code_read_widget.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint)
        self.hex_code_read_widget.show()

    def copy_pointer(self, tc, pos, tcx, tcy, block_text, hex_start):
        addr, hex_code = get_hex_code(tc, pos, tcx, tcy, block_text, hex_start, "copy_pointer")
        pointer = hex(int(''.join(reversed(hex_code.split(' '))), 16))
        QApplication.clipboard().setText(pointer)

    def set_watch_on_addr(self, action_type, addr, caller):
        if addr is not None:
            if (prefix := '0x') not in addr:
                addr = ''.join((prefix, addr))
            self.watch_on_addr_widget.addr_to_watch = addr
        else:
            tc = self.textCursor()
            indices = [i for i, x in enumerate(tc.block().text()) if x == " "]
            self.watch_on_addr_widget.addr_to_watch = ''.join(('0x', tc.block().text()[:indices[0]])).strip()

        try:
            if not self.watch_on_addr_widget.watch_list and not gvar.frida_instrument.receivers(gvar.frida_instrument.message_signal):
                # Watch list is empty. set connect once
                gvar.frida_instrument.message_signal.connect(self.message_sig_func)

            if caller == "history_remove_row_sig_func" or \
                    not any(watch_item == [self.watch_on_addr_widget.addr_to_watch,
                                           True if action_type == "watch_regs" else False]
                            for watch_item in self.watch_on_addr_widget.watch_list):
                watch_regs = False
                minimum_nargs = 1
                default_nargs = 3
                maximum_nargs = 10

                if action_type == "watch_regs":
                    watch_regs = True
                    default_nargs = 5
                    maximum_nargs = 34

                self.watch_on_addr_widget.slider.setMinimum(minimum_nargs)  # Minimum number of arguments to watch
                self.watch_on_addr_widget.slider.setMaximum(maximum_nargs)  # Maximum number of arguments to watch
                self.watch_on_addr_widget.slider.setValue(default_nargs)  # Default number of arguments to watchZ
                # print(f"[hex_viewer] set watch on {self.watch_on_addr_widget.addr_to_watch}")
                gvar.frida_instrument.set_nargs(default_nargs)
                gvar.frida_instrument.set_watch_list(self.watch_on_addr_widget.addr_to_watch, watch_regs)

                for watch_item in self.watch_on_addr_widget.watch_list:
                    if self.watch_on_addr_widget.addr_to_watch == watch_item[0] and watch_regs != watch_item[1]:
                        watch_item[1] = watch_regs
                        break

                if caller == "history_remove_row_sig_func" or \
                        not any(watch_item[0] == self.watch_on_addr_widget.addr_to_watch
                                for watch_item in self.watch_on_addr_widget.watch_list):
                    gvar.frida_instrument.set_watch(self.watch_on_addr_widget.addr_to_watch)
                    if caller != "history_remove_row_sig_func":
                        self.watch_on_addr_widget.watch_list.append(
                            [self.watch_on_addr_widget.addr_to_watch, watch_regs])

                self.watch_list_signal.emit(self.watch_on_addr_widget.watch_list)

        except Exception as e:
            print(f"[hex_viewer] {inspect.currentframe().f_code.co_name}: {e}")
            return

        cursor_pos = QCursor.pos()
        # Move the widget to the cursor position
        self.watch_on_addr_widget.move(cursor_pos)
        self.watch_on_addr_widget.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint)
        self.watch_on_addr_widget.show()

    def mem_patch(self, addr):
        if (prefix := '0x') not in addr:
            addr = ''.join((prefix, addr))
        self.mem_patch_addr_signal.emit(addr)

    def set_watchpoint(self, addr):
        if (prefix := '0x') not in addr:
            addr = ''.join((prefix, addr))
        self.set_watchpoint_addr_signal.emit(addr)


class HexToArmWidget(QWidget):
    def __init__(self, text):
        super().__init__()
        self.setWindowTitle("HEX to ARM")
        self.text_edit = QTextEdit()
        self.text_edit.setPlainText(text)
        self.text_edit.setReadOnly(True)  # Make the text edit read-only
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.text_edit)
        self.setLayout(self.layout)


# Custom TextEdit class for WatchOnAddrWidget
class WatchOnAddrTextEdit(QTextEdit):
    def __init__(self, parent=None):
        super(WatchOnAddrTextEdit, self).__init__(parent)
        self.key = None
        self.args_index = None
        self.args_value = None
        self.addr = None

        self.checkedStates = {}
        self.hex_dump_widgets = []
        self.backtrace_widgets = []

    def mousePressEvent(self, event):
        super().mousePressEvent(event)
        if event.button() == Qt.MouseButton.LeftButton:
            cursor = self.cursorForPosition(event.pos())
            cursor.select(QTextCursor.SelectionType.WordUnderCursor)
            self.setTextCursor(cursor)

    def closeEvent(self, e: QtGui.QCloseEvent) -> None:
        self.checkedStates.clear()
        try:
            if gvar.frida_instrument is not None:
                gvar.frida_instrument.hexdump_signal.disconnect()
                gvar.frida_instrument.backtrace_signal.disconnect()
        except Exception as e:
            pass
        self.hex_dump_widgets.clear()
        self.backtrace_widgets.clear()

    def get_args_index_and_addr_from_selected_text(self):
        # Get the currently selected text
        tc = self.textCursor()
        selected_text = self.textCursor().selectedText()
        if ":" in selected_text:
            self.args_index = selected_text[4:selected_text.index(":")]
            index = tc.block().text().find(selected_text)
            match = re.search(r"0x[a-f0-9]+", tc.block().text()[index:])
            if match:
                self.args_value = match.group(0)
        else:
            self.args_index = selected_text[4:]
            index = tc.block().text().find(selected_text)
            match = re.search(r"0x[a-f0-9]+", tc.block().text()[index:])
            if match:
                self.args_value = match.group(0)

        if selected_text in ('r', 're', 'ret', 'retu', 'retur', 'return'):
            self.args_index = ""

        while True:
            tc.movePosition(QTextCursor.MoveOperation.Up, QTextCursor.MoveMode.MoveAnchor)
            if re.search(r"] 0x[a-f0-9]+", tc.block().text()):
                self.addr = tc.block().text()[4:].strip()
                break

    def contextMenuEvent(self, e: QtGui.QContextMenuEvent) -> None:
        menu = super(WatchOnAddrTextEdit, self).createStandardContextMenu()  # Get the default context menu
        select_all_action = None

        for action in menu.actions():  # loop over the existing actions
            if "Select All" in action.text():
                select_all_action = action
                break

        if select_all_action:  # if the "Select All" action was found then insert menus
            args_regx = re.compile(r'(\bargs\d+\b|\breturn\b)')
            if self.textCursor().selectedText() in ('a', 'ar', 'arg', 'args', 'r', 're', 'ret', 'retu', 'retur'):
                self.moveCursor(QTextCursor.MoveOperation.EndOfWord, QTextCursor.MoveMode.KeepAnchor)
            self.get_args_index_and_addr_from_selected_text()
            match = args_regx.match(self.textCursor().selectedText())

            on_leave_check = QCheckBox("OnLeave", self) if self.textCursor().selectedText() != "return" else None
            if match is not None:
                self.key = (self.addr, self.args_index)  # Use a tuple as the key
                # If the key is not in the checkedStates dictionary, add it with a default state of unchecked
                if self.key not in self.checkedStates:
                    self.checkedStates[self.key] = Qt.CheckState.Unchecked.value

                if on_leave_check is not None:
                    # Set the checked state based on the checkedStates dictionary
                    on_leave_check.setCheckState(Qt.CheckState(self.checkedStates[self.key]))
                    # Connect the checkbox's stateChanged signal to a function
                    on_leave_check.stateChanged.connect(lambda state: self.on_leave_check_state_changed(state, self.key))

                    check_action = QWidgetAction(self)
                    check_action.setDefaultWidget(on_leave_check)
                    menu.insertAction(select_all_action, check_action)

                actions = [
                    ("hexdump", self.hex_dump),
                    ("readPointer", self.read_pointer),
                    ("readUtf8String", self.read_utf8_string),
                    ("readUtf16String", self.read_utf16_string),
                    ("readU8", self.read_u8),
                    ("readU16", self.read_u16),
                    ("readU32", self.read_u32),
                    ("readU64", self.read_u64),
                    ("readFloat", self.read_float),
                    ("readDouble", self.read_double),
                    ("readByteArray", self.read_bytearray),
                    ("reset", self.reset)
                ]

                for text, method in actions:
                    action = QAction(text, self)
                    action.setEnabled(True)
                    action.triggered.connect(method)
                    menu.insertAction(select_all_action, action)

            addr_regex = re.compile(r'^\[\+]\s0x[a-f0-9]+$')
            addr_match = addr_regex.match(self.textCursor().block().text())
            if addr_match is not None:
                action = QAction("Backtrace", self)
                action.setEnabled(True)
                action.triggered.connect(lambda: self.set_backtrace(addr_match.group(0).split(' ')[1]))
                menu.insertAction(select_all_action, action)

            menu.exec(e.globalPos())

    def on_leave_check_state_changed(self, state, key):
        self.checkedStates[key] = state
        self.read_args_with_options("")

    def hex_dump(self):
        self.read_args_with_options("hexdump")
        if self.hex_dump_widgets:
            for item in self.hex_dump_widgets:
                if self.key in item and self.args_value in item and self.checkedStates[self.key] in item:
                    item[3].show()
                    return
        # Create a new HexDumpWidget and connect to the signal
        if self.textCursor().selectedText() == "return":
            # self.args_index == "", self.checkedStates == 2 for the return value hexdump
            hexdump_widget = HexDumpWidget(self.addr, self.args_index, self.args_value, 2)
            hexdump_widget.setWindowTitle(f"HexDump return: {self.args_value}")
        else:
            hexdump_widget = HexDumpWidget(self.addr, self.args_index, self.args_value, self.checkedStates[self.key])
            if self.checkedStates[self.key] == 0:
                hexdump_widget.setWindowTitle(f"OnEnter HexDump args{self.args_index}: {self.args_value}")
            else:
                hexdump_widget.setWindowTitle(f"OnLeave HexDump args{self.args_index}: {self.args_value}")
        gvar.frida_instrument.hexdump_signal.connect(hexdump_widget.hexdump_sig_func)
        cursor_pos = QCursor.pos()
        hexdump_widget.move(cursor_pos)
        hexdump_widget.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint)
        self.hex_dump_widgets.append([self.key, self.args_value, self.checkedStates[self.key], hexdump_widget])
        hexdump_widget.show()

    def read_pointer(self):
        self.read_args_with_options("readPointer")

    def read_utf8_string(self):
        self.read_args_with_options("readUtf8String")

    def read_utf16_string(self):
        self.read_args_with_options("readUtf16String")

    def read_u8(self):
        self.read_args_with_options("readU8")

    def read_u16(self):
        self.read_args_with_options("readU16")

    def read_u32(self):
        self.read_args_with_options("readU32")

    def read_u64(self):
        self.read_args_with_options("readU64")

    def read_float(self):
        self.read_args_with_options("readFloat")

    def read_double(self):
        self.read_args_with_options("readDouble")

    def read_bytearray(self):
        self.read_args_with_options("readByteArray")

    def reset(self):
        self.read_args_with_options("")

    def set_backtrace(self, addr):
        addr_to_backtrace = addr
        try:
            gvar.frida_instrument.set_backtrace(addr_to_backtrace, True)
        except Exception as e:
            print(e)
            return

        if self.backtrace_widgets:
            for item in self.backtrace_widgets:
                if addr_to_backtrace in item:
                    item[1].show()
                    return

        backtrace_widget = BackTraceWidget(addr_to_backtrace)
        backtrace_widget.setWindowTitle(f"Backtrace: {addr_to_backtrace}")

        gvar.frida_instrument.backtrace_signal.connect(backtrace_widget.backtrace_sig_func)
        cursor_pos = QCursor.pos()
        backtrace_widget.move(cursor_pos)
        backtrace_widget.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint)
        self.backtrace_widgets.append([addr_to_backtrace, backtrace_widget])
        backtrace_widget.show()

    def read_args_with_options(self, option):
        try:
            if self.textCursor().selectedText() == "return":
                gvar.frida_instrument.set_read_retval_options(self.addr, option)
            else:
                gvar.frida_instrument.set_read_args_options(self.addr, self.args_index, option,
                                                              self.checkedStates[self.key])
        except Exception as e:
            print(f"[hex_viewer] {inspect.currentframe().f_code.co_name}: {e}")
            return


class WatchOnAddrWidget(QWidget):
    watch_on_addr_widget_close_event_signal = QtCore.pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Watch on Addr")
        self.addr_to_watch = ''
        self.watch_list = []
        self.text_edit = WatchOnAddrTextEdit()
        self.text_edit.setReadOnly(True)  # Make the text edit read-only

        # Create a QSlider
        self.slider = QSlider(Qt.Orientation.Horizontal)

        # Create a QLabel for the slider value
        self.slider_value_label = QLabel()

        # Update the nargs, label when the slider value changes
        self.slider.valueChanged.connect(self.update_num_args)
        self.slider.valueChanged.connect(self.update_slider_value_label)

        # Create a QPushButton for clearing the QTextEdit
        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.text_edit.clear)

        # Create a QHBoxLayout
        slider_layout = QHBoxLayout()
        slider_layout.addWidget(self.slider)
        slider_layout.addWidget(self.slider_value_label)
        slider_layout.addWidget(self.clear_button)

        self.layout = QVBoxLayout()
        # Add the QHBoxLayout to the QVBoxLayout
        self.layout.addLayout(slider_layout)
        self.layout.addWidget(self.text_edit)
        self.setLayout(self.layout)
        self.resize(550, 350)

    def closeEvent(self, e: QtGui.QCloseEvent) -> None:
        self.text_edit.clear()
        self.text_edit.closeEvent(e)
        self.watch_list.clear()
        self.watch_on_addr_widget_close_event_signal.emit()
        try:
            if gvar.frida_instrument is not None:
                gvar.frida_instrument.detach_all()
        except Exception as e:
            print(f"[hex_viewer] {inspect.currentframe().f_code.co_name}: {e}")
            if str(e) == gvar.ERROR_SCRIPT_DESTROYED:
                gvar.frida_instrument.sessions.clear()
            return

        super().closeEvent(e)

    @pyqtSlot(int)
    def update_num_args(self, num_args: int):
        try:
            gvar.frida_instrument.set_nargs(num_args)
        except Exception as e:
            print(f"[hex_viewer] {inspect.currentframe().f_code.co_name}: {e}")
            return

    @pyqtSlot(int)
    def update_slider_value_label(self, value):
        self.slider_value_label.setText(str(value))


class BackTraceTextEdit(QTextEdit):
    def __init__(self, parent=None):
        super(BackTraceTextEdit, self).__init__(parent)

    def mousePressEvent(self, e: QtGui.QMouseEvent) -> None:
        pos = e.pos()
        tc = self.cursorForPosition(pos)
        text_block = tc.block().text()
        addr = text_block.split(' ')[0]
        if gvar.hex_viewer_signal_manager is not None:
            gvar.hex_viewer_signal_manager.backtrace_text_edit_backtrace_addr_clicked_signal.emit(addr)


class BackTraceWidget(QWidget):
    def __init__(self, addr):
        super().__init__()
        self.addr_to_backtrace = addr

        self.text_edit = BackTraceTextEdit()
        font = QtGui.QFont("Courier New", 9) if platform.system() == 'Windows' else QtGui.QFont("Courier New", 13)
        self.text_edit.setFont(font)
        self.text_edit.setReadOnly(True)  # Make the text edit read-only

        self.layout = QVBoxLayout()
        self.layout.addWidget(self.text_edit)

        gvar.hex_viewer_signal_manager.close_backtrace_signal.connect(self.close_backtrace_sig_func)

        self.setLayout(self.layout)
        self.resize(510, 250) if platform.system() == 'Windows' else self.resize(550, 250)

    @pyqtSlot(tuple)
    def backtrace_sig_func(self, sig: tuple):
        addr, backtrace_log = sig
        if addr == self.addr_to_backtrace:
            self.text_edit.setPlainText(backtrace_log)

    @pyqtSlot()
    def close_backtrace_sig_func(self):
        self.close()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            self.close()
        else:
            super().keyPressEvent(event)

    def closeEvent(self, e: QtGui.QCloseEvent) -> None:
        try:
            if gvar.frida_instrument is not None:
                gvar.frida_instrument.set_backtrace(self.addr_to_backtrace, False)
        except Exception as e:
            print(f"[hex_viewer] {inspect.currentframe().f_code.co_name}: {e}")
            if str(e) == gvar.ERROR_SCRIPT_DESTROYED:
                gvar.frida_instrument.sessions.clear()
            return

        super().closeEvent(e)


class HexCodeReadWidget(QWidget):
    def __init__(self, hex_code):
        super().__init__()
        self.hex_code = hex_code

        self.u8_label = QLabel("")
        self.u16_label = QLabel("")
        self.u32_label = QLabel("")
        self.int_label = QLabel("")
        self.u8_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.u16_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.u32_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.int_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        self.u64_label = None
        self.float_label = None
        self.double_label = None
        self.pointer_label = None
        if not len(self.hex_code.split(' ')) == 4:
            self.u64_label = QLabel("")
            self.float_label = QLabel("")
            self.double_label = QLabel("")
            self.pointer_label = QLabel("")

            self.u64_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.float_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.double_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.pointer_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        layout = QVBoxLayout()
        layout.addWidget(self.u8_label)
        layout.addWidget(self.u16_label)
        layout.addWidget(self.u32_label)
        if self.u64_label is not None:
            layout.addWidget(self.u64_label)
        layout.addWidget(self.int_label)
        if self.u64_label is not None:
            layout.addWidget(self.float_label)
            layout.addWidget(self.double_label)
            layout.addWidget(self.pointer_label)

        self.setLayout(layout)
        font = QtGui.QFont("Courier New", 9) if platform.system() == 'Windows' else QtGui.QFont("Courier New", 12)
        self.setFont(font)
        self.resize(250, 50) if platform.system() == 'Windows' else self.resize(50, 50)

    def set_label(self):
        u8_value = misc.hex_code_read_as_u8(self.hex_code)
        u16_value = misc.hex_code_read_as_u16(self.hex_code)
        u32_value = misc.hex_code_read_as_u32(self.hex_code)
        int_value = misc.hex_code_read_as_int(self.hex_code)
        self.u8_label.setText(f"u8: {u8_value}")
        self.u16_label.setText(f"u16: {u16_value}")
        self.u32_label.setText(f"u32: {u32_value}")
        self.int_label.setText(f"int: {int_value}")
        if not len(self.hex_code.split(' ')) == 4:
            u64_value = misc.hex_code_read_as_u64(self.hex_code)
            float_value = misc.hex_code_read_as_float(self.hex_code)
            double_value = misc.hex_code_read_as_double(self.hex_code)
            pointer = hex(int(''.join(reversed(self.hex_code.split(' '))), 16))
            self.u64_label.setText(f"u64: {u64_value}")
            self.float_label.setText(f"float: {float_value}")
            self.double_label.setText(f"double: {double_value}")
            self.pointer_label.setText(f"pointer: {pointer}")

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            self.close()
        else:
            super().keyPressEvent(event)


class HexDumpTextEdit(QTextEdit):
    def __init__(self, parent=None):
        super(HexDumpTextEdit, self).__init__(parent)
        self.hex_code_read_widget = None
        self.hex_code_read_tc = None
        self.hex_code_read_pos = None
        self.hex_code_read_tcx = None
        self.hex_code_read_tcy = None
        self.hex_code_read_block_text = None
        self.hex_code_read_hex_start = None

        self.textChanged.connect(self.text_changed_event)

    def text_changed_event(self):
        # Update hex code read
        tc = self.textCursor()
        tc.movePosition(QTextCursor.MoveOperation.Down, QTextCursor.MoveMode.MoveAnchor)
        line = tc.block().text()

        if self.hex_code_read_widget is not None and self.hex_code_read_widget.isVisible():
            target_addr = int(self.hex_code_read_widget.windowTitle(), 16)
            current_block_text_addr = int(line[:line.find(" ")], 16)
            hex_code = None
            # print(f"[hex_viewer] target_addr: {target_addr}, current_block_text_addr: {current_block_text_addr}")
            if target_addr >= current_block_text_addr:
                # Strip the "0x" prefix
                hex_digits = hex(target_addr - current_block_text_addr)[2:]
                # Separate the last digit and the preceding digits (if any)
                if len(hex_digits) == 1:
                    result = [0, int(hex_digits, 16)]
                else:
                    # Split into the preceding part and the last digit
                    result = [int(hex_digits[:-1], 16), int(hex_digits[-1], 16)]
                y, x = result
                for i in range(y):
                    tc.movePosition(QTextCursor.MoveOperation.Down, QTextCursor.MoveMode.MoveAnchor)
                hex_code_list = tc.block().text()[self.hex_code_read_hex_start + x * 3:].split(' ')
                hex_code_list_length = len(hex_code_list)
                # print(f"[hex_viewer] hex_code_list: {hex_code_list}")
                if hex_code_list_length - 8 > 0:
                    hex_code_list = hex_code_list[:-(hex_code_list_length - 8)]
                    hex_code = " ".join(hex_code_list)
                # print(f"[hex_viewer] hex_code_list_length: {hex_code_list_length}")
                if hex_code_list_length - 6 == 0:
                    hex_code_list = hex_code_list[:-2]
                    hex_code = " ".join(hex_code_list)
                # print(f"[hex_viewer] hex_code: {hex_code}")

            if hex_code is not None:
                self.hex_code_read_widget.hex_code = hex_code
                self.hex_code_read_widget.set_label()
                self.hex_code_read_widget.show()

    def mousePressEvent(self, e: QtGui.QMouseEvent) -> None:
        cursor = self.cursorForPosition(e.pos())
        cursor.select(QTextCursor.SelectionType.WordUnderCursor)
        self.setTextCursor(cursor)

    def contextMenuEvent(self, e: QtGui.QContextMenuEvent) -> None:
        tc = self.cursorForPosition(e.pos())
        pos = tc.position()
        tcx = tc.positionInBlock()
        tcy = tc.anchor()
        block_text = tc.block().text()

        menu = super(HexDumpTextEdit, self).createStandardContextMenu()  # Get the default context menu
        select_all_action = next((action for action in menu.actions() if "Select All" in action.text()), None)

        if select_all_action:
            # Check if the selected text matches the hex_regex
            hex_regex = re.compile(r'(\b0x[a-fA-F0-9]+\b|\b[a-fA-F0-9]{6,}\b)')
            match = hex_regex.match(self.textCursor().selectedText())
            is_selected = bool(self.textCursor().selectedText())

            def create_action(text, enabled, func):
                action = QAction(text, self)
                action.setEnabled(enabled)
                action.triggered.connect(func)
                return action

            # Create and insert the actions
            copy_hex_action = create_action("Copy Hex", is_selected and match is None, self.copy_hex)
            hex_code_read_action = None
            copy_pointer_action = None
            addr_match = hex_regex.match(tc.block().text())
            if addr_match is not None:
                addr_length = len(addr_match[0])
                hex_start = addr_length + 2
                cursor_len_4bytes = 12  # '00 00 00 00 '
                cursor_len_8bytes = 2 * 12
                make_hex_code_read_action = False
                make_copy_pointer_action = False
                if (tcx in [hex_start, hex_start + 1, hex_start + 2] or
                    tcx in [hex_start + cursor_len_8bytes, hex_start + cursor_len_8bytes + 1, hex_start + cursor_len_8bytes + 2]):
                    if gvar.arch == "arm64":
                        make_copy_pointer_action = True
                if (tcx in [hex_start, hex_start + 1, hex_start + 2] or
                    tcx in [hex_start + cursor_len_4bytes, hex_start + cursor_len_4bytes + 1, hex_start + cursor_len_4bytes + 2] or
                    tcx in [hex_start + cursor_len_8bytes, hex_start + cursor_len_8bytes + 1, hex_start + cursor_len_8bytes + 2] or
                    tcx in [hex_start + 3 * cursor_len_4bytes, hex_start + 3 * cursor_len_4bytes + 1, hex_start + 3 * cursor_len_4bytes + 2]):
                    make_hex_code_read_action = True
                    if gvar.arch == "arm":
                        make_copy_pointer_action = True

                if make_hex_code_read_action:
                    hex_code_read_action = create_action("Read", match is None,
                                                lambda : self.hex_code_read(tc, pos, tcx, tcy, block_text, hex_start))
                if make_copy_pointer_action:
                    copy_pointer_action = create_action("Copy Pointer", match is None,
                                                        lambda: self.copy_pointer(tc, pos, tcx, tcy, block_text, hex_start))

            menu.insertAction(select_all_action, copy_hex_action)
            if hex_code_read_action is not None:
                menu.insertAction(select_all_action, hex_code_read_action)
            if copy_pointer_action is not None:
                menu.insertAction(select_all_action, copy_pointer_action)

        menu.exec(e.globalPos())

    def copy_hex(self):
        hex_string = self.selected_text()
        QApplication.clipboard().setText(hex_string)  # Copies the hex text to the clipboard

    def selected_text(self) -> str:
        selected_text = self.textCursor().selectedText()  # gets the currently selected text
        selected_text = selected_text.replace('\u2029', '\n')
        lines = selected_text.strip().split('\n')
        if len(lines) <= 2:
            hex_data = []
            for line in lines:
                matches = re.findall(r'\b[0-9a-fA-F]{2}\b', line)
                hex_data.append(' '.join(matches))
            hex_string = '\n'.join(hex_data)
            return hex_string
        elif len(lines) > 2:
            # Determine the length of the second line
            second_line_length = len(lines[1])
            # If the first line is shorter, pad it with spaces at the beginning
            if len(lines[0]) < second_line_length:
                difference = second_line_length - len(lines[0])
                lines[0] = ' ' * difference + lines[0]
            # If the last line is shorter, pad it with spaces at the end
            if len(lines[-1]) < second_line_length:
                difference = second_line_length - len(lines[-1])
                lines[-1] += ' ' * difference
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
            # Join hex data into a single string
            hex_string = '\n'.join(hex_data)
            return hex_string

    def hex_code_read(self, tc, pos, tcx, tcy, block_text, hex_start):
        self.hex_code_read_tc = tc
        self.hex_code_read_pos = pos
        self.hex_code_read_tcx = tcx
        self.hex_code_read_tcy = tcy
        self.hex_code_read_block_text = block_text
        self.hex_code_read_hex_start = hex_start
        addr, hex_code = get_hex_code(tc, pos, tcx, tcy, block_text, hex_start, "hex_code_read")
        if hex_code is None:
            return
        self.hex_code_read_widget = HexCodeReadWidget(hex_code)
        self.hex_code_read_widget.setWindowTitle(addr)
        self.hex_code_read_widget.set_label()
        cursor_pos = QCursor.pos()
        self.hex_code_read_widget.move(cursor_pos)
        self.hex_code_read_widget.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint)
        self.hex_code_read_widget.show()

    def copy_pointer(self, tc, pos, tcx, tcy, block_text, hex_start):
        addr, hex_code = get_hex_code(tc, pos, tcx, tcy, block_text, hex_start, "copy_pointer")
        pointer = hex(int(''.join(reversed(hex_code.split(' '))), 16))
        QApplication.clipboard().setText(pointer)


class HexDumpWidget(QWidget):
    def __init__(self, addr, args_index, dump_target_addr, on_leave):
        super().__init__()
        # Unique identifier for this instance.
        self.addr = addr
        self.args_index = args_index
        self.dump_target_addr = dump_target_addr
        self.on_leave = on_leave

        self.offset_input = QLineEdit(self)
        self.offset_input.setPlaceholderText("Offset")
        self.offset_input.returnPressed.connect(self.set_offset)
        self.offset_input.setAlignment(Qt.AlignmentFlag.AlignRight)

        self.address_input = QLineEdit(self)
        self.address_input.setPlaceholderText("Address")
        self.address_input.returnPressed.connect(self.set_address)
        self.address_input.setAlignment(Qt.AlignmentFlag.AlignRight)

        self.set_offset_button = QPushButton("Set", self)
        self.set_offset_button.clicked.connect(self.set_offset)
        self.set_address_button = QPushButton("set", self)
        self.set_address_button.clicked.connect(self.set_address)

        self.input_layout = QHBoxLayout()
        self.input_layout.addWidget(self.offset_input)
        self.input_layout.addWidget(self.set_offset_button)
        self.input_layout.addWidget(self.address_input)
        self.input_layout.addWidget(self.set_address_button)

        # self.text_edit = QTextEdit(self)
        self.text_edit = HexDumpTextEdit()
        font = QtGui.QFont("Courier New", 10) if platform.system() == 'Windows' else QtGui.QFont("Courier New", 13)
        self.text_edit.setFont(font)
        self.text_edit.setReadOnly(True)

        self.layout = QVBoxLayout()
        self.layout.addLayout(self.input_layout)
        self.layout.addWidget(self.text_edit)

        self.setLayout(self.layout)
        self.resize(650, 340) if platform.system() == 'Windows' else self.resize(670, 370)

        self.interested_widgets = []
        QApplication.instance().installEventFilter(self)

    @pyqtSlot(tuple)
    def hexdump_sig_func(self, sig: tuple):
        # Unpack the hexdump signal
        address, args_index, dump_target_addr, on_leave, message = sig
        args_index = str(args_index)
        # Check if the signal's key matches this widget's key
        # Case: target argument's value is not changing
        if (address == self.addr) and (args_index != "") and (args_index == self.args_index) and \
                (dump_target_addr == self.dump_target_addr) and (on_leave == self.on_leave):
            self.text_edit.setPlainText(message)
        # Case: the target argument's value is changing, but the rest of it matches.
        if (address == self.addr) and (args_index != "") and (args_index == self.args_index) and \
                (dump_target_addr != self.dump_target_addr) and (on_leave == self.on_leave):
            self.text_edit.setPlainText(message)
            if self.on_leave == 0:
                self.setWindowTitle(f"OnEnter HexDump args{self.args_index}: {dump_target_addr}")
            else:
                self.setWindowTitle(f"OnLeave HexDump args{self.args_index}: {dump_target_addr}")
        # Case: hexdump return value
        if (address == self.addr) and (args_index == "") and (args_index == self.args_index) and \
                (on_leave == self.on_leave):
            self.text_edit.setPlainText(message)
            if dump_target_addr != self.dump_target_addr:
                self.setWindowTitle(f"HexDump return: {dump_target_addr}")

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            self.close()
        else:
            super().keyPressEvent(event)

    def set_offset(self):
        text = self.offset_input.text()
        if text == '':
            text = "0x0"
        elif text != '':
            hex_regex = re.compile(r'(\b0x[a-fA-F0-9]+\b|\b[a-fA-F0-9]+\b)')
            match = hex_regex.match(text)
            if match is not None:
                if "0x" not in text:
                    text = "".join(("0x", text))

        try:
            gvar.frida_instrument.set_hex_dump_offset(self.addr, self.args_index, text)
        except Exception as e:
            print(e)
            return

    def set_address(self):
        text = self.address_input.text()
        if text == '':
            text = "0x0"
        elif text != '':
            hex_regex = re.compile(r'(\b0x[a-fA-F0-9]+\b|\b[a-fA-F0-9]+\b)')
            match = hex_regex.match(text)
            if match is not None:
                if "0x" not in text:
                    text = "".join(("0x", text))

        try:
            if "HexDump args" in self.windowTitle():
                gvar.frida_instrument.set_hex_dump_target_address(self.addr, self.args_index, text)
                if self.on_leave == 0:
                    self.setWindowTitle(f"OnEnter HexDump args{self.args_index}: {self.dump_target_addr if text == '0x0' else text}")
                else:
                    self.setWindowTitle(f"OnLeave HexDump args{self.args_index}: {self.dump_target_addr if text == '0x0' else text}")
            elif "HexDump return" in self.windowTitle():
                gvar.frida_instrument.set_hex_dump_target_address(self.addr, self.args_index, text)
                self.setWindowTitle(
                    f"HexDump return: {self.dump_target_addr if text == '0x0' else text}")
        except Exception as e:
            print(e)
            return

    def eventFilter(self, obj, event):
        self.interested_widgets = [self.offset_input, self.address_input]
        if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Tab:
            try:
                index = self.interested_widgets.index(self.focusWidget())
                self.interested_widgets[(index + 1) % len(self.interested_widgets)].setFocus()
            except ValueError:
                self.interested_widgets[0].setFocus()

            return True

        return super().eventFilter(obj, event)
