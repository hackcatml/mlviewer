import inspect
import re

from PyQt6 import QtGui, QtCore
from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QTextCursor, QAction, QCursor
from PyQt6.QtWidgets import QTextEdit, QApplication, QWidget, QVBoxLayout, QSlider, QLabel, QHBoxLayout, QPushButton, \
    QCheckBox, QWidgetAction

import gvar


class HexViewerClass(QTextEdit):
    wheel_up_signal = QtCore.pyqtSignal(str)
    wheel_signal = QtCore.pyqtSignal(str)
    scroll_signal = QtCore.pyqtSignal(int)
    move_signal = QtCore.pyqtSignal(int)
    refresh_signal = QtCore.pyqtSignal(int)

    def __init__(self, args):
        super(HexViewerClass, self).__init__(args)
        self.hit_count = 0
        self.verticalScrollBar().sliderMoved.connect(self.setScrollBarPos)
        self.statusBar = None
        self.new_watch_widget = NewWatchWidget()
        # hexviewer text changed event
        self.textChanged.connect(self.text_changed_event)

    def setScrollBarPos(self, value):
        # print("[hackcatml] slidermoved: ", value)
        self.scroll_signal.emit(value)
        gvar.current_frame_block_number = round(value / 15)

    # wheelevent https://spec.tistory.com/449
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
        # if key is hexedit shortcut key then just return. if not hexeditor behavior is weird
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

        # change color on edited hex as black -> red
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

        # backspace, delete, enter, left key and space is not allowed
        if e.key() in (
                QtCore.Qt.Key.Key_Backspace, QtCore.Qt.Key.Key_Delete, QtCore.Qt.Key.Key_Return, Qt.Key.Key_Left, Qt.Key.Key_Space
        ): return

        # hexedit 모드에서 ctrl + a, cmd + a (select all), ctrl + v, cmd + v (paste) is not allowed
        # if self.isReadOnly() is False:
        if (e.keyCombination().keyboardModifiers() == QtCore.Qt.KeyboardModifier.MetaModifier or e.keyCombination().keyboardModifiers() == QtCore.Qt.KeyboardModifier.ControlModifier) and e.key() == QtCore.Qt.Key.Key_A:
            # print("ctrl + a, cmd + a is not allowed")
            return
        if (e.keyCombination().keyboardModifiers() == QtCore.Qt.KeyboardModifier.MetaModifier or e.keyCombination().keyboardModifiers() == QtCore.Qt.KeyboardModifier.ControlModifier) and e.key() == QtCore.Qt.Key.Key_V:
            # print("ctrl + v, cmd + v is not allowed")
            return

        # cmd, ctrl, alt, shift + up, right, left, down selection not allowed
        # print(str(e.keyCombination().keyboardModifiers()))
        if str(e.keyCombination().keyboardModifiers()) in ["KeyboardModifier.KeypadModifier|ShiftModifier", "KeyboardModifier.AltModifier", "KeyboardModifier.KeypadModifier|ControlModifier|ShiftModifier", "KeyboardModifier.KeypadModifier|MetaModifier|ShiftModifier","KeyboardModifier.KeypadModifier|AltModifier|ShiftModifier", "KeyboardModifier.KeypadModifier|ControlModifier"]: return

        # editable only hex area. indices => [9, 10, 13, 16, 19, 22, 25, 28, 31, 34, 37, 40, 43, 46, 49, 52, 55, 58, 59]
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
        # memory pattern search 한 결과창에서 마우스 클릭한 경우
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

        # mouse left click on non hex editable region at normal hexviewer
        if e.buttons() == QtCore.Qt.MouseButton.LeftButton and len(indices) > 0:
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
        # If in hexedit mode, don't create a context menu on right click
        if not self.isReadOnly():
            return

        tc = self.cursorForPosition(e.pos())
        tcx = tc.positionInBlock()

        menu = super(HexViewerClass, self).createStandardContextMenu()  # Get the default context menu
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
            disassemble_action = create_action("Hex to Arm", is_selected and match is None, self.request_armconverter)

            copy_pointer_action = None
            if gvar.frida_instrument is None:
                self.statusBar.showMessage(f"Attach first", 3000)
                return
            addr_match = hex_regex.match(tc.block().text())
            if addr_match is not None:
                addr_length = len(addr_match[0])
                hex_start = addr_length + 2
                cursor_len_4bytes = 12  # '00 00 00 00 '
                cursor_len_8bytes = 2 * 12
                if gvar.arch == "arm64" and (tcx in [hex_start, hex_start + 1, hex_start + 2] or tcx in [hex_start + cursor_len_8bytes, hex_start + cursor_len_8bytes + 1, hex_start + cursor_len_8bytes + 2]):
                    make_copy_pointer_action = True
                elif gvar.arch == "arm" and (tcx in [hex_start, hex_start + 1, hex_start + 2] or tcx in [hex_start + cursor_len_4bytes, hex_start + cursor_len_4bytes + 1, hex_start + cursor_len_4bytes + 2] or tcx in [hex_start + cursor_len_8bytes, hex_start + cursor_len_8bytes + 1, hex_start + cursor_len_8bytes + 2] or tcx in [hex_start + 3 * cursor_len_4bytes, hex_start + 3 * cursor_len_4bytes + 1, hex_start + 3 * cursor_len_4bytes + 2]):
                    make_copy_pointer_action = True
                else:
                    make_copy_pointer_action = False

                if make_copy_pointer_action:
                    copy_pointer_action = create_action("Copy Pointer", match is None,
                                                        lambda: self.copy_pointer(tc, hex_start))

            if match:
                watch_action = create_action("Set Watch Func", True, lambda: self.set_watch_on_addr("watch_func"))
                watch_regs_action = create_action("Set Watch Regs", True, lambda: self.set_watch_on_addr("watch_regs"))

                menu.insertAction(select_all_action, watch_action)
                menu.insertAction(select_all_action, watch_regs_action)

            menu.insertAction(select_all_action, copy_hex_action)
            menu.insertAction(select_all_action, disassemble_action)
            if copy_pointer_action is not None:
                menu.insertAction(select_all_action, copy_pointer_action)

        menu.exec(e.globalPos())

    def text_changed_event(self):
        tc = self.textCursor()
        tcx = tc.positionInBlock()
        line = tc.block().text()
        # print("[hackcatml] text changed: " + tc.block().text())

        # if tc.block().text() == "", index out of error occurs
        if line == "": return

        # check if it's the mem scan result view
        if self.toPlainText() is not None and re.search(r"\d+\. 0x[0-9a-f]+, module:", self.toPlainText()):
            is_mem_scan_result_view = True
        else:
            is_mem_scan_result_view = False

        # if changed text is not hex, then refresh the hex viewer
        # print(f"text: {line[len(line) - 66:len(line) - 16]}")
        if re.search(r"[^0-9a-f\s]+", line[len(line) - 66:len(line) - 16]) and not re.search(r"\d+\. 0x[0-9a-f]+, module:", line):
            if is_mem_scan_result_view:
                self.setText(gvar.current_mem_scan_hex_view_result)
            else:
                self.refresh_signal.emit(1) if gvar.is_frida_attached else None
            return

        indices = [i for i, x in enumerate(line) if x == " "]
        try:
            hexstart = indices[1] + 1
        except Exception as e:
            print(f"{inspect.currentframe().f_code.co_name}: {e}")
            self.clear()
            return

        # print("[hackcatml] (tcx - hexstart) // 3 = ", (tcx - hexstart) // 3)
        if (tcx - hexstart) // 3 < 0 or (tcx - hexstart) // 3 > 15: return

        addr = hex(int(line[:line.find(" ")], 16) + (tcx - hexstart) // 3)
        # print("[hackcatml] text changed addr: ", addr)

        changed = line[3 * ((tcx - hexstart) // 3) + hexstart: 3 * ((tcx - hexstart) // 3) + hexstart + 2]
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
        # print(f"text changed pos: {tcx}")

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
        QApplication.clipboard().setText(hex_string)  # copies the hex text to the clipboard

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
            self.new_hex_to_arm_widget = NewHexToArmWidget(hex_to_arm_result)
            cursor_pos = QCursor.pos()
            # Move the widget to the cursor position
            self.new_hex_to_arm_widget.move(cursor_pos)
            self.new_hex_to_arm_widget.show()
        else:
            print("Fail to hex to arm convert")

    def copy_pointer(self, tc: QTextCursor, hex_start):
        tcx = tc.positionInBlock()
        cursor_len_4bytes = 12
        cursor_len_8bytes = 12 * 2
        hex_code = None
        if tcx in [hex_start, hex_start + 1, hex_start + 2]:
            hex_code = tc.block().text()[hex_start:hex_start + cursor_len_8bytes - 1] if gvar.arch == "arm64" else tc.block().text()[hex_start:hex_start + cursor_len_4bytes - 1]
        elif tcx in [hex_start + cursor_len_4bytes, hex_start + cursor_len_4bytes + 1, hex_start + cursor_len_4bytes + 2]:
            hex_code = tc.block().text()[hex_start + cursor_len_4bytes:hex_start + cursor_len_8bytes - 1]
        elif tcx in [hex_start + cursor_len_8bytes, hex_start + cursor_len_8bytes + 1, hex_start + cursor_len_8bytes + 2]:
            hex_code = tc.block().text()[hex_start + cursor_len_8bytes:hex_start + 2 * cursor_len_8bytes - 1] if gvar.arch == "arm64" else tc.block().text()[hex_start + cursor_len_8bytes:hex_start + 3 * cursor_len_4bytes - 1]
        elif tcx in [hex_start + 3 * cursor_len_4bytes, hex_start + 3 * cursor_len_4bytes + 1, hex_start + 3 * cursor_len_4bytes + 2]:
            hex_code = tc.block().text()[hex_start + 3 * cursor_len_4bytes:hex_start + 4 * cursor_len_4bytes - 1]
        pointer = hex(int(''.join(reversed(hex_code.split(' '))), 16))
        QApplication.clipboard().setText(pointer)

    @pyqtSlot(str)
    def messagesig_func(self, message: str):
        # print(f"watching...{message}")
        # Append the new message to the text edit
        self.new_watch_widget.text_edit.append(message)

    def set_watch_on_addr(self, action_type):
        tc = self.textCursor()
        indices = [i for i, x in enumerate(tc.block().text()) if x == " "]
        self.new_watch_widget.addr_to_watch = ''.join(('0x', tc.block().text()[:indices[0]])).strip()
        try:
            if not self.new_watch_widget.watch_list and not gvar.frida_instrument.receivers(gvar.frida_instrument.message_signal):
                # watch list is empty. set connect once
                gvar.frida_instrument.message_signal.connect(self.messagesig_func)

            if self.new_watch_widget.addr_to_watch not in self.new_watch_widget.watch_list:
                watch_regs = False
                minimum_nargs = 1
                default_nargs = 3
                maximum_nargs = 10

                if action_type == "watch_regs":
                    watch_regs = True
                    default_nargs = 5
                    maximum_nargs = 34

                self.new_watch_widget.slider.setMinimum(minimum_nargs)  # Minimum number of arguments to watch
                self.new_watch_widget.slider.setMaximum(maximum_nargs)  # Maximum number of arguments to watch
                self.new_watch_widget.slider.setValue(default_nargs)  # Default number of arguments to watchZ
                # print(f"set watch on {self.new_watch_widget.addr_to_watch}")
                gvar.frida_instrument.set_nargs(default_nargs)
                gvar.frida_instrument.set_watch(self.new_watch_widget.addr_to_watch, watch_regs)
                self.new_watch_widget.watch_list.append(self.new_watch_widget.addr_to_watch)
        except Exception as e:
            print(f"{inspect.currentframe().f_code.co_name}: {e}")
            return

        cursor_pos = QCursor.pos()
        # Move the widget to the cursor position
        self.new_watch_widget.move(cursor_pos)
        # self.new_watch_widget.setWindowFlags(Qt.WindowType.Dialog)
        self.new_watch_widget.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint)
        self.new_watch_widget.show()


class NewHexToArmWidget(QWidget):
    def __init__(self, text):
        super().__init__()
        self.setWindowTitle("HEX to ARM")
        self.text_edit = QTextEdit()
        self.text_edit.setPlainText(text)
        self.text_edit.setReadOnly(True)  # Make the text edit read-only
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.text_edit)
        self.setLayout(self.layout)


# Custom TextEdit class for NewWatchWidget
class CustomTextEdit(QTextEdit):
    def __init__(self, parent=None):
        super(CustomTextEdit, self).__init__(parent)
        self.key = None
        self.args_index = None
        self.addr = None
        self.checkedStates = {}

    def closeEvent(self, e: QtGui.QCloseEvent) -> None:
        self.checkedStates.clear()

    def get_args_index_and_addr_from_selected_text(self):
        # Get the currently selected text
        tc = self.textCursor()
        selected_text = self.textCursor().selectedText()
        if ":" in selected_text:
            self.args_index = selected_text[4:selected_text.index(":")]
        else:
            self.args_index = selected_text[4:]

        while True:
            tc.movePosition(QTextCursor.MoveOperation.Up, QTextCursor.MoveMode.MoveAnchor)
            if re.search(r"] 0x[a-f0-9]+", tc.block().text()):
                self.addr = tc.block().text()[4:].strip()
                break

    def contextMenuEvent(self, e: QtGui.QContextMenuEvent) -> None:
        menu = super(CustomTextEdit, self).createStandardContextMenu()  # Get the default context menu
        select_all_action = None
        self.get_args_index_and_addr_from_selected_text()

        for action in menu.actions():  # loop over the existing actions
            if "Select All" in action.text():
                select_all_action = action
                break

        if select_all_action:  # if the "Select All" action was found then insert menus
            args_regx = re.compile(r'(\bargs\d+\b|\breturn\b)')
            match = args_regx.match(self.textCursor().selectedText())

            on_leave_check = QCheckBox("OnLeave", self)
            if match is not None:
                self.key = (self.addr, self.args_index)  # Use a tuple as the key
                # If the key is not in the checkedStates dictionary, add it with a default state of unchecked
                if self.key not in self.checkedStates:
                    self.checkedStates[self.key] = Qt.CheckState.Unchecked.value
                # Set the checked state based on the checkedStates dictionary
                on_leave_check.setCheckState(Qt.CheckState(self.checkedStates[self.key]))
                # Connect the checkbox's stateChanged signal to a function
                on_leave_check.stateChanged.connect(lambda state: self.on_leave_check_state_changed(state, self.key))

                check_action = QWidgetAction(self)
                check_action.setDefaultWidget(on_leave_check)
                menu.insertAction(select_all_action, check_action)

                actions = [
                    ("readPointer", self.read_pointer),
                    ("readUtf8String", self.read_utf8_string),
                    ("readUtf16String", self.read_utf16_string),
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

            # Show the context menu.
            menu.exec(e.globalPos())

    # handle the checkbox state change
    def on_leave_check_state_changed(self, state, key):
        # Update the checked state in the checkedStates dictionary
        self.checkedStates[key] = state

    def read_pointer(self):
        self.read_args_with_options("readPointer")

    def read_utf8_string(self):
        self.read_args_with_options("readUtf8String")

    def read_utf16_string(self):
        self.read_args_with_options("readUtf16String")

    def read_float(self):
        self.read_args_with_options("readFloat")

    def read_double(self):
        self.read_args_with_options("readDouble")

    def read_bytearray(self):
        self.read_args_with_options("readByteArray")

    def reset(self):
        self.read_args_with_options("")

    def read_args_with_options(self, option):
        try:
            if self.textCursor().selectedText() == "return":
                gvar.frida_instrument.set_read_retval_options(self.addr, option)
            else:
                gvar.frida_instrument.set_read_args_options(self.addr, self.args_index, option,
                                                              self.checkedStates[self.key])
        except Exception as e:
            print(f"{inspect.currentframe().f_code.co_name}: {e}")
            return


class NewWatchWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Watch on Addr")
        self.addr_to_watch = ''
        self.watch_list = []
        self.text_edit = CustomTextEdit()
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
        self.resize(450, 250)

    def closeEvent(self, e: QtGui.QCloseEvent) -> None:
        self.text_edit.clear()
        self.text_edit.closeEvent(e)
        self.watch_list.clear()
        try:
            if gvar.frida_instrument is not None:
                gvar.frida_instrument.detach_all()
        except Exception as e:
            print(f"{inspect.currentframe().f_code.co_name}: {e}")
            if str(e) == gvar.ERROR_SCRIPT_DESTROYED:
                gvar.frida_instrument.sessions.clear()
            return

        super().closeEvent(e)

    @pyqtSlot(int)
    def update_num_args(self, num_args: int):
        try:
            gvar.frida_instrument.set_nargs(num_args)
        except Exception as e:
            print(f"{inspect.currentframe().f_code.co_name}: {e}")
            return

    @pyqtSlot(int)
    def update_slider_value_label(self, value):
        self.slider_value_label.setText(str(value))

