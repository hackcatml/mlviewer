import inspect
import re

from PyQt6 import QtGui, QtCore
from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QTextCursor, QAction, QCursor
from PyQt6.QtWidgets import QTextEdit, QApplication, QWidget, QVBoxLayout, QSlider, QLabel, QHBoxLayout, QListWidget, \
    QPushButton, QMenu, QCheckBox, QWidgetAction

import globvar


class HexViewerClass(QTextEdit):
    wheelupsig = QtCore.pyqtSignal(str)

    def __init__(self, args):
        super(HexViewerClass, self).__init__(args)
        self.hitcount = 0
        self.verticalScrollBar().sliderMoved.connect(self.setScrollBarPos)

        self.new_watch_widget = NewWatchWidget()

    def setScrollBarPos(self, value):
        # print("[hackcatml] slidermoved: ", value)
        globvar.currentFrameBlockNumber = round(value / 15)

    # wheelevent https://spec.tistory.com/449
    def wheelEvent(self, e: QtGui.QWheelEvent) -> None:
        # wheel down
        if e.angleDelta().y() < 0:
            globvar.currentFrameBlockNumber += -1 * e.angleDelta().y() / 120 * 4
        # wheel up
        elif e.angleDelta().y() > 0 and globvar.currentFrameBlockNumber > 0:
            globvar.currentFrameBlockNumber -= e.angleDelta().y() / 120 * 4

        tc = self.textCursor()
        tc.movePosition(QTextCursor.MoveOperation.Start, QTextCursor.MoveMode.MoveAnchor, 1)
        tc.movePosition(QTextCursor.MoveOperation.Down, QTextCursor.MoveMode.MoveAnchor, globvar.currentFrameBlockNumber)
        globvar.currentFrameStartAddress = "".join(("0x", tc.block().text()[:tc.block().text().find(' ')]))

        if tc.blockNumber() == 0 and re.search(r"\d+\. 0x[0-9a-f]+, module:", tc.block().text()) is None:
            self.hitcount += 1
            if self.hitcount > 0:
                self.wheelupsig.emit(globvar.currentFrameStartAddress)
                self.hitcount = 0

        # print("[hackcatml] globvar.currentFrameBlockNumber: ", globvar.currentFrameBlockNumber)
        # print("[hackcatml] tc.blockNumber(): ", tc.blockNumber())
        # print("[hackcatml] tc.block().text(): ", tc.block().text())
        # print("[hackcatml] globvar.currentFrameStartAddress: ", globvar.currentFrameStartAddress)

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

        # backspace, delete, enter, left key is not allowed
        if e.key() in (
                QtCore.Qt.Key.Key_Backspace, QtCore.Qt.Key.Key_Delete, QtCore.Qt.Key.Key_Return, Qt.Key.Key_Left
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
        tcy = tc.blockNumber()
        # print(tc.block().text())
        # print("mousepress pos: ", tcx, tcy)

        indices = [i for i, x in enumerate(tc.block().text()) if x == " "]
        # memory pattern search 한 결과창에서 마우스 클릭한 경우
        if len(indices) == 0:
            for i in range(2): self.moveCursor(QTextCursor.MoveOperation.Up)
            self.moveCursor(QTextCursor.MoveOperation.NextWord)
            return
        # elif tc.block().text().find(', module:') != -1:
        elif re.search(r"\d+\. 0x[a-f0-9]+, module:", tc.block().text()):
            self.moveCursor(QTextCursor.MoveOperation.Down)
            self.moveCursor(QTextCursor.MoveOperation.StartOfBlock)
            self.moveCursor(QTextCursor.MoveOperation.NextWord)
            return
        # mouse left click on non hex editable region at normal hexviewer
        if e.buttons() == QtCore.Qt.MouseButton.LeftButton and len(indices) > 0:
            # ADDRESS region
            if tcx in range(indices[1] + 1):
                self.moveCursor(QTextCursor.MoveOperation.NextWord)
                return
            # ASCII String Region
            if tcx in range(indices[len(indices) - 1], len(tc.block().text()) + 1):
                self.moveCursor(QTextCursor.MoveOperation.StartOfLine)
                for i in range(len(indices) - 3): self.moveCursor(QTextCursor.MoveOperation.NextWord)
                return
            # if (tcx - 9) % 3 == 0 or (tcx - 9) % 3 == 1:
            if tcx in indices or (tcx + 1) in indices:
                self.moveCursor(QTextCursor.MoveOperation.PreviousWord)
                return

    def contextMenuEvent(self, e: QtGui.QContextMenuEvent) -> None:
        # hexedit 모드인 경우 마우스 우측 버튼 클릭으로 메뉴 생성 안되게 하기 https://freeprog.tistory.com/334
        if self.isReadOnly() is False:
            return
        else:
            menu = super(HexViewerClass, self).createStandardContextMenu()  # Get the default context menu
            select_all_action = None
            for action in menu.actions():  # loop over the existing actions
                if action.text() == "Select All":
                    select_all_action = action
                    break

            if select_all_action:  # if the "Select All" action was found then insert menus
                hex_regex = re.compile(r'(\b0x[a-fA-F0-9]+\b|\b[a-fA-F0-9]{6,}\b)')
                match = hex_regex.match(self.textCursor().selectedText())

                # define "Copy Hex" menu
                copy_hex_action = QAction("Copy Hex", self)
                copy_hex_action.setEnabled(bool(self.textCursor().selectedText()))
                # in address region, not selectable
                if match is not None:
                    copy_hex_action.setEnabled(False)
                copy_hex_action.triggered.connect(self.copy_hex)

                # define "Hex to Arm" menu
                disassemble_action = QAction("Hex to Arm", self)
                disassemble_action.setEnabled(bool(self.textCursor().selectedText()))
                # in address region, not selectable
                if match is not None:
                    disassemble_action.setEnabled(False)
                disassemble_action.triggered.connect(self.request_armconverter)

                # define "Set Watch" menu only selectable in address region
                watch_action = QAction("Set Watch Func")
                if match is not None:
                    watch_action.setEnabled(True)
                    watch_action.triggered.connect(lambda: self.set_watch_on_addr("watch_func"))
                    menu.insertAction(select_all_action, watch_action)

                # define "Set Watch Regs" menu only selectable in address region
                watch_regs_action = QAction("Set Watch Regs")
                if match is not None:
                    watch_regs_action.setEnabled(True)
                    watch_regs_action.triggered.connect(lambda: self.set_watch_on_addr("watch_regs"))
                    menu.insertAction(select_all_action, watch_regs_action)

                # insert menus
                menu.insertAction(select_all_action, copy_hex_action)
                menu.insertAction(select_all_action, disassemble_action)

            menu.exec(e.globalPos())

    def selected_text(self, request_to_armconverter: bool) -> str:
        selected_text = self.textCursor().selectedText()  # gets the currently selected text
        selected_text = selected_text.replace('\u2029', '\n')
        lines = selected_text.strip().split('\n')
        hex_string = ''
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
        arch = ''
        try:
            arch = globvar.fridaInstrument.arch()
        except Exception as e:
            print(f"{inspect.currentframe().f_code.co_name}: {e}")
            return

        payload = {"hex":hex_string,"offset":"","arch":[arch]}
        response = requests.post(url, json=payload)
        data = response.json()

        if data['asm'][arch][0] is True:
            hex_to_arm_result = data['asm'][arch][1]
            # Show the copied text in a new widget
            self.new_hex_to_arm_widget = NewHexToArmWidget(hex_to_arm_result)
            cursor_pos = QCursor.pos()
            # Move the widget to the cursor position
            self.new_hex_to_arm_widget.move(cursor_pos)
            self.new_hex_to_arm_widget.show()
        else:
            print("Fail to hex to arm convert")

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
            if not self.new_watch_widget.watch_list:
                # watch list is empty. set connect once
                globvar.fridaInstrument.messagesig.connect(self.messagesig_func)

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
                globvar.fridaInstrument.set_nargs(default_nargs)
                globvar.fridaInstrument.set_watch(self.new_watch_widget.addr_to_watch, watch_regs)
                self.new_watch_widget.watch_list.append(self.new_watch_widget.addr_to_watch)
        except Exception as e:
            print(f"{inspect.currentframe().f_code.co_name}: {e}")
            return

        cursor_pos = QCursor.pos()
        # Move the widget to the cursor position
        self.new_watch_widget.move(cursor_pos)
        self.new_watch_widget.setWindowFlags(Qt.WindowType.Dialog)
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
            if action.text() == "Select All":
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

            read_pointer_action = QAction("readPointer", self)
            if match is not None:
                read_pointer_action.setEnabled(True)
                read_pointer_action.triggered.connect(self.read_pointer)
                menu.insertAction(select_all_action, read_pointer_action)

            read_utf8_action = QAction("readUtf8String", self)
            if match is not None:
                read_utf8_action.setEnabled(True)
                read_utf8_action.triggered.connect(self.read_utf8_string)
                menu.insertAction(select_all_action, read_utf8_action)

            read_utf16_action = QAction("readUtf16String", self)
            if match is not None:
                read_utf16_action.setEnabled(True)
                read_utf16_action.triggered.connect(self.read_utf16_string)
                menu.insertAction(select_all_action, read_utf16_action)

            read_float_action = QAction("readFloat", self)
            if match is not None:
                read_float_action.setEnabled(True)
                read_float_action.triggered.connect(self.read_float)
                menu.insertAction(select_all_action, read_float_action)

            read_double_action = QAction("readDouble", self)
            if match is not None:
                read_double_action.setEnabled(True)
                read_double_action.triggered.connect(self.read_double)
                menu.insertAction(select_all_action, read_double_action)

            read_bytearray_action = QAction("readByteArray", self)
            if match is not None:
                read_bytearray_action.setEnabled(True)
                read_bytearray_action.triggered.connect(self.read_bytearray)
                menu.insertAction(select_all_action, read_bytearray_action)

            read_reset_action = QAction("reset", self)
            if match is not None:
                read_reset_action.setEnabled(True)
                read_reset_action.triggered.connect(self.reset)
                menu.insertAction(select_all_action, read_reset_action)

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
                globvar.fridaInstrument.set_read_retval_options(self.addr, option)
            else:
                globvar.fridaInstrument.set_read_args_options(self.addr, self.args_index, option,
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
            globvar.fridaInstrument.detach_all()
        except Exception as e:
            print(f"{inspect.currentframe().f_code.co_name}: {e}")
            if str(e) == globvar.errorType1:
                globvar.fridaInstrument.sessions.clear()
            return

        super().closeEvent(e)

    @pyqtSlot(int)
    def update_num_args(self, num_args: int):
        try:
            globvar.fridaInstrument.set_nargs(num_args)
        except Exception as e:
            print(f"{inspect.currentframe().f_code.co_name}: {e}")
            return

    @pyqtSlot(int)
    def update_slider_value_label(self, value):
        self.slider_value_label.setText(str(value))

