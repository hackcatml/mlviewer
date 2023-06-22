import inspect
import re

from PyQt6 import QtGui, QtCore
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QTextCursor, QAction, QCursor
from PyQt6.QtWidgets import QTextEdit, QApplication, QWidget, QVBoxLayout

import globvar


class HexViewerClass(QTextEdit):
    wheelupsig = QtCore.pyqtSignal(str)

    def __init__(self, args):
        super(HexViewerClass, self).__init__(args)
        self.hitcount = 0
        self.verticalScrollBar().sliderMoved.connect(self.setScrollBarPos)

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
                # define "Copy Hex" menu
                copy_hex_action = QAction("Copy Hex", self)
                copy_hex_action.setEnabled(bool(self.textCursor().selectedText()))
                copy_hex_action.triggered.connect(self.copy_hex)
                # define "Hex to Arm" menu
                disassemble_action = QAction("Hex to Arm", self)
                disassemble_action.setEnabled(bool(self.textCursor().selectedText()))
                disassemble_action.triggered.connect(self.request_armconverter)
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
            self.new_widget = NewTextWidget(hex_to_arm_result)
            cursor_pos = QCursor.pos()
            # Move the widget to the cursor position
            self.new_widget.move(cursor_pos)
            self.new_widget.show()
        else:
            print("Fail to hex to arm convert")


class NewTextWidget(QWidget):
    def __init__(self, text):
        super().__init__()
        self.setWindowTitle("HEX to ARM")
        self.text_edit = QTextEdit()
        self.text_edit.setPlainText(text)
        self.text_edit.setReadOnly(True)  # Make the text edit read-only
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.text_edit)
        self.setLayout(self.layout)
