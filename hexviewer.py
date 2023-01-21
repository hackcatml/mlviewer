import re

from PyQt6 import QtGui, QtCore
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QTextCursor
from PyQt6.QtWidgets import QTextEdit

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
            self.setTextColor(QtGui.QColor("black"))

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

    def contextMenuEvent(self, e: QtGui.QContextMenuEvent) -> None:
        # hexedit 모드인 경우 마우스 우측 버튼 클릭으로 메뉴 생성 안되게 하기 https://freeprog.tistory.com/334
        if self.isReadOnly() is False:
            return
        else:
            return super(HexViewerClass, self).contextMenuEvent(e)

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




