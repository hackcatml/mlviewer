from PyQt6 import QtGui, QtCore
from PyQt6.QtWidgets import QTextBrowser


class ListImgViewerClass(QTextBrowser):
    modulenamesig = QtCore.pyqtSignal(str)

    def __init__(self, args):
        super(ListImgViewerClass, self).__init__(args)

    def mousePressEvent(self, e: QtGui.QMouseEvent) -> None:
        super(ListImgViewerClass, self).mousePressEvent(e)
        pos = e.pos()
        tc = self.cursorForPosition(pos)
        if tc.block().text().startswith("Dumped file at:"):
            return
        self.modulenamesig.emit(tc.block().text())


class MemSearchResultBrowserClass(QTextBrowser):
    searchresultaddrsig = QtCore.pyqtSignal(str)

    def __init__(self, args):
        super(MemSearchResultBrowserClass, self).__init__(args)

    def mousePressEvent(self, e: QtGui.QMouseEvent) -> None:
        super(MemSearchResultBrowserClass, self).mousePressEvent(e)
        pos = e.pos()
        tc = self.cursorForPosition(pos)
        self.searchresultaddrsig.emit(tc.block().text()[:tc.block().text().find(', ')])
