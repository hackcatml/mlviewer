from PyQt6 import QtGui, QtCore
from PyQt6.QtWidgets import QTextBrowser


class ListImgViewerClass(QTextBrowser):
    module_name_signal = QtCore.pyqtSignal(str)

    def __init__(self, args):
        super(ListImgViewerClass, self).__init__(args)

    def mousePressEvent(self, e: QtGui.QMouseEvent) -> None:
        super(ListImgViewerClass, self).mousePressEvent(e)
        pos = e.pos()
        tc = self.cursorForPosition(pos)
        if tc.block().text().startswith("Dumped file at:"):
            return
        self.module_name_signal.emit(tc.block().text())


class MemSearchResultBrowserClass(QTextBrowser):
    search_result_addr_signal = QtCore.pyqtSignal(str)

    def __init__(self, args):
        super(MemSearchResultBrowserClass, self).__init__(args)

    def mousePressEvent(self, e: QtGui.QMouseEvent) -> None:
        super(MemSearchResultBrowserClass, self).mousePressEvent(e)
        pos = e.pos()
        tc = self.cursorForPosition(pos)
        self.search_result_addr_signal.emit(tc.block().text()[:tc.block().text().find(', ')])
