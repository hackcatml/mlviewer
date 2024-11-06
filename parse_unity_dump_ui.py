import platform

from PyQt6 import QtWidgets, QtCore


class DroppableTextEdit(QtWidgets.QTextEdit):
    file_dropped_sig = QtCore.pyqtSignal(str)

    def __init__(self, parent=None, text_edit_for_file1or2=None):
        super().__init__(parent)
        self.text_edit_for_file = text_edit_for_file1or2
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        for url in event.mimeData().urls():
            if url.isLocalFile():
                file_path = url.toLocalFile()
                self.clear()
                self.setText(file_path)
                self.file_dropped_sig.emit(file_path)


class Ui_ParseUnityDumpFileDialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(300, 150) if platform.system() == 'Windows' else Dialog.resize(250, 150)
        self.gridLayout = QtWidgets.QGridLayout(Dialog)
        self.gridLayout.setObjectName("gridLayout")
        self.textEdit = DroppableTextEdit(parent=Dialog, text_edit_for_file1or2="file")
        self.textEdit.setReadOnly(True)
        self.textEdit.setObjectName("textEdit")
        self.gridLayout.addWidget(self.textEdit, 0, 0, 1, 1)
        self.fileBtn = QtWidgets.QPushButton(Dialog)
        self.fileBtn.setObjectName("fileBtn")
        self.fileBtn.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)
        self.gridLayout.addWidget(self.fileBtn, 1, 0, 1, 1)
        self.doParseBtn = QtWidgets.QPushButton(Dialog)
        self.doParseBtn.setObjectName("doParseBtn")
        self.doParseBtn.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)
        self.gridLayout.addWidget(self.doParseBtn, 2, 0, 1, 1)

        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Parse Unity Dump File"))
        font_family = ".AppleSystemUIFont" if platform.system() == "Darwin" else "Courier New"
        font_size = "13pt" if platform.system() == "Darwin" else "9pt"
        self.textEdit.setHtml(_translate("Dialog",
                                             "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
                                             "<html><head><meta name=\"qrichtext\" content=\"1\" /><meta charset=\"utf-8\" /><style type=\"text/css\">\n"
                                             "p, li { white-space: pre-wrap; }\n"
                                             "hr { height: 1px; border-width: 0; }\n"
                                             "li.unchecked::marker { content: \"\\2610\"; }\n"
                                             "li.checked::marker { content: \"\\2612\"; }\n"
                                             f"</style></head><body style=\" font-family:{font_family}; font-size:{font_size}; font-weight:400; font-style:normal;\">\n"
                                             "<p align=\"center\" style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p>\n"
                                             "<p align=\"center\" style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">File </p>\n"
                                             "<p align=\"center\" style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">(Drag &amp; Drop)</p></body></html>"))
        self.fileBtn.setText(_translate("Dialog", "File"))
        self.doParseBtn.setText(_translate("Dialog", "Parse"))

