import platform

from PyQt6 import QtCore, QtGui, QtWidgets


class Ui_prepareGadgetDialogUi(object):
    def setupUi(self, prepareGadgetDialogUi):
        prepareGadgetDialogUi.setObjectName("prepareGadgetDialogUi")
        prepareGadgetDialogUi.resize(600, 350) if platform.system() == 'Windows' else prepareGadgetDialogUi.resize(690, 350)
        font = QtGui.QFont()
        font.setFamily("Courier New")
        prepareGadgetDialogUi.setFont(font)
        self.gridLayout = QtWidgets.QGridLayout(prepareGadgetDialogUi)
        self.gridLayout.setObjectName("gridLayout")
        self.prepareGadgetBrowser = QtWidgets.QTextBrowser(prepareGadgetDialogUi)
        self.prepareGadgetBrowser.setObjectName("prepareGadgetBrowser")
        self.gridLayout.addWidget(self.prepareGadgetBrowser, 0, 0, 1, 3)
        self.fridaPortalModeCheckBox = QtWidgets.QCheckBox(prepareGadgetDialogUi)
        self.fridaPortalModeCheckBox.setObjectName("fridaPortalModeCheckBox")
        self.gridLayout.addWidget(self.fridaPortalModeCheckBox, 1, 0, 1, 1)
        self.pkgNameInput = QtWidgets.QLineEdit(prepareGadgetDialogUi)
        self.pkgNameInput.setEnabled(True)
        self.pkgNameInput.setFocusPolicy(QtCore.Qt.FocusPolicy.StrongFocus)
        self.pkgNameInput.setText("")
        self.pkgNameInput.setFrame(True)
        self.pkgNameInput.setObjectName("pkgNameInput")
        self.gridLayout.addWidget(self.pkgNameInput, 2, 0, 1, 1)
        self.sleepTimeInput = QtWidgets.QLineEdit(prepareGadgetDialogUi)
        self.sleepTimeInput.setFocusPolicy(QtCore.Qt.FocusPolicy.StrongFocus)
        self.sleepTimeInput.setText("")
        self.sleepTimeInput.setObjectName("sleepTimeInput")
        self.gridLayout.addWidget(self.sleepTimeInput, 2, 1, 1, 1)
        self.prepareGadgetBtn = QtWidgets.QPushButton(prepareGadgetDialogUi)
        self.prepareGadgetBtn.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)
        self.prepareGadgetBtn.setObjectName("prepareGadgetBtn")
        self.gridLayout.addWidget(self.prepareGadgetBtn, 2, 2, 1, 1)
        self.fridaPortalListeningLabel = QtWidgets.QLabel(prepareGadgetDialogUi)
        self.fridaPortalListeningLabel.setObjectName("fridaPortalListeningLabel")
        self.gridLayout.addWidget(self.fridaPortalListeningLabel, 1, 1, 1, 1)

        self.retranslateUi(prepareGadgetDialogUi)
        QtCore.QMetaObject.connectSlotsByName(prepareGadgetDialogUi)

    def retranslateUi(self, prepareGadgetDialogUi):
        _translate = QtCore.QCoreApplication.translate
        if platform.system() == 'Darwin':
            prepareGadgetDialogUi.setWindowTitle(_translate("prepareGadgetDialogUi", "Prepare Gadget"))
            self.prepareGadgetBrowser.setHtml(_translate("prepareGadgetDialogUi",
                                                         "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
                                                         "<html><head><meta name=\"qrichtext\" content=\"1\" /><meta charset=\"utf-8\" /><style type=\"text/css\">\n"
                                                         "p, li { white-space: pre-wrap; }\n"
                                                         "hr { height: 1px; border-width: 0; }\n"
                                                         "li.unchecked::marker { content: \"\\2610\"; }\n"
                                                         "li.checked::marker { content: \"\\2612\"; }\n"
                                                         "</style></head><body style=\" font-family:\'Courier New\'; font-size:13pt; font-weight:400; font-style:normal;\">\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-weight:700;\">[*] Introdunction</span></p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Prepare the zygisk module to load frida-gadget upon the application\'s startup.</p>\n"
                                                         "<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-weight:700;\"><br /></p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-weight:700;\">[*] Prerequisites</span></p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">1. Zygisk enabled.</p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">2. ADB enabled.</p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">3. Turn off frida-server on your device, if it\'s on.</p>\n"
                                                         "<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-weight:700;\">[*] Usage</span></p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">1. Enter the package name (e.g., com.android.chrome).</p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">2. Enter the sleep time (in microseconds) to delay the loading of the frida-gadget.</p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">3. Click the &quot;Prepare&quot; button. Your device will reboot.</p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">4. After rebooting, launch the target app.</p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">5. Attach to the target app.</p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-weight:700;\">[*] frida-portal mode</span></p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">In this mode, the gadget will attempt to attach to your computer. </p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Ensure that your device and computer are on the same local network.</p>\n"
                                                         "<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-weight:700;\">[*] Remove</span></p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">1. Remove the ZygiskGadget module in Magisk Manager.</p>\n"
                                                         "</body></html>"))
        elif platform.system() == 'Windows':
            prepareGadgetDialogUi.setWindowTitle(_translate("prepareGadgetDialogUi", "Prepare Gadget"))
            self.prepareGadgetBrowser.setHtml(_translate("prepareGadgetDialogUi",
                                                         "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
                                                         "<html><head><meta name=\"qrichtext\" content=\"1\" /><meta charset=\"utf-8\" /><style type=\"text/css\">\n"
                                                         "p, li { white-space: pre-wrap; }\n"
                                                         "hr { height: 1px; border-width: 0; }\n"
                                                         "li.unchecked::marker { content: \"\\2610\"; }\n"
                                                         "li.checked::marker { content: \"\\2612\"; }\n"
                                                         "</style></head><body style=\" font-family:\'Courier New\'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-weight:700;\">[*] Introdunction</span></p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Prepare the zygisk module to load frida-gadget upon the application\'s startup.</p>\n"
                                                         "<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px; font-weight:700;\"><br /></p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-weight:700;\">[*] Prerequisites</span></p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">1. Zygisk enabled.</p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">2. ADB enabled.</p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">3. Turn off frida-server on your device, if it\'s on.</p>\n"
                                                         "<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-weight:700;\">[*] Usage</span></p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">1. Enter the package name (e.g., com.android.chrome).</p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">2. Enter the sleep time (in microseconds) to delay the loading of the frida-gadget.</p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">3. Click the &quot;Prepare&quot; button. Your device will reboot.</p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">4. After rebooting, launch the target app.</p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">5. Attach to the target app.</p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-weight:700;\">[*] frida-portal mode</span></p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">In this mode, the gadget will attempt to attach to your computer. </p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Ensure that your device and computer are on the same local network.</p>\n"
                                                         "<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-weight:700;\">[*] Remove</span></p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Remove the ZygiskGadget module in Magisk Manager.</p></body></html>"))
        self.pkgNameInput.setPlaceholderText(_translate("prepareGadgetDialogUi", "com.android.chrome"))
        self.fridaPortalModeCheckBox.setText(_translate("prepareGadgetDialogUi", "frida-portal mode"))
        self.prepareGadgetBtn.setText(_translate("prepareGadgetDialogUi", "Prepare"))
        self.sleepTimeInput.setPlaceholderText(_translate("prepareGadgetDialogUi", "sleep time(e.g., 500000)"))
        self.pkgNameInput.setPlaceholderText(_translate("prepareGadgetDialogUi", "com.android.chrome"))
        self.prepareGadgetBtn.setText(_translate("prepareGadgetDialogUi", "Prepare"))
        self.fridaPortalListeningLabel.setText(_translate("prepareGadgetDialogUi", ""))
