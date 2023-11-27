import os
import shutil
import warnings
import zipfile
import platform

from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtCore import Qt, QEvent
from PyQt6.QtWidgets import QApplication


def unzip(target_zip: str, target_file: str) -> None:
    # Open the zip file using 'with' statement
    with zipfile.ZipFile(target_zip, 'r') as zip_ref:
        # Check if the file exists in the zip archive
        for file in zip_ref.namelist():
            if target_file in file:
                # Extract the specific file to the current working directory
                zip_ref.extract(file)


def add_file_to_zip(target_zip: str, file_to_insert: str, target_dir: str):
    # Open the existing zip file in append mode
    with zipfile.ZipFile(target_zip, 'a') as zip_ref:
        arcname = os.path.join(target_dir, os.path.basename(file_to_insert))
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            zip_ref.write(file_to_insert, arcname=arcname)
        print(f"[*] {file_to_insert} added into {target_zip}")


class Ui_prepareGadgetDialogUi(object):
    def setupUi(self, prepareGadgetDialogUi):
        prepareGadgetDialogUi.setObjectName("prepareGadgetDialogUi")
        prepareGadgetDialogUi.resize(690, 350)
        if platform.system() == 'Windows':
            prepareGadgetDialogUi.resize(600, 350)
        font = QtGui.QFont()
        font.setFamily("Courier New")
        prepareGadgetDialogUi.setFont(font)
        self.gridLayout = QtWidgets.QGridLayout(prepareGadgetDialogUi)
        self.gridLayout.setObjectName("gridLayout")
        self.prepareGadgetBrowser = QtWidgets.QTextBrowser(prepareGadgetDialogUi)
        self.prepareGadgetBrowser.setObjectName("prepareGadgetBrowser")
        self.gridLayout.addWidget(self.prepareGadgetBrowser, 0, 0, 1, 3)
        self.pkgNameInput = QtWidgets.QLineEdit(prepareGadgetDialogUi)
        self.pkgNameInput.setEnabled(True)
        self.pkgNameInput.setFocusPolicy(QtCore.Qt.FocusPolicy.StrongFocus)
        self.pkgNameInput.setText("")
        self.pkgNameInput.setFrame(True)
        self.pkgNameInput.setObjectName("pkgNameInput")
        self.gridLayout.addWidget(self.pkgNameInput, 1, 0, 1, 1)
        self.prepareGadgetBtn = QtWidgets.QPushButton(prepareGadgetDialogUi)
        self.prepareGadgetBtn.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)
        self.prepareGadgetBtn.setObjectName("prepareGadgetBtn")
        self.gridLayout.addWidget(self.prepareGadgetBtn, 1, 2, 1, 1)
        self.sleepTimeInput = QtWidgets.QLineEdit(prepareGadgetDialogUi)
        self.sleepTimeInput.setFocusPolicy(QtCore.Qt.FocusPolicy.StrongFocus)
        self.sleepTimeInput.setText("")
        self.sleepTimeInput.setObjectName("sleepTimeInput")
        self.gridLayout.addWidget(self.sleepTimeInput, 1, 1, 1, 1)

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
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">2. Enter the sleep time (in milliseconds) before loading the frida-gadget.</p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">3. Click the &quot;Prepare&quot; button. Your device will reboot.</p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">4. After rebooting, launch the target app.</p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">5. Attach to the target app.</p>\n"
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
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">2. Enter the sleep time (in milliseconds) before loading the frida-gadget.</p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">3. Click the &quot;Prepare&quot; button. Your device will reboot.</p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">4. After rebooting, launch the target app.</p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:12px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">5. Attach to the target app.</p>\n"
                                                         "<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><span style=\" font-weight:700;\">[*] Remove</span></p>\n"
                                                         "<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">Remove the ZygiskGadget module in Magisk Manager.</p></body></html>"))
        self.pkgNameInput.setPlaceholderText(_translate("prepareGadgetDialogUi", "com.android.chrome"))
        self.prepareGadgetBtn.setText(_translate("prepareGadgetDialogUi", "Prepare"))
        self.sleepTimeInput.setPlaceholderText(_translate("prepareGadgetDialogUi", "sleep time(ex. 500000)"))
        self.pkgNameInput.setPlaceholderText(_translate("prepareGadgetDialogUi", "com.android.chrome"))
        self.prepareGadgetBtn.setText(_translate("prepareGadgetDialogUi", "Prepare"))
        self.sleepTimeInput.setPlaceholderText(_translate("prepareGadgetDialogUi", "sleep time(ex. 500000)"))


class GadgetDialogClass(QtWidgets.QDialog):
    def __init__(self):
        super(GadgetDialogClass, self).__init__()
        self.gadgetdialog = QtWidgets.QDialog()
        self.gadgetdialog.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint)
        # self.spawndialog.setWindowModality(Qt.WindowModality.ApplicationModal)
        self.gadgetui = Ui_prepareGadgetDialogUi()
        self.gadgetui.setupUi(self.gadgetdialog)
        self.gadgetui.sleepTimeInput.returnPressed.connect(self.sleep_time_input_return_pressed_func)
        self.gadgetui.prepareGadgetBtn.clicked.connect(lambda: self.prepare_gadget("clicked", None, None))
        self.gadgetdialog.show()

        self.interested_widgets = []
        QApplication.instance().installEventFilter(self)

    def sleep_time_input_return_pressed_func(self):
        if (pkgName := self.gadgetui.pkgNameInput.text()) and (sleepTime := self.gadgetui.sleepTimeInput.text()):
            self.prepare_gadget("returnPressed", pkgName, sleepTime)
        else:
            return

    def prepare_gadget(self, caller, pkgName, sleepTime):
        if caller == "returnPressed":
            pkgName = pkgName
            sleepTime = sleepTime
        elif caller == "clicked":
            if not (pkgName := self.gadgetui.pkgNameInput.text()) or not (sleepTime := self.gadgetui.sleepTimeInput.text()):
                return

        gadget_dir = "gadget"
        zygisk_gadget_name = "zygisk-gadget-v1.0.0-release.zip"
        zygisk_gadget_path = f"{gadget_dir}/{zygisk_gadget_name}"
        for item in ["targetpkg", "sleeptime"]:
            with open(f"{gadget_dir}/{item}", "w") as f:
                f.write(pkgName) if item == "targetpkg" else f.write(sleepTime)
                f.close()
            unzip(zygisk_gadget_path, item)
            add_file_to_zip(zygisk_gadget_path, f"{gadget_dir}/{item}", "")
            os.remove(item)
            os.remove(f"{gadget_dir}/{item}")
        # install zygisk-gadget
        os.system(f"adb push {zygisk_gadget_path} /data/local/tmp/")
        os.system(f"adb shell su -c \"magisk --install-module /data/local/tmp/{zygisk_gadget_name}\"")
        os.system(f"adb shell su -c \"rm -rf /data/local/tmp/{zygisk_gadget_name}\"")
        os.system("adb reboot")

    def eventFilter(self, obj, event):
        self.interested_widgets = [self.gadgetui.pkgNameInput]
        if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Tab:
            try:
                if self.gadgetui.pkgNameInput.isEnabled():
                    self.interested_widgets.append(self.gadgetui.sleepTimeInput)
                index = self.interested_widgets.index(self.gadgetdialog.focusWidget())

                self.interested_widgets[(index + 1) % len(self.interested_widgets)].setFocus()
            except ValueError:
                self.interested_widgets[0].setFocus()

            return True

        return super().eventFilter(obj, event)
