import os
import shutil
import socket
import subprocess
import warnings
import zipfile
import platform
import json

import frida
from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtCore import Qt, QEvent, pyqtSlot, QThread
from PyQt6.QtWidgets import QApplication

import frida_portal
import gvar


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


def get_local_ip():
    try:
        # Create a socket to connect to an Internet host
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Connect the socket to a remote server on the internet
            s.connect(("8.8.8.8", 80))  # Google's DNS
            # Get the socket's own address
            local_ip = s.getsockname()[0]
            return local_ip
    except Exception as e:
        print(f"Error obtaining local IP: {e}")
        return None


def command_exists_on_device(device_command):
    try:
        # Construct the full adb command
        full_command = f"adb shell su -c \"{device_command}\""

        # Run the command and capture the output
        result = subprocess.run(full_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Determine if the command exists based on the output or error
        # Adjust this logic based on what you observe in the output
        if "not found" not in result.stderr:
            return True
        else:
            return False
    except subprocess.CalledProcessError:
        # The command failed to execute
        return False


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
        self.sleepTimeInput.setPlaceholderText(_translate("prepareGadgetDialogUi", "sleep time(ex. 500000)"))
        self.pkgNameInput.setPlaceholderText(_translate("prepareGadgetDialogUi", "com.android.chrome"))
        self.prepareGadgetBtn.setText(_translate("prepareGadgetDialogUi", "Prepare"))
        self.fridaPortalListeningLabel.setText(_translate("prepareGadgetDialogUi", ""))


class GadgetDialogClass(QtWidgets.QDialog):
    frida_portal_node_info_signal = QtCore.pyqtSignal(list)

    def __init__(self):
        super(GadgetDialogClass, self).__init__()
        self.gadget_dialog = QtWidgets.QDialog()
        self.gadget_dialog.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint)
        # self.spawn_dialog.setWindowModality(Qt.WindowModality.ApplicationModal)
        self.gadget_ui = Ui_prepareGadgetDialogUi()
        self.gadget_ui.setupUi(self.gadget_dialog)
        self.gadget_ui.sleepTimeInput.returnPressed.connect(self.sleep_time_input_return_pressed)
        self.gadget_ui.prepareGadgetBtn.clicked.connect(lambda: self.prepare_gadget("clicked", None, None))
        self.gadget_ui.fridaPortalModeCheckBox.stateChanged.connect(self.frida_portal_checkbox)
        self.is_frida_portal_mode_checked = False
        self.frida_portal_worker = None
        self.gadget_dialog.show()

        self.interested_widgets = []
        QApplication.instance().installEventFilter(self)

    @pyqtSlot(list)
    def frida_portal_node_joined_sig(self, sig: list):
        if sig:
            self.frida_portal_node_info_signal.emit(sig)

    def run_frida_portal(self):
        # run frida-portal
        self.frida_portal_worker = frida_portal.FridaPortalClassWorker()
        self.frida_portal_worker.node_joined_signal.connect(self.frida_portal_node_joined_sig)
        self.frida_portal_worker.start()

    def stop_frida_portal(self):
        if self.frida_portal_worker is not None:
            try:
                self.frida_portal_worker.process_stop()
                self.frida_portal_worker.terminate()
                self.frida_portal_worker = None
                frida.get_device_manager().remove_remote_device('localhost')
                QThread.msleep(500)
            except Exception as e:
                print(e)

    def frida_portal_checkbox(self, state):
        self.is_frida_portal_mode_checked = state == Qt.CheckState.Checked.value
        if self.is_frida_portal_mode_checked:
            self.stop_frida_portal()
            self.run_frida_portal()
            self.gadget_ui.fridaPortalListeningLabel.setText(f"Listening on {get_local_ip()}:{gvar.frida_portal_cluster_port}")
        else:
            self.stop_frida_portal()
            self.gadget_ui.fridaPortalListeningLabel.setText("")
        return

    def sleep_time_input_return_pressed(self):
        if (pkg := self.gadget_ui.pkgNameInput.text()) and (delay := self.gadget_ui.sleepTimeInput.text()):
            self.prepare_gadget("returnPressed", pkg, delay)
        else:
            return

    def prepare_gadget(self, caller, pkg, delay):
        if caller == "clicked":
            if not (pkg := self.gadget_ui.pkgNameInput.text()) or not (delay := self.gadget_ui.sleepTimeInput.text()):
                return

        gadget_dir = "gadget"
        zygisk_gadget_name = "zygisk-gadget-v1.2.0-release.zip"
        zygisk_gadget_path = f"{gadget_dir}/{zygisk_gadget_name}"
        shutil.copy2(zygisk_gadget_path, f"{gadget_dir}/temp.zip")
        temp_zip_name = "temp.zip"
        temp_zip_path = f"{gadget_dir}/{temp_zip_name}"
        config_name = "config"

        json_data = {
            "package": {
                "name": pkg,
                "delay": int(delay),
                "mode": {
                    "config": True
                }
            }
        }

        with open(f"{gadget_dir}/{config_name}", "w") as f:
            json.dump(json_data, f, indent=4)

        unzip(temp_zip_path, config_name)
        add_file_to_zip(temp_zip_path, f"{gadget_dir}/{config_name}", "")
        os.remove(config_name)
        os.remove(f"{gadget_dir}/{config_name}")

        if self.is_frida_portal_mode_checked:
            frida_config_name = "ajeossida-gadget.config"
            local_ip = get_local_ip()
            content = f'''{{\n "interaction": {{\n\t "type": "connect",\n\t "address": "{local_ip}",\n\t "port": {gvar.frida_portal_cluster_port}\n }}\n}}'''
            with open(f"{gadget_dir}/{frida_config_name}", "w") as f:
                f.write(content)
                f.close()

            add_file_to_zip(temp_zip_path, f"{gadget_dir}/{frida_config_name}", "")
            os.remove(f"{gadget_dir}/{frida_config_name}")

        # install zygisk-gadget
        os.system(f"adb push {temp_zip_path} /data/local/tmp/")
        os.remove(temp_zip_path)
        if command_exists_on_device("ksud"):
            os.system(f"adb shell su -c \"ksud module install /data/local/tmp/{temp_zip_name}\"")
        else:
            os.system(f"adb shell su -c \"magisk --install-module /data/local/tmp/{temp_zip_name}\"")
        os.system(f"adb shell su -c \"rm -rf /data/local/tmp/{temp_zip_name}\"")
        os.system("adb reboot")

    def eventFilter(self, obj, event):
        self.interested_widgets = [self.gadget_ui.pkgNameInput]
        if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Tab:
            try:
                if self.gadget_ui.pkgNameInput.isEnabled():
                    self.interested_widgets.append(self.gadget_ui.sleepTimeInput)
                index = self.interested_widgets.index(self.gadget_dialog.focusWidget())

                self.interested_widgets[(index + 1) % len(self.interested_widgets)].setFocus()
            except ValueError:
                self.interested_widgets[0].setFocus()

            return True

        return super().eventFilter(obj, event)
