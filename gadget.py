import json
import os
import shutil
import socket
import subprocess
import warnings
import zipfile

import frida
from PyQt6 import QtCore, QtWidgets
from PyQt6.QtCore import Qt, QEvent, pyqtSlot, QThread
from PyQt6.QtWidgets import QApplication

import frida_portal
import gadget_ui
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
        print(f"[gadget] [*] {file_to_insert} added into {target_zip}")


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
        print(f"[gadget] Error obtaining local IP: {e}")
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


class GadgetDialogClass(QtWidgets.QDialog):
    frida_portal_node_info_signal = QtCore.pyqtSignal(list)

    def __init__(self):
        super(GadgetDialogClass, self).__init__()
        self.gadget_dialog = QtWidgets.QDialog()
        self.gadget_dialog.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint)
        # self.spawn_dialog.setWindowModality(Qt.WindowModality.ApplicationModal)
        self.gadget_ui = gadget_ui.Ui_prepareGadgetDialogUi()
        self.gadget_ui.setupUi(self.gadget_dialog)
        self.gadget_ui.sleepTimeInput.returnPressed.connect(self.sleep_time_input_return_pressed)
        self.gadget_ui.prepareGadgetBtn.clicked.connect(lambda: self.prepare_gadget("clicked", None, None))
        self.gadget_ui.fridaPortalModeCheckBox.stateChanged.connect(self.frida_portal_checkbox)
        self.is_frida_portal_mode_checked = False
        self.frida_portal_worker = None

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
                self.frida_portal_worker.quit()
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
        zygisk_gadget_name = "zygisk-gadget-v1.2.1-release.zip"
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
