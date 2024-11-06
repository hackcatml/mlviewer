import re

import frida
from PyQt6 import QtCore, QtWidgets
from PyQt6.QtCore import Qt, pyqtSlot, QEvent
from PyQt6.QtWidgets import QMessageBox, QApplication

import spawn_ui


class SpawnDialogClass(QtWidgets.QDialog):
    attach_target_name_signal = QtCore.pyqtSignal(str)
    spawn_target_id_signal = QtCore.pyqtSignal(str)

    def __init__(self):
        super(SpawnDialogClass, self).__init__()
        self.is_pid_list_checked = False
        self.application_list = None
        self.spawn_target_id = None
        self.spawn_dialog = QtWidgets.QDialog()
        self.spawn_dialog.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint)
        # self.spawn_dialog.setWindowModality(Qt.WindowModality.ApplicationModal)
        self.spawn_ui = spawn_ui.Ui_SpawnDialogUi()
        self.spawn_ui.setupUi(self.spawn_dialog)
        self.spawn_ui.remoteAddrInput.returnPressed.connect(self.get_app_list)
        self.spawn_ui.spawnTargetIdInput.returnPressed.connect(self.set_spawn_target)
        self.spawn_ui.spawnTargetIdInput.textChanged.connect(self.search_target)
        self.spawn_ui.spawnBtn.clicked.connect(self.spawn_launch)
        self.spawn_ui.appListBtn.clicked.connect(self.get_app_list)
        self.spawn_ui.appListBrowser.target_id_clicked_signal.connect(self.target_id_clicked_sig_func)
        self.spawn_dialog.show()

        self.interested_widgets = []
        QApplication.instance().installEventFilter(self)

    @pyqtSlot(str)
    def target_id_clicked_sig_func(self, sig: str):
        spawn_target_id_input = self.spawn_ui.spawnTargetIdInput
        spawn_target_id_input.setText(sig[sig.find("\t"):].strip()) if self.is_pid_list_checked else spawn_target_id_input.setText(sig[:sig.find("\t")])

    def set_spawn_target(self):
        self.spawn_target_id = self.spawn_ui.spawnTargetIdInput.text().strip()
        self.spawn_ui.spawnBtn.setFocus()

    def spawn_launch(self):
        if self.spawn_target_id is None:
            self.spawn_target_id = self.spawn_ui.spawnTargetIdInput.text().strip()
        btn_name = self.spawn_ui.spawnBtn.text()
        sig = self.spawn_target_id_signal if btn_name == "Spawn" else self.attach_target_name_signal
        sig.emit(self.spawn_target_id)

    def get_app_list(self):
        if self.spawn_ui.remoteAddrInput.isEnabled() is False:
            try:
                device = frida.get_usb_device(1)
            except Exception as e:
                print(f"[spawn] {e}")
                return
        else:
            IP = self.spawn_ui.remoteAddrInput.text().strip()
            if re.search(r"^\d+\.\d+\.\d+\.\d+:\d+$", IP) is None:
                QMessageBox.information(self, "info", "Enter IP:PORT")
                return
            try:
                device = frida.get_device_manager().add_remote_device(IP)
            except Exception as e:
                print(f"[spawn] {e}")
                return
        try:
            enumeration_function = device.enumerate_processes if self.is_pid_list_checked else device.enumerate_applications
            self.application_list = [app for app in enumeration_function()]
        except Exception as e:
            print(f"[spawn] {e}")
            return

        app_list_text = ''
        for app in self.application_list:
            app_list_text += (str(app.pid) + '\t' + app.name + '\n') if self.is_pid_list_checked \
                else (app.identifier + '\t' + app.name + '\n')

        self.spawn_ui.appListBrowser.setText(app_list_text)

    def search_target(self):
        if self.application_list is None:
            return

        if len(self.application_list) > 0:
            app_list_text = ''
            for app in self.application_list:
                appid = str(app.pid) if self.is_pid_list_checked else app.identifier
                appname = app.name
                if appid.lower().find(self.spawn_ui.spawnTargetIdInput.text().lower()) != -1 or appname.lower().find(self.spawn_ui.spawnTargetIdInput.text().lower()) != -1:
                    app_list_text += appid + '\t' + appname + '\n'
            self.spawn_ui.appListBrowser.setText(app_list_text)

    def eventFilter(self, obj, event):
        self.interested_widgets = [self.spawn_ui.spawnTargetIdInput]
        if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Tab:
            try:
                if self.spawn_ui.remoteAddrInput.isEnabled():
                    self.interested_widgets.append(self.spawn_ui.remoteAddrInput)
                index = self.interested_widgets.index(self.spawn_dialog.focusWidget())

                self.interested_widgets[(index + 1) % len(self.interested_widgets)].setFocus()
            except ValueError:
                self.interested_widgets[0].setFocus()

            return True

        return super().eventFilter(obj, event)
