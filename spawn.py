# Form implementation generated from reading ui file 'spawn.ui'
#
# Created by: PyQt6 UI code generator 6.4.0
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.
import re

import frida
from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtCore import Qt, pyqtSlot, QEvent
from PyQt6.QtWidgets import QMessageBox, QTextBrowser, QApplication


class Ui_SpawnDialogUi(object):
    def setupUi(self, SpawnDialogUi):
        SpawnDialogUi.setObjectName("SpawnDialogUi")
        SpawnDialogUi.resize(317, 435)
        font = QtGui.QFont()
        font.setFamily("Courier New")
        SpawnDialogUi.setFont(font)
        self.gridLayout = QtWidgets.QGridLayout(SpawnDialogUi)
        self.gridLayout.setObjectName("gridLayout")
        # self.appListBrowser = QtWidgets.QTextBrowser(SpawnDialogUi)
        self.appListBrowser = AppListBrowserClass(SpawnDialogUi)
        self.appListBrowser.setObjectName("appListBrowser")
        self.gridLayout.addWidget(self.appListBrowser, 1, 0, 1, 2)
        self.spawnBtn = QtWidgets.QPushButton(SpawnDialogUi)
        self.spawnBtn.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)
        self.spawnBtn.setObjectName("spawnBtn")
        self.gridLayout.addWidget(self.spawnBtn, 3, 1, 1, 1)
        self.spawnTargetIdInput = QtWidgets.QLineEdit(SpawnDialogUi)
        self.spawnTargetIdInput.setFocusPolicy(QtCore.Qt.FocusPolicy.StrongFocus)
        self.spawnTargetIdInput.setObjectName("spawnTargetIdInput")
        self.gridLayout.addWidget(self.spawnTargetIdInput, 3, 0, 1, 1)
        self.appListLabel = QtWidgets.QLabel(SpawnDialogUi)
        self.appListLabel.setObjectName("appListLabel")
        self.appListLabel.setIndent(2)
        self.gridLayout.addWidget(self.appListLabel, 0, 0, 1, 2)
        self.remoteAddrInput = QtWidgets.QLineEdit(SpawnDialogUi)
        self.remoteAddrInput.setEnabled(True)
        self.remoteAddrInput.setFocusPolicy(QtCore.Qt.FocusPolicy.StrongFocus)
        self.remoteAddrInput.setFrame(True)
        self.remoteAddrInput.setObjectName("remoteAddrInput")
        self.gridLayout.addWidget(self.remoteAddrInput, 2, 0, 1, 1)
        self.appListBtn = QtWidgets.QPushButton(SpawnDialogUi)
        self.appListBtn.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)
        self.appListBtn.setObjectName("appListBtn")
        self.gridLayout.addWidget(self.appListBtn, 2, 1, 1, 1)

        self.retranslateUi(SpawnDialogUi)
        QtCore.QMetaObject.connectSlotsByName(SpawnDialogUi)

    def retranslateUi(self, SpawnDialogUi):
        _translate = QtCore.QCoreApplication.translate
        SpawnDialogUi.setWindowTitle(_translate("SpawnDialogUi", "App List"))
        self.spawnBtn.setText(_translate("SpawnDialogUi", "Spawn"))
        self.spawnTargetIdInput.setPlaceholderText(_translate("SpawnDialogUi", "com.example.test"))
        self.appListLabel.setText(_translate("SpawnDialogUi", "Identifier           Name"))
        self.remoteAddrInput.setPlaceholderText(_translate("SpawnDialogUi", "IP:PORT"))
        self.appListBtn.setText(_translate("SpawnDialogUi", "List"))


class AppListBrowserClass(QTextBrowser):
    clickedtargetidsig = QtCore.pyqtSignal(str)

    def __init__(self, args):
        super(AppListBrowserClass, self).__init__(args)

    def mousePressEvent(self, e: QtGui.QMouseEvent) -> None:
        super(AppListBrowserClass, self).mousePressEvent(e)
        pos = e.pos()
        tc = self.cursorForPosition(pos)
        self.clickedtargetidsig.emit(tc.block().text())


class SpawnDialogClass(QtWidgets.QDialog):
    attachtargetnamesig = QtCore.pyqtSignal(str)
    spawntargetidsig = QtCore.pyqtSignal(str)

    def __init__(self):
        super(SpawnDialogClass, self).__init__()
        self.ispidlistchecked = False
        self.applicationlist = None
        self.spawntargetid = None
        self.spawndialog = QtWidgets.QDialog()
        self.spawndialog.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint)
        # self.spawndialog.setWindowModality(Qt.WindowModality.ApplicationModal)
        self.spawnui = Ui_SpawnDialogUi()
        self.spawnui.setupUi(self.spawndialog)
        self.spawnui.remoteAddrInput.returnPressed.connect(self.get_app_list)
        self.spawnui.spawnTargetIdInput.returnPressed.connect(self.set_spawn_target)
        self.spawnui.spawnTargetIdInput.textChanged.connect(self.search_target)
        self.spawnui.spawnBtn.clicked.connect(self.spawn_launch)
        self.spawnui.appListBtn.clicked.connect(self.get_app_list)
        self.spawnui.appListBrowser.clickedtargetidsig.connect(self.clickedtargetidsig_func)
        self.spawndialog.show()

        self.interested_widgets = []
        QApplication.instance().installEventFilter(self)

    @pyqtSlot(str)
    def clickedtargetidsig_func(self, clickedtargetidsig: str):
        spawn_target_id_input = self.spawnui.spawnTargetIdInput
        spawn_target_id_input.setText(clickedtargetidsig[clickedtargetidsig.find("\t"):].strip()) if self.ispidlistchecked else spawn_target_id_input.setText(clickedtargetidsig[:clickedtargetidsig.find("\t")])

    def set_spawn_target(self):
        self.spawntargetid = self.spawnui.spawnTargetIdInput.text().strip()
        self.spawnui.spawnBtn.setFocus()

    def spawn_launch(self):
        if self.spawntargetid is None:
            self.spawntargetid = self.spawnui.spawnTargetIdInput.text().strip()
        btn_name = self.spawnui.spawnBtn.text()
        sig = self.spawntargetidsig if btn_name == "Spawn" else self.attachtargetnamesig
        sig.emit(self.spawntargetid)

    def get_app_list(self):
        if self.spawnui.remoteAddrInput.isEnabled() is False:
            try:
                device = frida.get_usb_device(1)
            except Exception as e:
                print(e)
                return
        else:
            IP = self.spawnui.remoteAddrInput.text().strip()
            if re.search(r"^\d+\.\d+\.\d+\.\d+:\d+$", IP) is None:
                QMessageBox.information(self, "info", "Enter IP:PORT")
                return
            try:
                device = frida.get_device_manager().add_remote_device(IP)
            except Exception as e:
                print(e)
                return
        try:
            enumeration_function = device.enumerate_processes if self.ispidlistchecked else device.enumerate_applications
            self.applicationlist = [app for app in enumeration_function()]
        except Exception as e:
            print(e)
            return

        applisttext = ''
        for app in self.applicationlist:
            applisttext += (str(app.pid) + '\t' + app.name + '\n') if self.ispidlistchecked \
                else (app.identifier + '\t' + app.name + '\n')

        self.spawnui.appListBrowser.setText(applisttext)

    def search_target(self):
        if self.applicationlist is None:
            return

        if len(self.applicationlist) > 0:
            applisttext = ''
            for app in self.applicationlist:
                appid = str(app.pid) if self.ispidlistchecked else app.identifier
                appname = app.name
                if appid.lower().find(self.spawnui.spawnTargetIdInput.text().lower()) != -1 or appname.lower().find(self.spawnui.spawnTargetIdInput.text().lower()) != -1:
                    applisttext += appid + '\t' + appname + '\n'
            self.spawnui.appListBrowser.setText(applisttext)

    def eventFilter(self, obj, event):
        self.interested_widgets = [self.spawnui.spawnTargetIdInput]
        if event.type() == QEvent.Type.KeyPress and event.key() == Qt.Key.Key_Tab:
            try:
                if self.spawnui.remoteAddrInput.isEnabled():
                    self.interested_widgets.append(self.spawnui.remoteAddrInput)
                index = self.interested_widgets.index(self.spawndialog.focusWidget())

                self.interested_widgets[(index + 1) % len(self.interested_widgets)].setFocus()
            except ValueError:
                self.interested_widgets[0].setFocus()

            return True

        return super().eventFilter(obj, event)
