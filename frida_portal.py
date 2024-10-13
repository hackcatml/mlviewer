# -*- coding: utf-8 -*-
import frida
from PyQt6 import QtCore
from PyQt6.QtCore import QThread
from frida_tools.application import Reactor

import gvar

ENABLE_CONTROL_INTERFACE = True


class FridaPortalClassWorker(QThread):
    node_joined_signal = QtCore.pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self._reactor = Reactor(run_until_return=self._process_input)

        cluster_params = frida.EndpointParameters(address="0.0.0.0",
                                                  port=gvar.frida_portal_cluster_port)

        if ENABLE_CONTROL_INTERFACE:
            control_params = frida.EndpointParameters(address="::1",
                                                      port=gvar.frida_portal_controller_port)
        else:
            control_params = None

        service = frida.PortalService(cluster_params, control_params)
        self._service = service
        self._device = service.device

        service.on('node-connected', lambda *args: self._reactor.schedule(lambda: self._on_node_connected(*args)))
        service.on('node-joined', lambda *args: self._reactor.schedule(lambda: self._on_node_joined(*args)))
        service.on('node-left', lambda *args: self._reactor.schedule(lambda: self._on_node_left(*args)))
        service.on('node-disconnected', lambda *args: self._reactor.schedule(lambda: self._on_node_disconnected(*args)))
        service.on('controller-connected', lambda *args: self._reactor.schedule(lambda: self._on_controller_connected(*args)))
        service.on('controller-disconnected', lambda *args: self._reactor.schedule(lambda: self._on_controller_disconnected(*args)))

    def run(self):
        self._reactor.schedule(self._start)
        self._reactor.run()

    def process_stop(self):
        self._stop()

    def _start(self):
        self._service.start()
        self._device.enable_spawn_gating()

    def _stop(self):
        self._service.stop()

    def _process_input(self, reactor):
        while True:
            try:
                QThread.msleep(100)
                continue
            except KeyboardInterrupt:
                self._reactor.cancel_io()
                return

    def _on_node_connected(self, connection_id, remote_address):
        print("on_node_connected()", connection_id, remote_address)

    def _on_node_joined(self, connection_id, application):
        print("on_node_joined()", connection_id, application)
        self.node_joined_signal.emit([application.name, application.pid])
        self._device.resume(application.pid)
        gvar.frida_portal_mode = True

    def _on_node_left(self, connection_id, application):
        print("on_node_left()", connection_id, application)
        gvar.frida_portal_mode = False

    def _on_node_disconnected(self, connection_id, remote_address):
        print("on_node_disconnected()", connection_id, remote_address)

    def _on_controller_connected(self, connection_id, remote_address):
        print("on_controller_connected()", connection_id, remote_address)

    def _on_controller_disconnected(self, connection_id, remote_address):
        print("on_controller_disconnected()", connection_id, remote_address)

