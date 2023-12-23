import inspect
import os
import platform
import threading
from math import floor

import frida
from PyQt6 import QtCore
from PyQt6.QtCore import QObject
from frida_tools.application import Reactor

import globvar

MESSAGE = ""
ERRMESSAGE = ""


def change_frida_script(script_text):
    globvar.fridaInstrument.script_text = script_text
    globvar.fridaInstrument.script = globvar.fridaInstrument.sessions[0].create_script(
        globvar.fridaInstrument.read_frida_js_source())
    globvar.fridaInstrument.script.on('message', globvar.fridaInstrument.on_message)
    globvar.fridaInstrument.script.load()


def revert_frida_script():
    change_frida_script("scripts/default.js")


def clean_message():
    global MESSAGE
    MESSAGE = ''


class Instrument(QObject):
    attachsig = QtCore.pyqtSignal(int)
    messagesig = QtCore.pyqtSignal(str)
    parsesig = QtCore.pyqtSignal(dict)
    appinfosig = QtCore.pyqtSignal(dict)

    def __init__(self, script_text, isremote, remoteaddr, target, isspawn):
        super().__init__()
        self.name = None
        self.sessions = []
        self.script = None
        self.script_text = script_text
        self.device = None
        self.isspawn = isspawn
        self.attachtarget = None
        self.spawntarget = None
        self.remoteaddr = ''
        self.pid = None
        if isremote is True and remoteaddr != '':
            if remoteaddr == 'localhost':
                self.remoteaddr = remoteaddr
                self.device = frida.get_device_manager().add_remote_device(self.remoteaddr)
            else:
                self.remoteip = remoteaddr[:remoteaddr.find(':')].strip()
                self.remoteport = remoteaddr[remoteaddr.find(':') + 1:].strip()
                self.remoteaddr = self.remoteip + ':' + self.remoteport
                self.device = frida.get_device_manager().add_remote_device(self.remoteip + ':' + self.remoteport)
        else:
            self.device = frida.get_usb_device(1)

        # spawn mode
        if target is not None and isspawn:
            self.spawntarget = target
        # list pid mode
        else:
            self.attachtarget = target

    def __del__(self):
        for session in self.sessions:
            session.detach()

    def is_attached(self, attached: bool):
        self.attachsig.emit(1) if attached is True else self.attachsig.emit(0)

    def on_destroyed(self):
        self.attachsig.emit(0)

    # frida script에서 send 함수로 보내는 메시지는 on_message에서 처리됨
    def on_message(self, message, data):
        # print(message)
        global MESSAGE
        if 'payload' in message and message['payload'] is not None:
            if 'scancompletedratio' in message['payload']:
                globvar.scanProgressRatio = floor(message['payload']['scancompletedratio'])
                # print(globvar.scanProgressRatio)
            if 'watchArgs' in message['payload']:
                self.messagesig.emit(message['payload']['watchArgs'])
                return
            if 'watchRegs' in message['payload']:
                self.messagesig.emit(message['payload']['watchRegs'])
                return
            if 'parseMachO' in message['payload']:
                self.parsesig.emit(message['payload']['parseMachO'])
                return
            if 'parseElf' in message['payload']:
                self.parsesig.emit(message['payload']['parseElf'])
                return
            if (key := "appInfo") in message['payload']:
                self.appinfosig.emit(message['payload'][key])
                return
            MESSAGE = message['payload']
        if message['type'] == 'error':
            ERRMESSAGE = message['description']
            ERRMESSAGE += message['stack']
            print("[hackcatml] errmessage: ", ERRMESSAGE)

    def read_frida_js_source(self):
        # on Windows should open frida script with encoding option('cp949 issue')
        with open(self.script_text, 'r', encoding="UTF8") if platform.system() == 'Windows' \
                else open(self.script_text, "r") as f:
            return f.read()

    def instrument(self, caller):
        if not caller == "frida_portal_sig_func" and not any([self.spawntarget, self.attachtarget, self.device.get_frontmost_application()]):
            return "Launch the target app first"

        if self.attachtarget:  # list pid mode
            session = self.device.attach(self.attachtarget)
            self.name = self.attachtarget
        else:
            if self.spawntarget:  # spawn mode
                self.pid = self.device.spawn([self.spawntarget])
                session = self.device.attach(self.pid)
                self.device.resume(self.pid)
            else:  # attach frontmost application
                self.pid = self.device.get_frontmost_application().pid
                session = self.device.attach(self.pid)

            if self.device.get_frontmost_application():
                self.name = self.device.get_frontmost_application().name

        session.on('detached', self.is_attached)    # register is_attached callback func for a session's on detach event
        self.sessions.append(session)
        self.script = session.create_script(self.read_frida_js_source())
        self.script.on('message', self.on_message)
        self.script.on('destroyed', self.on_destroyed)
        self.script.load()
        self.is_attached(True)

    def get_agent(self):
        return self.script.exports_sync

    # just dummy func for checking script is destroyed or not
    def dummy_script(self):
        self.script.exports.dummy()
        return MESSAGE

    def arch(self):
        self.script.exports.arch()
        return MESSAGE

    def platform(self):
        self.script.exports.platform()
        return MESSAGE

    def find_sym_addr_by_name(self, name):
        result = self.script.exports.findsymaddrbyname(name)
        return result

    def find_sym_name_by_addr(self, module, addr):
        result = self.script.exports.find_sym_name_by_addr(module, addr)
        return result

    def list_modules(self):
        self.script.exports.listmodules()
        return MESSAGE

    def get_module_name_by_addr(self, addr):
        clean_message()
        self.script.exports.getmodulenamebyaddr(addr)
        return MESSAGE

    def mem_enumerate_ranges(self, prot):
        enumranges = self.script.exports.enumerateranges(prot)
        return enumranges

    def read_mem_offset(self, name, offset, size):
        if name == "" or name is None:
            # print(f'self.name = {self.name}')
            self.name = self.list_modules()[0]['name']
            self.script.exports.hexdumpoffset(self.name, offset, size)
        else:
            self.script.exports.hexdumpoffset(name, offset, size)
        return MESSAGE

    def read_mem_addr(self, addr, size):
        self.script.exports.hexdumpaddr(addr, size)
        return MESSAGE

    def force_read_mem_addr(self, yes_or_no):
        self.script.exports.forcereadmemaddr(yes_or_no)

    def write_mem_addr(self, arg):
        for target in arg:
            targetAddr = target[0]
            targetPatchCode = target[1]
            targetProt = target[3]
            self.script.exports.writememaddr(targetAddr, targetPatchCode, targetProt)

    def mem_scan(self, ranges, pattern):
        global MESSAGE
        MESSAGE = ''
        # memory scan start
        self.script.exports.memscan(ranges, pattern)
        # return MESSAGE

    def mem_scan_with_img(self, name, pattern):
        global MESSAGE
        MESSAGE = ''
        result = self.script.exports.memscanwithimg(name, pattern)
        if result == 'module not found':
            return result

    def mem_scan_and_replace(self, replacecode):
        self.script.exports.memscanandreplace(replacecode)

    def get_mem_scan_result(self):
        return MESSAGE

    def stop_mem_scan(self):
        self.script.exports.stopmemscan()

    def dump_ios_module(self, name):
        dumpresult = self.script.exports.dumpmodule(name)
        if dumpresult == 1:
            dumpmodule_path = self.script.exports.dumpmodulepath()
            return dumpmodule_path
        else:
            return False

    def dump_so(self, name):
        module_info = self.script.exports.findmodule(name)
        if module_info != -1:
            base = module_info["base"]
            size = module_info["size"]
            module_buffer = self.script.exports.dumpmodule(name)
            dumpdir = os.getcwd() + "\\dump\\" if platform.system() == "Windows" else os.getcwd() + "/dump/"
            dump_so_name = f"{dumpdir}{name}_{base}_{size}.dump.so"
            with open(dump_so_name, "wb") as f:
                f.write(module_buffer)
                f.close()
            return dump_so_name
        else:
            return False

    def module_status(self, name):
        clean_message()
        self.script.exports.modulestatus(name)
        return MESSAGE

    def il2cpp_dump(self):
        result = self.script.exports.il2cppdump()
        return result

    # set the number of arguments to watch
    def set_nargs(self, nargs):
        self.script.exports.setnargs(nargs)

    # set watch on address
    def set_watch(self, addr, is_reg_watch):
        clean_message()
        self.script.exports.setwatch(addr, is_reg_watch)

    def detach_all(self):
        self.script.exports.detachall()

    def set_read_args_options(self, addr, index, option, on_leave):
        self.script.exports.setreadargsoptions(addr, index, option, on_leave)

    def set_read_retval_options(self, addr, option):
        self.script.exports.setreadretvalsoptions(addr, option)

    def parse_macho(self, base):
        clean_message()
        self.script.exports.machoparse(base)

    def parse_elf(self, base):
        clean_message()
        self.script.exports.elfparse(base)

    def app_info(self):
        clean_message()
        self.script.exports.app_info()

    def pull_package(self, arg):
        result = self.script.exports.get_package_name() if arg == "getPackageName" else self.script.exports.get_apk_paths()
        return result

    def is_rootless(self):
        return self.script.exports.is_rootless()

    def is_palera1n(self):
        return self.script.exports.is_palera1n_jb()

    def get_bundle_id(self):
        return self.script.exports.get_bundle_id()

    def get_bundle_path(self):
        return self.script.exports.get_bundle_path()

    def get_executable_name(self):
        return self.script.exports.get_executable_name()


def frida_shell_exec(command, thread_instance):  # It's not working on Dopamine JB
    if globvar.fridaInstrument.is_rootless():
        shell = "/var/jb/usr/bin/sh"
        command = "/var/jb/usr/bin/" + command
    else:
        shell = "/bin/sh"
    cmd = Shell([shell, '-c', command], None, globvar.fridaInstrument.device, thread_instance)
    cmd.exec()
    for chunk in cmd.output:
        print(chunk.strip().decode())


# frida shell command exec
# https://stackoverflow.com/questions/72581924/run-cp-command-from-frida-script
class Shell(object):
    def __init__(self, argv, env, device, thread_instance):
        self._stop_requested = threading.Event()
        self._reactor = Reactor(run_until_return=lambda reactor: self._stop_requested.wait())

        self._device = device
        self._sessions = set()

        self._device.on("output", lambda pid, fd, data: self._reactor.schedule(lambda: self._on_output(pid, fd, data)))

        self.argv = argv
        self.env = env
        self.output = []  # stdout will pushed into array

        self.thread_instance = thread_instance

    def exec(self):
        self._reactor.schedule(lambda: self._start())
        self._reactor.run()

    def _start(self):
        print(f"✔ spawn(argv={self.argv})")
        cwd = "/var/mobile/Documents/"
        if globvar.fridaInstrument.is_rootless():
            cwd = "/var/jb/var/mobile/"
        pid = self._device.spawn(self.argv, env=self.env, cwd=cwd, stdio='pipe', aslr='auto')
        self._instrument(pid)

    def _stop_if_idle(self):
        if len(self._sessions) == 0:
            self._stop_requested.set()

    def _instrument(self, pid):
        print(f"✔ attach(pid={pid})")
        try:
            session = self._device.attach(pid)
            self._device.resume(pid)
            self._sessions.add(session)
        except Exception as e:
            print(f"{inspect.currentframe().f_code.co_name}: {e}")
            self.thread_instance.terminate()
            return

    def _on_output(self, pid, fd, data):
        # fd=0 (input) fd=1(stdout) fd=2(stderr)
        if fd != 2:
            # print(f"⚡ output: pid={pid}, fd={fd}, data={data}")
            self.output.append(data)
        else:
            session = None
            for session in self._sessions:
                session = session
            if session is not None:
                self._sessions.remove(session)
                self._reactor.schedule(self._stop_if_idle, delay=0.3)
