import inspect
import os
import platform
import threading

import frida
import math
from PyQt6 import QtCore
from PyQt6.QtCore import QObject
from frida_tools.application import Reactor
from math import floor

import gvar

MESSAGE = ""
ERRMESSAGE = ""


def change_frida_script(script_text):
    if script_text != 'scripts/default.js':
        gvar.frida_instrument.change_frida_script_signal.emit(script_text)
    gvar.frida_instrument.script_text = script_text
    gvar.frida_instrument.script = gvar.frida_instrument.sessions[0].create_script(
        gvar.frida_instrument.read_frida_js_source())
    gvar.frida_instrument.script.on('message', gvar.frida_instrument.on_message)
    gvar.frida_instrument.script.load()
    if script_text == 'scripts/default.js':
        gvar.frida_instrument.change_frida_script_signal.emit(script_text)


def revert_frida_script():
    change_frida_script("scripts/default.js")


def clean_message():
    global MESSAGE
    MESSAGE = ''


class Instrument(QObject):
    attach_signal = QtCore.pyqtSignal(int)

    change_frida_script_signal = QtCore.pyqtSignal(str)

    scan_match_signal = QtCore.pyqtSignal(dict)
    update_scanned_value_signal = QtCore.pyqtSignal(dict)
    memory_scan_done_signal = QtCore.pyqtSignal(int)

    message_signal = QtCore.pyqtSignal(str)
    backtrace_signal = QtCore.pyqtSignal(tuple)
    hexdump_signal = QtCore.pyqtSignal(tuple)

    parse_signal = QtCore.pyqtSignal(dict)
    app_info_signal = QtCore.pyqtSignal(dict)

    refresh_hexdump_result_signal = QtCore.pyqtSignal(str)

    watchpoint_signal = QtCore.pyqtSignal(tuple)

    get_file_from_device_signal = QtCore.pyqtSignal(bytes)

    def __init__(self, script_text, is_remote, remote_addr, target, is_spawn):
        super().__init__()
        self.name = None
        self.sessions = []
        self.script = None
        self.script_text = script_text
        self.device = None
        self.is_spawn = is_spawn
        self.attach_target = None
        self.spawn_target = None
        self.remote_addr = ''
        self.pid = None
        if is_remote is True and remote_addr != '':
            if remote_addr == 'localhost':
                self.remote_addr = remote_addr
                self.device = frida.get_device_manager().add_remote_device(self.remote_addr)
            else:
                self.remote_ip = remote_addr[:remote_addr.find(':')].strip()
                self.remote_port = remote_addr[remote_addr.find(':') + 1:].strip()
                self.remote_addr = self.remote_ip + ':' + self.remote_port
                self.device = frida.get_device_manager().add_remote_device(self.remote_ip + ':' + self.remote_port)
        else:
            self.device = frida.get_usb_device(1)

        # Spawn mode
        if target is not None and is_spawn:
            self.spawn_target = target
        # List pid mode
        else:
            self.attach_target = target

    def __del__(self):
        for session in self.sessions:
            session.detach()

    def is_attached(self, sig: bool):
        self.attach_signal.emit(1) if sig is True else self.attach_signal.emit(0)

    def on_destroyed(self):
        self.attach_signal.emit(0)

    # Frida script에서 send 함수로 보내는 메시지는 on_message에서 처리됨
    def on_message(self, message, data):
        # print(f"[code] {message}")
        global MESSAGE
        if 'payload' in message and message['payload'] is not None:
            if 'scan_match' in message['payload']:
                # scan_match --> { match_count: #, match_address: # } / { match_count: #, match_address: #, match_value: # }
                scan_match = message['payload']['scan_match']
                self.scan_match_signal.emit(scan_match)
                gvar.scan_matches.append(scan_match)
            if 'next_scan_match' in message['payload']:
                # next_scan_match --> { match_count: #, match_address: # } / { match_count: #, match_address: #, match_value: # }
                next_scan_match = message['payload']['next_scan_match']
                gvar.scan_matches.append(next_scan_match)
            if 'scan_completed_ratio' in message['payload']:
                gvar.scan_progress_ratio = floor(message['payload']['scan_completed_ratio'])
            if 'scan_result' in message['payload']:
                gvar.scan_matches = message['payload']['scan_result']
            if 'scanned_value' in message['payload']:
                # scanned_value --> { match_count: #, match_address: #, updated_value: # }
                gvar.scanned_value = message['payload']['scanned_value']
                self.update_scanned_value_signal.emit(gvar.scanned_value)
            if 'watch_args' in message['payload']:
                self.message_signal.emit(message['payload']['watch_args'])
                return
            if 'watch_regs' in message['payload']:
                self.message_signal.emit(message['payload']['watch_regs'])
                return
            if 'backtrace' in message['payload']:
                address = message['payload']['backtrace']['address']
                backtrace_log = message['payload']['backtrace']['backtrace_log']
                self.backtrace_signal.emit((address, backtrace_log))
            if 'on_enter_hexdump' in message['payload']:
                # Emit the signal with a unique key and the message
                address = message['payload']['on_enter_hexdump']['address']
                args_index = message['payload']['on_enter_hexdump']['args_index']
                dump_target_address = message['payload']['on_enter_hexdump']['dump_target_address']
                self.hexdump_signal.emit((address, args_index, dump_target_address, 0, f"{message['payload']['on_enter_hexdump']['dump_result']}"))
                # print(f"[code] onEnter: {message['payload']['on_enter_hexdump']}")
                return
            if 'on_leave_hexdump' in message['payload']:
                address = message['payload']['on_leave_hexdump']['address']
                args_index = message['payload']['on_leave_hexdump']['args_index']
                dump_target_address = message['payload']['on_leave_hexdump']['dump_target_address']
                self.hexdump_signal.emit((address, args_index, dump_target_address, 2, f"{message['payload']['on_leave_hexdump']['dump_result']}"))
                # print(f"[code] onLeave: {message['payload']['on_leave_hexdump']}")
                return
            if 'refresh_hexdump' in message['payload']:
                refresh_hexdump_result = message['payload']['refresh_hexdump']
                self.refresh_hexdump_result_signal.emit(refresh_hexdump_result)
            if 'watchpoint' in message['payload']:
                if 'address' in message['payload']['watchpoint'] and \
                        'stat' in message['payload']['watchpoint']:
                    addr = message['payload']['watchpoint']['address']
                    stat = message['payload']['watchpoint']['stat']
                    self.watchpoint_signal.emit((addr, stat))
                else:
                    what = message['payload']['watchpoint']['what']
                    how = message['payload']['watchpoint']['how']
                    where = message['payload']['watchpoint']['where']
                    what_hexdump = message['payload']['watchpoint']['what_hexdump']
                    thread_id = message['payload']['watchpoint']['thread_id']
                    if message['payload']['watchpoint'].get('thread_name') is not None:
                        thread_name = message['payload']['watchpoint']['thread_name']
                    else:
                        thread_name = 'Undefined'
                    self.watchpoint_signal.emit((what, how, where, what_hexdump, thread_id, thread_name))
            if 'parse_macho' in message['payload']:
                self.parse_signal.emit(message['payload']['parse_macho'])
                return
            if 'parse_elf' in message['payload']:
                self.parse_signal.emit(message['payload']['parse_elf'])
                return
            if (key := "app_info") in message['payload']:
                self.app_info_signal.emit(message['payload'][key])
                return
            if '[!] Memory Scan Done' in message['payload']:
                self.memory_scan_done_signal.emit(1)
            if 'get_file_from_device' in message['payload']:
                self.get_file_from_device_signal.emit(data)
            MESSAGE = message['payload']
        if message['type'] == 'error':
            ERRMESSAGE = message['description']
            ERRMESSAGE += message['stack']
            print(f"[code] errmessage: {ERRMESSAGE}")

    def read_frida_js_source(self):
        # On Windows should open frida script with encoding option('cp949 issue')
        with open(self.script_text, 'r', encoding="UTF8") if platform.system() == 'Windows' \
                else open(self.script_text, "r") as f:
            return f.read()

    def instrument(self, caller):
        if not caller == "frida_portal_node_info_sig_func" \
                and not any([self.spawn_target, self.attach_target] if gvar.frida_portal_mode else
                            [self.spawn_target, self.attach_target, self.device.get_frontmost_application()]):
            return "Launch the target app first"

        if self.attach_target:  # List pid mode
            session = self.device.attach(self.attach_target)
            self.name = self.attach_target
        else:
            if self.spawn_target:  # Spawn mode
                self.pid = self.device.spawn([self.spawn_target])
                session = self.device.attach(self.pid)
                self.device.resume(self.pid)
            else:  # Attach front most application
                self.pid = self.device.get_frontmost_application().pid
                session = self.device.attach(self.pid)

            if self.device.get_frontmost_application():
                self.name = self.device.get_frontmost_application().name

        session.on('detached', self.is_attached)    # Register is_attached callback func for a session's on detach event
        self.sessions.append(session)
        self.script = session.create_script(self.read_frida_js_source())
        self.script.on('message', self.on_message)
        self.script.on('destroyed', self.on_destroyed)
        self.script.load()
        self.is_attached(True)

    def get_agent(self):
        return self.script.exports_sync

    # Just dummy func for checking script is destroyed or not
    def dummy_script(self):
        self.script.exports.dummy()
        return MESSAGE

    def arch(self):
        self.script.exports.arch()
        return MESSAGE

    def platform(self):
        self.script.exports.platform()
        return MESSAGE

    def find_sym_addr_by_name(self, module_name, sym_name):
        result = self.script.exports.find_sym_addr_by_name(module_name, sym_name)
        return result

    def find_sym_name_by_addr(self, module, addr):
        result = self.script.exports.find_sym_name_by_addr(module, addr)
        return result

    def list_modules(self):
        self.script.exports.list_modules()
        return MESSAGE

    def get_module_by_name(self, name):
        clean_message()
        self.script.exports.get_module_by_name(name)
        return MESSAGE

    def get_module_by_addr(self, addr):
        clean_message()
        self.script.exports.get_module_by_addr(addr)
        return MESSAGE

    def mem_enumerate_ranges(self, prot):
        enum_ranges = self.script.exports.enumerate_ranges(prot)
        return enum_ranges

    def read_mem_offset(self, name, offset, size):
        if name == "" or name is None:
            # print(f'[code] self.name = {self.name}')
            self.name = self.list_modules()[0]['name']
            self.script.exports.hex_dump_offset(self.name, offset, size)
        else:
            self.script.exports.hex_dump_offset(name, offset, size)
        return MESSAGE

    def read_mem_addr(self, addr, size):
        self.script.exports.hex_dump_addr(addr, size)
        return MESSAGE

    def force_read_mem_addr(self, yes_or_no):
        self.script.exports.force_read_mem_addr(yes_or_no)

    def write_mem_addr(self, arg):
        for target in arg:
            target_addr = target[0]
            target_patch_code = target[1]
            target_prot = target[3]
            self.script.exports.write_mem_addr(target_addr, target_patch_code, target_prot)

    def mem_scan(self, ranges, pattern):
        clean_message()
        # Memory scan start
        self.script.exports.mem_scan(ranges, pattern)
        # return MESSAGE

    def mem_scan_reduce(self, matches, value, option):
        clean_message()
        self.script.exports.mem_scan_reduce(matches, value, option)

    def update_scanned_value(self, values, option):
        clean_message()
        self.script.exports.update_scanned_value(values, option)

    def clear_update_scanned_value_interval(self):
        self.script.exports.clear_update_scanned_value_interval()

    def stop_mem_scan(self):
        self.script.exports.stop_mem_scan()

    def start_mem_refresh(self):
        self.script.exports.start_mem_refresh()

    def get_mem_refresh(self, interval, addr):
        self.script.exports.get_mem_refresh(interval, addr)

    def stop_mem_refresh(self):
        self.script.exports.stop_mem_refresh()

    def is_mem_refresh_on(self):
        return self.script.exports.is_mem_refresh_on()

    def mem_patch(self, addr, value, option):
        self.script.exports.mem_patch(addr, value, option)

    def dump_ios_module(self, name):
        dump_result = self.script.exports.dump_module(name)
        if dump_result == 1:
            dump_module_path = self.script.exports.dump_module_path()
            return dump_module_path
        else:
            return False

    def dump_so(self, name):
        MAX_SIZE = 100 * 1024 * 1024  # 100MB in bytes.  Maximum message length is 128MiB
        module_info = self.script.exports.find_module(name)
        if module_info != -1:
            base = module_info["base"]
            size = module_info["size"]

            module_chunks = []
            if size > MAX_SIZE:
                for i in range(math.ceil(size / MAX_SIZE)):
                    chunk_base = int(base, 16) + (i * MAX_SIZE)
                    chunk_size = min(MAX_SIZE, size - (i * MAX_SIZE))  # Calculate the chunk size
                    chunk = self.script.exports.dump_module_chunk(chunk_base, chunk_size)
                    if chunk is not None:
                        module_chunks.append(chunk)
                    else:
                        print(f"[code] Warning: Received a None chunk for {name} at base {chunk_base}")
            else:
                module_buffer = self.script.exports.dump_module(name)
                if module_buffer is not None:
                    module_chunks.append(module_buffer)
                else:
                    print(f"[code] Warning: Received a None buffer for {name}")

            dump_dir = os.getcwd() + "\\dump\\" if platform.system() == "Windows" else os.getcwd() + "/dump/"
            os.makedirs(dump_dir, exist_ok=True)  # Ensure the dump directory exists
            dump_so_name = f"{dump_dir}{name}_{base}_{size}.dump.so"

            with open(dump_so_name, "wb") as f:
                for chunk in module_chunks:
                    f.write(chunk)

            return dump_so_name
        else:
            return False

    def module_status(self, name):
        clean_message()
        self.script.exports.module_status(name)
        return MESSAGE

    def il2cpp_dump(self):
        result = self.script.exports.il2cpp_dump()
        return result

    # Set the number of arguments to watch
    def set_nargs(self, nargs):
        self.script.exports.set_nargs(nargs)

    def set_watch_list(self, addr, is_reg_watch):
        self.script.exports.set_watch_list(addr, is_reg_watch)

    def set_backtrace(self, addr, yes_or_no):
        self.script.exports.set_backtrace(addr, yes_or_no)

    def set_hex_dump_target_address(self, addr, index, target_addr):
        self.script.exports.set_hex_dump_target_address(addr, index, target_addr)

    def set_hex_dump_offset(self, addr, index, offset):
        self.script.exports.set_hex_dump_offset(addr, index, offset)

    # Set watch on address
    def set_watch(self, addr):
        clean_message()
        self.script.exports.set_watch(addr)

    def detach_all(self):
        self.script.exports.detach_all()

    def set_read_args_options(self, addr, index, option, on_leave):
        self.script.exports.set_read_args_options(addr, index, option, on_leave)

    def set_read_retval_options(self, addr, option):
        self.script.exports.set_read_retval_options(addr, option)

    def get_process_threads(self):
        result = self.script.exports.get_process_threads()
        return result

    def set_watchpoint(self, watchpoint_addr, watchpoint_size: int, watchpoint_type):
        # print(f"[code][set_watchpoint] {watchpoint_addr}, {watchpoint_size}, {watchpoint_type}")
        self.script.exports.set_watchpoint(watchpoint_addr, watchpoint_size, watchpoint_type)

    def stop_watchpoint(self):
        self.script.exports.stop_watchpoint()

    def get_file_from_device(self, file_path):
        self.script.exports.get_file_from_device(file_path)

    def parse_macho(self, base):
        clean_message()
        self.script.exports.parse_macho(base)

    def parse_elf(self, base):
        clean_message()
        self.script.exports.parse_elf(base)

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

    def show_maps(self):
        return self.script.exports.show_maps()


def frida_shell_exec(command, thread_instance):  # It's not working on Dopamine JB
    if gvar.frida_instrument.is_rootless():
        shell = "/var/jb/usr/bin/sh"
        command = "/var/jb/usr/bin/" + command
    else:
        shell = "/bin/sh"
    cmd = Shell([shell, '-c', command], None, gvar.frida_instrument.device, thread_instance)
    cmd.exec()
    for chunk in cmd.output:
        print(chunk.strip().decode())


# Frida shell command exec
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
        self.output = []  # Stdout will pushed into array

        self.thread_instance = thread_instance

    def exec(self):
        self._reactor.schedule(lambda: self._start())
        self._reactor.run()

    def _start(self):
        print(f"✔ spawn(argv={self.argv})")
        cwd = "/var/mobile/Documents/"
        if gvar.frida_instrument.is_rootless():
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
            print(f"[code] {inspect.currentframe().f_code.co_name}: {e}")
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
