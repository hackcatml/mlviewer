import os
import platform
from math import floor

import frida

import globvar

MESSAGE = ""
ERRMESSAGE = ""


class Instrument:
    def __init__(self, script_text, isremote, remoteaddr, spawntargetid):
        self.name = None
        self.sessions = []
        self.script = None
        self.script_text = script_text
        self.device = None
        self.spawntarget = None
        self.remoteaddr = ''
        if isremote is True and remoteaddr != '':
            self.remoteip = remoteaddr[:remoteaddr.find(':')].strip()
            self.remoteport = remoteaddr[remoteaddr.find(':') + 1:].strip()
            self.remoteaddr = self.remoteip + ':' + self.remoteport
            self.device = frida.get_device_manager().add_remote_device(self.remoteip + ':' + self.remoteport)
        else:
            self.device = frida.get_usb_device(1)

        if spawntargetid is not None:
            self.spawntarget = spawntargetid

    def __del__(self):
        for session in self.sessions:
            session.detach()

    # frida script에서 send 함수로 보내는 메시지는 on_message에서 처리됨
    def on_message(self, message, data):
        # print(message)
        global MESSAGE
        if 'payload' in message:
            if message['payload'] is not None and 'scancompletedratio' in message['payload']:
                globvar.scanProgressRatio = floor(message['payload']['scancompletedratio'])
                # print(globvar.scanProgressRatio)
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

    def instrument(self):
        if self.spawntarget is None and self.device.get_frontmost_application() is None:
            msg = "Launch the target app first"
            return msg

        if self.spawntarget is not None:
            pid = self.device.spawn([self.spawntarget])
        else:
            pid = self.device.get_frontmost_application().pid
        session = self.device.attach(pid)
        self.sessions.append(session)
        # print("[hackcatml] fridaInstrument sessions: ", self.sessions)
        if self.spawntarget is not None:
            self.device.resume(pid)
        self.name = self.device.get_frontmost_application().name
        self.script = session.create_script(self.read_frida_js_source())
        self.script.on('message', self.on_message)
        self.script.load()

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

    def find_export_by_name(self, name):
        self.script.exports.findexportbyname(name)
        return MESSAGE

    def list_modules(self):
        self.script.exports.listmodules()
        return MESSAGE

    def get_module_name_by_addr(self, addr):
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
            dumpdir = os.getcwd() + "/dump"
            dump_so_name = f"{dumpdir}/{name}_{base}_{size}.dump.so"
            with open(dump_so_name, "wb") as f:
                f.write(module_buffer)
                f.close()
            return dump_so_name
        else:
            return False

    def module_status(self, name):
        self.script.exports.modulestatus(name)
        return MESSAGE

    def il2cpp_dump(self):
        result = self.script.exports.il2cppdump()
        return result
