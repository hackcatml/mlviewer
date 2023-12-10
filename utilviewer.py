import inspect
import os
import re
import shutil
import warnings
import zipfile

from PyQt6 import QtCore, QtGui
from PyQt6.QtCore import pyqtSlot, QThread, Qt
from PyQt6.QtGui import QAction, QTextCursor
from PyQt6.QtWidgets import QTextBrowser, QTextEdit, QLineEdit, QVBoxLayout, QWidget, QPushButton, QCheckBox

import code
import dumper
import globvar


def add_file_to_zip(target_zip: str, file_to_insert: str, target_dir: str):
    # Open the existing zip file in append mode
    with zipfile.ZipFile(target_zip, 'a') as zip_ref:
        arcname = os.path.join(target_dir, os.path.basename(file_to_insert).split('.')[0])
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            zip_ref.write(file_to_insert, arcname=arcname)
        print(f"[*] {file_to_insert} added into {target_zip}")


class PullIPAWorker(QThread):
    pullipasig = QtCore.pyqtSignal(list)

    def __init__(self, fridaInstrument, statusBar):
        super(PullIPAWorker, self).__init__()
        self.fridaInstrument = fridaInstrument
        self.statusBar = statusBar

    def run(self) -> None:
        try:
            code.change_frida_script("scripts/util.js")
            bundle_path = self.fridaInstrument.get_bundle_path()
            bundle_id = self.fridaInstrument.get_bundle_id()
            executable_name = self.fridaInstrument.get_executable_name()
            code.revert_frida_script()

            payload_path = bundle_path.rpartition("/")[0]
            app_name = bundle_path.rpartition("/")[-1].partition(".")[0]

            dir_to_save = os.getcwd() + f"/dump/{bundle_id}"
            if os.path.exists(dir_to_save):
                shutil.rmtree(dir_to_save, ignore_errors=True)
            os.makedirs(dir_to_save)

            # dump decrypted binary
            code.change_frida_script("scripts/dump-ios-module.js")
            remote_path_to_pull_executable = self.fridaInstrument.dump_ios_module(executable_name)
            if remote_path_to_pull_executable is not False:
                if globvar.remote is False:
                    os.system(f"frida-pull -U \"{remote_path_to_pull_executable}\" {dir_to_save}")
                else:
                    os.system(
                        f"frida-pull -H {globvar.fridaInstrument.remoteaddr} \"{remote_path_to_pull_executable}\" {dir_to_save}")
            code.revert_frida_script()

            shell_cmd = f"rm -rf Payload"
            code.frida_shell_exec(shell_cmd, self)

            shell_cmd = f"ln -s {payload_path} Payload"
            code.frida_shell_exec(shell_cmd, self)

            self.statusBar.showMessage("Creating IPA...")
            # just in case, zip command isn't installed on the device
            shell_cmd = "apt-get install zip -y"
            code.frida_shell_exec(shell_cmd, self)
            # zip it
            shell_cmd = f"zip -r {app_name}.ipa Payload"
            code.frida_shell_exec(shell_cmd, self)

            self.statusBar.showMessage("Pulling IPA...")
            remote_path_to_pull = f"/var/mobile/Documents/{app_name}.ipa"
            if globvar.fridaInstrument.is_rootless():
                remote_path_to_pull = f"/var/jb/var/mobile/{app_name}.ipa"
            if globvar.remote is False:
                os.system(f"frida-pull -U {remote_path_to_pull} {dir_to_save}")
            else:
                os.system(
                    f"frida-pull -H {globvar.fridaInstrument.remoteaddr} {remote_path_to_pull} {dir_to_save}")

            # repackage ipa with the dumped binary
            add_file_to_zip(f"{dir_to_save}/{app_name}.ipa", f"{dir_to_save}/{executable_name}.decrypted", f"Payload/{bundle_path.split('/')[-1]}")

            # clean up
            os.remove(f"{dir_to_save}/{executable_name}.decrypted")
            shell_cmd = f"rm -rf Payload"
            code.frida_shell_exec(shell_cmd, self)
            shell_cmd = f"rm -rf {app_name}.ipa"
            code.frida_shell_exec(shell_cmd, self)
            shell_cmd = f"rm -rf {remote_path_to_pull_executable}"
            code.frida_shell_exec(shell_cmd, self)

            self.pullipasig.emit([app_name, dir_to_save])

        except Exception as e:
            print(f"{inspect.currentframe().f_code.co_name}: {e}")
            self.pullipasig.emit([])
            return


class DexDumpWorker(QThread):
    dex_dump_finished_sig = QtCore.pyqtSignal(bool)

    def __init__(self, dexDumpFridaInstrument, deepDexDumpMode):
        super().__init__()
        self.dexDumpFridaInstrument = dexDumpFridaInstrument
        self.deep_dex_dump = deepDexDumpMode

        self.name = self.dexDumpFridaInstrument.name
        self.remoteaddr = self.dexDumpFridaInstrument.remoteaddr
        self.pid = self.dexDumpFridaInstrument.pid

        self.out_dir = os.getcwd() + "/dump/dex_dump"
        if not os.path.exists(self.out_dir):
            os.makedirs(self.out_dir)
        else:
            shutil.rmtree(self.out_dir)
            os.makedirs(self.out_dir)

    def run(self):
        deep_dex_dump_option = ''
        if self.deep_dex_dump:
            deep_dex_dump_option = '-d'

        try:
            if self.remoteaddr != '':
                if self.pid is not None:
                    os.system(f"frida-dexdump -H {self.remoteaddr} -p {self.pid} -o \"{self.out_dir}\" {deep_dex_dump_option}")
                elif self.name is not None:
                    os.system(f"frida-dexdump -H {self.remoteaddr} -n \"{self.name}\" -o \"{self.out_dir}\" {deep_dex_dump_option}")
            else:
                if self.name is not None:
                    os.system(f"frida-dexdump -UF -n \"{self.name}\" -o \"{self.out_dir}\" {deep_dex_dump_option}")
                elif self.pid is not None:
                    os.system(f"frida-dexdump -UF -p {self.pid} -o \"{self.out_dir}\" {deep_dex_dump_option}")

            self.dex_dump_finished_sig.emit(True)

        except Exception as e:
            print(e)
            self.dex_dump_finished_sig.emit(False)


class UtilViewerClass(QTextEdit):
    def __init__(self, args):
        super(UtilViewerClass, self).__init__(args)
        self.parse_img_name = QLineEdit(None)
        self.parse_img_base = QTextBrowser(None)
        self.parse_img_path = QTextBrowser(None)
        self.parseImgName = QLineEdit(None)

        self.got_detail = ''
        self.la_symbol_ptr_detail = ''

        self.dynsym_header_checked = False
        self.dynsym_detail = ''
        self.dynsym_detail_list = []
        self.rela_plt_detail = ''
        self.got_plt_detail = ''
        self.symtab_header_checked = False
        self.symtab_detail = ''
        self.symtab_detail_list = []

        self.platform = None
        self.statusBar = None

        self.app_info_btn = QPushButton(None)
        self.pull_package_btn = QPushButton(None)
        self.full_memory_dump_btn = QPushButton(None)
        self.fullMemoryDumpInstrument = None

        self.pullIpaWorker = None
        self.fullMemoryDumpWorker = None

        self.dex_dump_btn = QPushButton(None)
        self.dex_dump_check_box = QCheckBox(None)
        self.is_deep_dex_dump_checked = False
        self.dex_dump_worker = None

    @pyqtSlot(dict)
    def parsesig_func(self, message: dict):
        # self.setPlainText(message['segname'])
        if self.platform == 'darwin':
            text = ''
            if (key := 'cmdnum') in message:
                text += f"Number of Load Commands: {str(message[key])}"
            if (key := 'command') in message:
                if message[key] == "SEGMENT_64":
                    if 'secname' in message:
                        if len(message['secname']) > 16:
                            message['secname'] = message['secname'][:16]
                        text += f"   |--Section: {message['secname']}, section_start: 0x{message['section_start']}"
                    else:
                        text += f"{message[key]}(0x{message['segment_offset']})\n|--Segment: {message['segname']}, vmaddr_start: 0x{message['vmaddr_start']}, vmaddr_end: 0x{message['vmaddr_end']}, file_offset: 0x{message['file_offset']}"
                elif message[key] == "LOAD_DYLINKER" or message[key] == "ID_DYLIB" or message[key] == "LOAD_DYLIB"\
                        or message[key] == "LOAD_WEAK_DYLIB" or message[key] == "RPATH":
                    text += f"{message[key]}(0x{message['command_offset']})\n|--Name: {message['name']}({message['img_base']})"
                elif message[key] == "SYMTAB":
                    text += f"{message[key]}(0x{message['command_offset']})\n|--Symbol_table_offset: 0x{message['symbol_table_offset']}, string_table_offset: 0x{message['string_table_offset']}"
                elif message[key] == "DYSYMTAB":
                    text += f"{message[key]}(0x{message['command_offset']})\n|--Indirect_symbol_table_offset: 0x{message['indirect_symbol_table_offset']}"
                elif message[key] == "MAIN":
                    text += f"{message[key]}(0x{message['command_offset']})\n|--Entry_offset: 0x{message['entry_offset']}"
                elif message[key] == "ENCRYPTION_INFO_64":
                    text += f"{message[key]}(0x{message['command_offset']})\n|--Crypt_offset: 0x{message['crypt_offset']}, crypt_size: {message['crypt_size']}, crypt_id: {message['crypt_id']}"
                else:
                    text += f"{message[key]}(0x{message['command_offset']})"
            if (key := 'secdetail') in message:
                if message[key] == "__got":
                    self.got_detail += f"symbol: {message['symbol']} --> address: {message['symbol_addr']} ({message['location']})\n"
                elif message[key] == "__la_symbol_ptr":
                    self.la_symbol_ptr_detail += f"symbol: {message['symbol']} --> address: {message['symbol_addr']} ({message['location']})\n"

            if text != '':
                self.append(text)
                self.moveCursor(QTextCursor.MoveOperation.Start, QTextCursor.MoveMode.MoveAnchor)

        elif self.platform == 'linux':
            text = ''
            if (key := 'header') in message:
                if message[key] == 'Elf_Ehdr':
                    text += f"Elf_Ehdr(Elf Header)\n|--e_phoff: {message['e_phoff']}, e_shoff: {message['e_shoff']}, e_phentsize: {message['e_phentsize']}, e_phnum: {message['e_phnum']}, e_shentsize: {message['e_shentsize']}, e_shnum: {message['e_shnum']}, e_shstrndx: {message['e_shstrndx']}"
                if message[key] == 'Elf_Phdr':
                    header_text = "\nElf_Phdr(Program Header)\n" if 'Elf_Phdr' not in self.toPlainText() else ""
                    details = f"|--p_type: {message['p_type']}, p_offset: {message['p_offset']}, p_vaddr: {message['p_vaddr']}, p_paddr: {message['p_paddr']}, p_filesz: {message['p_filesz']}, p_memsz: {message['p_memsz']}, p_flags: {message['p_flags']}, p_align: {message['p_align']}"
                    text += header_text + details
            if (key := 'section') in message:
                if message[key] == 'Dynamic Tags[.dynamic]':
                    text += f"\n{message[key]} section({message['section_offset']})"
                elif message[key] == '.got.plt' or message[key] == '.dynstr' or message[key] == '.dynsym' or message[key] == '.rela.plt':
                    text += f"|--d_tag: {message['d_tag']}({message[key]}), d_value: {message['d_value']}"
                else:
                    text += f"|--d_tag: {message['d_tag']}({message['d_tag_name']}), d_value: {message['d_value']}"
            if (key := 'section_detail') in message:
                if message[key] == "Symbol Table[.dynsym]":
                    header_text = ""
                    if not self.dynsym_header_checked:
                        header_text = f"\n{message[key]} section({message['section_offset']})"
                        self.dynsym_header_checked = True
                    self.dynsym_detail_list.append(f"st_name: {message['st_name']} --> symbol: {message['symbol_name']}, st_value: {message['st_value']}, st_size: {message['st_size']}, st_info: {message['st_info']}, st_other: {message['st_other']}, st_shndx: {message['st_shndx']}")
                    text += header_text
                if message[key] == "String Table[.dynstr]":
                    header_text = f"{message[key]} section({message['section_offset']})" if 'String Table' not in self.toPlainText() else ""
                    text += header_text
                if message[key] == "RELA[.rela.plt]":
                    header_text = f"{message[key]} section({message['section_offset']})" if 'RELA[.rela.plt]' not in self.toPlainText() else ""
                    self.rela_plt_detail += f"r_offset: {message['r_offset']}, r_info: {message['r_info']}, r_addend: {message['r_addend']}\n"
                    self.got_plt_detail += f"symbol: {message['symbol']} --> addr: {message['symbol_addr']}({message['location']})\n"
                    text += header_text
                if message[key] == ".got.plt":
                    text += f"{message[key]} section({message['section_offset']})"
                if message[key] == "Symbol Table[.symtab]":
                    header_text = ""
                    if not self.symtab_header_checked:
                        header_text = f"{message[key]} section"
                        self.symtab_header_checked = True
                    self.symtab_detail_list.append(f"st_name: {message['st_name']} --> symbol: {message['symbol_name']}, st_value: {message['st_value']}, st_size: {message['st_size']}, st_info: {message['st_info']}, st_other: {message['st_other']}, st_shndx: {message['st_shndx']}")
                    text += header_text
            if text != '':
                self.append(text)
                self.moveCursor(QTextCursor.MoveOperation.Start, QTextCursor.MoveMode.MoveAnchor)

    def parse(self, caller):
        self.setPlainText('')
        if globvar.fridaInstrument is None:
            self.statusBar.showMessage(f"Attach first", 3000)
            return
        elif globvar.fridaInstrument is not None:
            try:
                name = self.parse_img_name.text() if caller == "parse_img_name" else self.parseImgName.text()
                if self.platform == 'linux' and ('.so.1' in name or '.odex' in name):
                    self.statusBar.showMessage(f"Can't parse {name}", 5000)
                    return
                result = globvar.fridaInstrument.module_status(name)
                if result != '':
                    self.parse_img_name.setText(result['name'])
                    self.parse_img_base.setText(result['base'])
                    self.parse_img_path.setText(result['path'])
                    code.change_frida_script("scripts/util.js")
                    globvar.fridaInstrument.parsesig.connect(self.parsesig_func)

                    if self.platform == 'darwin':
                        # If module is not in an ".app/" directory (ex. /System/Library/Frameworks/Security.framework/Security)
                        # Parsing result seems wrong...
                        self.got_detail = ''
                        self.la_symbol_ptr_detail = ''
                        globvar.fridaInstrument.parse_macho(self.parse_img_base.toPlainText())
                    elif self.platform == 'linux':
                        self.dynsym_header_checked = False
                        self.dynsym_detail = ''
                        self.dynsym_detail_list.clear()
                        self.rela_plt_detail = ''
                        self.got_plt_detail = ''
                        self.symtab_header_checked = False
                        self.symtab_detail = ''
                        self.symtab_detail_list.clear()
                        globvar.fridaInstrument.parse_elf(self.parse_img_base.toPlainText())
                else:
                    self.statusBar.showMessage(f"No module {self.parse_img_name.text() if caller == 'parse_img_name' else self.parseImgName.text()} found")
                    return
            except Exception as e:
                # self.statusBar.showMessage(f"Error: {e}")
                print(f"Error: {e}")
                globvar.fridaInstrument.parsesig.disconnect(self.parsesig_func)
                code.revert_frida_script()
                return
            globvar.fridaInstrument.parsesig.disconnect(self.parsesig_func)
            code.revert_frida_script()

    @pyqtSlot(dict)
    def appinfosig_func(self, message: dict):
        text = ''
        if self.platform == "darwin":
            if (key := "pid") in message:
                text += f"[*] PID: {message[key]}\n"
            if (key := "display_name") in message:
                text += f"\n[*] Display Name: {message[key]}\n"
            if (key := "executable_name") in message:
                text += f"\n[*] Executable Name: {message[key]}\n"
            if (key := "bundleId") in message:
                text += f"\n[*] Bundle Identifier: {message[key]}\n"
            if (key := "minimum_os_version") in message:
                text += f"\n[*] Minimum OS Version: {message[key]}\n"
            if (key := "uisupported_devices") in message:
                text += f"\n[*] UISupportedDevices:\n{message[key]}\n"
            if (key := "bundle_path") in message:
                text += f"\n[*] Bundle Path:\n{message[key]}\n"
            if (key := "data_container_path") in message:
                text += f"\n[*] Data Container Path:\n{message[key]}\n"
            if (key := "info_plist") in message:
                text += f"\n[*] info.plist:\n{message[key]}\n"
        elif self.platform == "linux":
            if (key := "pid") in message:
                text += f"[*] PID:\n{message[key]}\n"
            if (key := "application_main") in message:
                text += f"\n[*] Application Main:\n{message[key]}\n"
            if (key := "package_name") in message:
                text += f"\n[*] Package Name:\n{message[key]}\n"
            if (key := "permissions") in message:
                permissions = '\n'.join(message[key])
                text += f"\n[*] Permissions:\n{permissions}\n"
            if (key := "base_code_path") in message:
                text += f"\n[*] Base Code Path:\n{message[key]}\n"
            if (key := "split_code_path") in message:
                try:
                    iter(message[key])
                    split_code_path = '\n'.join(message[key])
                except TypeError:
                    split_code_path = message[key]
                text += f"\n[*] Split Code Path:\n{split_code_path}\n"
            if (key := "data_dir") in message:
                text += f"\n[*] Data Directory:\n{message[key]}\n"

        if text != '':
            self.append(text)
            self.moveCursor(QTextCursor.MoveOperation.Start, QTextCursor.MoveMode.MoveAnchor)

    def app_info(self):
        self.setPlainText('')
        if globvar.fridaInstrument is None or globvar.isFridaAttached is False:
            self.statusBar.showMessage(f"Attach first", 3000)
            return
        elif globvar.fridaInstrument is not None:
            try:
                code.change_frida_script("scripts/util.js")
                globvar.fridaInstrument.appinfosig.connect(self.appinfosig_func)
                globvar.fridaInstrument.app_info()
            except Exception as e:
                print(f"Error: {e}")
                globvar.fridaInstrument.appinfosig.disconnect(self.appinfosig_func)
                code.revert_frida_script()
                return
            globvar.fridaInstrument.appinfosig.disconnect(self.appinfosig_func)
            code.revert_frida_script()

    @pyqtSlot(list)
    def pullipasig_func(self, sig: list):
        if len(sig) != 0:
            QThread.msleep(100)
            app_name = sig[0]
            dir_to_save = sig[1]
            self.statusBar.showMessage(f"Done! pulled ipa at {dir_to_save}/{app_name}", 5000)
            self.pullIpaWorker.terminate()
            return
        else:
            QThread.msleep(100)
            self.statusBar.showMessage("")
            self.pullIpaWorker.terminate()
            return

    def pull_package(self):
        if globvar.fridaInstrument is None or globvar.isFridaAttached is False:
            self.statusBar.showMessage(f"Attach first", 3000)
            return

        if self.platform == "darwin" and globvar.fridaInstrument is not None:
            self.pullIpaWorker = PullIPAWorker(globvar.fridaInstrument, self.statusBar)
            self.pullIpaWorker.pullipasig.connect(self.pullipasig_func)
            self.pullIpaWorker.start()
        elif self.platform == "linux" and globvar.fridaInstrument is not None:
            try:
                code.change_frida_script("scripts/util.js")
                package_name = globvar.fridaInstrument.pull_package("getPackageName")
                paths_to_pull = globvar.fridaInstrument.pull_package("getApkPaths")
                dir_to_save = os.getcwd() + f"/dump/{package_name}"
                os.makedirs(dir_to_save)
                for path in paths_to_pull:
                    if globvar.remote is False:
                        os.system(f"adb pull {path} {dir_to_save}")
                    else:
                        os.system(f"frida-pull -H {globvar.fridaInstrument.remoteaddr} {path} {dir_to_save}")
                self.statusBar.showMessage(f"Done! pulled at {dir_to_save}", 10000)
            except Exception as e:
                self.statusBar.showMessage(f"Error: {e}", 5000)
                code.revert_frida_script()
                return
            code.revert_frida_script()

    @pyqtSlot(int)
    def fullmemorydumpsig_func(self, sig: int):
        if sig == 1:
            QThread.msleep(100)
            self.fullMemoryDumpWorker.terminate()
            self.fullMemoryDumpInstrument.sessions.clear()
            self.fullMemoryDumpInstrument = None
            self.statusBar.showMessage(f"Done! check dump/full_memory_dump directory", 5000)

    @pyqtSlot(list)
    def progresssig_func(self, sig: list):
        if sig is not None and sig[0] == "memdump":
            self.statusBar.showMessage(f"Memory dumping...{sig[1]}%")
        elif sig is not None and sig[0] == "strdump":
            self.statusBar.showMessage(f"Running strings...{sig[1]}%")

    def full_memory_dump(self):
        if globvar.isFridaAttached is False:
            self.statusBar.showMessage("Attach first", 5000)
            return
        elif globvar.isFridaAttached is True:
            try:
                globvar.fridaInstrument.dummy_script()
            except Exception as e:
                if str(e) == globvar.errorType1:
                    globvar.fridaInstrument.sessions.clear()
                self.statusBar().showMessage(f"{inspect.currentframe().f_code.co_name}: {e}", 3000)
                return

        if self.fullMemoryDumpInstrument is None or len(self.fullMemoryDumpInstrument.sessions) == 0:
            self.fullMemoryDumpInstrument = code.Instrument("scripts/fullmemorydump.js",
                                                            globvar.remote,
                                                            globvar.fridaInstrument.remoteaddr,
                                                            globvar.fridaInstrument.attachtarget,
                                                            False)
            msg = self.fullMemoryDumpInstrument.instrument("full_memory_dump")
            if msg is not None:
                self.statusBar.showMessage(f"{inspect.currentframe().f_code.co_name}: {msg}", 3000)
                return
        # full memory dump thread worker start
        self.fullMemoryDumpWorker = dumper.FullMemoryDumpWorker(self.fullMemoryDumpInstrument, self.statusBar)
        self.fullMemoryDumpWorker.fullmemorydumpsig.connect(self.fullmemorydumpsig_func)
        self.fullMemoryDumpWorker.progresssig.connect(self.progresssig_func)
        self.fullMemoryDumpWorker.start()
        self.statusBar.showMessage("Start memory dump...")
        return

    @pyqtSlot(bool)
    def dex_dump_finished_sig_func(self, sig: bool):
        if sig is True:
            self.statusBar.showMessage(f"Dex dump done!", 3000)
            self.dex_dump_worker.quit()
        elif sig is False:
            self.statusBar.showMessage(f"Dex dump failed", 3000)
            self.dex_dump_worker.quit()

    def dex_dump_checkbox(self, state):
        self.is_deep_dex_dump_checked = state == Qt.CheckState.Checked.value

    def dex_dump(self):
        if self.platform == 'darwin':
            self.statusBar.showMessage(f"Dex dump is only for Android", 3000)
            return

        self.dex_dump_worker = DexDumpWorker(globvar.fridaInstrument, self.is_deep_dex_dump_checked)
        self.dex_dump_worker.dex_dump_finished_sig.connect(self.dex_dump_finished_sig_func)
        self.dex_dump_worker.start()

    def contextMenuEvent(self, e: QtGui.QContextMenuEvent) -> None:
        menu = super(UtilViewerClass, self).createStandardContextMenu()  # Get the default context menu
        select_all_action = next((action for action in menu.actions() if "Select All" in action.text()), None)

        if select_all_action:
            # parse more on __got, __la_symbol_ptr tables
            selected_text = self.textCursor().selectedText()
            if self.platform == 'linux':
                detail_section = ['.dynsym', '.rela.plt', '.got.plt', '.symtab']
                for item in detail_section:
                    if item in self.textCursor().block().text():
                        selected_text = item
            regex = re.compile(r'(\b__got\b|\b__la_symbol_ptr\b|\.dynsym|\.rela.plt|\.got\.plt|\.symtab)')
            match = regex.match(selected_text)
            is_selected = bool(selected_text)

            def create_action(text, enabled, func):
                action = QAction(text, self)
                action.setEnabled(enabled)
                action.triggered.connect(func)
                return action

            if match and is_selected:
                detail_action = create_action(f"Parse {selected_text}", True, lambda: self.detail(selected_text))
                menu.insertAction(select_all_action, detail_action)

        menu.exec(e.globalPos())

    def detail(self, title):
        detail_of_what = None
        if title == "__got":
            detail_of_what = self.got_detail
        elif title == "__la_symbol_ptr":
            detail_of_what = self.la_symbol_ptr_detail
        elif title == ".dynsym":
            self.dynsym_detail = "\n".join(self.dynsym_detail_list)
            detail_of_what = self.dynsym_detail
        elif title == '.rela.plt':
            detail_of_what = self.rela_plt_detail
        elif title == '.got.plt':
            detail_of_what = self.got_plt_detail
        elif title == '.symtab':
            self.symtab_detail = "\n".join(self.symtab_detail_list)
            detail_of_what = self.symtab_detail
        self.new_detail_widget = NewDetailWidget(title, detail_of_what)
        self.new_detail_widget.show()


class ParseImgListImgViewerClass(QTextBrowser):
    modulenamesig = QtCore.pyqtSignal(str)

    def __init__(self, args):
        super(ParseImgListImgViewerClass, self).__init__(args)

    def mousePressEvent(self, e: QtGui.QMouseEvent) -> None:
        super(ParseImgListImgViewerClass, self).mousePressEvent(e)
        pos = e.pos()
        tc = self.cursorForPosition(pos)
        self.modulenamesig.emit(tc.block().text())


class NewDetailWidget(QWidget):
    def __init__(self, title, detail):
        super().__init__()
        self.setWindowTitle(f"{title}")
        self.detail = detail.strip().split('\n')
        self.search_input = QLineEdit()
        self.text_edit = QTextEdit()
        self.text_edit.setPlainText(detail)
        self.text_edit.setReadOnly(True)
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.text_edit)
        self.layout.addWidget(self.search_input)
        self.setLayout(self.layout)
        self.resize(500, 250)
        self.search_input.setFocus()

        self.search_input.textChanged.connect(self.search)

    def search(self):
        text_to_find = self.search_input.text().lower()

        matched = ''
        for string in self.detail:
            if string.lower().find(text_to_find) != -1:
                matched += string + '\n'
        self.text_edit.setText(matched)


