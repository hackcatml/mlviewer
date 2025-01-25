import inspect
import os
import re
import shutil
import warnings
import zipfile

from PyQt6 import QtCore, QtGui
from PyQt6.QtCore import pyqtSlot, QThread, Qt
from PyQt6.QtGui import QAction, QTextCursor
from PyQt6.QtWidgets import QTextBrowser, QTextEdit, QLineEdit, QVBoxLayout, QWidget, QPushButton, QCheckBox, \
    QMessageBox

import frida_code
import diff
import dumper
import gvar


def add_file_to_zip(target_zip: str, file_to_insert: str, target_dir: str):
    # Open the existing zip file in append mode
    with zipfile.ZipFile(target_zip, 'a') as zip_ref:
        arcname = os.path.join(target_dir, os.path.basename(file_to_insert).split('.')[0])
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            zip_ref.write(file_to_insert, arcname=arcname)
        print(f"[*] {file_to_insert} added into {target_zip}")


class PullIPAWorker(QThread):
    pull_ipa_signal = QtCore.pyqtSignal(list)

    def __init__(self, frida_instrument, statusBar):
        super(PullIPAWorker, self).__init__()
        self.frida_instrument = frida_instrument
        self.statusBar = statusBar

    def run(self) -> None:
        try:
            frida_code.change_frida_script("scripts/util.js")
            bundle_path = self.frida_instrument.get_bundle_path()
            bundle_id = self.frida_instrument.get_bundle_id()
            executable_name = self.frida_instrument.get_executable_name()
            frida_code.revert_frida_script()

            payload_path = bundle_path.rpartition("/")[0]
            app_name = bundle_path.rpartition("/")[-1].partition(".")[0]

            dir_to_save = os.getcwd() + f"/dump/{bundle_id}"
            if os.path.exists(dir_to_save):
                shutil.rmtree(dir_to_save, ignore_errors=True)
            os.makedirs(dir_to_save)

            # dump decrypted binary
            frida_code.change_frida_script("scripts/dump-ios-module.js")
            remote_path_to_pull_executable = self.frida_instrument.dump_ios_module(executable_name)
            if remote_path_to_pull_executable is not False:
                if gvar.remote is False:
                    os.system(f"frida-pull -U \"{remote_path_to_pull_executable}\" {dir_to_save}")
                else:
                    os.system(
                        f"frida-pull -H {gvar.frida_instrument.remote_addr} \"{remote_path_to_pull_executable}\" {dir_to_save}")
            frida_code.revert_frida_script()

            shell_cmd = f"rm -rf Payload"
            frida_code.frida_shell_exec(shell_cmd, self)

            shell_cmd = f"ln -s {payload_path} Payload"
            frida_code.frida_shell_exec(shell_cmd, self)

            self.statusBar.showMessage("\tCreating IPA...")
            # just in case, zip command isn't installed on the device
            shell_cmd = "apt-get install zip -y"
            frida_code.frida_shell_exec(shell_cmd, self)
            # zip it
            shell_cmd = f"zip -r {app_name}.ipa Payload"
            frida_code.frida_shell_exec(shell_cmd, self)

            self.statusBar.showMessage("\tPulling IPA...")
            remote_path_to_pull = f"/var/mobile/Documents/{app_name}.ipa"
            if gvar.frida_instrument.is_rootless():
                remote_path_to_pull = f"/var/jb/var/mobile/{app_name}.ipa"
            if gvar.remote is False:
                os.system(f"frida-pull -U {remote_path_to_pull} {dir_to_save}")
            else:
                os.system(
                    f"frida-pull -H {gvar.frida_instrument.remote_addr} {remote_path_to_pull} {dir_to_save}")

            # repackage ipa with the dumped binary
            add_file_to_zip(f"{dir_to_save}/{app_name}.ipa", f"{dir_to_save}/{executable_name}.decrypted", f"Payload/{bundle_path.split('/')[-1]}")

            # clean up
            os.remove(f"{dir_to_save}/{executable_name}.decrypted")
            shell_cmd = f"rm -rf Payload"
            frida_code.frida_shell_exec(shell_cmd, self)
            shell_cmd = f"rm -rf {app_name}.ipa"
            frida_code.frida_shell_exec(shell_cmd, self)
            shell_cmd = f"rm -rf {remote_path_to_pull_executable}"
            frida_code.frida_shell_exec(shell_cmd, self)

            self.pull_ipa_signal.emit([app_name, dir_to_save])

        except Exception as e:
            print(f"{inspect.currentframe().f_code.co_name}: {e}")
            self.pull_ipa_signal.emit([])
            return


class DexDumpWorker(QThread):
    dex_dump_finished_signal = QtCore.pyqtSignal(bool)

    def __init__(self, dexDumpFridaInstrument, deepDexDumpMode):
        super().__init__()
        self.dex_dump_frida_instrument = dexDumpFridaInstrument
        self.deep_dex_dump = deepDexDumpMode

        self.name = self.dex_dump_frida_instrument.name
        self.remote_addr = self.dex_dump_frida_instrument.remote_addr
        self.pid = self.dex_dump_frida_instrument.pid

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
            if self.remote_addr != '':
                if self.pid is not None:
                    os.system(f"frida-dexdump -H {self.remote_addr} -p {self.pid} -o \"{self.out_dir}\" {deep_dex_dump_option}")
                elif self.name is not None:
                    os.system(f"frida-dexdump -H {self.remote_addr} -n \"{self.name}\" -o \"{self.out_dir}\" {deep_dex_dump_option}")
            else:
                if self.name is not None:
                    os.system(f"frida-dexdump -UF -n \"{self.name}\" -o \"{self.out_dir}\" {deep_dex_dump_option}")
                elif self.pid is not None:
                    os.system(f"frida-dexdump -UF -p {self.pid} -o \"{self.out_dir}\" {deep_dex_dump_option}")

            self.dex_dump_finished_signal.emit(True)

        except Exception as e:
            print(e)
            self.dex_dump_finished_signal.emit(False)


class UtilViewerClass(QTextEdit):
    def __init__(self, args):
        super(UtilViewerClass, self).__init__(args)
        self.parse_img_name = QLineEdit(None)
        self.parse_img_base = QTextBrowser(None)
        self.parse_img_path = QTextBrowser(None)
        self.parseImgName = QLineEdit(None)
        self.search_input = QLineEdit(None)
        self.search_button = QPushButton(None)
        self.last_search_query = ""
        self.search_start_position = 0

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
        self.full_memory_dump_instrument = None

        self.pull_ipa_worker = None
        self.full_memory_dump_worker = None

        self.binary_diff_btn = QPushButton(None)
        self.binary_diff_dialog = None

        self.dex_dump_btn = QPushButton(None)
        self.dex_dump_check_box = QCheckBox(None)
        self.is_deep_dex_dump_checked = False
        self.dex_dump_worker = None

        self.show_proc_self_maps_btn = QPushButton(None)

    @pyqtSlot(dict)
    def parse_sig_func(self, sig: dict):
        # self.setPlainText(sig['segname'])
        if self.platform == 'darwin':
            text = ''
            if (key := 'cmdnum') in sig:
                text += f"Number of Load Commands: {str(sig[key])}"
            if (key := 'command') in sig:
                if sig[key] == "SEGMENT_64":
                    if 'secname' in sig:
                        if len(sig['secname']) > 16:
                            sig['secname'] = sig['secname'][:16]
                        text += f"   |--Section: {sig['secname']}, section_start: 0x{sig['section_start']}"
                    else:
                        text += f"{sig[key]}(0x{sig['segment_offset']})\n|--Segment: {sig['segname']}, vmaddr_start: 0x{sig['vmaddr_start']}, vmaddr_end: 0x{sig['vmaddr_end']}, file_offset: 0x{sig['file_offset']}"
                elif sig[key] == "LOAD_DYLINKER" or sig[key] == "ID_DYLIB" or sig[key] == "LOAD_DYLIB"\
                        or sig[key] == "LOAD_WEAK_DYLIB" or sig[key] == "RPATH":
                    text += f"{sig[key]}(0x{sig['command_offset']})\n|--Name: {sig['name']}({sig['img_base']})"
                elif sig[key] == "SYMTAB":
                    text += f"{sig[key]}(0x{sig['command_offset']})\n|--Symbol_table_offset: 0x{sig['symbol_table_offset']}, string_table_offset: 0x{sig['string_table_offset']}"
                elif sig[key] == "DYSYMTAB":
                    text += f"{sig[key]}(0x{sig['command_offset']})\n|--Indirect_symbol_table_offset: 0x{sig['indirect_symbol_table_offset']}"
                elif sig[key] == "MAIN":
                    text += f"{sig[key]}(0x{sig['command_offset']})\n|--Entry_offset: 0x{sig['entry_offset']}"
                elif sig[key] == "ENCRYPTION_INFO_64":
                    text += f"{sig[key]}(0x{sig['command_offset']})\n|--Crypt_offset: 0x{sig['crypt_offset']}, crypt_size: {sig['crypt_size']}, crypt_id: {sig['crypt_id']}"
                else:
                    text += f"{sig[key]}(0x{sig['command_offset']})"
            if (key := 'sec_detail') in sig:
                if sig[key] == "__got":
                    self.got_detail += f"symbol: {sig['symbol']} --> address: {sig['symbol_addr']} ({sig['location']})\n"
                elif sig[key] == "__la_symbol_ptr":
                    self.la_symbol_ptr_detail += f"symbol: {sig['symbol']} --> address: {sig['symbol_addr']} ({sig['location']})\n"

            if text != '':
                self.append(text)
                self.moveCursor(QTextCursor.MoveOperation.Start, QTextCursor.MoveMode.MoveAnchor)

        elif self.platform == 'linux':
            text = ''
            if (key := 'header') in sig:
                if sig[key] == 'Elf_Ehdr':
                    text += f"Elf_Ehdr(Elf Header)\n|--e_phoff: {sig['e_phoff']}, e_shoff: {sig['e_shoff']}, e_phentsize: {sig['e_phentsize']}, e_phnum: {sig['e_phnum']}, e_shentsize: {sig['e_shentsize']}, e_shnum: {sig['e_shnum']}, e_shstrndx: {sig['e_shstrndx']}"
                if sig[key] == 'Elf_Phdr':
                    header_text = "\nElf_Phdr(Program Header)\n" if 'Elf_Phdr' not in self.toPlainText() else ""
                    details = f"|--p_type: {sig['p_type']}, p_offset: {sig['p_offset']}, p_vaddr: {sig['p_vaddr']}, p_paddr: {sig['p_paddr']}, p_filesz: {sig['p_filesz']}, p_memsz: {sig['p_memsz']}, p_flags: {sig['p_flags']}, p_align: {sig['p_align']}"
                    text += header_text + details
            if (key := 'section') in sig:
                if sig[key] == 'Dynamic Tags[.dynamic]':
                    text += f"\n{sig[key]} section({sig['section_offset']})"
                elif sig[key] == '.got.plt' or sig[key] == '.dynstr' or sig[key] == '.dynsym' or sig[key] == '.rela.plt':
                    text += f"|--d_tag: {sig['d_tag']}({sig[key]}), d_value: {sig['d_value']}"
                else:
                    text += f"|--d_tag: {sig['d_tag']}({sig['d_tag_name']}), d_value: {sig['d_value']}"
            if (key := 'section_detail') in sig:
                if sig[key] == "Symbol Table[.dynsym]":
                    header_text = ""
                    if not self.dynsym_header_checked:
                        header_text = f"\n{sig[key]} section({sig['section_offset']})"
                        self.dynsym_header_checked = True
                    self.dynsym_detail_list.append(f"st_name: {sig['st_name']} --> symbol: {sig['symbol_name']}, st_value: {sig['st_value']}, st_size: {sig['st_size']}, st_info: {sig['st_info']}, st_other: {sig['st_other']}, st_shndx: {sig['st_shndx']}")
                    text += header_text
                if sig[key] == "String Table[.dynstr]":
                    header_text = f"{sig[key]} section({sig['section_offset']})" if 'String Table' not in self.toPlainText() else ""
                    text += header_text
                if sig[key] == "RELA[.rela.plt]":
                    header_text = f"{sig[key]} section({sig['section_offset']})" if 'RELA[.rela.plt]' not in self.toPlainText() else ""
                    self.rela_plt_detail += f"r_offset: {sig['r_offset']}, r_info: {sig['r_info']}, r_addend: {sig['r_addend']}\n"
                    self.got_plt_detail += f"symbol: {sig['symbol']} --> addr: {sig['symbol_addr']}({sig['location']})\n"
                    text += header_text
                if sig[key] == ".got.plt":
                    text += f"{sig[key]} section({sig['section_offset']})"
                if sig[key] == "Symbol Table[.symtab]":
                    header_text = ""
                    if not self.symtab_header_checked:
                        header_text = f"{sig[key]} section"
                        self.symtab_header_checked = True
                    self.symtab_detail_list.append(f"st_name: {sig['st_name']} --> symbol: {sig['symbol_name']}, st_value: {sig['st_value']}, st_size: {sig['st_size']}, st_info: {sig['st_info']}, st_other: {sig['st_other']}, st_shndx: {sig['st_shndx']}")
                    text += header_text
            if text != '':
                self.append(text)
                self.moveCursor(QTextCursor.MoveOperation.Start, QTextCursor.MoveMode.MoveAnchor)

    @pyqtSlot(dict)
    def app_info_sig_func(self, sig: dict):
        text = ''
        if self.platform == "darwin":
            if (key := "pid") in sig:
                text += f"[*] PID: {sig[key]}\n"
            if (key := "display_name") in sig:
                text += f"\n[*] Display Name: {sig[key]}\n"
            if (key := "executable_name") in sig:
                text += f"\n[*] Executable Name: {sig[key]}\n"
            if (key := "bundleId") in sig:
                text += f"\n[*] Bundle Identifier: {sig[key]}\n"
            if (key := "minimum_os_version") in sig:
                text += f"\n[*] Minimum OS Version: {sig[key]}\n"
            if (key := "uisupported_devices") in sig:
                text += f"\n[*] UISupportedDevices:\n{sig[key]}\n"
            if (key := "bundle_path") in sig:
                text += f"\n[*] Bundle Path:\n{sig[key]}\n"
            if (key := "data_container_path") in sig:
                text += f"\n[*] Data Container Path:\n{sig[key]}\n"
            if (key := "info_plist") in sig:
                text += f"\n[*] info.plist:\n{sig[key]}\n"
        elif self.platform == "linux":
            if (key := "pid") in sig:
                text += f"[*] PID:\n{sig[key]}\n"
            if (key := "application_main") in sig:
                text += f"\n[*] Application Main:\n{sig[key]}\n"
            if (key := "package_name") in sig:
                text += f"\n[*] Package Name:\n{sig[key]}\n"
            if (key := "permissions") in sig:
                permissions = '\n'.join(sig[key])
                text += f"\n[*] Permissions:\n{permissions}\n"
            if (key := "base_code_path") in sig:
                text += f"\n[*] Base Code Path:\n{sig[key]}\n"
            if (key := "split_code_path") in sig:
                try:
                    iter(sig[key])
                    split_code_path = '\n'.join(sig[key])
                except TypeError:
                    split_code_path = sig[key]
                text += f"\n[*] Split Code Path:\n{split_code_path}\n"
            if (key := "data_dir") in sig:
                text += f"\n[*] Data Directory:\n{sig[key]}\n"

        if text != '':
            self.append(text)
            self.moveCursor(QTextCursor.MoveOperation.Start, QTextCursor.MoveMode.MoveAnchor)

    @pyqtSlot(list)
    def pull_ipa_sig_func(self, sig: list):
        if len(sig) != 0:
            QThread.msleep(100)
            app_name = sig[0]
            dir_to_save = sig[1]
            self.statusBar.showMessage(f"\tDone! pulled ipa at {dir_to_save}/{app_name}", 5000)
            self.pull_ipa_worker.terminate()
            return
        else:
            QThread.msleep(100)
            self.statusBar.showMessage("\t")
            self.pull_ipa_worker.terminate()
            return

    @pyqtSlot(int)
    def full_memory_dump_sig_func(self, sig: int):
        if sig == 1:
            QThread.msleep(100)
            self.full_memory_dump_worker.terminate()
            self.full_memory_dump_instrument.sessions.clear()
            self.full_memory_dump_instrument = None
            self.statusBar.showMessage(f"\tDone! check dump/full_memory_dump directory", 5000)

    @pyqtSlot(list)
    def progress_sig_func(self, sig: list):
        if sig is not None and sig[0] == "memdump":
            self.statusBar.showMessage(f"\tMemory dumping...{sig[1]}%")
        elif sig is not None and sig[0] == "strdump":
            self.statusBar.showMessage(f"\tRunning strings...{sig[1]}%")

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

    @pyqtSlot(bool)
    def dex_dump_finished_sig_func(self, sig: bool):
        if sig is True:
            self.statusBar.showMessage(f"\tDex dump done!", 3000)
            self.dex_dump_worker.quit()
        elif sig is False:
            self.statusBar.showMessage(f"\tDex dump failed", 3000)
            self.dex_dump_worker.quit()

    def parse(self, caller):
        self.setPlainText('')
        if gvar.frida_instrument is None:
            self.statusBar.showMessage(f"\tAttach first", 3000)
            return
        elif gvar.frida_instrument is not None:
            try:
                name = self.parse_img_name.text() if caller == "parse_img_name" else self.parseImgName.text()
                if self.platform == 'linux' and ('.so.1' in name or '.odex' in name):
                    self.statusBar.showMessage(f"\tCan't parse {name}", 5000)
                    return
                hex_regex_pattern = r'(\b0x[a-fA-F0-9]+\b)'
                hex_regex = re.compile(hex_regex_pattern)
                addr_match = hex_regex.match(name)
                if addr_match is not None:
                    result = gvar.frida_instrument.get_module_by_addr(addr_match[0])
                else:
                    result = gvar.frida_instrument.module_status(name)
                if result != '':
                    self.parse_img_name.setText(result['name'])
                    self.parse_img_base.setText(result['base'])
                    self.parse_img_path.setText(result['path'])
                elif result == '' and addr_match is not None:
                    self.parse_img_name.setText('')
                    self.parse_img_base.setText(addr_match[0])
                    self.parse_img_path.setText('')
                else:
                    self.statusBar.showMessage(
                        f"No module {self.parse_img_name.text() if caller == 'parse_img_name' else self.parseImgName.text()} found")
                    return

                frida_code.change_frida_script("scripts/util.js")
                gvar.frida_instrument.parse_signal.connect(self.parse_sig_func)
                if self.platform == 'darwin':
                    # If module is not in an ".app/" directory (ex. /System/Library/Frameworks/Security.framework/Security)
                    # Parsing result seems wrong...
                    self.got_detail = ''
                    self.la_symbol_ptr_detail = ''
                    gvar.frida_instrument.parse_macho(self.parse_img_base.toPlainText())
                elif self.platform == 'linux':
                    self.dynsym_header_checked = False
                    self.dynsym_detail = ''
                    self.dynsym_detail_list.clear()
                    self.rela_plt_detail = ''
                    self.got_plt_detail = ''
                    self.symtab_header_checked = False
                    self.symtab_detail = ''
                    self.symtab_detail_list.clear()
                    gvar.frida_instrument.parse_elf(self.parse_img_base.toPlainText())
            except Exception as e:
                # self.statusBar.showMessage(f"\tError: {e}")
                print(f"Error: {e}")
                gvar.frida_instrument.parse_signal.disconnect(self.parse_sig_func)
                frida_code.revert_frida_script()
                return
            gvar.frida_instrument.parse_signal.disconnect(self.parse_sig_func)
            frida_code.revert_frida_script()

    def app_info(self):
        self.setPlainText('')
        if gvar.frida_instrument is None or gvar.is_frida_attached is False:
            self.statusBar.showMessage(f"\tAttach first", 3000)
            return
        elif gvar.frida_instrument is not None:
            try:
                frida_code.change_frida_script("scripts/util.js")
                gvar.frida_instrument.app_info_signal.connect(self.app_info_sig_func)
                gvar.frida_instrument.app_info()
            except Exception as e:
                print(f"Error: {e}")
                gvar.frida_instrument.app_info_signal.disconnect(self.app_info_sig_func)
                frida_code.revert_frida_script()
                return
            gvar.frida_instrument.app_info_signal.disconnect(self.app_info_sig_func)
            frida_code.revert_frida_script()

    def pull_package(self):
        if gvar.frida_instrument is None or gvar.is_frida_attached is False:
            self.statusBar.showMessage(f"\tAttach first", 3000)
            return

        if self.platform == "darwin" and gvar.frida_instrument is not None:
            self.pull_ipa_worker = PullIPAWorker(gvar.frida_instrument, self.statusBar)
            self.pull_ipa_worker.pull_ipa_signal.connect(self.pull_ipa_sig_func)
            self.pull_ipa_worker.start()
        elif self.platform == "linux" and gvar.frida_instrument is not None:
            try:
                frida_code.change_frida_script("scripts/util.js")
                package_name = gvar.frida_instrument.pull_package("getPackageName")
                paths_to_pull = gvar.frida_instrument.pull_package("getApkPaths")
                dir_to_save = os.getcwd() + f"/dump/{package_name}"
                os.makedirs(dir_to_save)
                for path in paths_to_pull:
                    if gvar.remote is False:
                        os.system(f"adb pull {path} {dir_to_save}")
                    else:
                        os.system(f"frida-pull -H {gvar.frida_instrument.remote_addr} {path} {dir_to_save}")
                self.statusBar.showMessage(f"\tDone! pulled at {dir_to_save}", 10000)
            except Exception as e:
                self.statusBar.showMessage(f"\tError: {e}", 5000)
                frida_code.revert_frida_script()
                return
            frida_code.revert_frida_script()

    def full_memory_dump(self):
        if gvar.is_frida_attached is False:
            self.statusBar.showMessage("\tAttach first", 5000)
            return
        elif gvar.is_frida_attached is True:
            try:
                gvar.frida_instrument.dummy_script()
            except Exception as e:
                if str(e) == gvar.ERROR_SCRIPT_DESTROYED:
                    gvar.frida_instrument.sessions.clear()
                self.statusBar.showMessage(f"\t{inspect.currentframe().f_code.co_name}: {e}", 3000)
                return

        if self.full_memory_dump_instrument is None or len(self.full_memory_dump_instrument.sessions) == 0:
            self.full_memory_dump_instrument = frida_code.Instrument("scripts/full-memory-dump.js",
                                                            gvar.remote,
                                                            gvar.frida_instrument.remote_addr,
                                                            gvar.frida_instrument.attachtarget,
                                                            False)
            msg = self.full_memory_dump_instrument.instrument("full_memory_dump")
            if msg is not None:
                self.statusBar.showMessage(f"\t{inspect.currentframe().f_code.co_name}: {msg}", 3000)
                return
        # full memory dump thread worker start
        self.full_memory_dump_worker = dumper.FullMemoryDumpWorker(self.full_memory_dump_instrument, self.statusBar)
        self.full_memory_dump_worker.full_memory_dump_signal.connect(self.full_memory_dump_sig_func)
        self.full_memory_dump_worker.progress_signal.connect(self.progress_sig_func)
        self.full_memory_dump_worker.start()
        self.statusBar.showMessage("\tStart memory dump...")
        return

    def binary_diff(self):
        if self.binary_diff_dialog is not None and self.binary_diff_dialog.diff_result is not None:
            reply = QMessageBox.question(
                self,
                "Binary Diff",
                "There's a binary diff result already done. Show the result?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes
            )

            if reply == QMessageBox.StandardButton.Yes:
                self.binary_diff_dialog.binary_diff_result_window.show()
            else:
                self.binary_diff_dialog = diff.DiffDialogClass(self.statusBar)
                self.binary_diff_dialog.diff_dialog.show()
        elif self.binary_diff_dialog is not None:   # and self.binary_diff_dialog.binary_diff_result_window is not None:
            # self.binary_diff_dialog.binary_diff_result_window.show()
            self.binary_diff_dialog.diff_dialog.show()
        else:
            self.binary_diff_dialog = diff.DiffDialogClass(self.statusBar)
            self.binary_diff_dialog.diff_dialog.show()

    def dex_dump_checkbox(self, state):
        self.is_deep_dex_dump_checked = state == Qt.CheckState.Checked.value

    def dex_dump(self):
        if not gvar.is_frida_attached:
            self.statusBar.showMessage(f"\tAttach first", 5000)
            return
        if self.platform == 'darwin':
            self.statusBar.showMessage(f"\tDex dump is only for Android", 5000)
            return

        self.dex_dump_worker = DexDumpWorker(gvar.frida_instrument, self.is_deep_dex_dump_checked)
        self.dex_dump_worker.dex_dump_finished_signal.connect(self.dex_dump_finished_sig_func)
        self.dex_dump_worker.start()

    def show_maps(self):
        if not gvar.is_frida_attached:
            self.statusBar.showMessage(f"\tAttach first", 5000)
            return
        if self.platform == 'darwin':
            self.statusBar.showMessage(f"\tShow maps is only for Android", 5000)
            return
        self.setPlainText('')
        if gvar.frida_instrument is not None:
            try:
                frida_code.change_frida_script("scripts/util.js")
                result = gvar.frida_instrument.show_maps()
            except Exception as e:
                print(f"Error: {e}")
                frida_code.revert_frida_script()
                return
            if result is not None:
                self.setPlainText(result)
            frida_code.revert_frida_script()

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

    def search_text(self):
        search_query = self.search_input.text()
        if not search_query:
            return

        if search_query != self.last_search_query:
            self.search_start_position = 0
            self.last_search_query = search_query

        cursor = self.textCursor()
        cursor.setPosition(self.search_start_position)
        self.setTextCursor(cursor)

        found = self.find(search_query)

        if found:
            self.search_start_position = self.textCursor().position()
            # Highlight the line containing the found text
            cursor = self.textCursor()
            cursor.select(QTextCursor.SelectionType.LineUnderCursor)
            self.setTextCursor(cursor)
        else:
            # Reset to the beginning for the next search
            self.search_start_position = 0


class ParseImgListImgViewerClass(QTextBrowser):
    module_name_signal = QtCore.pyqtSignal(str)

    def __init__(self, args):
        super(ParseImgListImgViewerClass, self).__init__(args)

    def mousePressEvent(self, e: QtGui.QMouseEvent) -> None:
        super(ParseImgListImgViewerClass, self).mousePressEvent(e)
        pos = e.pos()
        tc = self.cursorForPosition(pos)
        self.module_name_signal.emit(tc.block().text())


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


