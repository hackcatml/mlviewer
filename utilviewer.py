import re

from PyQt6 import QtCore, QtGui
from PyQt6.QtCore import pyqtSlot
from PyQt6.QtGui import QAction, QTextCursor
from PyQt6.QtWidgets import QTextBrowser, QTextEdit, QLineEdit, QVBoxLayout, QWidget

import code
import globvar


class UtilViewerClass(QTextEdit):
    def __init__(self, args):
        super(UtilViewerClass, self).__init__(args)
        self.parse_img_name = QLineEdit(None)
        self.parse_img_base = QTextBrowser(None)
        self.parse_img_path = QTextBrowser(None)
        self.parseImgName = QLineEdit(None)

        self.got_detail = ''
        self.la_symbol_ptr_detail = ''

        self.rela_plt_detail = ''

        self.platform = None
        self.statusBar = None

    @pyqtSlot(dict)
    def messagedictsig_func(self, message: dict):
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
            if (key := 'section') in message:
                if message[key] == ".rela.plt":
                    text += f"symbol: {message['symbol']} --> addr: {message['symbol_addr']}({message['location']})"

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
                    globvar.fridaInstrument.messagedictsig.connect(self.messagedictsig_func)

                    if self.platform == 'darwin':
                        # If module is not in an ".app/" directory (ex. /System/Library/Frameworks/Security.framework/Security)
                        # Parsing result seems wrong...
                        self.got_detail = ''
                        self.la_symbol_ptr_detail = ''
                        globvar.fridaInstrument.parse_macho(self.parse_img_base.toPlainText())
                    elif self.platform == 'linux':
                        self.rela_plt_detail = ''
                        globvar.fridaInstrument.parse_elf(self.parse_img_base.toPlainText())
                else:
                    self.statusBar.showMessage(f"No module {self.parse_img_name.text() if caller == 'parse_img_name' else self.parseImgName.text()} found")
                    return
            except Exception as e:
                # self.statusBar.showMessage(f"Error: {e}")
                print(f"Error: {e}")
                code.revert_frida_script()
                return
            globvar.fridaInstrument.messagedictsig.disconnect(self.messagedictsig_func)
            code.revert_frida_script()

    def contextMenuEvent(self, e: QtGui.QContextMenuEvent) -> None:
        menu = super(UtilViewerClass, self).createStandardContextMenu()  # Get the default context menu
        select_all_action = next((action for action in menu.actions() if "Select All" in action.text()), None)

        if select_all_action:
            # parse more on __got, __la_symbol_ptr tables
            selected_text = self.textCursor().selectedText()
            regex = re.compile(r'(\b__got\b|\b__la_symbol_ptr\b)')
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
        if title == "__got":
            self.new_detail_widget = NewDetailWidget(title, self.got_detail)
        elif title == "__la_symbol_ptr":
            self.new_detail_widget = NewDetailWidget(title, self.la_symbol_ptr_detail)
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

        self.search_input.textChanged.connect(self.search)

    def search(self):
        text_to_find = self.search_input.text().lower()

        matched = ''
        for string in self.detail:
            if string.lower().find(text_to_find) != -1:
                matched += string + '\n'
        self.text_edit.setText(matched)

