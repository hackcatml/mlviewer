import inspect
import re

from PyQt6 import QtWidgets, QtCore
from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QStandardItemModel, QStandardItem, QColor
from PyQt6.QtWidgets import QFileDialog, QTableView, QLineEdit, QVBoxLayout, QDialog

import gvar
import parse_unity_dump_ui


class ParseResultTableView(QDialog):
    method_clicked_signal = QtCore.pyqtSignal(str)

    def __init__(self, file_path):
        super().__init__()
        self.setWindowTitle("Unity Data Table")
        self.resize(800, 400)

        self.table_view = QTableView()
        self.table_view.setAutoScroll(False)
        self.model = QStandardItemModel()
        self.model.setHorizontalHeaderLabels(['Class', 'Field', 'Method', 'Offset'])
        self.table_view.setModel(self.model)
        self.previous_row = -1

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search...")
        self.search_box.textChanged.connect(self.filter_table)

        layout = QVBoxLayout(self)
        layout.addWidget(self.table_view)
        layout.addWidget(self.search_box)

        self.file_path = file_path
        self.original_data = []
        self.populate_table(self.file_path)

        self.platform = None
        self.il2cpp_base = None
        self.table_view.clicked.connect(self.table_click)

    def populate_table(self, file_path):
        with open(file_path, 'r') as file:
            try:
                lines = file.readlines()
            except Exception as e:
                print(f"[parse_unity_dump]{inspect.currentframe().f_code.co_name}: {e}")
                return

        # self.original_data = []  # Store original data for filtering
        class_type = None
        class_name = None
        for line in lines:
            # Match class declaration
            class_match = re.match(r'(class|struct|enum)\s+(.*)\s+:', line)
            if class_match:
                class_type, class_name = class_match.groups()
                continue

            # Match fields with offset
            field_match = re.match(r'\s+(.*)\s+(.*[^()]);\s+//\s+(0x[\da-fA-F]+)', line)
            static_field_match = re.match(r'\s+(.*=\s+(-?)\d+)', line)
            if field_match:
                field_type, field_name, offset = field_match.groups()
                field = f"{field_type} {field_name}"
                method = ""  # No method for fields
                # Store the data for filtering
                self.original_data.append((class_name, field, method, offset))
                self.add_row_to_table(class_name, field, method, offset)
                continue
            if not field_match and static_field_match:
                field = static_field_match.groups()[0]
                method = ""
                offset = ""
                self.original_data.append((class_name, field, method, offset))
                self.add_row_to_table(class_name, field, method, offset)
                continue

            if class_type == "enum":
                enum_match = re.match(r'\s+(.*=\s+(-?)\d+)', line)
                if enum_match:
                    enum_data = enum_match.groups()[0]
                    method = ""
                    offset = ""
                    self.original_data.append((class_name, enum_data, method, offset))
                    self.add_row_to_table(class_name, enum_data, method, offset)
                    continue

            # Match methods with offset
            method_match = re.match(r'\s+(.*)\s+(.*)\((.*?)\);\s+//\s+(0x[\da-fA-F]+)', line)
            if method_match:
                return_type, method_name, params, offset = method_match.groups()
                field = ""  # No field for methods
                method = f"{return_type} {method_name}({params})"

                self.original_data.append((class_name, field, method, offset))
                self.add_row_to_table(class_name, field, method, offset)

    def add_row_to_table(self, class_name, field, method, offset):
        row = [
            QStandardItem(class_name),
            QStandardItem(field),
            QStandardItem(method),
            QStandardItem(offset),
        ]
        self.model.appendRow(row)

    def filter_table(self, search_text):
        # Clear the table
        self.model.removeRows(0, self.model.rowCount())

        # Filter rows based on search text
        for class_name, field, method, offset in self.original_data:
            if (search_text.lower() in class_name.lower() or
                    search_text.lower() in field.lower() or
                    search_text.lower() in method.lower() or
                    search_text.lower() in offset.lower()):
                self.add_row_to_table(class_name, field, method, offset)

    def table_click(self, index):
        # Remove highlight from the previous row if it exists
        if self.previous_row != -1:
            for col in range(self.model.columnCount()):
                self.model.setData(self.model.index(self.previous_row, col), Qt.GlobalColor.transparent,
                                   Qt.ItemDataRole.BackgroundRole)

        # Highlight the current row without selecting it
        row = index.row()
        for col in range(self.model.columnCount()):
            self.model.setData(self.model.index(row, col), QColor("gray"), Qt.ItemDataRole.BackgroundRole)

        # Update the previous_row to the current row
        self.previous_row = row

        # Method click
        if index.column() == 2:
            if self.model.data(index) != '':
                offset_index = self.model.index(index.row(), 3)
                offset = self.model.data(offset_index)
                if self.il2cpp_base is None:
                    try:
                        module_name = 'libil2cpp.so' if self.platform == 'linux' else 'UnityFramework'
                        module: dict = gvar.frida_instrument.get_module_by_name(module_name)
                        if module is None:
                            print(f"[parse_unity_dump][table_click] Cannot find the module")
                            return
                        self.il2cpp_base = module['base']
                    except Exception as e:
                        print(f"[parse_unity_dump]{inspect.currentframe().f_code.co_name}: {e}")
                        return
                addr = hex(int(self.il2cpp_base, 16) + int(offset, 16))
                self.method_clicked_signal.emit(addr)


class ParseUnityDumpFile(QtWidgets.QDialog):
    parse_result_table_created_signal = QtCore.pyqtSignal(int)

    def __init__(self):
        super(ParseUnityDumpFile, self).__init__()
        self.parse_unity_dump_file_dialog = QtWidgets.QDialog()
        self.parse_unity_dump_file_dialog.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint)
        self.parse_unity_dump_file_dialog_ui = parse_unity_dump_ui.Ui_ParseUnityDumpFileDialog()
        self.parse_unity_dump_file_dialog_ui.setupUi(self.parse_unity_dump_file_dialog)

        self.parse_unity_dump_file_dialog_ui.textEdit.file_dropped_sig.connect(self.file_dropped_sig_func)
        self.parse_unity_dump_file_dialog_ui.fileBtn.clicked.connect(self.select_file)

        self.parse_unity_dump_file_dialog_ui.doParseBtn.setDisabled(True)
        self.parse_unity_dump_file_dialog_ui.doParseBtn.clicked.connect(
            lambda: self.do_parse(self.parse_unity_dump_file_dialog_ui.doParseBtn.text()))

        self.platform = None
        self.file = None
        self.parse_result = None

    @pyqtSlot(str)
    def file_dropped_sig_func(self, dropped_file: str):
        self.file = dropped_file
        if self.file is not None:
            self.parse_unity_dump_file_dialog_ui.doParseBtn.setEnabled(True)

    def select_file(self):
        file, _ = QFileDialog.getOpenFileNames(self, caption="Select a dumped file to parse", directory="./dump", initialFilter="All Files (*)")
        self.file = "" if len(file) == 0 else file[0]
        if self.file:
            self.parse_unity_dump_file_dialog_ui.textEdit.setText(self.file)
            if self.parse_result is not None and self.parse_result.file_path != self.file and \
                    self.parse_unity_dump_file_dialog_ui.doParseBtn.text() == 'Show':
                self.parse_unity_dump_file_dialog_ui.doParseBtn.setText('Parse')
            self.parse_unity_dump_file_dialog_ui.doParseBtn.setEnabled(True)

    def do_parse(self, button_text):
        if button_text == 'Parse':
            if '.cs' not in self.file:
                print(f"[parse_unity_dump][ParseUnityDumpFile][do_parse] need .cs file to parse")
                return
            self.parse_result = ParseResultTableView(self.file)
            self.parse_result.platform = self.platform
            self.parse_result_table_created_signal.emit(1)
        elif button_text == 'Show':
            self.parse_result_table_created_signal.emit(0)
        self.parse_result.show()
        self.parse_unity_dump_file_dialog.close()
