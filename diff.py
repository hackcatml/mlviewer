import os

from PyQt6 import QtCore, QtWidgets
from PyQt6.QtCore import Qt, pyqtSlot, QThread
from PyQt6.QtGui import QPalette
from PyQt6.QtWidgets import QFileDialog, QApplication
import r2pipe

import diff_ui


class ProcessDiffResultWorker(QThread):
    process_diff_result_signal = QtCore.pyqtSignal(str)
    process_diff_finished_signal = QtCore.pyqtSignal()

    def __init__(self, formatted_diffs):
        super().__init__()
        self.formatted_diffs = formatted_diffs

    def is_dark_mode(self):
        palette = QApplication.palette()
        background_color = palette.color(QPalette.ColorRole.Window)
        return background_color.lightness() < 128  # Check if the background color is dark

    def run(self) -> None:
        line = ''
        line_count = 0

        for block_start, (block1, block2) in self.formatted_diffs.items():
            line_count += 1
            if line_count == 1:
                line += "ADDRESS ".rjust(len(f"0x{block_start:08x} "))
                line += "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F || 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
                self.process_diff_result_signal.emit(line)
                line = ''
                QThread.msleep(1)

            line += f"0x{block_start:08x} "
            for b1, b2 in zip(block1, block2):
                if b1 != b2:
                    color = "red"
                    formatted_b1 = '00' if b1 is None else f'{b1:02x}'
                    line += f'<span style="color:{color};">{formatted_b1} </span>'
                else:
                    formatted_b1 = '00' if b1 is None else f'{b1:02x}'
                    line += f'{formatted_b1} '
            line += "!= "
            for b1, b2 in zip(block1, block2):
                if b1 != b2:
                    color = "red"
                    formatted_b2 = '00' if b2 is None else f'{b2:02x}'
                    line += f'<span style="color:{color};">{formatted_b2} </span>'
                else:
                    formatted_b2 = '00' if b2 is None else f'{b2:02x}'
                    line += f'{formatted_b2} '

            self.process_diff_result_signal.emit(line)
            line = ''
            QThread.msleep(1)

        self.process_diff_result_signal.emit(line)
        self.process_diff_finished_signal.emit()


class BinaryCompareWorker(QThread):
    binary_compare_finished_sig = QtCore.pyqtSignal(str)

    """Comparing two binary files"""
    def __init__(self, file1, file2, sections):
        """Get the files to compare and initialise message, offset and diff list.
        :param file1: a file
        :type file1: string
        :param file2: another file to compare
        :type file2: string
        """
        super().__init__()
        self._buffer_size = 512
        self.message = None
        '''message of diff result: "not found", "size", "content", "identical"'''
        self.offset = None
        '''offset where files start to differ'''
        self.diff_list = []
        '''list of diffs made of tuples: (offset, hex(byte1), hex(byte2))'''
        self.file1 = file1
        self.file2 = file2

        self.file1_contents = None
        self.file2_contents = None

        self.sections = sections

        self.offset_differs = None

    def read_file_contents(self, filename, start, size):
        '''Read file contents into a list of bytes.'''
        with open(filename, 'rb') as file:
            if start is not None:
                file.seek(start)
                try:
                    return list(file.read(size))
                except Exception as e:
                    return list()
            else:
                try:
                    return list(file.read())
                except Exception as e:
                    return list()

    def run(self) -> None:
        """Compare the two files
        :returns: Comparison result: True if similar, False if different.
        Set vars offset and message if there's a difference.
        """
        self.message = None
        self.offset_differs = None
        offset = 0
        if not os.path.isfile(self.file1) or not os.path.isfile(self.file2):
            self.message = "not found"
            return
        if os.path.getsize(self.file1) != os.path.getsize(self.file2):
            self.message = "size"
            self.binary_compare_finished_sig.emit("size")
            return
        self.binary_compare_finished_sig.emit("start")
        result = True
        self.diff_list.clear()

        # Compare each section
        for section in self.sections:
            start = section['start']
            size = section['size']

            # Read section contents
            data1 = self.read_file_contents(self.file1, start, size)
            data2 = self.read_file_contents(self.file2, start, size)

            if not data1 or not data2:
                self.message = "cannot read"
                self.binary_compare_finished_sig.emit(self.message)
                return

            # Compare the contents byte by byte
            for offset, (byte1, byte2) in enumerate(zip(data1, data2), start=start if start is not None else 0):
                if byte1 != byte2:
                    result = False
                    self.diff_list.append((offset, byte1, byte2))

            if not result:
                self.message = "content"
                self.offset = hex(offset)

        # Sort the diff_list by offset in ascending order
        self.diff_list.sort(key=lambda x: x[0])

        # Read file contents into lists after comparison
        self.file1_contents = self.read_file_contents(self.file1, None, None)
        self.file2_contents = self.read_file_contents(self.file2, None, None)

        if result:
            self.message = "identical"
        else:
            self.message = "finished"
        self.binary_compare_finished_sig.emit(self.message)

    def format_diff(self, block_size=16):
        """Format the differences in blocks of specified size."""

        formatted_diffs = {}
        for offset, byte1, byte2 in self.diff_list:
            block_start = offset - (offset % block_size)
            if block_start not in formatted_diffs:
                block1 = [self.file1_contents[i] if i < len(self.file1_contents) else None for i in
                          range(block_start, block_start + block_size)]
                block2 = [self.file2_contents[i] if i < len(self.file2_contents) else None for i in
                          range(block_start, block_start + block_size)]
                formatted_diffs[block_start] = (block1, block2)
            index = offset % block_size
            formatted_diffs[block_start][0][index] = byte1
            formatted_diffs[block_start][1][index] = byte2

        return formatted_diffs


class DiffDialogClass(QtWidgets.QDialog):
    def __init__(self, statusBar):
        super(DiffDialogClass, self).__init__(statusBar)
        self.diff_dialog = QtWidgets.QDialog()
        self.diff_dialog.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint)
        self.diff_dialog_ui = diff_ui.Ui_DiffDialog()
        self.diff_dialog_ui.setupUi(self.diff_dialog)

        self.statusBar = statusBar

        self.file1 = None
        self.file2 = None
        self.sections = None
        self.checked_sections = []

        self.diff_dialog_ui.textEdit.file_dropped_sig.connect(self.file_dropped_sig_func)
        self.diff_dialog_ui.textEdit_2.file_dropped_sig.connect(self.file_dropped_sig_func)

        self.diff_dialog_ui.file1Btn.clicked.connect(lambda: self.select_file("file1"))
        self.diff_dialog_ui.file2Btn.clicked.connect(lambda: self.select_file("file2"))

        self.diff_dialog_ui.doDiffBtn.setDisabled(True)
        self.diff_dialog_ui.doDiffBtn.clicked.connect(self.do_diff)

        self.binary_compare_worker = None

        self.binary_diff_result_window = QtWidgets.QWidget()
        self.binary_diff_result_ui = diff_ui.CompareFilesWindow()
        self.binary_diff_result_ui.setupUi(self.binary_diff_result_window)
        self.binary_diff_result_ui.stopDiffBtn.clicked.connect(self.stop_diff)

        self.process_diff_result_worker = None
        self.process_diff_result_sig_count = 0

        self.diff_result = None

    @pyqtSlot(list)
    def file_dropped_sig_func(self, sig: list):
        if sig[0] == "file1":
            self.file1 = sig[1]
        elif sig[0] == "file2":
            self.file2 = sig[1]

        if self.file1 and self.file2:
            self.diff_dialog_ui.doDiffBtn.setEnabled(True)

    @pyqtSlot(str)
    def binary_compare_finished_sig_func(self, sig: str):
        if sig == "start":
            self.binary_diff_result_window.show()
        elif sig == "size":
            self.statusBar.showMessage("\tThe sizes of the two files are different", 5000)
        elif sig == "identical":
            if self.checked_sections and len(self.checked_sections) == 1 and self.checked_sections[0]['name'] != 'All':
                self.statusBar.showMessage(f"\t{self.checked_sections[0]['name']} is identical", 5000)
            elif self.checked_sections and len(self.checked_sections) > 1:
                self.statusBar.showMessage(f"\tSections are identical", 5000)
            else:
                self.statusBar.showMessage("\tTwo files are identical", 5000)
        elif sig == "cannot read":
            self.statusBar.showMessage("\tCannot read file contents", 5000)
            self.binary_diff_result_window.close()
            self.diff_dialog.show()
        elif sig == "finished":
            self.process_diff_result()

    @pyqtSlot(str)
    def process_diff_result_sig_func(self, sig: str):
        self.process_diff_result_sig_count += 1
        if sig and self.process_diff_result_sig_count == 1:
            self.binary_diff_result_ui.file1TextEdit.setText(f"file1:\n{self.file1}")
            self.binary_diff_result_ui.file2TextEdit.setText(f"file2:\n{self.file2}")
            self.binary_diff_result_ui.addressTextEdit.setText(sig)
            self.binary_diff_result_window.show()
        else:
            self.binary_diff_result_ui.binaryDiffResultView.append(sig)

    @pyqtSlot()
    def process_diff_finished_sig_func(self):
        self.process_diff_result_worker.quit()
        self.diff_result = self.binary_diff_result_ui.binaryDiffResultView.toPlainText()
        self.statusBar.showMessage("\tBinary diff is done!", 5000)

    def section_checkbox(self, checkbox_name, state):
        if state == Qt.CheckState.Checked.value:    # Check
            if checkbox_name == 'All':
                self.checked_sections.append({
                    "start": None,
                    "size": None,
                    "name": checkbox_name
                })
                for checkbox in self.diff_dialog_ui.checkboxes:
                    if checkbox.text() != 'All':
                        checkbox.setChecked(False)
                        checkbox.setEnabled(False)
            else:
                for section in self.sections:
                    if section['name'] == checkbox_name:
                        self.checked_sections.append(section)
                        break
        else:   # Uncheck
            if checkbox_name == 'All':
                self.checked_sections.clear()
                for checkbox in self.diff_dialog_ui.checkboxes:
                    if checkbox.text() != 'All':
                        checkbox.setEnabled(True)
            else:
                self.checked_sections = [section for section in self.checked_sections
                                         if section['name'] != checkbox_name]

    def select_file(self, file1or2):
        file, _ = QFileDialog.getOpenFileNames(self, caption="Select a file to compare", directory="./dump", initialFilter="All Files (*)")
        if file1or2 == "file1":
            self.file1 = "" if len(file) == 0 else file[0]
            if self.file1:
                self.diff_dialog_ui.textEdit.setText(self.file1)
        elif file1or2 == "file2":
            self.file2 = "" if len(file) == 0 else file[0]
            if self.file2:
                self.diff_dialog_ui.textEdit_2.setText(self.file2)

        if self.file1 and self.file2:
            self.diff_dialog_ui.doDiffBtn.setEnabled(True)
            while self.diff_dialog_ui.checkboxGridLayout.count():
                item = self.diff_dialog_ui.checkboxGridLayout.takeAt(0)  # Remove the item at position 0
                widget = item.widget()  # Get the widget associated with the item
                if widget:
                    widget.deleteLater()  # Schedule the widget for deletion

            r2 = r2pipe.open(self.file1)
            sections_info = r2.cmdj("iSj")
            self.sections = [
                {
                    "start": section["paddr"],
                    "size": section["size"],
                    "name": section["name"]
                }
                for section in sections_info
            ]

            section_found_count = 0
            max_columns = 4  # Limit the number of checkboxes per row
            row, col = 0, 0
            for section in self.sections:
                if section['name']:
                    section_found_count += 1
                    if section_found_count == 1:
                        label = QtWidgets.QLabel("Sections:")
                        self.diff_dialog_ui.checkboxGridLayout.addWidget(label, row, col)
                        row += 1

                    # print(f"Name: {section['name']}, Start: {hex(section['start'])}, Size: {section['size']}")
                    if section_found_count == 1:
                        section_checkbox = QtWidgets.QCheckBox("All", self.diff_dialog)
                        section_checkbox.setObjectName(f"checkbox_all")
                        section_checkbox.setChecked(True)
                        self.checked_sections.append({
                            "start": None,
                            "size": None,
                            "name": "All"
                        })
                    else:
                        section_checkbox = QtWidgets.QCheckBox(section['name'], self.diff_dialog)
                        section_checkbox.setObjectName(f"checkbox_{section['name']}")
                        section_checkbox.setChecked(False)
                        section_checkbox.setEnabled(False)
                    section_checkbox.stateChanged.connect(lambda state, cb=section_checkbox:
                                                          self.section_checkbox(cb.text(), state))
                    self.diff_dialog_ui.checkboxes.append(section_checkbox)
                    self.diff_dialog_ui.checkboxGridLayout.addWidget(section_checkbox, row, col)
                    col += 1
                    if col >= max_columns:  # Move to the next row if column limit is reached
                        col = 0
                        row += 1

    def process_diff_result(self):
        formatted_diffs = self.binary_compare_worker.format_diff(16)
        self.binary_compare_worker.quit()

        self.process_diff_result_worker = ProcessDiffResultWorker(formatted_diffs)
        self.process_diff_result_worker.process_diff_result_signal.connect(self.process_diff_result_sig_func)
        self.process_diff_result_worker.process_diff_finished_signal.connect(self.process_diff_finished_sig_func)
        self.process_diff_result_worker.start()

    def stop_diff(self):
        if self.process_diff_result_worker is not None:
            try:
                self.process_diff_result_worker.process_diff_result_signal.disconnect(self.process_diff_result_sig_func)
                self.process_diff_result_worker.process_diff_finished_signal.disconnect(self.process_diff_finished_sig_func)
            except Exception as e:
                print(e)
            if self.process_diff_result_worker.isRunning():
                self.process_diff_result_worker.quit()
            self.diff_result = self.binary_diff_result_ui.binaryDiffResultView.toPlainText()
            self.statusBar.showMessage("\tBinary diff is done!", 5000)

    def do_diff(self):
        if len(self.checked_sections) == 0:
            self.statusBar.showMessage("\tChoose sections to compare", 5000)
            return
        self.diff_dialog.close()
        if self.file1 and self.file2:
            self.binary_compare_worker = BinaryCompareWorker(self.file1, self.file2, self.checked_sections)
            self.binary_compare_worker.binary_compare_finished_sig.connect(self.binary_compare_finished_sig_func)
            self.binary_compare_worker.start()
        else:
            self.statusBar.showMessage("\tChoose two files to compare", 5000)
            return
