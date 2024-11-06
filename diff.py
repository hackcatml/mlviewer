import os

from PyQt6 import QtCore, QtWidgets
from PyQt6.QtCore import Qt, pyqtSlot, QThread
from PyQt6.QtGui import QPalette
from PyQt6.QtWidgets import QFileDialog, QApplication

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

        dark_mode = self.is_dark_mode()
        default_color = "white" if dark_mode else "black"

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
    def __init__(self, file1, file2):
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

        self.offset_differs = None

    def read_file_contents(self, filename):
        '''Read file contents into a list of bytes.'''
        with open(filename, 'rb') as file:
            return list(file.read())

    def run(self) -> None:
        """Compare the two files
                :returns: Comparison result: True if similar, False if different.
                Set vars offset and message if there's a difference.
                """
        self.message = None
        self.offset_differs = None
        offset = 0
        offset_diff = 0
        first = False
        if not os.path.isfile(self.file1) or not os.path.isfile(self.file2):
            self.message = "not found"
            return
        if os.path.getsize(self.file1) != os.path.getsize(self.file2):
            self.message = "size"
            self.binary_compare_finished_sig.emit("size")
            return
        result = True
        f1 = open(self.file1, 'rb')
        f2 = open(self.file2, 'rb')
        loop = True
        while loop:
            buffer1 = f1.read(self._buffer_size)
            buffer2 = f2.read(self._buffer_size)
            if len(buffer1) == 0 or len(buffer2) == 0:
                loop = False
            for byte1, byte2 in zip(buffer1, buffer2):
                if byte1 != byte2:
                    if first == False:
                        first = True
                    result = False
                    self.diff_list.append((offset, byte1, byte2))
                offset += 1
                if not first:
                    offset_diff += 1
        f1.close()
        f2.close()
        if not result:
            self.message = 'content'
            self.offset = hex(offset_diff)
        else:
            self.message = 'identical'

        # Read file contents into lists after comparison
        self.file1_contents = self.read_file_contents(self.file1)
        self.file2_contents = self.read_file_contents(self.file2)

        if result:
            self.binary_compare_finished_sig.emit("identical")
        else:
            self.binary_compare_finished_sig.emit("finished")

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
        # self.diff_dialog.setWindowModality(Qt.WindowModality.ApplicationModal)
        self.diff_dialog_ui = diff_ui.Ui_DiffDialog()
        self.diff_dialog_ui.setupUi(self.diff_dialog)

        self.statusBar = statusBar

        self.file1 = None
        self.file2 = None

        self.diff_dialog_ui.textEdit.file_dropped_sig.connect(self.file_dropped_sig_func)
        self.diff_dialog_ui.textEdit_2.file_dropped_sig.connect(self.file_dropped_sig_func)

        self.diff_dialog_ui.file1Btn.clicked.connect(lambda: self.select_file("file1"))
        self.diff_dialog_ui.file2Btn.clicked.connect(lambda: self.select_file("file2"))

        self.diff_dialog_ui.doDiffBtn.setDisabled(True)
        self.diff_dialog_ui.doDiffBtn.clicked.connect(self.do_diff)

        self.binary_diff_result_window = None
        self.binary_diff_result_ui = None
        self.binary_compare_worker = None

        self.process_diff_result_worker = None
        self.process_diff_result_sig_count = 0

        self.diff_result = None

    @pyqtSlot(list)
    def file_dropped_sig_func(self, dropped_file: list):
        if dropped_file[0] == "file1":
            self.file1 = dropped_file[1]
        elif dropped_file[0] == "file2":
            self.file2 = dropped_file[1]

        if self.file1 and self.file2:
            self.diff_dialog_ui.doDiffBtn.setEnabled(True)

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

    @pyqtSlot(str)
    def binary_compare_finished_sig_func(self, is_finished: str):
        if is_finished == "size":
            self.statusBar.showMessage("\tThe sizes of the two files are different", 5000)
        elif is_finished == "identical":
            self.statusBar.showMessage("\tTwo files are identical", 5000)
        elif is_finished == "finished":
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

    def process_diff_result(self):
        self.binary_diff_result_window = QtWidgets.QWidget()
        self.binary_diff_result_ui = diff_ui.CompareFilesWindow()
        self.binary_diff_result_ui.setupUi(self.binary_diff_result_window)
        self.binary_diff_result_ui.stopDiffBtn.clicked.connect(self.stop_diff)

        formatted_diffs = self.binary_compare_worker.format_diff(16)
        self.binary_compare_worker.quit()

        self.process_diff_result_worker = ProcessDiffResultWorker(formatted_diffs)
        self.process_diff_result_worker.process_diff_result_signal.connect(self.process_diff_result_sig_func)
        self.process_diff_result_worker.process_diff_finished_signal.connect(self.process_diff_finished_sig_func)
        self.process_diff_result_worker.start()

    def stop_diff(self):
        if self.process_diff_result_worker is not None:
            self.process_diff_result_worker.process_diff_result_signal.disconnect(self.process_diff_result_sig_func)
            self.process_diff_result_worker.process_diff_finished_signal.disconnect(self.process_diff_finished_sig_func)
            self.process_diff_result_worker.terminate()
            self.diff_result = self.binary_diff_result_ui.binaryDiffResultView.toPlainText()
            self.statusBar.showMessage("\tBinary diff is done!", 5000)

    def do_diff(self):
        self.diff_dialog.close()

        if self.file1 and self.file2:
            self.binary_compare_worker = BinaryCompareWorker(self.file1, self.file2)
            self.binary_compare_worker.binary_compare_finished_sig.connect(self.binary_compare_finished_sig_func)
            self.binary_compare_worker.start()
        else:
            self.statusBar.showMessage("\tChoose two files to compare", 5000)
            return
