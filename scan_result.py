import copy
import inspect
import platform
import re

from PyQt6 import QtCore
from PyQt6.QtCore import QObject, Qt, QThread, pyqtSlot, QPoint
from PyQt6.QtWidgets import QWidget, QTableWidgetItem

import frida_code
import gvar
import misc
import scan_result_ui
import scan_result_win_ui


class MemScanSignalEmitWorker(QThread):
    mem_scan_signal = QtCore.pyqtSignal(int)

    def __init__(self):
        super(MemScanSignalEmitWorker, self).__init__()

    def run(self) -> None:
        while True:
            self.mem_scan_signal.emit(0)
            if type(frida_code.MESSAGE) is str and frida_code.MESSAGE.find('[!] Memory Scan Done') != -1:
                print(f"[scan_result][MemScanSignalEmitWorker][run] Memory Scan Done")
                break
            self.msleep(100)

    @pyqtSlot(int)
    def memory_scan_done_sig_func(self, sig: int):
        if sig == 1:
            self.mem_scan_signal.emit(sig)
            print(f"[scan_result][MemScanSignalEmitWorker][memory_scan_done_sig_func] mem_scan_signal_emitted")


class MemScanWorker(QThread):
    def __init__(self):
        super(MemScanWorker, self).__init__()
        self.pattern = None
        self.ranges = None
        self.value = None
        self.matches = None
        self.scan_type = None
        self.scan_count = None

    def run(self) -> None:
        try:
            if self.scan_count is not None and self.scan_count == 1:
                gvar.frida_instrument.mem_scan(self.ranges, self.pattern)
            elif self.scan_count is not None and self.scan_count > 1:
                gvar.frida_instrument.mem_scan_reduce(self.matches, self.value, self.scan_type)
        except Exception as e:
            print(f"[scan_result]{inspect.currentframe().f_code.co_name} Error: {e}")


class ScanResultViewWidget(QWidget):
    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            self.close()
        else:
            super().keyPressEvent(event)


class ScanResultViewWorker(QObject):
    set_scan_options_signal = QtCore.pyqtSignal(str)
    get_scan_options_signal = QtCore.pyqtSignal(list)
    notify_mem_scan_to_main_signal = QtCore.pyqtSignal(list)
    scan_result_addr_signal = QtCore.pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.scan_result_view = ScanResultViewWidget()
        self.scan_result_view.setWindowFlags(Qt.WindowType.WindowStaysOnTopHint)
        self.scan_result_view_ui = scan_result_win_ui.Ui_Form() if platform.system() == 'Windows' else (
            scan_result_ui.Ui_Form())
        self.scan_result_view_ui.setupUi(self.scan_result_view)

        self.mem_scan_worker = MemScanWorker()
        self.mem_scan_signal_emit_worker = MemScanSignalEmitWorker()
        self.mem_scan_signal_emit_worker.mem_scan_signal.connect(self.mem_scan_sig_func)
        self.mem_scan_signal_connected = True

        self.scan_tab_clicked_count = 0
        self.scan_result_view_ui.startScanBtn.clicked.connect(lambda: self.mem_scan_func(self.scan_result_view_ui.startScanBtn.text()))
        self.scan_result_view_ui.nextScanBtn.clicked.connect(lambda: self.mem_scan_func(self.scan_result_view_ui.nextScanBtn.text()))
        self.scan_result_view_ui.stopScanBtn.clicked.connect(self.stop_mem_scan)
        self.scan_result_view_ui.memScanResultTableWidget.itemClicked.connect(self.addr_clicked)

        self.get_scan_options_signal.connect(self.get_scan_options_sig_func)

        self.scan_value = None
        self.is_hex_checked = None
        self.scan_type = None
        self.scan_module_name = None
        self.scan_start_addr = None
        self.scan_end_addr = None
        self.scan_prot = None
        self.ranges = None

        self.scan_count = 0
        self.memory_scan_done_signal_received_count = 0

        self.scan_match_signal_connected = False
        self.update_scanned_value_signal_connected = False
        self.memory_scan_done_signal_connected = False

    @pyqtSlot(int)
    def mem_scan_sig_func(self, sig: int):
        # Memory scan progressing...
        if sig == 0:
            self.scan_result_view_ui.scanMatchFoundLabel.setText(f"Found: {str(len(gvar.scan_matches))}")
            self.scan_result_view_ui.scanPercentProgressLabel.setText(f"{str(gvar.scan_progress_ratio)} %")
        # Memory scan completed
        if sig == 1:
            print(f"[scan_result][ScanResultViewWorker][mem_scan_sig_func] Memory scan completed, {self.scan_count}")
            if self.scan_count == 1:
                self.scan_result_view_ui.startScanBtn.setEnabled(True)
                self.scan_result_view_ui.startScanBtn.setText("New Scan")
                self.notify_mem_scan_to_main_signal.emit(["First Scan", 1])

            if self.scan_count > 1:
                self.scan_result_view_ui.nextScanBtn.setEnabled(True)
                self.adjust_row_after_next_scan(gvar.scan_matches)
                self.notify_mem_scan_to_main_signal.emit(["Next Scan", 1])

            if not self.scan_type == 'Pointer':
                try:
                    if self.update_scanned_value_signal_connected is False:
                        gvar.frida_instrument.update_scanned_value_signal.connect(self.update_scanned_value_sig_func)
                        self.update_scanned_value_signal_connected = True
                        print(f"[scan result][ScanResultViewWorker][mem_scan_sig_func] "
                              f"update_scanned_value_signal_connected: {self.update_scanned_value_signal_connected}")
                    # Due to overload, the maximum number of scanned values updated is limited to 100 from the top.
                    update_scanned_value_targets = gvar.scan_matches[:100] if len(gvar.scan_matches) > 100 else \
                        gvar.scan_matches
                    gvar.frida_instrument.update_scanned_value(update_scanned_value_targets, self.scan_type)
                except Exception as e:
                    print(f"[scan_result]{inspect.currentframe().f_code.co_name} Error: {e}")

    @pyqtSlot(list)
    def get_scan_options_sig_func(self, sig: list):
        if sig is not None:
            self.scan_value = sig[0]
            self.is_hex_checked = sig[1]
            # First Scan
            if self.scan_count == 1:
                self.scan_type = sig[2]
                self.scan_module_name = sig[3]
                self.scan_start_addr = sig[4]
                self.scan_end_addr = sig[5]
                self.scan_prot = sig[6]
                self.ranges = self.filter_ranges(self.scan_start_addr, self.scan_end_addr, self.scan_prot)
            if self.scan_count > 1:
                self.scan_type = sig[2]
            if self.scan_value is not None and self.ranges is not None:
                self.mem_scan_func("get_scan_options_sig_func")

    @pyqtSlot(dict)
    def update_scanned_value_sig_func(self, scanned_value: dict):
        # print(f"[scan_result] scanned value: {scanned_value}")
        if scanned_value is None:
            return
        match_count = scanned_value['match_count']
        match_address = scanned_value['match_address']
        updated_value = scanned_value['updated_value']

        # print(f"[scan_result] match_count: {match_count}, "
        #       f"match_address: {match_address}, updated_value: {updated_value}")
        row_count = self.scan_result_view_ui.memScanResultTableWidget.rowCount()
        for row in range(row_count):
            address_item = self.scan_result_view_ui.memScanResultTableWidget.item(row, 0)
            if address_item is not None:
                address_text = address_item.text()
                # Check if this address matches any in scanned_value
                if address_text in match_address:
                    # print(f"[scan_result] row: {row}, new_value: {updated_value}")
                    # Update the value in the second column
                    self.scan_result_view_ui.memScanResultTableWidget.setItem(row, 1, QTableWidgetItem(f"* {updated_value}"))

    @pyqtSlot(dict)
    def add_row(self, sig: dict):
        # sig --> { match_count: #, match_address: # }
        row_position = sig['match_count'] - 1
        # Too many rows, I think it's useless so just skip adding row.
        if row_position > 1000:
            return
        self.scan_result_view_ui.memScanResultTableWidget.insertRow(row_position)

        # Address column (non-editable)
        base_addr_item = QTableWidgetItem(f"{sig['match_address']}")
        base_addr_item.setFlags(base_addr_item.flags() & ~Qt.ItemFlag.ItemIsEditable)  # Make it non-editable
        self.scan_result_view_ui.memScanResultTableWidget.setItem(row_position, 0, base_addr_item)

        # Value column (non-editable)
        if (scan_value := sig.get('match_value')) is not None:
            value_item = QTableWidgetItem(f"{scan_value}")
        else:
            value_item = QTableWidgetItem(f"{self.scan_value}")
        value_item.setFlags(value_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self.scan_result_view_ui.memScanResultTableWidget.setItem(row_position, 1, value_item)

        # First scan column (non-editable)
        # Rounded value scan
        if (type(self.scan_value) is dict) and ((rounded_value := self.scan_value.get('rounded_value')) is not None):
            first_scan_item = QTableWidgetItem(f"{rounded_value}")
        else:
            first_scan_item = QTableWidgetItem(f"{self.scan_value}")
        first_scan_item.setFlags(first_scan_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self.scan_result_view_ui.memScanResultTableWidget.setItem(row_position, 2, first_scan_item)

    def adjust_row_after_next_scan(self, scan_matches):
        print(f"[scan_result][ScanResultViewWorker][adjust_row_after_next_scan]"
              f" adjust_row_after_next_scan scan_matches: {len(scan_matches)}")
        if len(scan_matches) > 0:
            for index, item in enumerate(gvar.scan_matches):
                item['match_count'] = index + 1

            next_scan_column = self.scan_count + 1
            horizontal_header_item_text = misc.number_to_ordinal(self.scan_count)
            self.scan_result_view_ui.memScanResultTableWidget.horizontalHeaderItem(next_scan_column).setText(
                f"{horizontal_header_item_text} Scan")

            base_addr_column = 0
            value_column = 1
            first_scan_column = 2
            first_scan_item_text = self.scan_result_view_ui.memScanResultTableWidget.item(0, first_scan_column).text()
            value_item_text = self.scan_value
            next_scan_item_text = self.scan_value
            if type(self.scan_value) is dict and (rounded_value := self.scan_value.get('rounded_value')) is not None:
                next_scan_item_text = str(rounded_value)

            previous_next_scan_items = []
            for column in range(first_scan_column + 1, next_scan_column):
                previous_next_scan_item_text = self.scan_result_view_ui.memScanResultTableWidget.item(0, column).text()
                previous_next_scan_items.append(previous_next_scan_item_text)

            self.scan_result_view_ui.memScanResultTableWidget.clearContents()
            self.scan_result_view_ui.memScanResultTableWidget.setRowCount(0)

            row_count = 0
            for item in scan_matches:
                row_position = row_count
                # Too many rows, I think it's useless so just skip adding row.
                if row_position > 1000:
                    return
                self.scan_result_view_ui.memScanResultTableWidget.insertRow(row_position)

                base_addr_item = QTableWidgetItem(f"{item['match_address']}")
                base_addr_item.setFlags(base_addr_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.scan_result_view_ui.memScanResultTableWidget.setItem(row_position, base_addr_column, base_addr_item)

                if (scan_match_value := item.get('match_value')) is not None:
                    value_item_text = str(scan_match_value)
                value_item = QTableWidgetItem(value_item_text)
                value_item.setFlags(value_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.scan_result_view_ui.memScanResultTableWidget.setItem(row_position, value_column, value_item)

                first_scan_item = QTableWidgetItem(first_scan_item_text)
                first_scan_item.setFlags(first_scan_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.scan_result_view_ui.memScanResultTableWidget.setItem(row_position, first_scan_column, first_scan_item)

                if previous_next_scan_items:
                    for index, element in enumerate(previous_next_scan_items):
                        column = first_scan_column + (index + 1)
                        prev_next_scan_item = QTableWidgetItem(element)
                        prev_next_scan_item.setFlags(first_scan_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                        self.scan_result_view_ui.memScanResultTableWidget.setItem(row_position, column, prev_next_scan_item)

                next_scan_item = QTableWidgetItem(next_scan_item_text)
                next_scan_item.setFlags(next_scan_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.scan_result_view_ui.memScanResultTableWidget.setItem(row_position, next_scan_column,
                                                                          next_scan_item)

                row_count += 1
        else:
            self.scan_result_view_ui.memScanResultTableWidget.clearContents()
            self.scan_result_view_ui.memScanResultTableWidget.setRowCount(0)

    def filter_ranges(self, start_addr, end_addr, prot):
        start_addr = int(start_addr, 16)
        end_addr = int(end_addr, 16)
        filtered_ranges = [
            item for item in gvar.enumerate_ranges
            if int(item[1], 16) >= start_addr and int(item[0], 16) <= end_addr and item[2] >= prot
        ]
        if (exclude_path := self.scan_result_view_ui.memScanExcludePath.toPlainText()) != '':
            if exclude_path == '.*':    # This regex filters out all the ranges
                return
            exclude_path_regex = fr'{exclude_path}'
            filtered_ranges = [
                item for item in filtered_ranges
                if not re.search(exclude_path_regex, item[4])
            ]
        return filtered_ranges

    def show_scan_result_view(self):
        self.scan_tab_clicked_count += 1
        self.scan_result_view.show()
        if self.scan_tab_clicked_count == 1:
            curr_pos = self.scan_result_view.pos()
            new_pos = curr_pos + QPoint(-130, 170)
            self.scan_result_view.move(new_pos)

    def mem_scan_func(self, caller):
        if gvar.frida_instrument is None:
            return

        if caller == "First Scan":
            self.scan_count = 1
            # Try refreshing the mem ranges before performing the first memory scan
            try:
                result = gvar.frida_instrument.mem_enumerate_ranges('r--')
                # enumerateRanges --> [(base, base + size - 1, prot, size, path), ... ]
                gvar.enumerate_ranges.clear()
                for i in range(len(result)):
                    gvar.enumerate_ranges.append(
                        (
                            result[i]['base'], hex(int(result[i]['base'], 16) + result[i]['size'] - 1),
                            result[i]['protection'],
                            result[i]['size'], result[i]['file']['path'] if result[i].get('file') is not None else ""))
            except Exception as e:
                print(f"[scan_result]{inspect.currentframe().f_code.co_name} Error: {e}")
            # Emit the set scan options signal
            self.set_scan_options_signal.emit(caller)
            try:
                if not self.scan_match_signal_connected:
                    gvar.frida_instrument.scan_match_signal.connect(self.add_row)
                    self.scan_match_signal_connected = True
            except Exception as e:
                print(f"[scan_result]{inspect.currentframe().f_code.co_name} Error: {e}")
                return

        if caller == "Next Scan":
            # The first scan should be completed before doing the next scan
            if self.scan_result_view_ui.startScanBtn.text() == "First Scan":
                return
            if self.scan_type == 'Pointer':
                return

            self.scan_count += 1
            if self.scan_count > 5:
                return
            self.scan_result_view_ui.nextScanBtn.setEnabled(False)
            if self.mem_scan_worker.isRunning():
                self.mem_scan_worker.quit()
            if self.mem_scan_signal_emit_worker.isRunning():
                if self.mem_scan_signal_connected is True:
                    try:
                        self.mem_scan_signal_emit_worker.mem_scan_signal.disconnect()
                        self.mem_scan_signal_connected = False
                    except Exception as e:
                        print(f"[scan_result]{inspect.currentframe().f_code.co_name} Error: {e}")
                self.mem_scan_signal_emit_worker.quit()
            self.set_scan_options_signal.emit(caller)

        if caller == "get_scan_options_sig_func":
            # print(f"[scan_result] get_scan_options_sig_func")
            try:
                if self.scan_count == 1:
                    self.scan_result_view_ui.startScanBtn.setEnabled(False)
                # Next Scan: If there's a running update for the scanned value interval, it needs to be stopped.
                if self.scan_count > 1:
                    gvar.frida_instrument.clear_update_scanned_value_interval()
            except Exception as e:
                print(f"[scan_result]{inspect.currentframe().f_code.co_name} Error: {e}")
            self.notify_mem_scan_to_main_signal.emit(["Scan", 0])
            if self.scan_count == 1:
                self.mem_scan_worker.scan_count = self.scan_count
                self.mem_scan_worker.pattern = self.scan_value
                self.mem_scan_worker.ranges = self.ranges
            elif self.scan_count > 1:
                self.mem_scan_worker.scan_count = self.scan_count
                if type(self.scan_type) == dict and self.scan_type.get('String'):
                    self.mem_scan_worker.value = misc.change_little_endian_hex_to_value(self.scan_value, 'String')
                else:
                    self.mem_scan_worker.value = self.scan_value
                self.mem_scan_worker.matches = copy.deepcopy(gvar.scan_matches)
                gvar.scan_matches.clear()
                self.mem_scan_worker.scan_type = self.scan_type
                self.scan_result_view_ui.scanMatchFoundLabel.setText(f"Found: 0")
                self.scan_result_view_ui.scanPercentProgressLabel.setText(f"0 %")
            self.mem_scan_worker.start()
            print(f"[scan_result][ScanResultViewWorker][get_scan_options_sig_func] mem_scan_worker started. "
                  f"scan_count: {self.scan_count}, scan_value: {self.scan_value}, scan_type: {self.scan_type}")
            if self.mem_scan_signal_connected is False:
                self.mem_scan_signal_emit_worker.mem_scan_signal.connect(self.mem_scan_sig_func)
                self.mem_scan_signal_connected = True
            self.mem_scan_signal_emit_worker.start()
            if gvar.frida_instrument is not None:
                if self.memory_scan_done_signal_connected is False:
                    gvar.frida_instrument.memory_scan_done_signal.connect(
                        self.mem_scan_signal_emit_worker.memory_scan_done_sig_func)
                    self.memory_scan_done_signal_connected = True
                print(f"[scan_result][ScanResultViewWorker][get_scan_options_sig_func] "
                      f"memory_scan_done_signal_connected: {self.memory_scan_done_signal_connected}")
            if (self.scan_type == '1 Byte' or self.scan_type == '2 Bytes' or self.scan_type == '4 Bytes'
                    or self.scan_type == '8 Bytes' or self.scan_type == 'Int') and self.scan_count == 1:
                self.scan_value = misc.change_little_endian_hex_to_value(self.scan_value, self.scan_type)
            if self.scan_type == 'Float' or self.scan_type == 'Double':
                if type(self.scan_value) == dict:   # Rounded value scan
                    pass
                else:   # Exact value scan.
                    if self.scan_count == 1:    # At the first  scan, value is represented in hexadecimal bytes
                        self.scan_value = misc.change_little_endian_hex_to_value(self.scan_value, self.scan_type)
            if type(self.scan_type) == dict and self.scan_type.get('String'):
                self.scan_value = misc.change_little_endian_hex_to_value(self.scan_value, 'String')
            if type(self.scan_type) == dict and self.scan_type.get('Array of Bytes'):
                pass
            if self.scan_type == 'Pointer':
                byte_pairs = misc.hex_value_byte_pairs(self.scan_value)
                byte_pairs = [item for item in byte_pairs if item != '00']
                reversed_bytes = "".join(reversed(byte_pairs))
                self.scan_value = "0x" + reversed_bytes
            print(f"[scan_result][ScanResultViewWorker][get_scan_options_sig_func] self.scan_value: {self.scan_value}, "
                  f"self.scan_type: {self.scan_type}")

        if caller == "New Scan":
            self.notify_mem_scan_to_main_signal.emit(["New Scan", 1])
            try:
                if gvar.frida_instrument is not None:
                    gvar.frida_instrument.scan_match_signal.disconnect()
                    self.scan_match_signal_connected = False
                    gvar.frida_instrument.memory_scan_done_signal.disconnect()
                    self.memory_scan_done_signal_connected = False
                    if not self.scan_type == 'Pointer':
                        gvar.frida_instrument.update_scanned_value_signal.disconnect()
                        self.update_scanned_value_signal_connected = False
                        gvar.frida_instrument.clear_update_scanned_value_interval()
                    print(
                        f"[scan_result][ScanResultViewWorker][get_scan_options_sig_func] scan_match_signal_connected: "
                        f"{self.scan_match_signal_connected}, update_scanned_value_signal_connected: "
                        f"{self.update_scanned_value_signal_connected}, memory_scan_done_signal_connected: "
                        f"{self.memory_scan_done_signal_connected}")
            except Exception as e:
                self.scan_match_signal_connected = False
                self.update_scanned_value_signal_connected = False
                self.memory_scan_done_signal_connected = False
                print(f"[scan_result]{inspect.currentframe().f_code.co_name} Error: {e}")

            self.scan_result_view_ui.memScanResultTableWidget.clearContents()
            self.scan_result_view_ui.memScanResultTableWidget.setRowCount(0)
            for column in range(3, self.scan_result_view_ui.memScanResultTableWidget.columnCount()):
                if self.scan_result_view_ui.memScanResultTableWidget.horizontalHeaderItem(column).text() != "-":
                    self.scan_result_view_ui.memScanResultTableWidget.horizontalHeaderItem(column).setText("-")

            gvar.scan_matches.clear()
            self.scan_value = None
            self.is_hex_checked = None
            self.scan_type = None
            self.scan_module_name = None
            self.scan_start_addr = None
            self.scan_end_addr = None
            self.ranges = None
            if self.mem_scan_worker.isRunning():
                self.mem_scan_worker.quit()
            if self.mem_scan_signal_emit_worker.isRunning():
                if self.mem_scan_signal_connected is True:
                    try:
                        self.mem_scan_signal_emit_worker.mem_scan_signal.disconnect()
                        self.mem_scan_signal_connected = False
                    except Exception as e:
                        print(f"[scan_result]{inspect.currentframe().f_code.co_name} Error: {e}")
                self.mem_scan_signal_emit_worker.quit()
            self.scan_result_view_ui.startScanBtn.setText("First Scan")
            self.scan_result_view_ui.scanMatchFoundLabel.setText("")
            self.scan_result_view_ui.scanPercentProgressLabel.setText("")

    def stop_mem_scan(self):
        stop_mem_scan = False
        try:
            if self.scan_result_view_ui.startScanBtn.text() == "First Scan" and \
                    self.scan_result_view_ui.startScanBtn.isEnabled() is False:
                self.scan_result_view_ui.startScanBtn.setText("New Scan")
                self.scan_result_view_ui.startScanBtn.setEnabled(True)
                stop_mem_scan = True
            if self.scan_result_view_ui.nextScanBtn.isEnabled() is False:
                self.scan_result_view_ui.nextScanBtn.setEnabled(True)
                stop_mem_scan = True
            if stop_mem_scan:
                self.notify_mem_scan_to_main_signal.emit(["Stop Scan", 1])
                if gvar.frida_instrument is not None:
                    gvar.frida_instrument.stop_mem_scan()
        except Exception as e:
            print(f"[scan_result]{inspect.currentframe().f_code.co_name} Error: {e}")

    def addr_clicked(self, item):
        if item.column() == 0:
            self.scan_result_addr_signal.emit(item.text())

