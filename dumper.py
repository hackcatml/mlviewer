import inspect
import os
import re
import shutil
import sys

from PyQt6 import QtCore
from PyQt6.QtCore import QThread

STRINGS = True
DIRECTORY = os.getcwd() + "/dump/full_memory_dump"
MAX_SIZE = 20971520
PERMS = 'r--'
mem_access_viol = ""


def dump_to_file(agent, base, size, error, directory):
    try:
        filename = str(base) + '_dump.data'
        if inspect.currentframe().f_back.f_code.co_name == "splitter":
            dump = agent.read_memory_chunk(base, size)
        else:
            dump = agent.read_memory(base, size)
        f = open(os.path.join(directory, filename), 'wb')
        f.write(dump)
        f.close()
        return error
    except Exception as e:
        print("Oops, memory access violation!")
        return error


# Read bytes that are bigger than the max_size value, split them into chunks and save them to a file
def splitter(agent, base, size, max_size, error, directory):
    times = size // max_size
    diff = size % max_size

    global cur_base
    cur_base = int(base, 0)

    for time in range(times):
        dump_to_file(agent, hex(cur_base), max_size, error, directory)
        cur_base = cur_base + max_size

    if diff != 0:
        dump_to_file(agent, hex(cur_base), diff, error, directory)


def printProgress(purpose, sig, times, total, prefix='', suffix='', decimals=2, bar=100):
    filled = int(round(bar * times / float(total)))
    percents = round(100.00 * (times / float(total)), decimals)
    sig.emit([purpose, str(percents)])
    bar = '#' * filled + '-' * (bar - filled)
    sys.stdout.write('%s [%s] %s%s %s\r' %
                     (prefix, bar, percents, '%', suffix)),
    sys.stdout.flush()
    if times == total:
        print("\n")


# A very basic implementations of Strings
def strings(filename, directory, min=4):
    strings_file = os.path.join(directory, "strings.txt")
    path = os.path.join(directory, filename)
    with open(path, encoding='Latin-1') as infile:
        str_list = re.findall("[A-Za-z0-9/\-:;.,_$%'!()[\]<> \#]+", infile.read())
        with open(strings_file, "a") as st:
            for string in str_list:
                if len(string) > min:
                    st.write(string + "\n")


class FullMemoryDumpWorker(QThread):
    full_memory_dump_signal = QtCore.pyqtSignal(int)
    progress_signal = QtCore.pyqtSignal(list)

    def __init__(self, frida_instrument, statusBar):
        super(FullMemoryDumpWorker, self).__init__()
        self.frida_instrument = frida_instrument
        self.agent = self.frida_instrument.get_agent()
        self.statusBar = statusBar

        self.ranges = self.agent.enumerate_ranges(PERMS)
        self.platform = self.agent.get_platform()
        self.is_palera1n = self.agent.is_palera1n_jb()

    def run(self) -> None:
        global mem_access_viol
        # filter out ranges that are not useful before performing the dump on iOS15+
        # also It can reduce the chance of memory access violation
        if self.platform == "darwin" and self.is_palera1n:
            self.ranges = [range_dict for range_dict in self.ranges if 'file' not in range_dict or all(
                substr not in range_dict['file']['path'] for substr in
                ["/System", "/MobileSubstrate/", "substitute", "substrate", "/private/preboot/", "/tmp/frida-",
                 "/usr/share/icu"])]

        i = 0
        l = len(self.ranges)

        if not os.path.exists(DIRECTORY):
            os.makedirs(DIRECTORY)
        else:
            shutil.rmtree(DIRECTORY)
            os.makedirs(DIRECTORY)

        # Performing the memory dump
        for range in self.ranges:
            if range["size"] > MAX_SIZE:
                mem_access_viol = splitter(self.agent, range["base"], range["size"], MAX_SIZE, mem_access_viol, DIRECTORY)
                continue
            mem_access_viol = dump_to_file(
                self.agent, range["base"], range["size"], mem_access_viol, DIRECTORY)
            i += 1
            printProgress("memdump", self.progress_signal, i, l, prefix='Progress:', suffix='Complete', bar=50)

        # Run Strings if selected
        if STRINGS:
            files = os.listdir(DIRECTORY)
            i = 0
            l = len(files)
            print("Running strings on all files:")
            for f1 in files:
                strings(f1, DIRECTORY)
                i += 1
                printProgress("strdump", self.progress_signal, i, l, prefix='Progress:',
                                    suffix='Complete', bar=50)
        print("Finished!")
        self.full_memory_dump_signal.emit(1)
