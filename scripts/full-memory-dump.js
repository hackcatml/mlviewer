var isPalera1n;

rpc.exports = {
  getPlatform: function() {
    return Process.platform;
  },
  isPalera1nJb: function() {
    var access = new NativeFunction(Module.findExportByName(null, "access"), 'int', ['pointer', 'int'])
    var path = Memory.allocUtf8String("/var/mobile/Library/palera1n/helper");
    isPalera1n = access(path, 0) === 0
    return isPalera1n;
  },
  enumerateRanges: function (prot) {
    return Process.enumerateRangesSync(prot);
  },
  readMemory: function (address, size) {
    if (ObjC.available && isPalera1n) {
      try {
        // Looks up a memory range by address. Throws an exception if not found.
        var range = Process.getRangeByAddress(ptr(address));
        return Memory.readByteArray(range.base, range.size);
      } catch (e) {
        console.log(e);
      }
    }
    else {
      return Memory.readByteArray(ptr(address), size);
    }
  },
  readMemoryChunk: function (address, size) {
    try {
      // Looks up a memory range by address. Throws an exception if not found.
      Process.getRangeByAddress(ptr(address));
      return Memory.readByteArray(ptr(address), size);
    } catch (e) {
      console.log(e);
    }
  }
};