// 合作&交流  git：https://github.com/lich4 个人Q：571652571 Q群：560017652

/*
	Usage:   dumpModule("BWA.app");   dumpModule("aaa.dylib")
	[iPhone::PID::20457]-> dumpModule(".app")
	Fix decrypted at:ac0
	Fix decrypted at:4000
*/

var O_RDONLY = 0;
var O_WRONLY = 1;
var O_RDWR = 2;
var O_CREAT = 512;

var SEEK_SET = 0;
var SEEK_CUR = 1;
var SEEK_END = 2;

function allocStr(str) {
    return Memory.allocUtf8String(str);
}

function getU32(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readU32(addr);
}

function putU64(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeU64(addr, n);
}

function malloc(size) {
    return Memory.alloc(size);
}

function getExportFunction(type, name, ret, args) {
    var nptr;
    nptr = Module.findExportByName(null, name);
    if (nptr === null) {
        console.log("cannot find " + name);
        return null;
    } else {
        if (type === "f") {
            var funclet = new NativeFunction(nptr, ret, args);
            if (typeof funclet === "undefined") {
                console.log("parse error " + name);
                return null;
            }
            return funclet;
        } else if (type === "d") {
            var datalet = Memory.readPointer(nptr);
            if (typeof datalet === "undefined") {
                console.log("parse error " + name);
                return null;
            }
            return datalet;
        }
    }
}

var NSSearchPathForDirectoriesInDomains = getExportFunction("f", "NSSearchPathForDirectoriesInDomains", "pointer", ["int", "int", "int"]);
var wrapper_open = getExportFunction("f", "open", "int", ["pointer", "int", "int"]);
var read = getExportFunction("f", "read", "int", ["int", "pointer", "int"]);
var write = getExportFunction("f", "write", "int", ["int", "pointer", "int"]);
var lseek = getExportFunction("f", "lseek", "int64", ["int", "int64", "int"]);
var close = getExportFunction("f", "close", "int", ["int"]);

function getCacheDir(index) {
	var NSUserDomainMask = 1;
	var npdirs = NSSearchPathForDirectoriesInDomains(index, NSUserDomainMask, 1);
	var len = ObjC.Object(npdirs).count();
	if (len == 0) {
		return '';
	}
	return ObjC.Object(npdirs).objectAtIndex_(0).toString();
}

function open(pathname, flags, mode) {
    if (typeof pathname == "string") {
        pathname = allocStr(pathname);
    }
    return wrapper_open(pathname, flags, mode);
}

// Export function
var modules = null;
function getAllAppModules() {
	if (modules == null) {
		modules = new Array();
		var tmpmods = Process.enumerateModulesSync();
		for (var i = 0; i < tmpmods.length; i++) {
			if (tmpmods[i].path.indexOf(".app") != -1) {
				modules.push(tmpmods[i]);
			}
		}
	}
	return modules;
}

var MH_MAGIC = 0xfeedface;
var MH_CIGAM = 0xcefaedfe;
var MH_MAGIC_64 = 0xfeedfacf;
var MH_CIGAM_64 = 0xcffaedfe;
var LC_SEGMENT = 0x1;
var LC_SEGMENT_64 = 0x19;
var LC_ENCRYPTION_INFO = 0x21;
var LC_ENCRYPTION_INFO_64 = 0x2C;

var export_dumpmodpath;
// You can dump .app or dylib (Encrypt/No Encrypt)
rpc.exports = {
    dumpmodule: function dumpModule(name) {
        if (modules == null) {
            modules = getAllAppModules();
        }
        var targetmod = null;
        for (var i = 0; i < modules.length; i++) {
            if (modules[i].path.indexOf(name) != -1) {
                targetmod = modules[i];
                break;
            }
        }
        if (targetmod == null) {
            console.log("Cannot find module");
            return -1;
        }
        var modbase = modules[i].base;
        var modsize = modules[i].size;
        var newmodname = modules[i].name + ".decrypted";
        var finddir = false;
        var newmodpath = "";
        var fmodule = -1;
        var index = 1;
        while (!finddir) { // 找到一个可写路径
            try {
                var base = getCacheDir(index);
                if (base != null) {
                    newmodpath = getCacheDir(index) + "/" + newmodname;
                    fmodule = open(newmodpath, O_CREAT | O_RDWR, 0);
                    if (fmodule != -1) {
                        break;
                    };
                }
            }
            catch(e) {
            }
            index++;
        }

        var oldmodpath = modules[i].path;
        var foldmodule = open(oldmodpath, O_RDONLY, 0);
        if (fmodule == -1 || foldmodule == -1) {
            console.log("Cannot open file" + newmodpath);
            return 0;
        }

        var BUFSIZE = 4096;
        var buffer = malloc(BUFSIZE);
        while (read(foldmodule, buffer, BUFSIZE)) {
            write(fmodule, buffer, BUFSIZE);
        }

        // Find crypt info and recover
        var is64bit = false;
        var size_of_mach_header = 0;
        var magic = getU32(modbase);
        if (magic == MH_MAGIC || magic == MH_CIGAM) {
            is64bit = false;
            size_of_mach_header = 28;
        }
        else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
            is64bit = true;
            size_of_mach_header = 32;
        }
        // ncmds offset 0x10
        var ncmds = getU32(modbase.add(16));
        // size_of_mach_header == 0x20 이므로 Commands offset 0x20
        var off = size_of_mach_header;
        var offset_cryptoff = -1;
        var crypt_off = 0;
        var crypt_size = 0;
        var segments = [];
        for (var i = 0; i < ncmds; i++) {
            var cmd = getU32(modbase.add(off));
            var cmdsize = getU32(modbase.add(off + 4));
            if (cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64) {
                offset_cryptoff = off + 8;
                crypt_off = getU32(modbase.add(off + 8));
                crypt_size = getU32(modbase.add(off + 12));
            }
            off += cmdsize;
        }

        if (offset_cryptoff != -1) {
            var tpbuf = malloc(8);
            console.log("Fix decrypted at:" + offset_cryptoff.toString(16));
            putU64(tpbuf, 0);
            lseek(fmodule, offset_cryptoff, SEEK_SET);
            write(fmodule, tpbuf, 8);
            console.log("Fix decrypted at:" + crypt_off.toString(16));
            lseek(fmodule, crypt_off, SEEK_SET);
            write(fmodule, modbase.add(crypt_off), crypt_size);
        }
        console.log("Decrypted file at:" + newmodpath + " 0x" + modsize.toString(16));
        close(fmodule);
        close(foldmodule);
        export_dumpmodpath = newmodpath
        return 1;
    },
    dumpmodulepath: () => { return export_dumpmodpath }
}
