/* stuffs for mach-o parsing start */
// https://opensource.apple.com/source/xnu/xnu-7195.81.3/EXTERNAL_HEADERS/mach-o/loader.h.auto.html
var load_commands = {
    "LC_SEGMENT": {"code":0x1, "name":"SEGMENT"},
    "LC_SYMTAB": {"code":0x2, "name":"SYMTAB"},
    "LC_SYMSEG": {"code":0x3, "name":"SYMSEG"},	/* link-edit gdb symbol table info (obsolete) */
    "LC_THREAD": {"code":0x4, "name":"THREAD"},
    "LC_UNIXTHREAD": {"code":0x5, "name":"UNIXTHREAD"},
    "LC_LOADFVMLIB": {"code":0x6, "name":"LOADFVMLIB"},
    "LC_IDFVMLIB": {"code":0x7, "name":"IDFVMLIB"},
    "LC_IDENT": {"code":0x8, "name":"IDENT"},
    "LC_FVMFILE": {"code":0x9, "name":"FVMFILE"},
    "LC_PREPAGE": {"code":0xa, "name":"PREPAGE"},
    "LC_DYSYMTAB": {"code":0xb, "name":"DYSYMTAB"},
    "LC_LOAD_DYLIB": {"code":0xc, "name":"LOAD_DYLIB"},
    "LC_ID_DYLIB": {"code":0xd, "name":"ID_DYLIB"},
    "LC_LOAD_DYLINKER": {"code":0xe, "name":"LOAD_DYLINKER"},
    "LC_ID_DYLINKER": {"code":0xf, "name":"ID_DYLINKER"},
    "LC_PREBOUND_DYLIB": {"code":0x10, "name":"PREBOUND_DYLIB"},
    "LC_ROUTINES": {"code":0x11, "name":"ROUTINES"},
    "LC_SUB_FRAMEWORK": {"code":0x12, "name":"SUB_FRAMEWORK"},
    "LC_SUB_UMBRELLA": {"code":0x13, "name":"SUB_UMBRELLA"},
    "LC_SUB_CLIENT": {"code":0x14, "name":"SUB_CLIENT"},
    "LC_SUB_LIBRARY": {"code":0x15, "name":"SUB_LIBRARY"},
    "LC_TWOLEVEL_HINTS": {"code":0x16, "name":"TWOLEVEL_HINTS"},
    "LC_PREBIND_CKSUM": {"code":0x17, "name":"PREBIND_CKSUM"},
    "LC_LOAD_WEAK_DYLIB": {"code":0x80000018, "name":"LOAD_WEAK_DYLIB"},    /* load a dynamically linked shared library that is allowed to be missing (all symbols are weak imported). */
    "LC_SEGMENT_64": {"code":0x19, "name":"SEGMENT_64"},
    "LC_ROUTINES_64": {"code":0x1a, "name":"ROUTINES_64"},
    "LC_UUID": {"code":0x1b, "name":"UUID"},
    "LC_RPATH": {"code":0x8000001c, "name":"RPATH"},
    "LC_CODE_SIGNATURE": {"code":0x1d, "name":"CODE_SIGNATURE"},
    "LC_SEGMENT_SPLIT_INFO": {"code":0x1e, "name":"SEGMENT_SPLIT_INFO"},
    "LC_REEXPORT_DYLIB": {"code":0x8000001f, "name":"REEXPORT_DYLIB"},   /* load and re-export dylib */
    "LC_LAZY_LOAD_DYLIB": {"code":0x20, "name":"LAZY_LOAD_DYLIB"}, 	/* delay load of dylib until first use */
    "LC_DYLD_INFO": {"code":0x22, "name":"DYLD_INFO"}, 		/* compressed dyld information */
    "LC_DYLD_INFO_ONLY": {"code":0x80000022, "name":"DYLD_INFO_ONLY"},  /* compressed dyld information only */
    "LC_LOAD_UPWARD_DYLIB": {"code":0x80000023, "name":"LOAD_UPWARD_DYLIB"}, /* load upward dylib */
    "LC_VERSION_MIN_MACOSX": {"code":0x24, "name":"VERSION_MIN_MACOSX"},    /* build for MacOSX min OS version */
    "LC_VERSION_MIN_IPHONEOS": {"code":0x25, "name":"VERSION_MIN_IPHONEOS"},
    "LC_FUNCTION_STARTS": {"code":0x26, "name":"FUNCTION_STARTS"},
    "LC_DYLD_ENVIRONMENT": {"code":0x27, "name":"DYLD_ENVIRONMENT"},  /* string for dyld to treat like environment variable */
    "LC_MAIN": {"code":0x80000028, "name":"MAIN"},
    "LC_DATA_IN_CODE": {"code":0x29, "name":"DATA_IN_CODE"},
    "LC_SOURCE_VERSION": {"code":0x2a, "name":"SOURCE_VERSION"},
    "LC_DYLIB_CODE_SIGN_DRS": {"code":0x2B, "name":"DYLIB_CODE_SIGN_DRS"},  /* Code signing DRs copied from linked dylibs */
    "LC_ENCRYPTION_INFO_64": {"code":0x2c, "name":"ENCRYPTION_INFO_64"},
    "LC_LINKER_OPTION": {"code":0x2d, "name":"LINKER_OPTION"},
    "LC_LINKER_OPTIMIZATION_HINT": {"code":0x2e, "name":"LINKER_OPTIMIZATION_HINT"},
    "LC_VERSION_MIN_TVOS": {"code":0x2f, "name":"VERSION_MIN_TVOS"},
    "LC_VERSION_MIN_WATCHOS": {"code":0x30, "name":"VERSION_MIN_WATCHOS"},
    "LC_NOTE": {"code":0x31, "name":"NOTE"},
    "LC_BUILD_VERSION": {"code":0x32, "name":"BUILD_VERSION"},
    "LC_DYLD_EXPORTS_TRIE": {"code":0x80000033, "name":"DYLD_EXPORTS_TRIE"},
    "LC_DYLD_CHAINED_FIXUPS": {"code":0x80000034, "name":"DYLD_CHAINED_FIXUPS"},
    "LC_FILESET_ENTRY": {"code":0x80000035, "name":"FILESET_ENTRY"},
}
/* stuffs for mach-o parsing end */

rpc.exports = {
    machoparse: (base) => {
        base = ptr(base)
        var magic = base.readU32();
        var is64bit = false;
        if (magic == 0xfeedfacf) {
            is64bit = true;
            var number_of_commands_offset = 0x10
            var command_size_offset = 0x4
            var segment_name_offset = 0x8
            var vm_address_offset = 0x18
            var vm_size_offset = 0x20
            var file_offset = 0x28
            var number_of_sections_offset = 0x40
            var section64_header_base_offset = 0x48
            var section64_header_size = 0x50

            var file_offset_to_vmaddr = null

            var got_exists = false
            var got_section_header = null
            var got_section_start_addr = null
            var la_symbol_ptr_exists = false
            var la_symbol_ptr_section_header = null
            var la_symbol_ptr_section_start_addr = null

            var symbol_table_addr = null
            var indirect_symbol_table_addr = null
            var string_table_addr = null
        } else {
            console.log('Unknown magic:' + magic);
        }
        var cmdnum = base.add(number_of_commands_offset).readU32();
        send({'parseMachO': {'cmdnum': cmdnum}})
        var cmdoff = is64bit ? 0x20 : 0x1C;
        for (var i = 0; i < cmdnum; i++) {
            var cmd = base.add(cmdoff).readU32();
            var cmdsize = base.add(cmdoff + command_size_offset).readU32();
            if (cmd === load_commands.LC_SEGMENT_64.code) { // SEGMENT_64
                var segname = base.add(cmdoff + segment_name_offset).readUtf8String();
                var vmaddr = base.add(cmdoff + vm_address_offset).readU32();
                var vmsize = base.add(cmdoff + vm_size_offset).readU32();
                var fileoffset = base.add(cmdoff + file_offset).readU32();
                var nsects = base.add(cmdoff + number_of_sections_offset).readU8();
                var secbase = base.add(cmdoff + section64_header_base_offset);
                send({
                        'parseMachO': {
                            'command': load_commands.LC_SEGMENT_64.name,
                            'segname': segname,
                            'segment_offset': parseInt(cmdoff).toString(16),
                            'vmaddr_start': parseInt(vmaddr).toString(16),
                            'vmaddr_end': parseInt(vmaddr + vmsize).toString(16),
                            'file_offset': parseInt(fileoffset).toString(16)
                        }
                    }
                )
                if (base.add(cmdoff + command_size_offset).readU32() >= section64_header_base_offset + nsects * section64_header_size) {
                    for (var i = 0; i < nsects; i++) {
                        var secname = secbase.add(i * section64_header_size).readUtf8String()
                        var section_start_offset = secbase.add(i * section64_header_size + 0x30).readU32();
                        if (secname === "__got") {
                            got_exists = true
                            got_section_header = secbase.add(i * section64_header_size)
                            got_section_start_addr = base.add(section_start_offset)
                        } else if (secname === "__la_symbol_ptr") {
                            la_symbol_ptr_exists = true
                            la_symbol_ptr_section_header = secbase.add(i * section64_header_size)
                            la_symbol_ptr_section_start_addr = base.add(section_start_offset)
                        }
                        send({
                            'parseMachO': {
                                'command': load_commands.LC_SEGMENT_64.name,
                                'secname': secname,
                                'section_start': parseInt(section_start_offset).toString(16)
                            }
                        })
                    }
                }
                if (segname === "__LINKEDIT") {
                    file_offset_to_vmaddr = vmaddr - fileoffset
                }
            } else {
                for (var key in load_commands) {
                    if (cmd === load_commands[key].code) {
                        var str_offset = base.add(cmdoff + 0x8).readU8()
                        if (cmd === load_commands.LC_LOAD_DYLINKER.code || cmd === load_commands.LC_ID_DYLIB.code || cmd === load_commands.LC_LOAD_DYLIB.code || cmd === load_commands.LC_LOAD_WEAK_DYLIB.code || cmd === load_commands.LC_RPATH.code) {
                            var name = base.add(cmdoff + str_offset).readUtf8String()
                            var img_base = Module.findBaseAddress(name.split('/').pop())
                        }
                        if (cmd === load_commands.LC_ENCRYPTION_INFO_64.code) {
                            var crypt_offset = base.add(cmdoff + 0x8).readU32()
                            var crypt_size = base.add(cmdoff + 0xc).readU32()
                            var crypt_id = base.add(cmdoff + 0x10).readU32()
                        }
                        if (cmd === load_commands.LC_MAIN.code) {
                            var entry_offset = base.add(cmdoff + 0x8).readU64()
                        }
                        if (cmd === load_commands.LC_SYMTAB.code) {
                            var symbol_table_offset = base.add(cmdoff + 0x8).readU32() + file_offset_to_vmaddr
                            symbol_table_addr = base.add(symbol_table_offset)
                            var string_table_offset = base.add(cmdoff + 0x10).readU32() + file_offset_to_vmaddr
                            string_table_addr = base.add(string_table_offset)
                        }
                        if (cmd === load_commands.LC_DYSYMTAB.code) {
                            var indirect_symbol_table_offset = base.add(cmdoff + 0x38).readU32() + file_offset_to_vmaddr
                            indirect_symbol_table_addr = base.add(indirect_symbol_table_offset)
                        }
                        send({
                                'parseMachO': {
                                    'command': load_commands[key].name,
                                    'command_offset': parseInt(cmdoff).toString(16),
                                    'name': name,
                                    'img_base': img_base,
                                    'entry_offset': parseInt(entry_offset).toString(16),
                                    'crypt_offset': parseInt(crypt_offset).toString(16),
                                    'crypt_size': crypt_size,
                                    'crypt_id': crypt_id,
                                    'symbol_table_offset': parseInt(symbol_table_offset).toString(16),
                                    'string_table_offset': parseInt(string_table_offset).toString(16),
                                    'indirect_symbol_table_offset': parseInt(indirect_symbol_table_offset).toString(16),
                                }
                            }
                        )
                    }
                }
            }
            cmdoff += cmdsize;
        }
        if (got_exists) {
            var got_section_size = got_section_header.add(0x28).readU64()
            var alignment_value = got_section_header.add(0x34).readU32()
            var got_section_alignment = 1
            for (var i = 0; i < alignment_value; i++) {
                got_section_alignment = 2 * got_section_alignment
            }
            var number_of_symbols_got = parseInt(got_section_size) / parseInt(got_section_alignment)
            var got_indirect_symbol_index = got_section_header.add(0x44).readU32()

            for (var i = 0; i < number_of_symbols_got; i++) {
                var got_symbol = ''
                if (indirect_symbol_table_addr.add(0x4 * (got_indirect_symbol_index + i)).readU8() !== 0) {
                    var got_symbol_index = indirect_symbol_table_addr.add(0x4 * (got_indirect_symbol_index + i)).readU32()
                    var got_symbol_string_table_index = symbol_table_addr.add(0x10 * got_symbol_index).readU32()
                    got_symbol = string_table_addr.add(got_symbol_string_table_index).readUtf8String()
                }
                var got_symbol_addr = got_section_start_addr.add(got_section_alignment * i).readPointer()
                var location = Process.findModuleByAddress(got_symbol_addr) == null ? null : Process.findModuleByAddress(got_symbol_addr)['name']
                send({
                    'parseMachO': {
                        'secdetail': got_section_header.readUtf8String(),
                        'symbol': got_symbol,
                        'symbol_addr': got_symbol_addr,
                        'location': location,
                    }
                })
            }
        }
        if (la_symbol_ptr_exists) {
            var la_symbol_ptr_section_size = la_symbol_ptr_section_header.add(0x28).readU64()
            var alignment_value = la_symbol_ptr_section_header.add(0x34).readU32()
            var la_symbol_ptr_section_alignment = 1
            for (var i = 0; i < alignment_value; i++) {
                la_symbol_ptr_section_alignment = 2 * la_symbol_ptr_section_alignment
            }
            var number_of_symbols_la_symbol_ptr = parseInt(la_symbol_ptr_section_size) / parseInt(la_symbol_ptr_section_alignment)
            var la_symbol_ptr_indirect_symbol_index = la_symbol_ptr_section_header.add(0x44).readU32()

            for (var i = 0; i < number_of_symbols_la_symbol_ptr; i++) {
                var la_symbol_ptr_symbol = ''
                if (indirect_symbol_table_addr.add(0x4 * (la_symbol_ptr_indirect_symbol_index + i)).readU8() !== 0) {
                    var la_symbol_ptr_symbol_index = indirect_symbol_table_addr.add(0x4 * (la_symbol_ptr_indirect_symbol_index + i)).readU32()
                    var la_symbol_ptr_symbol_string_table_index = symbol_table_addr.add(0x10 * la_symbol_ptr_symbol_index).readU32()
                    la_symbol_ptr_symbol = string_table_addr.add(la_symbol_ptr_symbol_string_table_index).readUtf8String()
                }
                var la_symbol_ptr_symbol_addr = la_symbol_ptr_section_start_addr.add(la_symbol_ptr_section_alignment * i).readPointer()
                var location = Process.findModuleByAddress(la_symbol_ptr_symbol_addr) == null ? null : Process.findModuleByAddress(la_symbol_ptr_symbol_addr)['name']
                send({
                    'parseMachO': {
                        'secdetail': la_symbol_ptr_section_header.readUtf8String(),
                        'symbol': la_symbol_ptr_symbol,
                        'symbol_addr': la_symbol_ptr_symbol_addr,
                        'location': location,
                    }
                })
            }
        }
    }
}

/* stuffs for elf parsing start */
var O_RDONLY = 0;
var O_WRONLY = 1;
var O_RDWR = 2;
var O_APPEND = 1024;
var O_LARGEFILE = 32768;
var O_CREAT = 64;
var SEEK_SET = 0;
var SEEK_CUR = 1;
var SEEK_END = 2;

var p_types = {
    "PT_NULL":		0,		/* Program header table entry unused */
    "PT_LOAD":		1,		/* Loadable program segment */
    "PT_DYNAMIC":	2,		/* Dynamic linking information */
    "PT_INTERP":	3,		/* Program interpreter */
    "PT_NOTE":		4,		/* Auxiliary information */
    "PT_SHLIB":	    5,		/* Reserved */
    "PT_PHDR":		6,		/* Entry for header table itself */
    "PT_TLS":		7,		/* Thread-local storage segment */
    "PT_NUM":		8,		/* Number of defined types */
    "PT_LOOS":		0x60000000,	/* Start of OS-specific */
    "PT_GNU_EH_FRAME":	0x6474e550,	/* GCC .eh_frame_hdr segment */
    "PT_GNU_STACK":	0x6474e551,	/* Indicates stack executability */
    "PT_GNU_RELRO":	0x6474e552,	/* Read-only after relocation */
    "PT_GNU_PROPERTY":	0x6474e553,	/* GNU property */
    "PT_LOSUNW":	0x6ffffffa,
    "PT_SUNWBSS":	0x6ffffffa,	/* Sun Specific segment */
    "PT_SUNWSTACK":	0x6ffffffb,	/* Stack segment */
    "PT_HISUNW":	0x6fffffff,
    "PT_HIOS":		0x6fffffff,	/* End of OS-specific */
    "PT_LOPROC":	0x70000000,	/* Start of processor-specific */
    "PT_HIPROC":	0x7fffffff,	/* End of processor-specific */
}

var d_tags = {
    "DT_NULL":		0,		/* Marks end of dynamic section */
    "DT_NEEDED":	1,		/* Name of needed library */
    "DT_PLTRELSZ":	2,		/* Size in bytes of PLT relocs */
    "DT_PLTGOT":	3,		/* Processor defined value */
    "DT_HASH":		4,		/* Address of symbol hash table */
    "DT_STRTAB":	5,		/* Address of string table */
    "DT_SYMTAB":	6,		/* Address of symbol table */
    "DT_RELA":		7,		/* Address of Rela relocs */
    "DT_RELASZ":	8,		/* Total size of Rela relocs */
    "DT_RELAENT":	9,		/* Size of one Rela reloc */
    "DT_STRSZ":	    10,		/* Size of string table */
    "DT_SYMENT":	11,		/* Size of one symbol table entry */
    "DT_INIT":		12,		/* Address of init function */
    "DT_FINI":		13,		/* Address of termination function */
    "DT_SONAME":	14,		/* Name of shared object */
    "DT_RPATH":	    15,		/* Library search path (deprecated) */
    "DT_SYMBOLIC":	16,		/* Start symbol search here */
    "DT_REL":		17,		/* Address of Rel relocs */
    "DT_RELSZ":	    18,		/* Total size of Rel relocs */
    "DT_RELENT":	19,		/* Size of one Rel reloc */
    "DT_PLTREL":	20,		/* Type of reloc in PLT */
    "DT_DEBUG":	    21,		/* For debugging; unspecified */
    "DT_TEXTREL":	22,		/* Reloc might modify .text */
    "DT_JMPREL":	23,		/* Address of PLT relocs */
    "DT_BIND_NOW":	24,		/* Process relocations of object */
    "DT_INIT_ARRAY":	25,		/* Array with addresses of init fct */
    "DT_FINI_ARRAY":	26,		/* Array with addresses of fini fct */
    "DT_INIT_ARRAYSZ":	27,		/* Size in bytes of DT_INIT_ARRAY */
    "DT_FINI_ARRAYSZ":	28,		/* Size in bytes of DT_FINI_ARRAY */
    "DT_RUNPATH":	29,		/* Library search path */
    "DT_FLAGS":	    30,		/* Flags for the object being loaded */
    "DT_ENCODING":	32,		/* Start of encoded range */
    "DT_PREINIT_ARRAY": 32,		/* Array with addresses of preinit fct*/
    "DT_PREINIT_ARRAYSZ": 33,		/* size in bytes of DT_PREINIT_ARRAY */
    "DT_SYMTAB_SHNDX":	34,		/* Address of SYMTAB_SHNDX section */
    "DT_NUM":		35,		/* Number used */
    "DT_LOOS":		0x6000000d,	/* Start of OS-specific */
    "DT_HIOS":		0x6ffff000,	/* End of OS-specific */
    "DT_LOPROC":	0x70000000,	/* Start of processor-specific */
    "DT_HIPROC":	0x7fffffff,	/* End of processor-specific */
    "DT_PROCNUM":	0x37,	/* Most used by any processor */
}
/* stuffs for elf parsing end */

function getExportFunction(name, ret, args) {
    var funcPtr;
    funcPtr = Module.findExportByName(null, name);
    if (funcPtr === null) {
        console.log("cannot find " + name);
        return null;
    } else {
        var func = new NativeFunction(funcPtr, ret, args);
        if (typeof func === "undefined") {
            console.log("parse error " + name);
            return null;
        }
        return func;
    }
}

var open = getExportFunction("open", "int", ["pointer", "int", "int"])
var close = getExportFunction("close", "int", ["int"]);
var lseek = getExportFunction("lseek", "int", ["int", "int", "int"]);
var read = getExportFunction("read", "int", ["int", "pointer", "int"]);

rpc.exports = {
    elfparse: (base) => {
        base = ptr(base);
        var module = Process.findModuleByAddress(base);
        var fd = null;
        if (module !== null) {
            fd = open(Memory.allocUtf8String(module.path), O_RDONLY, 0);
        }

        // Read elf header
        var magic = "464c457f"
        var elf_magic = base.readU32()
        if (parseInt(elf_magic).toString(16) != magic) {
            console.log("[!] Wrong magic...ignore")
        }

        var arch = Process.arch
        var is32bit = arch == "arm" ? 1 : 0 // 1:32 0:64

        var size_of_Elf32_Ehdr = 0x34;
        var off_of_Elf32_Ehdr_phoff = 28; // 4
        var off_of_Elf32_Ehdr_shoff = 32; // 4
        var off_of_Elf32_Ehdr_phentsize = 42; // 2
        var off_of_Elf32_Ehdr_phnum = 44; // 2
        var off_of_Elf32_Ehdr_shentsize = 46; // 2
        var off_of_Elf32_Ehdr_shnum = 48; // 2
        var off_of_Elf32_Ehdr_shstrndx = 50; // 2

        var size_of_Elf64_Ehdr = 0x40;
        var off_of_Elf64_Ehdr_phoff = 32; // 8
        var off_of_Elf64_Ehdr_shoff = 40; // 8
        var off_of_Elf64_Ehdr_phentsize = 54; // 2
        var off_of_Elf64_Ehdr_phnum = 56; // 2
        var off_of_Elf64_Ehdr_shentsize = 58; // 2
        var off_of_Elf64_Ehdr_shnum = 60; // 2
        var off_of_Elf64_Ehdr_shstrndx = 62; // 2

        var got_plt_secition_addr = null;
        var dynamic_section_addr = null;
        var dynamic_section_indices = null;
        var dynamic_section_entsize = null
        var dynstr_section_addr = null;
        var dynsym_section_addr = null;
        var rela_plt_section_addr = null;

        // Parse Ehdr(Elf header)
        var phoff = is32bit ? size_of_Elf32_Ehdr : size_of_Elf64_Ehdr   // Program header table file offset
        var shoff = is32bit ? base.add(off_of_Elf32_Ehdr_shoff).readU32() : base.add(off_of_Elf64_Ehdr_shoff).readU64();   // Section header table file offset
        var phentsize = is32bit ? base.add(off_of_Elf32_Ehdr_phentsize).readU16() : base.add(off_of_Elf64_Ehdr_phentsize).readU16();    // Size of entries in the program header table
        if (is32bit && phentsize != 32) {  // 0x20
            console.log("[!] Wrong e_phentsize. Should be 32. Let's assume it's 32");
            phentsize = 32;
        } else if (!is32bit && phentsize != 56) {
            console.log("[!] Wrong e_phentsize. Should be 56. Let's assume it's 56");
            phentsize = 56;
        }
        var phnum = is32bit ? base.add(off_of_Elf32_Ehdr_phnum).readU16() : base.add(off_of_Elf64_Ehdr_phnum).readU16();    // Number of entries in program header table
        if (phnum == 0) {
            if (fd != null && fd != -1){
                console.log("[!] phnum is 0. Try to get it from the file")
                var ehdrs_from_file = Memory.alloc(64);
                lseek(fd, 0, SEEK_SET);
                read(fd, ehdrs_from_file, 64);
                phnum = is32bit ? ehdrs_from_file.add(off_of_Elf32_Ehdr_phnum).readU16() : ehdrs_from_file.add(off_of_Elf64_Ehdr_phnum).readU16();
                if (phnum == 0) {
                    console.log("[!] phnum is still 0. Let's assume it's 10. because we just need to find .dynamic section");
                    phnum = 10;
                } else {
                    console.log(`[*] phnum from the file: ${phnum}`)
                }
            } else {
                console.log("[!] phnum is 0. Let's assume it's 10. because we just need to find .dynamic section")
                phnum = 10;
            }
        }
        var shentsize = is32bit ? base.add(off_of_Elf32_Ehdr_shentsize).readU16() : base.add(off_of_Elf64_Ehdr_shentsize).readU16();    // Size of the section header
        if (is32bit && shentsize != 40) {  // 0x28
            console.log("[!] Wrong e_shentsize. Should be 40 but ignore...");
        } else if (!is32bit && shentsize != 64) {
            console.log("[!] Wrong e_shentsize. Should be 64 but ignore...");
        }
        var shnum = is32bit ? base.add(off_of_Elf32_Ehdr_shnum).readU16() : base.add(off_of_Elf64_Ehdr_shnum).readU16();    // Number of entries in section header table
        var shstrndx = is32bit ? base.add(off_of_Elf32_Ehdr_shstrndx).readU16() : base.add(off_of_Elf64_Ehdr_shstrndx).readU16();  // Section header table index of the entry associated with the section name string table
        // console.log(`phoff: ${phoff}, shoff: ${shoff}, phentsize: ${phentsize}, phnum: ${phnum}, shentsize: ${shentsize}, shnum: ${shnum}, shstrndx: ${shstrndx}`)
        send({'parseElf': {
                'header':'Elf_Ehdr',
                'e_phoff':ptr(phoff),
                'e_shoff':ptr(shoff),
                'e_phentsize':ptr(phentsize),
                'e_phnum':phnum,
                'e_shentsize':ptr(shentsize),
                'e_shnum':shnum,
                'e_shstrndx':shstrndx,
            }
        })

        // Parse Phdr(Program header)
        var phdrs = base.add(phoff)
        for (var i = 0; i < phnum; i++) {
            var phdr = phdrs.add(i * phentsize);
            var p_type = phdr.readU32();

            // if p_type is 0 check if it's really 0 from the file
            var phdrs_from_file = null;
            if (p_type === 0 && fd != null && fd !== -1) {
                phdrs_from_file = Memory.alloc(phnum * phentsize);
                lseek(fd, phoff, SEEK_SET);
                read(fd, phdrs_from_file, phnum * phentsize);
                p_type = phdrs_from_file.add(i * phentsize).readU32();
            }
            var p_type_sym = null;

            // check if p_type matches the defined p_type
            var p_type_exists = false;
            for (let key in p_types) {
                if (p_types[key] === p_type) {
                    p_type_exists = true;
                    p_type_sym = key;
                    break;
                }
            }
            if (!p_type_exists) break;

            var p_offset = is32bit ? phdr.add(0x4).readU32() : phdr.add(0x8).readU64();
            var p_vaddr = is32bit ? phdr.add(0x8).readU32() : phdr.add(0x10).readU64();
            var p_paddr = is32bit ? phdr.add(0xc).readU32() : phdr.add(0x18).readU64();
            var p_filesz = is32bit ? phdr.add(0x10).readU32() : phdr.add(0x20).readU64();
            var p_memsz = is32bit ? phdr.add(0x14).readU32() : phdr.add(0x28).readU64();
            var p_flags = is32bit ? phdr.add(0x18).readU32() : phdr.add(0x4).readU32();
            var p_align = is32bit ? phdr.add(0x1c).readU32() : phdr.add(0x30).readU64();
            // console.log(`p_type: ${p_type}, p_offset: ${p_offset}, p_vaddr: ${p_vaddr}, p_paddr: ${p_paddr}, p_filesz: ${p_filesz}, p_memsz: ${p_memsz}, p_flags: ${p_flags}, p_align: ${p_align}`);

            // if p_flags is 0, check it from the file
            if (p_flags === 0 && fd != null && fd !== -1) {
                phdrs_from_file = Memory.alloc(phnum * phentsize);
                lseek(fd, phoff, SEEK_SET);
                read(fd, phdrs_from_file, phnum * phentsize);
                var phdr_from_file = phdrs_from_file.add(i * phentsize);
                p_offset = is32bit ? phdr_from_file.add(0x4).readU32() : phdr_from_file.add(0x8).readU64();
                p_vaddr = is32bit ? phdr_from_file.add(0x8).readU32() : phdr_from_file.add(0x10).readU64();
                p_paddr = is32bit ? phdr_from_file.add(0xc).readU32() : phdr_from_file.add(0x18).readU64();
                p_filesz = is32bit ? phdr_from_file.add(0x10).readU32() : phdr_from_file.add(0x20).readU64();
                p_memsz = is32bit ? phdr_from_file.add(0x14).readU32() : phdr_from_file.add(0x28).readU64();
                p_flags = is32bit ? phdr_from_file.add(0x18).readU32() : phdr_from_file.add(0x4).readU32();
                p_align = is32bit ? phdr_from_file.add(0x1c).readU32() : phdr_from_file.add(0x30).readU64();
            }

            send({
                'parseElf': {
                    'header': 'Elf_Phdr',
                    'p_type': p_type_sym,
                    'p_offset': ptr(p_offset),
                    'p_vaddr': ptr(p_vaddr),
                    'p_paddr': ptr(p_paddr),
                    'p_filesz': ptr(p_filesz),
                    'p_memsz': ptr(p_memsz),
                    'p_flags': ptr(p_flags),
                    'p_align': ptr(p_align),
                }
            })

            if (p_type === 0x2) {
                // .dynamic
                dynamic_section_addr = base.add(p_vaddr);
                dynamic_section_indices = parseInt(p_memsz) / parseInt(p_align) * 2
                dynamic_section_entsize = p_align * 2
            }
        }

        // Parse .dynamic section
        send({'parseElf': {
                'section':'Dynamic Tags[.dynamic]',
                'section_offset':dynamic_section_addr.sub(base),
            }
        })
        for (var j = 0; j < dynamic_section_indices; j++) {
            var section_name = null;
            var d_tag = is32bit ? dynamic_section_addr.add(j * dynamic_section_entsize).readU32() : dynamic_section_addr.add(j * dynamic_section_entsize).readU64()
            if (d_tag == 0) {
                break;
            }
            var d_value = is32bit ? dynamic_section_addr.add(j * dynamic_section_entsize + 4).readU32() : dynamic_section_addr.add(j * dynamic_section_entsize + 8).readU64()
            // console.log(`d_tag: ${d_tag}, d_value: ${d_value}`)
            if (d_tag == 0x3) {
                // .got.plt
                section_name = '.got.plt'
                got_plt_secition_addr = base.add(d_value);
                // console.log(`got_plt_secition_addr: ${got_plt_secition_addr}`)
            } else if (d_tag == 0x5) {
                // .dynstr
                section_name = '.dynstr'
                dynstr_section_addr = base.add(d_value);
                // console.log(`dynstr_section_addr: ${dynstr_section_addr}`)
            } else if (d_tag == 0x6) {
                // .dynsym
                section_name = '.dynsym'
                dynsym_section_addr = base.add(d_value);
                // console.log(`dynsym_section_addr: ${dynsym_section_addr}`)
            } else if (d_tag == 0x17) {
                // .rela.plt
                section_name = '.rela.plt'
                rela_plt_section_addr = base.add(d_value);
                // console.log(`rela_plt_section_addr: ${rela_plt_section_addr}`)
            }
            var d_tag_name = null
            for (var key in d_tags) {
                if (d_tags[key] == d_tag) {
                    d_tag_name = key;
                }
            }
            send({'parseElf': {
                    'section':section_name,
                    'section_offset':ptr(d_value),
                    'd_tag':d_tag,
                    'd_tag_name':d_tag_name,
                    'd_value':ptr(d_value)
                }
            })
        }

        // Parse .dynsym section
        var dynsym_section_entsize = is32bit ? 0x10 : 0x18;
        var dynsyms = {};
        var st_infos = [
            0x00,   // LOCAL NOTYPE
            0x03,   // LOCAL SECTION
            0x10,   // GLOBAL NOTYPE
            0x11,   // GLOBAL OBJECT
            0x12,   // GLOBAL FUNC
            0x1a,   // GLOBAL LOOS
            0x20,   // WEAK NOTYPE
            0x21,   // WEAK OBJECT
            0x22,   // WEAK FUNC
        ]
        var st_others = [
            0x0,		/* STV_DEFAULT. Default symbol visibility rules */
            0x1,		/* STV_INTERNAL. Processor specific hidden class */
            0x2,		/* STV_HIDDEN. Sym unavailable in other modules */
            0x3,		/* STV_PROTECTED. Not preemptible, not exported */
        ]
        for (var i = 0, id = 0;;i += dynsym_section_entsize, id++) {
            var dynsym_section_entaddr = dynsym_section_addr.add(i)
            var st_name = is32bit ? dynsym_section_entaddr.readU32() : dynsym_section_entaddr.readU32();
            // console.log(`${id}. st_name: ${st_name}`)
            var st_value = is32bit ? dynsym_section_entaddr.add(0x4).readU32() : dynsym_section_entaddr.add(0x8).readU64();
            var st_size = is32bit ? dynsym_section_entaddr.add(0x8).readU32() : dynsym_section_entaddr.add(0x10).readU64();
            var st_info = is32bit ? dynsym_section_entaddr.add(0xc).readU8() : dynsym_section_entaddr.add(0x4).readU8();
            if (!st_infos.includes(st_info)) {
                // console.log(`st_info: ${st_info} is not a valid`)
                break;
            }
            var st_other = is32bit ? dynsym_section_entaddr.add(0xd).readU8() : dynsym_section_entaddr.add(0x5).readU8();
            if (!st_others.includes(st_other)) {
                console.log(`st_ohter: ${st_other} is not a valid`)
                break;
            }
            var st_shndx = is32bit ? dynsym_section_entaddr.add(0xe).readU16() : dynsym_section_entaddr.add(0x6).readU16();

            try {
                var symbol_name = dynstr_section_addr.add(st_name).readUtf8String();
            } catch (error) {
                break;
            }
            dynsyms[id] = {
                "symbol_name": symbol_name,
            }
            // console.log(`${id}. st_name: ${st_name} --> ${symbol_name}, st_value: ${st_value}, st_size: ${st_size}, st_info: ${st_info}, st_other: ${st_other}, st_shndx: ${st_shndx}`)
            send({
                'parseElf':{
                    'section_detail':'Symbol Table[.dynsym]',
                    'section_offset':dynsym_section_addr.sub(base),
                    'st_name': st_name,
                    'symbol_name': symbol_name,
                    'st_value': st_value,
                    'st_size': st_size,
                    'st_info': st_info,
                    'st_other': st_other,
                    'st_shndx': st_shndx,
                }
            })
        }

        // Just send .dynstr section info
        if (dynstr_section_addr != null) {
            send({
                'parseElf':{
                    'section_detail':'String Table[.dynstr]',
                    'section_offset':dynstr_section_addr.sub(base),
                }
            })
        }

        // Parse .rela.plt, .got.plt section
        var rela_plt_section_entsize = is32bit ? 0x8 : 0x18
        var R_ARM_JUMP_SLOT = 0x16  /* Create PLT entry */
        var R_AARCH64_JUMP_SLOT = 0x402
        for (var i = 0, id = 0;;i += rela_plt_section_entsize, id++) {
            var rela_plt_section_entaddr = rela_plt_section_addr.add(i);
            var r_offset = is32bit ? rela_plt_section_entaddr.readU32() : rela_plt_section_entaddr.readU64();
            var r_info_addr = is32bit ? rela_plt_section_entaddr.add(0x4) : rela_plt_section_entaddr.add(0x8);
            var reloc_type = is32bit ? r_info_addr.readU8() : r_info_addr.readU32();
            if ((is32bit && reloc_type != R_ARM_JUMP_SLOT) || (!is32bit && reloc_type != R_AARCH64_JUMP_SLOT)) {
                break;
            }

            var sym_index = is32bit ? r_info_addr.readU32() >>> 8 : r_info_addr.add(0x4).readU32();
            var symptr_in_got_plt = base.add(r_offset).readPointer();
            var r_addend = rela_plt_section_entaddr.add(0x10).readU64();
            var location = Process.findModuleByAddress(symptr_in_got_plt) === null ? 'None' : Process.findModuleByAddress(symptr_in_got_plt).name
            send({'parseElf': {
                    'section_detail': 'RELA[.rela.plt]',
                    'section_offset': rela_plt_section_addr.sub(base),
                    'r_offset': ptr(r_offset),
                    'r_info': `${ptr(reloc_type)}(reloc_type), ${ptr(sym_index)}(sym_index)`,
                    'r_addend': r_addend,
                    'symbol': dynsyms[sym_index]["symbol_name"],
                    'symbol_addr': symptr_in_got_plt,
                    'location': location
                }
            })
            // console.log(`${id}. symbol: ${dynsyms[sym_index]["symbol_name"]} --> addr: ${symptr_in_got_plt}(${Process.findModuleByAddress(symptr_in_got_plt).name})`)
            // console.log(`r_offset: ${r_offset}, symptr_in_got_plt: ${symptr_in_got_plt}, sym_index: ${sym_index}`)
        }

        // Just send .got.plt section info
        send({
            'parseElf':{
                'section_detail':'.got.plt',
                'section_offset':got_plt_secition_addr.sub(base),
            }
        })

        // Close the file
        if (fd != null && fd !== -1) {
            close(fd);
        }
    }
}