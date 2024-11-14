let completed = false;
let scan_destroyed = false;

let scanned_addresses = [];
let set_update_scanned_value_interval = null;

let num_args_to_watch = 0;
let read_args_options = {};
let read_retval_options = {};
let watch_list = {};

const log_tag = '[default.js]';

let mem_refresh_interval = null;
let is_mem_refresh_on = false;
let refresh_addr = null;

let unset_watchpoint = false;
let watchpoint_addr, watchpoint_size, watchpoint_type;
let threads = null
let target_thread = null;
let watchpoint_interval = null;

// Check if it's palera1n jb
let is_palera1n = false;
let force_read = false;
if (ObjC.available) {
    let access = new NativeFunction(Module.findExportByName(null, "access"), 'int', ['pointer', 'int'])
    let path = Memory.allocUtf8String("/cores/binpack/Applications/palera1nLoader.app");
    is_palera1n = access(path, 0) === 0
}

const ensureCodeReadableModule = new CModule(`
    #include <gum/gummemory.h>

    void ensure_code_readable(gconstpointer address, gsize size) {
        gum_ensure_code_readable(address, size);
    }
`);

let ensure_code_readable = new NativeFunction(ensureCodeReadableModule.ensure_code_readable, 'void', ['pointer', 'uint64']);

function readArgs(args, index, addr) {
    // if the argument's index is in the read_args_options for the current address
    if (read_args_options[addr] && read_args_options[addr][index]) {
        // get the option from the read_args_options
        var option = read_args_options[addr][index]["readOption"];
        // read the argument based on the option
        if (option === "hexdump") {
            let dump_target_address = args;
            let dump_result = null;
            let hexdump_type = ""   // onEnter hexdump || onLeave hexdump
            if (read_args_options[addr] && read_args_options[addr][index] && read_args_options[addr][index]["onLeave"]) {
                hexdump_type = 'on_leave_hexdump';
            } else {
                hexdump_type = 'on_enter_hexdump';
            }

            if (read_args_options[addr][index]["hexDumpTargetAddress"] !== '0x0') {
                dump_target_address = read_args_options[addr][index]["hexDumpTargetAddress"];
            }
            try {
                dump_result = hexdump(ptr(dump_target_address).add(read_args_options[addr][index]["hexDumpOffset"]));
            } catch(e) {
                dump_result = ''
            }

            if (hexdump_type === 'on_enter_hexdump') {
                send({ 'on_enter_hexdump' : {
                    address: ptr(addr),
                    args_index: index,
                    dump_target_address: ptr(args),
                    dump_result: dump_result
                }})
            } else {
                send({ 'on_leave_hexdump' : {
                    address: ptr(addr),
                    args_index: index,
                    dump_target_address: ptr(args),
                    dump_result: dump_result
                }})
            }

            return args;
        }

        if (option === 'readStdString') {
            let isTiny = (ptr(args).readU8() & 1) === 0;
            if (isTiny) {
                return ptr(args).add(1).readUtf8String();
            }
            return ptr(args).add(2 * Process.pointerSize).readPointer().readUtf8String();
        }

        if (option === "readByteArray") {
            let data = new Uint8Array(args[option](32))
            return Object.keys(data).map(key => data[key].toString(16).padStart(2, '0')).join(' ');
        }

        if (option === '') {
            return args
        }

        return args[option]();
    } else {
        // just log the argument if it's not in the read_args_options
        return args.toString();
    }
}

function readRetval(retval, addr) {
    // if the argument's index is in the read_args_options for the current address
    if (read_retval_options[addr]) {
        // get the option from the read_retval_options
        var option = read_retval_options[addr]["readOption"];
        // read the argument based on the option
        if(option === "readByteArray") {
            let data = new Uint8Array(retval[option](32))
            return Object.keys(data).map(key => data[key].toString(16).padStart(2, '0')).join(' ');
        }

        if (option === "hexdump") {
            let dump_target_address = retval;
            let dump_result = null;

            if (read_retval_options[addr]["hexDumpTargetAddress"] !== '0x0') {
                dump_target_address = read_retval_options[addr]["hexDumpTargetAddress"];
            }
            try {
                dump_result = hexdump(ptr(dump_target_address).add(read_retval_options[addr]["hexDumpOffset"]));
            } catch(e) {
                dump_result = ''
            }

            send({ 'on_leave_hexdump' : {
                    address: ptr(addr),
                    args_index: "",
                    dump_target_address: ptr(retval),
                    dump_result: dump_result
                }})

            return retval;
        }

        return retval[option]();
    } else {
        // just log the argument if it's not in the read_retval_options
        return retval.toString();
    }
}

rpc.exports = {
    // Dummy function for checking script is alive
    dummy:() => {
        send("")
    },
    arch:() => {
        send(Process.arch)
    },
    platform:() => {
        send(Process.platform)
    },
    isRootless: function() {
        var access = new NativeFunction(Module.findExportByName(null, "access"), "int", ["pointer", "int"]);
        var path = Memory.allocUtf8String("/var/jb/usr/bin/su");
        return access(path, 0) === 0
    },
    isPalera1nJb: function() {
        return is_palera1n;
    },
    findSymAddrByName:(module_name, sym_name) => {
        module_name = null ? module_name === '' : module_name;
        let symbol_addr = Module.findExportByName(module_name, sym_name);
        if(symbol_addr == null) {
            function findSymAddr(modules) {
                for (let m of modules) {
                    let result = Module.findExportByName(m['name'], sym_name);
                    if (result !== null) {
                        return result;
                    }
                    let symbols = Module.enumerateSymbols(m['name']);
                    for (let sym of symbols) {
                        if (sym['name'].indexOf(sym_name) !== -1) {
                            // console.log(`${log_tag}[findSymAddrByName] symbol name: ${sym['name']}, addr: ${sym['address']}`);
                            return sym['address'];
                        }
                    }
                }
                return null;
            }
            let modules = Process.enumerateModules()
            symbol_addr = findSymAddr(modules)
            return (symbol_addr == null || symbol_addr.isNull()) ? null : symbol_addr;
        } else {
            return symbol_addr
        }
    },
    findSymNameByAddr: (module_name, addr) => {
        let symbols = Module.enumerateSymbolsSync(module_name);
        let sym_name = null;
        symbols.some(x => {
            if (x.address == addr && (x.type === "function" || x.type === "section")) {
              sym_name = x.name;
              return true;
            }
        })
        return sym_name;
    },
    enumerateRanges:(prot) => {
        // send(Process.enumerateRangesSync(prot))
        return Process.enumerateRangesSync(prot)
    },
    listModules:() => {
        send(Process.enumerateModulesSync())
    },
    getModuleByName:(name) => {
        send(Process.findModuleByName(name));
    },
    getModuleByAddr:(addr) => {
        send(Process.findModuleByAddress(addr));
    },
    hexDumpOffset: (name, offset, size) => {
        var base = Process.findModuleByName(name).base
        var target = base.add(offset)
        if (is_palera1n && !force_read) {
            try {
                Process.getRangeByAddress(ptr(target));
                send(hexdump(target, {offset: 0, length: size}));
            } catch (e) {
                send({'palera1n':'Cannot access the address ' + ptr(target) + '. Try force read by "ctrl(cmd) + GO"'})
            }
        } else {
            send(hexdump(target, {offset: 0, length: size}));
        }
    },
    hexDumpAddr: (addr, size) => {
        if (is_palera1n && !force_read) {
            try {
                Process.getRangeByAddress(ptr(addr));
                send(hexdump(ptr(addr), {offset:0, length:size}))
            } catch (e) {
                send({'palera1n':'Cannot access the address ' + ptr(addr) + '. Try force read by "ctrl(cmd) + GO"'})
            }
        } else {
            send(hexdump(ptr(addr), {offset:0, length:size}))
        }
    },
    forceReadMemAddr: (yes_or_no) => {
        force_read = yes_or_no
    },
    writeMemAddr: (addr, code, prot) => {
        var newprot = prot
        if(prot == "r--" || prot == "r-x" || prot == "---") {
            newprot = "rw-"
        }
        Memory.protect(ptr(addr), 4, newprot)
        Memory.writeByteArray(ptr(addr), [code])
        if(prot == "---") return    // If memory protection is '---', then keep it as is, else revert to the original protection.
        Memory.protect(ptr(addr), 4, prot)
    },
    moduleStatus: (name) => {
        if(name == "") {
            send(Process.mainModule)
        }
        else {
            send(Process.findModuleByName(name))
        }
    },
    memScan: function scan(ranges, pattern) {
        let return_message = '';
        let scan_completed = 0;
        let total_scan_count = ranges.length;
        let scan_match_count = 0;
        let rounded_value_scan_match_count = 0;

        let rounded_value_scan = false;
        let scan_value_scan_type = '';
        let rounded_value_scan_read_option = '';
        let scan_value_byte_pairs_length = 0;
        let rounded_value = 0;
        let scan_value = '';

        let mask_pattern_scan = false;

        completed = false;
        scan_destroyed = false;

        if (typeof pattern === 'object' && pattern.scan_type !== undefined) {
            console.log(`${log_tag}[memScan] rounded_value_scan: ${JSON.stringify(pattern)}`);
            rounded_value_scan = true;
            scan_value_scan_type = pattern.scan_type;
            if (scan_value_scan_type === 'Float') {
                rounded_value_scan_read_option = 'readFloat';
            } else {
                rounded_value_scan_read_option = 'readDouble';
            }
            rounded_value = pattern.rounded_value;
            scan_value_byte_pairs_length = pattern.scan_value_length;
            scan_value = pattern.scan_value;
        } else if (typeof pattern === 'string' && pattern.indexOf('?') >= 0) {
            // Array of Bytes mask pattern scan. e.g., 50 00 ?? 58
            mask_pattern_scan = true;
        }

        var timer = setInterval(function() {
            if(completed){
                return_message += '[!] Memory Scan Done';
                send(return_message);
                completed = false;
                // scan_and_replace_mode = false;
                console.log(`${log_tag}[memScan] clear interval`);
                clearInterval(timer);
            }
        }, 100);

        function scanMemory(range, pattern) {
            ensure_code_readable(ptr(range[0]), range[3]);
            Memory.scan(ptr(range[0]), range[3], pattern, {
                onMatch: function (address, size) {
                    if (scan_destroyed) {
                        return;
                    }
                    scan_match_count += 1;
                    let match_addr;
                    let match_value;
                    if (rounded_value_scan) {
                        if (scan_value_scan_type === 'Float') {
                            match_addr = address.sub(4 - scan_value_byte_pairs_length);
                        } else if (scan_value_scan_type === 'Double') {
                            match_addr = address.sub(8 - scan_value_byte_pairs_length);
                        }
                        match_value = ptr(match_addr)[rounded_value_scan_read_option]();

                        if ((rounded_value + 0.4 >= match_value) && (rounded_value - 0.5 < match_value)) {
                            rounded_value_scan_match_count += 1;
                            send({'scan_match':
                                {
                                    match_count: rounded_value_scan_match_count,
                                    match_address: match_addr.toString(),
                                    match_value: match_value
                                }});
                            // console.log(`${log_tag}[memScan] match_value: ${match_value}`)
                        }
                    } else if (mask_pattern_scan) {
                        match_addr = address.toString();
                        let data = new Uint8Array(ptr(address)['readByteArray'](size));
                        match_value = Object.keys(data).map(key => data[key].toString(16).padStart(2, '0')).join(' ');
                        send({'scan_match':
                                {
                                    match_count: scan_match_count,
                                    match_address: match_addr,
                                    match_value: match_value
                                }});
                    } else {
                        match_addr = address.toString();
                        send({'scan_match':
                            {
                                match_count: scan_match_count,
                                match_address: match_addr,
                            }});
                    }
                    // locations.add(match_addr);
                },
                onError: function (reason) { console.log('[!] Error Scanning Memory: ' + reason); },
                onComplete: function () {
                    if (scan_destroyed) {
                        return;
                    }
                    scan_completed++;
                    // console.log(`${log_tag}[memScan] scan_completed: ${scan_completed} / total_scan_count: ${total_scan_count}`);
                    send({'scan_completed_ratio':(scan_completed / total_scan_count)*100})
                    if((scan_completed === total_scan_count)){
                        completed = true;
                        console.log(`${log_tag}[memScan] Memory Scan Done!`);
                    }
                }
            });
        }

        for (const r of ranges) {
            if (rounded_value_scan) {
                pattern = scan_value;
            }
            // console.log(`${log_tag}[memScan] pattern: ${pattern}`)
            scanMemory(r, pattern)
        }
    },
    memScanReduce: (matches, value, option) => {
        let return_message = '';
        let scan_completed = 0;
        let total_scan_count = matches.length;

        let rounded_value_scan = false;
        let rounded_value = 0;

        if (typeof value === 'object' && value.rounded_value !== undefined) {
            console.log(`${log_tag}[memScanReduce] rounded_value_scan: ${JSON.stringify(value)}`);
            rounded_value_scan = true;
            rounded_value = value.rounded_value;
        }

        completed = false;
        scan_destroyed = false;

        let timer = setInterval(function() {
            if (completed) {
                return_message += '[!] Memory Scan Done';
                send(return_message);
                completed = false;
                console.log(`${log_tag}[memScanReduce] clear interval`);
                clearInterval(timer);
            }
        }, 100);

        let read_option = '';
        if (option === '1 Byte') {
            read_option = 'readU8';
        } else if (option === '2 Bytes') {
            read_option = 'readU16';
        } else if (option === '4 Bytes') {
            read_option = 'readU32';
        } else if (option === '8 Bytes') {
            read_option = 'readU64';
        } else if (option === 'Int') {
            read_option = 'readInt';
        } else if (option === 'Float') {
            read_option = 'readFloat';
        } else if (option === 'Double') {
            read_option = 'readDouble';
        } else if (option['String']) {
            // option['String'] == pattern length
            read_option = 'readUtf8String';
        } else if (option['Array of Bytes']) {
            // option['Array of Bytes'] == pattern length
            read_option = 'readByteArray';
        }
        function filter(match, value) {
            if (scan_destroyed) {
                return;
            }
            try {
                if (rounded_value_scan) {
                    let match_value = ptr(match['match_address'])[read_option]();
                    if ((rounded_value + 0.4 >= match_value) && (rounded_value - 0.5 < match_value)) {
                        // console.log(`${log_tag}[memScanReduce] match_value: ${match_value}`);
                        send({ 'next_scan_match' : {
                                match_count: match['match_count'],
                                match_address: match['match_address'],
                                match_value: match_value
                            }});
                    }
                } else {
                    let match_value;
                    if (option['String']) {
                        match_value = ptr(match['match_address'])[read_option](option['String']);
                        console.log(`${log_tag}[memScanReduce] match_value: ${match_value}, value: ${value}`);
                    } else if (option['Array of Bytes']) {
                        let data = new Uint8Array(ptr(match['match_address'])[read_option](option['Array of Bytes']))
                        match_value = Object.keys(data).map(key => data[key].toString(16).padStart(2, '0')).join('');
                        value = value.replaceAll(' ', '');
                    } else {
                        match_value = ptr(match['match_address'])[read_option]().toString();
                    }
                    // console.log(`${log_tag}[memScanReduce] match_value: ${match_value}, value: ${value}`);
                    if (match_value === value) {
                        send({ 'next_scan_match' : {
                                match_count: match['match_count'],
                                match_address: match['match_address']
                            }});
                    }
                }
            } catch (e) {
                console.log(`${log_tag}[memScanReduce] ${e}`);
            }
            scan_completed++;
            // console.log(`${log_tag}[memScanReduce] scan_completed: ${scan_completed}, total_scan_count: ${total_scan_count}`)
            send({ 'scan_completed_ratio' : (scan_completed / total_scan_count)*100 });
            if (scan_completed === total_scan_count) {
                completed = true;
                console.log(`${log_tag}[memScanReduce] Memory Scan Done!`);
                return 0;
            }
        }

        for (const m of matches) {
            if (rounded_value_scan) {
                value = rounded_value;
            } else if (option === 'Float' || option === 'Double') {
                value = String(parseFloat(value));
            }
            filter(m, value);
        }
    },
    updateScannedValue: (values, option) => {
        scanned_addresses = scanned_addresses.concat(values);
        let read_option = '';
        if (option === '1 Byte') {
            read_option = 'readU8';
        } else if (option === '2 Bytes') {
            read_option = 'readU16';
        } else if (option === '4 Bytes') {
            read_option = 'readU32';
        } else if (option === '8 Bytes') {
            read_option = 'readU64';
        } else if (option === 'Int') {
            read_option = 'readInt';
        } else if (option === 'Float') {
            read_option = 'readFloat';
        } else if (option === 'Double') {
            read_option = 'readDouble';
        } else if (option['String']) {
            // option['String'] == pattern length
            read_option = 'readUtf8String';
        } else if (option['Array of Bytes']) {
            // option['Array of Bytes'] == pattern length
            read_option = 'readByteArray';
        }
        // console.log(`${log_tag}[updateScannedValue] scanned_addresses: ${scanned_addresses.length}, read_option: ${read_option}`);
        // Store the initial values at the memory addresses
        let previous_values = {};

        // Initialize previous values for each address
        function initializePreviousValues() {
            if (scanned_addresses.length === 0) {
                // console.log(`${log_tag}[updateScannedValue] scanned_addresses.length is 0, return initializePreviousValues`);
                return;
            }
            scanned_addresses.forEach(function(values) {
                if (option['Array of Bytes']) {
                    let data = new Uint8Array(ptr(values.match_address)[read_option](option['Array of Bytes']))
                    previous_values[values.match_address] = Object.keys(data).map(key => data[key].toString(16).padStart(2, '0')).join(' ');
                } else if (option['String']) {
                    previous_values[values.match_address] = ptr(values.match_address)[read_option](option['String']);
                } else {
                    previous_values[values.match_address] = ptr(values.match_address)[read_option]();
                }
            });
        }

        // Function to check memory at all specified addresses
        function checkMemoryValues() {
            if (scanned_addresses.length === 0) {
                // console.log(`${log_tag}[updateScannedValue] scanned_addresses.length == 0, return checkMemoryValues`);
                clearInterval(set_update_scanned_value_interval);
                return;
            }
            let current_value = null;
            scanned_addresses.forEach(function(values) {
                try {
                    if (option['Array of Bytes']) {
                        let data = new Uint8Array(ptr(values.match_address)[read_option](option['Array of Bytes']))
                        current_value = Object.keys(data).map(key => data[key].toString(16).padStart(2, '0')).join(' ');
                    } else if (option['String']) {
                        current_value = ptr(values.match_address)[read_option](option['String']);
                    } else {
                        current_value = ptr(values.match_address)[read_option]();
                    }
                } catch (e) {
                    current_value = "???"
                }
                // console.log(`${log_tag}[updateScannedValue] current_value: ${current_value}, previous_value: ${previous_values[values.match_address]}`);
                // Check if the value has changed
                if (current_value !== previous_values[values.match_address]) {
                    // console.log(`${log_tag}[updateScannedValue] Memory value changed at ${values.match_address}: ${previous_values[values.match_address].toString(16)} -> ${current_value.toString(16)}`);
                    // Send a udpated scanned value message
                    send({ 'scanned_value': {
                        match_count: values.match_count,
                        match_address: values.match_address,
                        updated_value: current_value.toString()
                    }});
                    // Update the previous value
                    previous_values[values.match_address] = current_value;
                }
            });
        }

        initializePreviousValues();
        // Set up a periodic interval to check the memory values (e.g., every 1000 ms)
        let check_interval = 1000; // Check every 1000 milliseconds
        set_update_scanned_value_interval = setInterval(checkMemoryValues, check_interval);
    },
    clearUpdateScannedValueInterval: () => {
        try {
            if (set_update_scanned_value_interval !== null) {
                clearInterval(set_update_scanned_value_interval);
                set_update_scanned_value_interval = null;
                scanned_addresses.length = 0;
                // console.log(`${log_tag}[clearUpdateScannedValueInterval] set_update_scanned_value_interval: ${set_update_scanned_value_interval}`);
            }
        } catch (e) {
            console.log(`${log_tag}[clearUpdateScannedValueInterval] ${e}`)
        }
    },
    stopMemScan: () => {
        completed = true;
        scan_destroyed = true;
    },
    setReadArgsOptions: (addr, index, option, onleave) => {
        // If the address is not in the read_args_options yet, add it
        if (!read_args_options[addr]) {
            read_args_options[addr] = {};
        }
        // Add/update the index and read options for the address
        read_args_options[addr][index] = {};
        read_args_options[addr][index]["readOption"] = option;
        read_args_options[addr][index]["onLeave"] = onleave !== 0;
        read_args_options[addr][index]["hexDumpOffset"] = 0;
        read_args_options[addr][index]["hexDumpTargetAddress"] = '0x0';
    },
    setReadRetvalOptions: (addr, option) => {
        // If the address is not in the read_retval_options yet, add it
        if (!read_retval_options[addr]) {
            read_retval_options[addr] = {};
        }
        // Add/update the index and option for the address
        read_retval_options[addr]["readOption"] = option;
        read_retval_options[addr]["hexDumpOffset"] = 0;
        read_retval_options[addr]["hexDumpTargetAddress"] = '0x0';
    },
    setNargs: (nargs) => {
        num_args_to_watch = nargs;
    },
    setWatchList: (addr, is_reg_watch) => {
        if (!watch_list[addr]) {
            watch_list[addr] = {};
        }
        watch_list[addr]["is_reg_watch"] = is_reg_watch;
    },
    setBacktrace: (addr, yes_or_no) => {
        if (watch_list[addr]) {
            watch_list[addr]["backtrace"] = yes_or_no;
        }
    },
    setHexDumpTargetAddress: (addr, index, target_addr) => {
        if (index === "") {
            read_retval_options[addr]["hexDumpTargetAddress"] = target_addr;
        } else {
            read_args_options[addr][index]["hexDumpTargetAddress"] = target_addr;
        }
    },
    setHexDumpOffset: (addr, index, offset) => {
        if (index === "") {
            read_retval_options[addr]["hexDumpOffset"] = offset;
        } else {
            read_args_options[addr][index]["hexDumpOffset"] = offset;
        }
    },
    setWatch: (addr) => {
        Interceptor.attach(ptr(addr), {
            onEnter: function (args) {
                this.argv = []
                for (let index = 0; index < num_args_to_watch; index++) {
                    this.argv[index] = args[index]
                }

                if (watch_list[addr]["backtrace"]) {
                    let backtrace_log = Thread.backtrace(this.context, Backtracer.ACCURATE)
                                                .map(DebugSymbol.fromAddress).join("\n");
                    send({ 'backtrace' : {
                            address: addr,
                            backtrace_log: backtrace_log
                        }});
                }

                if (watch_list[addr]["is_reg_watch"]) {
                    let count = 0
                    let log = `[+] ${ptr(addr)}:\n`
                    let reg_context_string = JSON.stringify(this.context);
                    let reg_context = JSON.parse(reg_context_string);
                    for (let key in reg_context) {
                        count++;
                        if (count >= num_args_to_watch) {
                            log += `${key}: ${reg_context[key]}`
                            break;
                        }
                        log += `${key}: ${reg_context[key]}, `
                    }
                    send({'watch_regs':log})
                } else {
                    let log = `[+] ${ptr(addr)}\n`
                    for (let index = 0; index < num_args_to_watch - 1; index++) {
                        if(read_args_options[ptr(addr)] && read_args_options[ptr(addr)][index] && read_args_options[ptr(addr)][index]["onLeave"]) {
                            continue;
                        }
                        log += `args${index}: ${readArgs(args[index], index, ptr(addr))}, `
                    }
                    if(read_args_options[ptr(addr)] && read_args_options[ptr(addr)][num_args_to_watch - 1] && read_args_options[ptr(addr)][num_args_to_watch - 1]["onLeave"]) {
                        send({'watch_args':log})
                    } else {
                        log += `args${num_args_to_watch - 1}: ${readArgs(args[num_args_to_watch - 1], num_args_to_watch - 1, ptr(addr))}`
                        send({'watch_args':log})
                    }
                }
            },
            onLeave: function(retval) {
                if (watch_list[addr]["is_reg_watch"]){
                    let count = 0
                    let log = `[-] ${ptr(addr)}:\n`
                    let reg_context_string = JSON.stringify(this.context);
                    let reg_context = JSON.parse(reg_context_string);
                    for (let key in reg_context) {
                        count++;
                        if (count >= num_args_to_watch) {
                            log += `${key}: ${reg_context[key]}`
                            break;
                        }
                        log += `${key}: ${reg_context[key]}, `
                    }
                    send({'watch_regs':log})
                } else {
                    let log = `return: ${readRetval(retval, ptr(addr))}\n`
                    for (let index = 0; index < num_args_to_watch; index++) {
                        if(read_args_options[ptr(addr)] && read_args_options[ptr(addr)][index] && read_args_options[ptr(addr)][index]["onLeave"]){
                            log += `args${index}: ${readArgs(this.argv[index], index, ptr(addr))}, `
                            this.onleave = true
                        }
                    }
                    if (this.onleave) {
                        log += '\n'
                    }
                    log += `[-] ${ptr(addr)}`
                    send({'watch_args':log})
                }
            }
        });
    },
    detachAll: () => {
        Interceptor.detachAll()
        num_args_to_watch = 0
        read_args_options = {}
        read_retval_options = {}
        watch_list = {}
    },
    startMemRefresh: () => {
        let do_send = false;
        let hexdump_result;
        is_mem_refresh_on = true;
        mem_refresh_interval = setInterval(function () {
            try {
                // console.log(`${log_tag}[startMemRefresh] ${refresh_addr}`);
                hexdump_result = hexdump(ptr(refresh_addr), {offset:0, length:2048});
                do_send = true;
            } catch (e) {
                // console.log(`${log_tag}[startMemRefresh] ${e}`);
                do_send = false;
            }

            if (do_send) {
                send({ 'refresh_hexdump' : hexdump_result })
            }
        }, 100)
    },
    getMemRefresh: (interval, addr) => {
        refresh_addr = addr;
    },
    stopMemRefresh: () => {
        clearInterval(mem_refresh_interval);
        mem_refresh_interval = null;
        is_mem_refresh_on = false;
    },
    isMemRefreshOn: () => {
        return is_mem_refresh_on;
    },
    memPatch: (addr, value, option) => {
        try {
            let orig_prot = Memory.queryProtection(ptr(addr));
            let size;
            if (option === 'writeU8') {
                size = 1;
            } else if (option === 'writeU16') {
                size = 2;
            } else if (option === 'writeU32') {
                size = 4;
            } else if (option === 'writeU64') {
                size = 8;
            } else if (option === 'writeInt') {
                size = 4;
            } else if (option === 'writeFloat') {
                size = 4;
            } else if (option === 'writeDouble') {
                size = 8;
            } else if (option === 'writeUtf8String') {
                size = value.length;
            } else if (option === 'writeByteArray') {
                size = value.length;
            }
            Memory.protect(ptr(addr), size, 'rwx');
            ptr(addr)[option](value);
            Memory.protect(ptr(addr), size, orig_prot);
        } catch (e) {
            console.log(`${log_tag}[memPatch] ${e}`);
        }
    },
    getProcessThreads: () => {
        if (threads !== null && threads.length !== 0) {
            return threads;
        } else {
            threads = Process.enumerateThreads();
            return threads;
        }
    },
    setWatchpoint: (addr, size, type) => {
        function installWatchpoint(addr, size, type) {
            // console.log(`${log_tag}[setWatchpoint] addr: ${addr}, size: ${size}, type: ${type}`);
            watchpoint_addr = addr;
            watchpoint_size = size;
            watchpoint_type = type;

            Process.setExceptionHandler(e => {
                if (['breakpoint', 'single-step'].includes(e.type)) {
                    if (target_thread !== null && target_thread.id === Process.getCurrentThreadId()) {
                        target_thread.unsetHardwareWatchpoint(0);
                        unset_watchpoint = true;
                    } else {
                        for (const thread of threads) {
                            if (thread.id === Process.getCurrentThreadId()) {
                                target_thread = thread;
                                unset_watchpoint = true;
                                try {
                                    thread.unsetHardwareWatchpoint(0);
                                } catch (e) {
                                    console.log(`${log_tag}[setWatchpoint][installWatchpoint] ${e}`);
                                    threads = threads.filter(t => t.id !== thread.id);
                                }
                            }
                        }
                    }
                    if (target_thread !== null) {
                        // console.log(`\n${log_tag}[setWatchpoint] [!] ${e.context.pc} tried to "${watchpoint_type}" at ${watchpoint_addr}`);
                        send({ 'watchpoint': {
                                what: e.context.pc,
                                how: watchpoint_type,
                                where: watchpoint_addr,
                                what_hexdump: hexdump(ptr(e.context.pc).sub(0x10), {offset:0, length:80}),
                                thread_id: target_thread.id,
                                thread_name: target_thread.name
                            }});
                    }
                    return true;
                }
                return false;
            });

            for (const thread of threads) {
                try {
                    thread.setHardwareWatchpoint(0, watchpoint_addr, watchpoint_size, watchpoint_type);
                    // console.log(`${log_tag}[setWatchpoint] [*] HardwareWatchpoint set at ${addr} (${thread.id} ${thread.name})`);
                } catch (error) {
                    console.log(`${log_tag}[setWatchpoint][installWatchpoint] ${error}`);
                    threads = threads.filter(t => t.id !== thread.id);
                    continue;
                }
                send({ 'watchpoint': {
                        address: addr,
                        stat: 1
                    }})
            }
        }

        function reInstallWatchPoint() {
            if (target_thread !== null) {
                try {
                    target_thread.setHardwareWatchpoint(0, watchpoint_addr, watchpoint_size, watchpoint_type);
                } catch (error) {
                    console.log(`${log_tag}[setWatchpoint][reInstallWatchpoint] ${error}`);
                }
            } else {
                for (const thread of threads) {
                    try {
                        thread.setHardwareWatchpoint(0, watchpoint_addr, watchpoint_size, watchpoint_type);
                    } catch (error) {
                        console.log(`${log_tag}[setWatchpoint][reInstallWatchpoint] ${error}`);
                        threads = threads.filter(t => t.id !== thread.id);
                    }
                }
            }
        }

        installWatchpoint(ptr(addr), size, type);

        watchpoint_interval = setInterval(() => {
            if (unset_watchpoint) {
                reInstallWatchPoint();
                unset_watchpoint = false;
            }
        }, 0);
    },
    stopWatchpoint: () => {
        if (target_thread !== null) {
            target_thread.unsetHardwareWatchpoint(0);
        } else {
            if (threads !== null && threads.length !== 0) {
                for (const thread of threads) {
                    try {
                        thread.unsetHardwareWatchpoint(0);
                    } catch (error) {
                        console.log(`${log_tag}[stopWatchpoint] ${error}`);
                        threads = threads.filter(t => t.id !== thread.id);
                    }
                }
            }
        }
        clearInterval(watchpoint_interval);
        // unset_watchpoint = true;
        console.log(`${log_tag}[stopWatchpoint] watchpoint stopped`);
    },
    getFileFromDevice: (file_path) => {
        let file = new File(file_path, "rb");
        if (!file) {
            console.log(`${log_tag}[getFileFromDevice] Failed to open file: ${file_path}`);
            return;
        }
        let bufferSize = 4096; // Read in 4 KB chunks
        let chunk;
        while ((chunk = file.readBytes(bufferSize)).byteLength > 0) {
            // Send each chunk to the host
            send('get_file_from_device', chunk);
        }
        send('get_file_from_device', new ArrayBuffer(0));
        file.close();
    },
    setException: () => {
        Process.setExceptionHandler(e => {
            let module = Process.findModuleByAddress(e.address);
            if (module !== null &&  module.name === 'libpairipcore.so') {
                // console.log(`${log_tag}[setException] type: ${e.type}, module: ${module.name}, base: ${module.base}, offset: ${e.address.sub(module.base)}, address: ${e.address}`);
                Memory.protect(ptr(e.address), 8, 'rwx');
                ptr(e.address).writeByteArray([0xC0, 0x03, 0x5F, 0xD6]);
                return true;
            }
            return false;
        });
    }
}
