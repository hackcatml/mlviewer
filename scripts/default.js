var completed = false
var scandestroyed = false
var scanandreplacemode = false
var replacecode = []

var count = 0
var modules = []

let num_args_to_watch = 0
let read_args_options = {}
let read_retval_options = {}
function getmemprotection(name, addr){
    count++
    var result
    // console.log("[hackcatml] re: " + re)
    if(count === 1){
        var re = new RegExp(name + "$")
        Process.enumerateRangesSync('r--')
            .filter(function(m){
                if(m.file != null) {
                    if(m.file.path.match(re) != null){ modules.push(m) }
                    // for android
                    if(m.file.path.match(/split_config\.arm/) != null){ modules.push(m) }
                }
            })
    }
    for (const idx in modules) {
        if(ptr(addr) >= modules[idx].base && ptr(addr) < modules[idx].base.add(modules[idx].size)){
            result = modules[idx].protection
            break
        }
    }
    return result
}

function readargs(args, index, addr) {
    // if the argument's index is in the read_args_options for the current address
    if (read_args_options[addr] && read_args_options[addr][index]) {
        // get the option from the read_args_options
        var option = read_args_options[addr][index]["readOption"];
        // read the argument based on the option
        if(option === "readByteArray") {
            let data = new Uint8Array(args[option](32))
            return Object.keys(data).map(key => data[key].toString(16).padStart(2, '0')).join(' ');
        }
        if(option === '') {
            return args
        }
        return args[option]();
    } else {
        // just log the argument if it's not in the read_args_options
        return args.toString();
    }
}

function readretval(retval, addr) {
    // if the argument's index is in the read_args_options for the current address
    if (read_retval_options[addr]) {
        // get the option from the read_retval_options
        var option = read_retval_options[addr];
        // read the argument based on the option
        if(option === "readByteArray") {
            let data = new Uint8Array(retval[option](32))
            return Object.keys(data).map(key => data[key].toString(16).padStart(2, '0')).join(' ');
        }
        return retval[option]();
    } else {
        // just log the argument if it's not in the read_retval_options
        return retval.toString();
    }
}

rpc.exports = {
    // just dummy function for checking script is alive
    dummy:() => {
        // console.log("muffin")
        send("")
    },
    arch:() => {
        send(Process.arch)
    },
    platform:() => {
        send(Process.platform)
    },
    findsymaddrbyname:(name) => {
        let symbol_addr = Module.findExportByName(null, name)
        if(symbol_addr == null) {
            function findsymaddr(modules) {
                for (let m of modules) {
                    let symbols = Module.enumerateSymbols(m['name']);
                    for (let sym of symbols) {
                        if (sym['name'].indexOf(name) !== -1) {
                            return sym['address'];
                        }
                    }
                }
                return null;
            }
            let modules = Process.enumerateModules()
            symbol_addr = findsymaddr(modules)
            return (symbol_addr == null || symbol_addr.isNull()) ? null : symbol_addr;
        } else {
            return symbol_addr
        }
    },
    enumerateranges:(prot) => {
        // send(Process.enumerateRangesSync(prot))
        return Process.enumerateRangesSync(prot)
    },
    listmodules:() => {
        send(Process.enumerateModulesSync())
    },
    getmodulenamebyaddr:(addr) => {
        send(Process.findModuleByAddress(addr))
    },
    hexdumpoffset: (name, offset, size) => {
        // console.log(`[hackcatml]: name: ${name}, offset: ${offset}, size: ${size}`)
        var base = Process.findModuleByName(name).base
        var target = base.add(offset)
        send(hexdump(target, {offset: 0, length: size}))
    },
    hexdumpaddr: (addr, size) => {
        send(hexdump(ptr(addr), {offset:0, length:size}))
    },
    writememaddr: (addr, code, prot) => {
        var newprot = prot
        if(prot == "r--" || prot == "r-x") {
            newprot = "rw-"
        }
        Memory.protect(ptr(addr), 4, newprot)
        Memory.writeByteArray(ptr(addr), [code])
        Memory.protect(ptr(addr), 4, prot)
    },
    modulestatus: (name) => {
        if(name == "") {
            send(Process.enumerateModulesSync()[0])
        }
        else {
            send(Process.findModuleByName(name))
        }
    },
    memscan: function scan(ranges, pattern) {
        var memranges = ranges
        var mempattern = pattern
        var returnmessage = ''
        var scancompleted = 0
        var totalscancount = memranges.length
        completed = false
        scandestroyed = false

        var timer = setInterval(function() {
            send({'scancompletedratio':(scancompleted/totalscancount)*100})
            if(completed && scandestroyed){
                returnmessage += '[!] Memory Scan Done'
                // console.log(returnmessage)
                send(returnmessage)
                completed = false
                scanandreplacemode = false
                console.log("[hackcatml] clear interval")
                clearInterval(timer)
                return
            }
        }, 100);

        function scanMemory() {
            var range = memranges.pop()
            if(!range || completed){
                completed = true
                console.log("[hackcatml] Memory Scan Done!")
                scandestroyed = true
                return 0;
            }
            Memory.scan(ptr(range[0]), range[3], mempattern, {
                onMatch: function (address, size) {
                    if(completed){
                        return
                    }
                    if(scanandreplacemode){
                        var newprot = range[2]
                        if(range[2] == "r--" || range[2] == "r-x") {
                            newprot = "rw-"
                        }
                        Memory.protect(address, replacecode.length, newprot)
                        Memory.writeByteArray(address, replacecode)
                        Memory.protect(address, replacecode.length, range[2])
                    }

                    var modulename = ''
                    var offset = 0
                    var result = Process.findModuleByAddress(address)
                    if(result != null) {
                        modulename = result.name
                        offset = address.sub(result.base)
                    }
                    returnmessage += address.toString() + ', module: ' + modulename + ', offset: ' + offset + '\n';
                    returnmessage += hexdump(address, {offset: 0, length: 32}) + '\n\n';
                },
                onError: function (reason) { console.log('[!] Error Scanning Memory: ' + reason); },
                onComplete: function () {
                    scancompleted++;
                    // Thread.sleep(0.05)
                    scanMemory()
                }
            });
        }
        scanMemory()
    },
    memscanwithimg: function scanImg(name, pattern) {
        var module = Process.findModuleByName(name)
        if(module == null){
            return 'module not found'
        }
        var mempattern = pattern
        var returnmessage = ''
        var scancompleted = 0
        var totalscancount = module.size
        completed = false
        scandestroyed = false

        var timer = setInterval(function() {
            send({'scancompletedratio':(scancompleted/totalscancount)*100})
            if(completed && scandestroyed){
                returnmessage += '[!] Memory Scan Done'
                send(returnmessage)
                completed = false
                scanandreplacemode = false
                modules.length = 0
                count = 0
                console.log("[hackcatml] clear interval")
                clearInterval(timer)
                return
            }
        }, 100);

        function scanMemory() {
            if(completed){
                console.log("[hackcatml] Memory Scan Done!")
                scandestroyed = true
                scancompleted = module.size
                return 0;
            }
            Memory.scan(ptr(module.base), module.size, mempattern, {
                onMatch: function (address, size) {
                    if(completed){
                        return
                    }
                    if(scanandreplacemode){
                        var origprot = getmemprotection(module.name, address)
                        var newprot = origprot
                        if(origprot == "r--" || origprot == "r-x") {
                            newprot = "rw-"
                        }
                        // console.log("[hackcatml] origprot: " + origprot + ", newprot: " + newprot)
                        Memory.protect(address, replacecode.length, newprot)
                        Memory.writeByteArray(address, replacecode)
                        Memory.protect(address, replacecode.length, origprot)
                    }
                    // console.log("[hackcatml] onMatch " + address)
                    var offset = address.sub(module.base)
                    scancompleted = ptr(offset).toUInt32()
                    returnmessage += address.toString() + ', module: ' + module.name + ', offset: ' + offset + '\n';
                    returnmessage += hexdump(address, {offset: 0, length: 32}) + '\n\n';
                },
                onError: function (reason) { console.log('[!] Error Scanning Memory: ' + reason); },
                onComplete: function () {
                    completed = true
                    scanMemory()
                }
            });
        }
        scanMemory()
    },
    memscanandreplace: (code) => {
        scanandreplacemode = true
        replacecode = code
        // send(replacecode)
    },
    stopmemscan: () => {
        completed = true
        scanandreplacemode = false
        replacecode.length = 0
        count = 0
        modules.length = 0
    },
    setreadargsoptions: (addr, index, option, onleave) => {
        // if the address is not in the read_args_options yet, add it
        if (!read_args_options[addr]) {
            read_args_options[addr] = {};
        }
        // add/update the index and read options for the address
        read_args_options[addr][index] = {};
        read_args_options[addr][index]["readOption"] = option
        read_args_options[addr][index]["onLeave"] = onleave !== 0;
    },
    setreadretvalsoptions: (addr, option) => {
        // if the address is not in the read_args_options yet, add it
        if (!read_retval_options[addr]) {
            read_retval_options[addr] = {};
        }
        // add/update the index and option for the address
        read_retval_options[addr] = option;
    },
    setnargs: (nargs) => {
        num_args_to_watch = nargs;
    },
    setwatch: (addr, is_reg_watch) => {
        Interceptor.attach(ptr(addr), {
            onEnter: function (args) {
                this.argv = []
                for (let index = 0; index < num_args_to_watch; index++) {
                    this.argv[index] = args[index]
                }

                if(is_reg_watch) {
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
                    send({'watchRegs':log})
                } else {
                    let log = `[+] ${ptr(addr)}\n`
                    for (let index = 0; index < num_args_to_watch - 1; index++) {
                        if(read_args_options[ptr(addr)] && read_args_options[ptr(addr)][index] && read_args_options[ptr(addr)][index]["onLeave"]) {
                            continue;
                        }
                        log += `args${index}: ${readargs(args[index], index, ptr(addr))}, `
                    }
                    if(read_args_options[ptr(addr)] && read_args_options[ptr(addr)][num_args_to_watch - 1] && read_args_options[ptr(addr)][num_args_to_watch - 1]["onLeave"]) {
                        send({'watchArgs':log})
                    } else {
                        log += `args${num_args_to_watch - 1}: ${readargs(args[num_args_to_watch - 1], num_args_to_watch - 1, ptr(addr))}`
                        send({'watchArgs':log})
                    }
                }
            },
            onLeave: function(retval) {
                if(is_reg_watch){
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
                    send({'watchRegs':log})
                } else {
                    let log = `return: ${readretval(retval, ptr(addr))}\n`
                    for (let index = 0; index < num_args_to_watch; index++) {
                        if(read_args_options[ptr(addr)] && read_args_options[ptr(addr)][index] && read_args_options[ptr(addr)][index]["onLeave"]){
                            log += `args${index}: ${readargs(this.argv[index], index, ptr(addr))}, `
                            this.onleave = true
                        }
                    }
                    if (this.onleave) {
                        log += '\n'
                    }
                    log += `[-] ${ptr(addr)}`
                    send({'watchArgs':log})
                }
            }
        });
    },
    detachall: () => {
        Interceptor.detachAll()
    },
}
