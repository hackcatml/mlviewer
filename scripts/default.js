var completed = false
var scandestroyed = false
var scanandreplacemode = false
var replacecode = []

var count = 0
var modules = []
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
    findexportbyname:(name) => {
        send(Module.findExportByName(null, name))
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
}
