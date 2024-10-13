const ensureCodeReadableModule = new CModule(`
    #include <gum/gummemory.h>

    void ensure_code_readable(gconstpointer address, gsize size) {
        gum_ensure_code_readable(address, size);
    }
`);

var ensure_code_readable = new NativeFunction(ensureCodeReadableModule.ensure_code_readable, 'void', ['pointer', 'uint64']);

rpc.exports = {
    findModule: function(so_name) {
        var libso = Process.findModuleByName(so_name);
        if (libso == null) {
            return -1;
        }
        return libso;
    },
    dumpModule: function(so_name) {
        var libso = Process.findModuleByName(so_name);
        if (libso == null) {
            return -1;
        }

        ensure_code_readable(ptr(libso.base), libso.size);

        var libso_buffer = ptr(libso.base).readByteArray(libso.size);
        return libso_buffer;
    },
    dumpModuleChunk: function(offset, size) {
        ensure_code_readable(ptr(offset), size);

        var chunk = ptr(offset).readByteArray(size);
        return chunk;
    }
}
