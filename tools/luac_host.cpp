#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>

#include "lua.h"
#include "lobject.h"
#include "lopcodes.h"
#include "lstate.h"
#include "lstring.h"

void* Lua_Red_realloc(void* block, unsigned int, unsigned int size)
{
    return size ? realloc(block, size) : (free(block), static_cast<void*>(NULL));
}

void Lua_Red_Free(void* block, unsigned int)
{
    free(block);
}

void __cdecl LuaScript_CallWARNINGF(char const* message)
{
    if (message) fprintf(stderr, "%s\n", message);
}

struct Input
{
    FILE* file;
    char buffer[4096];
};

static const char* read_chunk(lua_State*, void* data, size_t* size)
{
    Input* input = static_cast<Input*>(data);
    *size = fread(input->buffer, 1, sizeof(input->buffer), input->file);
    return *size ? input->buffer : NULL;
}

struct Output
{
    FILE* file;
    bool failed;
};

static int write_chunk(lua_State*, const void* data, size_t size, void* output)
{
    Output* target = static_cast<Output*>(output);
    if (fwrite(data, 1, size, target->file) != size) target->failed = true;
    return target->failed ? 1 : 0;
}

static void strip_proto(Proto* proto)
{
    proto->source = NULL;
    proto->sizelineinfo = 0;
    proto->sizelocvars = 0;
    proto->sizeupvalues = 0;
    for (int i = 0; i < proto->sizep; ++i) strip_proto(proto->p[i]);
}

static void list_proto(const Proto* proto, int depth)
{
    for (int i = 0; i < proto->sizecode; ++i) {
        Instruction instruction = proto->code[i];
        OpCode opcode = GET_OPCODE(instruction);
        printf("%*s%d\t%s\t%d", depth * 2, "", i + 1,
               luaP_opnames[opcode], GETARG_A(instruction));
        switch (getOpMode(opcode)) {
        case iABC:
            printf(" %d %d", GETARG_B(instruction), GETARG_C(instruction));
            break;
        case iABx:
            printf(" %d", GETARG_Bx(instruction));
            break;
        case iAsBx:
            printf(" %d", GETARG_sBx(instruction));
            break;
        }
        printf("\n");
    }
    for (int i = 0; i < proto->sizep; ++i) list_proto(proto->p[i], depth + 1);
}

// Reused by the lvl command in plan 03; leaves one compiled closure on L's stack.
static int compile_source(lua_State* L, const char* path)
{
    Input input;
    input.file = fopen(path, "rb");
    if (!input.file) {
        fprintf(stderr, "cannot open %s\n", path);
        return 1;
    }
    char* name = static_cast<char*>(malloc(strlen(path) + 2));
    if (!name) { fclose(input.file); return 1; }
    name[0] = '@';
    strcpy(name + 1, path);
    int status = lua_load(L, read_chunk, &input, name);
    free(name);
    if (ferror(input.file)) status = LUA_ERRFILE;
    fclose(input.file);
    if (status) {
        const char* error = lua_tostring(L, -1);
        fprintf(stderr, "%s: %s\n", path, error ? error : "read or compile failed");
        return 1;
    }
    return 0;
}

static int write_string(lua_State*, const void* bytes, size_t size, void* context)
{
    static_cast<std::string*>(context)->append(static_cast<const char*>(bytes), size);
    return 0;
}

int compile_lua_bytes(const std::string& path, std::string& bytes)
{
    lua_State* L = lua_open();
    if (!L) return 1;
    int failed = compile_source(L, path.c_str());
    if (!failed) {
        Proto* proto = clvalue(L->top - 1)->l.p;
        strip_proto(proto);
        proto->source = luaS_new(L, "=(none)");
        if (!lua_dump(L, write_string, &bytes)) failed = 1;
    }
    lua_close(L);
    return failed;
}

int build_lvls(int argc, char** argv);
int stage_gamedata(int argc, char** argv);

int main(int argc, char** argv)
{
    if (argc > 1 && !strcmp(argv[1], "lvl")) return build_lvls(argc - 2, argv + 2);
    if (argc > 1 && !strcmp(argv[1], "stage")) return stage_gamedata(argc - 2, argv + 2);
    bool strip = false;
    bool listing = false;
    const char* output = "luac.out";
    const char* input = NULL;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-s")) strip = true;
        else if (!strcmp(argv[i], "-l")) listing = true;
        else if (!strcmp(argv[i], "-o") && i + 1 < argc) output = argv[++i];
        else if (argv[i][0] != '-' && !input) input = argv[i];
        else { fprintf(stderr, "usage: luac [-s] [-l] [-o output] input.lua\n"); return 2; }
    }
    if (!input) { fprintf(stderr, "usage: luac [-s] [-l] [-o output] input.lua\n"); return 2; }
    lua_State* L = lua_open();
    if (!L) { fprintf(stderr, "lua_open failed\n"); return 1; }
    if (compile_source(L, input)) { lua_close(L); return 1; }
    Proto* proto = clvalue(L->top - 1)->l.p;
    if (listing) list_proto(proto, 0);
    if (strip) {
        strip_proto(proto);
        // The mod-tools luac writes this sentinel for the stripped main Proto.
        proto->source = luaS_new(L, "=(none)");
    }
    FILE* file = fopen(output, "wb");
    if (!file) { fprintf(stderr, "cannot write %s\n", output); lua_close(L); return 1; }
    Output target = {file, false};
    int dumped = lua_dump(L, write_chunk, &target);
    int failed = target.failed || ferror(file) || !dumped;
    if (fclose(file)) failed = 1;
    if (failed) fprintf(stderr, "failed to write bytecode: %s\n", output);
    lua_close(L);
    return failed ? 1 : 0;
}
