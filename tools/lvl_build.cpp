#include <windows.h>
#include <winioctl.h>
#include <wincrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <ctype.h>
#include <algorithm>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")

int compile_lua_bytes(const std::string&, std::string&);

static void fail(const std::string& message) { throw std::runtime_error(message); }

static std::string read_file(const std::string& path)
{
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) fail("cannot read " + path);
    if (fseek(f, 0, SEEK_END)) { fclose(f); fail("cannot seek " + path); }
    long size = ftell(f);
    if (size < 0 || fseek(f, 0, SEEK_SET)) { fclose(f); fail("cannot size " + path); }
    std::string data(static_cast<size_t>(size), '\0');
    if (size && fread(&data[0], 1, size, f) != static_cast<size_t>(size)) {
        fclose(f); fail("cannot read all of " + path);
    }
    fclose(f);
    return data;
}

static std::string sha256(const std::string& bytes)
{
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    BYTE digest[32];
    DWORD length = sizeof(digest);
    if (!CryptAcquireContextA(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
        !CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash) ||
        !CryptHashData(hash, reinterpret_cast<const BYTE*>(bytes.data()),
                       static_cast<DWORD>(bytes.size()), 0) ||
        !CryptGetHashParam(hash, HP_HASHVAL, digest, &length, 0)) {
        if (hash) CryptDestroyHash(hash);
        if (provider) CryptReleaseContext(provider, 0);
        fail("SHA-256 failed");
    }
    CryptDestroyHash(hash);
    CryptReleaseContext(provider, 0);
    static const char hex[] = "0123456789abcdef";
    std::string result;
    for (DWORD i = 0; i < length; ++i) {
        result += hex[digest[i] >> 4];
        result += hex[digest[i] & 15];
    }
    return result;
}

static uint32_t word(const std::string& data, size_t at)
{
    if (at > data.size() || data.size() - at < 4) fail("truncated chunk size");
    const unsigned char* p = reinterpret_cast<const unsigned char*>(data.data() + at);
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}

static void put_word(std::string& data, uint32_t size)
{
    for (int i = 0; i < 4; ++i) data += char(size >> (i * 8));
}

struct Node {
    std::string tag;
    size_t start, payload, finish, next;
    std::vector<Node> children;
};

static Node parse(const std::string& data, size_t at, size_t parent_end)
{
    if (at > parent_end || parent_end - at < 8) fail("truncated chunk header");
    Node node;
    node.tag = data.substr(at, 4);
    node.start = at;
    node.payload = at + 8;
    uint32_t size = word(data, at + 4);
    if (size > parent_end - node.payload) fail("chunk ends past parent");
    node.finish = node.payload + size;
    size_t aligned = (node.finish + 3) & ~size_t(3);
    node.next = aligned <= parent_end ? aligned : node.finish;
    if (node.next != aligned && node.finish != parent_end) fail("padding past parent");
    if (node.tag == "ucfb" || node.tag == "lvl_" || node.tag == "scr_") {
        for (size_t pos = node.payload; pos < node.finish;) {
            Node child = parse(data, pos, node.finish);
            pos = child.next;
            node.children.push_back(child);
        }
        if (!node.children.empty() && node.children.back().next != node.finish)
            fail("child alignment exceeds parent");
    }
    return node;
}

struct Entry { std::string lvl, name, source; };

// The index is generated JSON with flat script objects. Reject malformed records.
static void space(const std::string& data, size_t& p)
{
    while (p < data.size() && (data[p] == ' ' || data[p] == '\n' || data[p] == '\r' || data[p] == '\t')) ++p;
}

static std::string json_string(const std::string& data, size_t& p)
{
    space(data, p);
    if (p == data.size() || data[p++] != '"') fail("expected JSON string");
    std::string out;
    while (p < data.size()) {
        char c = data[p++];
        if (c == '"') return out;
        if (c == '\\') {
            if (p == data.size()) fail("truncated JSON escape");
            c = data[p++];
            if (c == 'n') c = '\n';
            else if (c == 'r') c = '\r';
            else if (c == 't') c = '\t';
            else if (c != '"' && c != '\\' && c != '/') fail("unsupported JSON escape");
        }
        out += c;
    }
    fail("unterminated JSON string");
    return out;
}

static std::vector<Entry> read_index(const std::string& path)
{
    std::string data = read_file(path);
    size_t p = data.find("\"scripts\"");
    if (p == std::string::npos || (p = data.find('[', p)) == std::string::npos)
        fail("index lacks scripts array");
    ++p;
    std::vector<Entry> entries;
    std::set<std::string> keys;
    for (;;) {
        space(data, p);
        if (p >= data.size()) fail("unterminated scripts array");
        if (data[p] == ']') break;
        if (data[p++] != '{') fail("expected script object");
        std::map<std::string, std::string> fields;
        for (;;) {
            std::string key = json_string(data, p);
            space(data, p);
            if (p == data.size() || data[p++] != ':') fail("expected JSON colon");
            fields[key] = json_string(data, p);
            space(data, p);
            if (p == data.size()) fail("unterminated script object");
            char separator = data[p++];
            if (separator == '}') break;
            if (separator != ',') fail("expected JSON comma");
        }
        Entry e = {fields["lvl"], fields["name"], fields["source"]};
        if (e.lvl.empty() || e.name.empty() || !keys.insert(e.lvl + ":" + e.name).second)
            fail("duplicate or incomplete index name");
        entries.push_back(e);
        space(data, p);
        if (p == data.size()) fail("unterminated scripts array");
        char separator = data[p++];
        if (separator == ']') break;
        if (separator != ',') fail("expected scripts comma");
    }
    return entries;
}

static std::string emit(const Node& node, const std::string& input,
                        const std::map<std::string, std::string>& bodies,
                        const std::set<std::string>& expected,
                        std::set<std::string>& seen, const std::string& lvl, bool& changed)
{
    if (node.tag == "BODY") {
        std::map<std::string, std::string>::const_iterator it = bodies.find(lvl);
        if (it != bodies.end()) {
            const std::string old_body = input.substr(node.payload, node.finish - node.payload);
            if (old_body != it->second) {
                changed = true;
                std::string result = "BODY";
                put_word(result, static_cast<uint32_t>(it->second.size()));
                result += it->second;
                result.append((4 - result.size() % 4) % 4, '\0');
                return result;
            }
        }
    }
    if (node.children.empty()) return input.substr(node.start, node.next - node.start);
    std::string name = lvl;
    if (node.tag == "scr_") {
        int names = 0, body_count = 0;
        for (size_t i = 0; i < node.children.size(); ++i) {
            const Node& child = node.children[i];
            if (child.tag == "NAME") {
                ++names;
                std::string raw = input.substr(child.payload, child.finish - child.payload);
                name = raw.substr(0, raw.find('\0'));
            }
            if (child.tag == "BODY") ++body_count;
        }
        if (names != 1 || body_count != 1) fail("scr_ needs exactly one NAME and BODY");
        if (!seen.insert(name).second) fail("duplicate script name " + name);
        if (expected.find(name) == expected.end()) fail("unindexed script " + name);
    }
    std::string payload;
    bool child_changed = false;
    for (size_t i = 0; i < node.children.size(); ++i) {
        bool one_changed = false;
        payload += emit(node.children[i], input, bodies, expected, seen, name, one_changed);
        child_changed |= one_changed;
    }
    if (!child_changed) return input.substr(node.start, node.next - node.start);
    changed = true;
    std::string result = node.tag;
    if (payload.size() > UINT32_MAX) fail("chunk exceeds 32-bit size");
    put_word(result, static_cast<uint32_t>(payload.size()));
    result += payload;
    result.append((4 - result.size() % 4) % 4, '\0');
    return result;
}

static void ensure_dir(const std::string& path)
{
    for (size_t p = 1; p < path.size(); ++p)
        if (path[p] == '/' || path[p] == '\\') CreateDirectoryA(path.substr(0, p).c_str(), NULL);
    if (!CreateDirectoryA(path.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
        fail("cannot create directory " + path);
}

static void atomic_write(const std::string& path, const std::string& bytes)
{
    std::string temp = path + ".tmp";
    FILE* f = fopen(temp.c_str(), "wb");
    if (!f) fail("cannot write " + temp);
    bool failed = fwrite(bytes.data(), 1, bytes.size(), f) != bytes.size();
    if (fclose(f)) failed = true;
    if (failed || !MoveFileExA(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        fail("atomic write failed for " + path);
}

static std::string lower(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), ::tolower);
    return value;
}

static std::string absolute_path(const std::string& path)
{
    char buffer[32768];
    DWORD size = GetFullPathNameA(path.c_str(), sizeof(buffer), buffer, NULL);
    if (!size || size >= sizeof(buffer)) fail("invalid path " + path);
    return lower(std::string(buffer, size));
}

int build_lvls(int argc, char** argv)
{
    try {
        std::string index = "data/scripts/index.json", out_dir, game_data;
        std::map<std::string, std::string> inputs;
        bool mismatch = false, incomplete = false;
        for (int i = 0; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--index" && i + 1 < argc) index = argv[++i];
            else if (arg == "--input" && i + 1 < argc) {
                std::string pair = argv[++i];
                size_t eq = pair.find('=');
                if (eq == std::string::npos || !inputs.insert(std::make_pair(pair.substr(0, eq), pair.substr(eq + 1))).second)
                    fail("invalid or duplicate --input");
            }
            else if (arg == "--out-dir" && i + 1 < argc) out_dir = argv[++i];
            else if (arg == "--gamedata" && i + 1 < argc) game_data = argv[++i];
            else if (arg == "--allow-input-hash-mismatch") mismatch = true;
            else if (arg == "--allow-incomplete") incomplete = true;
            else fail("usage: luac lvl --index file --input lvl=path [--input ...] --out-dir dir [--allow-incomplete] [--allow-input-hash-mismatch]");
        }
        if (out_dir.empty() || (!game_data.empty() && !inputs.empty())) fail("specify --out-dir and either --input or --gamedata");
        if (!game_data.empty()) {
            const char* lvls[] = {"shell", "common", "ingame", "mission"};
            for (int i = 0; i < 4; ++i) {
                std::string base = game_data + "/data/_lvl_pc/" + lvls[i] + ".lvl";
                std::string original = base + ".orig";
                inputs[lvls[i]] = GetFileAttributesA(original.c_str()) != INVALID_FILE_ATTRIBUTES ? original : base;
            }
        }
        if (inputs.empty()) fail("no lvl inputs specified");
        std::string output_absolute = absolute_path(out_dir);
        for (std::map<std::string, std::string>::const_iterator input = inputs.begin(); input != inputs.end(); ++input) {
            std::string input_absolute = absolute_path(input->second);
            if (output_absolute == input_absolute ||
                (input_absolute.size() > output_absolute.size() &&
                 input_absolute.compare(0, output_absolute.size(), output_absolute) == 0 &&
                 (input_absolute[output_absolute.size()] == '/' || input_absolute[output_absolute.size()] == '\\')))
                fail("output directory contains retail input " + input->second);
            size_t game = input_absolute.find("\\gamedata\\");
            if (game != std::string::npos) {
                std::string retail_root = input_absolute.substr(0, game + 10);
                if (output_absolute.compare(0, retail_root.size(), retail_root) == 0)
                    fail("output directory must be outside retail GameData");
            }
        }
        std::vector<Entry> entries = read_index(index);
        if (absolute_path(index) == absolute_path("data/scripts/index.json")) {
            const char* pending_names[] = {
                "shell:shell_interface", "shell:ifs_sp_campaign", "shell:ifs_trailer",
                "shell:ifs_mp_sessionlist", "shell:ifs_mp_leaderboard",
                "shell:ifs_missionselect_pcmulti", "shell:ifs_mpgs_galaxylogin",
                "common:ifs_opt_mp", "common:ifs_mp_lobby", "common:ifs_mpgs_friends"
            };
            std::set<std::string> declared(pending_names, pending_names + 10), actual;
            for (size_t i = 0; i < entries.size(); ++i)
                if (entries[i].source.empty()) actual.insert(entries[i].lvl + ":" + entries[i].name);
            bool unexpected_pending = false;
            for (std::set<std::string>::const_iterator it = actual.begin(); it != actual.end(); ++it)
                if (declared.find(*it) == declared.end()) unexpected_pending = true;
            if (entries.size() != 167 || unexpected_pending)
                fail("canonical index must contain 167 records and no undeclared pending names");
        }
        const std::map<std::string, std::string> known = {
            {"shell", "82335ab55e17689cd620ba174568e6a5481d4523b821549aa153a6b88a831009"},
            {"common", "60dfca80aaa21a01744eeddd4e2f71a5e732b492b5def9decca78e4b4afe9a58"},
            {"ingame", "cc78b5dfd6f4a082cb5a5da8cdfd67de5d45a092e25f57c47ad55c41499182dc"},
            {"mission", "f1000a76ec8d642b5e531833a6d53b9b5f37dbc0a3bbb4bfe605710fc66da10b"}
        };
        ensure_dir(out_dir);
        for (std::map<std::string, std::string>::const_iterator input = inputs.begin(); input != inputs.end(); ++input) {
            std::string lvl = input->first;
            if (known.find(lvl) == known.end()) fail("unknown lvl " + lvl);
            std::string original = read_file(input->second);
            std::string original_hash = sha256(original);
            if (!mismatch && original_hash != known.find(lvl)->second) fail("unknown input SHA-256 for " + lvl + ": " + original_hash);
            Node root = parse(original, 0, original.size());
            if (root.tag != "ucfb" || root.next != original.size()) fail("invalid root ucfb");
            std::map<std::string, std::string> bodies;
            std::set<std::string> expected;
            char module[MAX_PATH];
            if (!GetModuleFileNameA(NULL, module, sizeof(module))) fail("cannot identify host executable");
            std::string digest_material = original_hash + sha256(read_file(index)) + sha256(read_file(module));
            int pending = 0;
            for (size_t i = 0; i < entries.size(); ++i) if (entries[i].lvl == lvl) {
                const Entry& e = entries[i];
                expected.insert(e.name);
                if (e.source.empty()) {
                    if (!incomplete) fail("pending source " + lvl + ":" + e.name + " requires --allow-incomplete");
                    ++pending;
                    continue;
                }
                std::string source = read_file(e.source);
                digest_material += sha256(source);
            }
            std::string output_path = out_dir + "/" + lvl + ".lvl";
            std::string cache_path = output_path + ".cache";
            std::string digest = sha256(digest_material);
            if (GetFileAttributesA(output_path.c_str()) != INVALID_FILE_ATTRIBUTES &&
                GetFileAttributesA(cache_path.c_str()) != INVALID_FILE_ATTRIBUTES &&
                read_file(cache_path) == digest + "\n" + sha256(read_file(output_path))) {
                printf("%s: cached%s\n", lvl.c_str(), pending ? " (incomplete)" : "");
                continue;
            }
            for (size_t i = 0; i < entries.size(); ++i) if (entries[i].lvl == lvl && !entries[i].source.empty()) {
                std::string compiled;
                if (compile_lua_bytes(entries[i].source, compiled)) fail("compile failed for " + entries[i].source);
                if (compiled.empty()) fail("compiler returned empty bytecode");
                compiled += '\0';
                bodies[entries[i].name] = compiled;
            }
            std::set<std::string> seen;
            bool changed = false;
            std::string output = emit(root, original, bodies, expected, seen, "", changed);
            if (seen != expected) fail("script inventory differs from index for " + lvl);
            if (pending) printf("%s: incomplete mode, %d pending BODY passthroughs\n", lvl.c_str(), pending);
            Node check = parse(output, 0, output.size());
            if (check.tag != "ucfb" || check.next != output.size()) fail("rebuilt root invalid");
            std::set<std::string> output_names;
            bool ignored = false;
            emit(check, output, std::map<std::string, std::string>(), expected,
                 output_names, "", ignored);
            if (output_names != expected) fail("output inventory differs from index for " + lvl);
            atomic_write(output_path, output);
            atomic_write(cache_path, digest + "\n" + sha256(output));
            printf("%s: wrote %s SHA-256 %s\n", lvl.c_str(), output_path.c_str(), sha256(output).c_str());
        }
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "lvl: %s\n", e.what());
        return 1;
    }
}

// The exported build stages only into its own output tree. Directory links are
// checked against their resolved retail target before they are reused or removed.
static std::string final_directory(const std::string& path)
{
    HANDLE h = CreateFileA(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (h == INVALID_HANDLE_VALUE) fail("cannot resolve directory " + path);
    char resolved[32768];
    DWORD size = GetFinalPathNameByHandleA(h, resolved, sizeof(resolved), FILE_NAME_NORMALIZED);
    CloseHandle(h);
    if (!size || size >= sizeof(resolved)) fail("cannot resolve directory " + path);
    std::string result(resolved, size);
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    while (!result.empty() && (result[result.size() - 1] == '\\' || result[result.size() - 1] == '/'))
        result.resize(result.size() - 1);
    return result;
}

static bool junction(const std::string& path)
{
    WIN32_FIND_DATAA found;
    HANDLE h = FindFirstFileA(path.c_str(), &found);
    if (h == INVALID_HANDLE_VALUE) fail("cannot inspect " + path);
    FindClose(h);
    return (found.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
           found.dwReserved0 == IO_REPARSE_TAG_MOUNT_POINT;
}

static bool exists(const std::string& path)
{
    return GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

static void real_directory(const std::string& path)
{
    if (!exists(path) && !CreateDirectoryA(path.c_str(), NULL)) fail("cannot create " + path);
    DWORD attr = GetFileAttributesA(path.c_str());
    if (!(attr & FILE_ATTRIBUTE_DIRECTORY) || (attr & FILE_ATTRIBUTE_REPARSE_POINT))
        fail("expected real directory " + path);
}

static void stage_junction(const std::string& link, const std::string& target)
{
    if (exists(link)) {
        if (!junction(link) || final_directory(link) != final_directory(target))
            fail("existing entry is not a junction to retail: " + link);
        return;
    }
    // cmd's mklink is the Windows junction creator; reject shell metacharacters.
    if (link.find_first_of("\"&|<>^%!") != std::string::npos ||
        target.find_first_of("\"&|<>^%!") != std::string::npos)
        fail("unsupported character in junction path");
    std::string command = "cmd /d /c mklink /J \"" + link + "\" \"" + target + "\" >nul";
    if (system(command.c_str()) || !junction(link) ||
        final_directory(link) != final_directory(target))
        fail("cannot create junction " + link);
}

static void stage_copy(const std::string& source, const std::string& destination)
{
    if (exists(destination)) {
        DWORD attr = GetFileAttributesA(destination.c_str());
        if (attr & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
            fail("expected real file " + destination);
        WIN32_FILE_ATTRIBUTE_DATA a, b;
        if (!GetFileAttributesExA(source.c_str(), GetFileExInfoStandard, &a) ||
            !GetFileAttributesExA(destination.c_str(), GetFileExInfoStandard, &b))
            fail("cannot inspect file " + destination);
        if (a.nFileSizeHigh == b.nFileSizeHigh && a.nFileSizeLow == b.nFileSizeLow &&
            CompareFileTime(&a.ftLastWriteTime, &b.ftLastWriteTime) == 0) return;
    }
    if (!CopyFileA(source.c_str(), destination.c_str(), FALSE)) fail("cannot copy " + source);
}

static void stage_entries(const std::string& source, const std::string& destination, bool lvl)
{
    WIN32_FIND_DATAA found;
    HANDLE h = FindFirstFileA((source + "\\*").c_str(), &found);
    if (h == INVALID_HANDLE_VALUE) fail("cannot list " + source);
    do {
        std::string name = found.cFileName;
        if (name == "." || name == ".." || (lvl && name == "vidmode.ini")) continue;
        if (!lvl && name == "_lvl_pc") continue;
        if (lvl && (name == "shell.lvl" || name == "common.lvl" ||
                    name == "ingame.lvl" || name == "mission.lvl" ||
                    name == "mission.lvl.orig")) continue;
        std::string from = source + "\\" + name, to = destination + "\\" + name;
        if (found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) stage_junction(to, from);
        else if (lvl) stage_copy(from, to);
        else fail("top-level retail data file cannot be junctioned: " + from);
    } while (FindNextFileA(h, &found));
    DWORD error = GetLastError();
    FindClose(h);
    if (error != ERROR_NO_MORE_FILES) fail("cannot finish listing " + source);
}

int stage_gamedata(int argc, char** argv)
{
    try {
        std::string retail, output;
        for (int i = 0; i < argc; ++i) {
            if (!strcmp(argv[i], "--retail") && i + 1 < argc) retail = argv[++i];
            else if (!strcmp(argv[i], "--out") && i + 1 < argc) output = argv[++i];
            else fail("usage: LuaCompiler stage --retail GameData --out output");
        }
        if (retail.empty() || output.empty()) fail("retail and output are required");
        // MSBuild has already created OutDir for the tool executable. Requiring
        // it to exist avoids creating a directory under retail before the guard.
        if (!exists(output)) fail("output directory must already exist");
        real_directory(output);
        std::string retail_final = final_directory(retail), out_final = final_directory(output);
        if (out_final == retail_final ||
            (out_final.size() > retail_final.size() &&
             out_final.compare(0, retail_final.size(), retail_final) == 0 &&
             out_final[retail_final.size()] == '\\'))
            fail("output must be outside retail GameData");
        std::string retail_data = retail + "\\data", data = output + "\\data";
        if (exists(data) && junction(data)) {
            if (final_directory(data) != final_directory(retail_data))
                fail("old data junction points elsewhere");
            if (!RemoveDirectoryA(data.c_str())) fail("cannot remove old data junction");
        }
        real_directory(data);
        std::string lvl_source = retail_data + "\\_lvl_pc", lvl_out = data + "\\_lvl_pc";
        real_directory(lvl_out);
        stage_entries(lvl_source, lvl_out, true);
        stage_entries(retail_data, data, false);
        printf("staged GameData at %s\n", output.c_str());
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "stage: %s\n", e.what());
        return 1;
    }
}
