#define _WIN32_WINNT 0x0600
#pragma comment(linker, "/SUBSYSTEM:WINDOWS")

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <wchar.h>
#include <string.h>
#include <wintrust.h>
#include <softpub.h>
#include <shlwapi.h>
#include <wincrypt.h>
#include <winver.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "version.lib")

#define SLEEP_MS                10
#define HASH_SIZE               4096
#define MAX_BLACKLIST_ITEMS     300
#define MAX_WHITELIST_ITEMS     300
#define MAX_STR_LEN             512

// ====================== GLOBALS ======================
static wchar_t* blacklist[MAX_BLACKLIST_ITEMS];
static int blacklist_count = 0;

static wchar_t* whitelist[MAX_WHITELIST_ITEMS];
static int whitelist_count = 0;

static DWORD* handled_pids = NULL;
static size_t handled_count = 0;
static size_t handled_capacity = 0;

static DWORD* tainted_pids = NULL;
static size_t tainted_count = 0;
static size_t tainted_capacity = 0;

typedef struct ProcEntry {
    DWORD pid;
    DWORD ppid;
    wchar_t name[MAX_PATH];
    struct ProcEntry* next;
} ProcEntry;

static ProcEntry* hash_table[HASH_SIZE] = { NULL };
static FILE* log_file = NULL;

// ====================== UTILITIES ======================
static inline unsigned hash_func(DWORD pid) {
    return pid & (HASH_SIZE - 1);
}

static void fast_log(const char* fmt, ...) {
    if (!log_file) log_file = fopen("grim_monitor.log", "a");
    if (!log_file) return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(log_file, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);

    va_list args;
    va_start(args, fmt);
    vfprintf(log_file, fmt, args);
    va_end(args);
    fflush(log_file);
}

// ====================== CLEANUP ======================
static void free_lists(void) {
    for (int i = 0; i < blacklist_count; i++) free(blacklist[i]);
    for (int i = 0; i < whitelist_count; i++) free(whitelist[i]);
    blacklist_count = whitelist_count = 0;
}

static void free_previous(ProcEntry* prev[HASH_SIZE]) {
    for (int i = 0; i < HASH_SIZE; i++) {
        ProcEntry* cur = prev[i];
        while (cur) {
            ProcEntry* next = cur->next;
            free(cur);
            cur = next;
        }
        prev[i] = NULL;
    }
}

static void cleanup_all(void) {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
    free_lists();
    free(handled_pids);
    free(tainted_pids);
    // hash_table cleaned separately
}

// ====================== LISTS ======================
static void load_list(const char* filename, wchar_t** list, int* count, int max_items) {
    FILE* f = fopen(filename, "r");
    if (!f) {
        fast_log("Warning: %s not found\n", filename);
        return;
    }
    char line[MAX_STR_LEN];
    while (fgets(line, sizeof(line), f) && *count < max_items) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[--len] = '\0';
        if (len == 0 || line[0] == '#') continue;

        wchar_t* wline = malloc((len + 1) * sizeof(wchar_t));
        if (wline) {
            mbstowcs(wline, line, len + 1);
            list[*count] = wline;
            (*count)++;
        }
    }
    fclose(f);
}

static int matches_list(const wchar_t* text, wchar_t** list, int count) {
    if (!text || !*text) return 0;
    for (int i = 0; i < count; i++) {
        if (StrStrIW(text, list[i]) != NULL) return 1;
    }
    return 0;
}

// ====================== PROCESS CONTROL ======================
static void suspend_process(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te = { sizeof(te) };
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) {
                    SuspendThread(hThread);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

static void kill_process(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (h) {
        TerminateProcess(h, 0);
        CloseHandle(h);
    }
}

static void collect_descendants(DWORD parent, DWORD** out, size_t* count, size_t* cap) {
    for (int i = 0; i < HASH_SIZE; i++) {
        for (ProcEntry* e = hash_table[i]; e; e = e->next) {
            if (e->ppid == parent && e->pid != parent) {
                if (*count >= *cap) {
                    *cap = *cap ? *cap * 2 : 32;
                    *out = (DWORD*)realloc(*out, *cap * sizeof(DWORD));
                }
                (*out)[(*count)++] = e->pid;
                collect_descendants(e->pid, out, count, cap);
            }
        }
    }
}

static void kill_process_tree(DWORD root) {
    DWORD* descendants = NULL;
    size_t count = 0, cap = 0;
    collect_descendants(root, &descendants, &count, &cap);
    for (size_t i = 0; i < count; i++) kill_process(descendants[i]);
    kill_process(root);
    free(descendants);
}

// ====================== METADATA ======================
static wchar_t* get_digital_signer(const wchar_t* path) {
    wchar_t* signer = NULL;
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    DWORD enc, type, fmt;

    if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, path,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY, 0,
        &enc, &type, &fmt, &hStore, &hMsg, NULL) && hStore) {

        PCCERT_CONTEXT pCert = CertFindCertificateInStore(hStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_ANY, NULL, NULL);
        if (pCert) {
            wchar_t name[512] = {0};
            if (CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, name, 512) > 1)
                signer = _wcsdup(name);
            CertFreeCertificateContext(pCert);
        }
        CertCloseStore(hStore, 0);
    }
    if (hMsg) CryptMsgClose(hMsg);
    return signer;
}

static wchar_t* get_version_string(const wchar_t* path, const wchar_t* field) {
    DWORD sz = GetFileVersionInfoSizeW(path, NULL);
    if (!sz) return NULL;
    void* data = malloc(sz);
    if (!data) return NULL;
    if (!GetFileVersionInfoW(path, 0, sz, data)) {
        free(data);
        return NULL;
    }

    wchar_t* ret = NULL;
    struct LANGANDCODEPAGE { WORD lang; WORD cp; } *trans;
    UINT transSize = 0;

    if (VerQueryValueW(data, L"\\VarFileInfo\\Translation", (LPVOID*)&trans, &transSize) && transSize >= sizeof(*trans)) {
        wchar_t sub[256];
        swprintf_s(sub, 256, L"\\StringFileInfo\\%04X%04X\\%ls", trans[0].lang, trans[0].cp, field);
        wchar_t* val = NULL;
        UINT valLen = 0;
        if (VerQueryValueW(data, sub, (LPVOID*)&val, &valLen) && val && valLen > 0) {
            size_t len = wcslen(val) + 1;
            ret = malloc(len * sizeof(wchar_t));
            if (ret) wcscpy_s(ret, len, val);
        }
    }
    free(data);
    return ret;
}

typedef struct {
    wchar_t name[MAX_PATH];
    wchar_t path[MAX_PATH];
    wchar_t company[256];
    wchar_t product[256];
    wchar_t description[256];
    wchar_t comment[256];
    wchar_t signer[256];
} ProcMetadata;

static void get_process_metadata(DWORD pid, ProcMetadata* meta) {
    memset(meta, 0, sizeof(ProcMetadata));
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return;

    DWORD sz = MAX_PATH;
    QueryFullProcessImageNameW(hProc, 0, meta->path, &sz);
    CloseHandle(hProc);

    if (meta->path[0] == L'\0') return;

    wchar_t* tmp;
    tmp = get_version_string(meta->path, L"CompanyName");    if (tmp) { wcsncpy_s(meta->company, 256, tmp, _TRUNCATE); free(tmp); }
    tmp = get_version_string(meta->path, L"ProductName");     if (tmp) { wcsncpy_s(meta->product, 256, tmp, _TRUNCATE); free(tmp); }
    tmp = get_version_string(meta->path, L"FileDescription"); if (tmp) { wcsncpy_s(meta->description, 256, tmp, _TRUNCATE); free(tmp); }
    tmp = get_version_string(meta->path, L"Comments");        if (tmp) { wcsncpy_s(meta->comment, 256, tmp, _TRUNCATE); free(tmp); }
    tmp = get_digital_signer(meta->path);                     if (tmp) { wcsncpy_s(meta->signer, 256, tmp, _TRUNCATE); free(tmp); }
}

static int is_whitelisted(ProcMetadata* meta) {
    if (matches_list(meta->name, whitelist, whitelist_count)) return 1;
    if (matches_list(meta->path, whitelist, whitelist_count)) return 1;
    if (matches_list(meta->company, whitelist, whitelist_count)) return 1;
    if (matches_list(meta->product, whitelist, whitelist_count)) return 1;
    if (matches_list(meta->description, whitelist, whitelist_count)) return 1;
    if (matches_list(meta->comment, whitelist, whitelist_count)) return 1;
    if (matches_list(meta->signer, whitelist, whitelist_count)) return 1;
    return 0;
}

static int matches_blacklist(ProcMetadata* meta) {
    if (matches_list(meta->name, blacklist, blacklist_count)) return 1;
    if (matches_list(meta->path, blacklist, blacklist_count)) return 1;
    if (matches_list(meta->company, blacklist, blacklist_count)) return 1;
    if (matches_list(meta->product, blacklist, blacklist_count)) return 1;
    if (matches_list(meta->description, blacklist, blacklist_count)) return 1;
    if (matches_list(meta->comment, blacklist, blacklist_count)) return 1;
    if (matches_list(meta->signer, blacklist, blacklist_count)) return 1;
    return 0;
}

// ====================== HANDLED / TAINTED ======================
static int is_handled(DWORD pid) {
    for (size_t i = 0; i < handled_count; i++)
        if (handled_pids[i] == pid) return 1;
    return 0;
}

static void add_handled(DWORD pid) {
    if (is_handled(pid)) return;
    if (handled_count >= handled_capacity) {
        handled_capacity = handled_capacity ? handled_capacity * 2 : 128;
        handled_pids = (DWORD*)realloc(handled_pids, handled_capacity * sizeof(DWORD));
    }
    handled_pids[handled_count++] = pid;
}

static int is_tainted(DWORD pid) {
    for (size_t i = 0; i < tainted_count; i++)
        if (tainted_pids[i] == pid) return 1;
    return 0;
}

static void add_tainted(DWORD pid) {
    if (is_tainted(pid)) return;
    if (tainted_count >= tainted_capacity) {
        tainted_capacity = tainted_capacity ? tainted_capacity * 2 : 64;
        tainted_pids = (DWORD*)realloc(tainted_pids, tainted_capacity * sizeof(DWORD));
    }
    tainted_pids[tainted_count++] = pid;
}

static ProcEntry* find_proc(DWORD pid) {
    unsigned idx = hash_func(pid);
    for (ProcEntry* e = hash_table[idx]; e; e = e->next)
        if (e->pid == pid) return e;
    return NULL;
}

static int has_tainted_ancestor(DWORD pid) {
    DWORD cur = pid;
    while (cur != 0) {
        if (is_tainted(cur)) return 1;
        ProcEntry* e = find_proc(cur);
        if (!e) break;
        cur = e->ppid;
    }
    return 0;
}

// ====================== HASH TABLE ======================
static void clear_hash_table(void) {
    for (int i = 0; i < HASH_SIZE; i++) {
        ProcEntry* cur = hash_table[i];
        while (cur) {
            ProcEntry* next = cur->next;
            free(cur);
            cur = next;
        }
        hash_table[i] = NULL;
    }
}

static void build_hash_from_snapshot(HANDLE snap) {
    clear_hash_table();
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (!Process32FirstW(snap, &pe)) return;
    do {
        unsigned idx = hash_func(pe.th32ProcessID);
        ProcEntry* e = malloc(sizeof(ProcEntry));
        if (e) {
            e->pid = pe.th32ProcessID;
            e->ppid = pe.th32ParentProcessID;
            wcsncpy_s(e->name, MAX_PATH, pe.szExeFile, _TRUNCATE);
            e->next = hash_table[idx];
            hash_table[idx] = e;
        }
    } while (Process32NextW(snap, &pe));
}

// ====================== CTRL HANDLER ======================
static BOOL WINAPI CtrlHandler(DWORD ctrlType) {
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_CLOSE_EVENT) {
        fast_log("Shutdown received. Cleaning up...\n");
        cleanup_all();
        exit(0);
    }
    return FALSE;
}

// ====================== MAIN ======================
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmdLine, int show) {
    FreeConsole();
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    load_list("blacklist.txt", blacklist, &blacklist_count, MAX_BLACKLIST_ITEMS);
    load_list("whitelist.txt", whitelist, &whitelist_count, MAX_WHITELIST_ITEMS);

    fast_log("=== Grim AV Install Killer (10ms ULTRA MODE) ===\n");
    fast_log("Blacklist: %d | Whitelist: %d\n", blacklist_count, whitelist_count);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        build_hash_from_snapshot(snap);
        CloseHandle(snap);
    }

    ProcEntry* previous[HASH_SIZE] = { NULL };

    while (1) {
        Sleep(SLEEP_MS);

        snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) continue;

        build_hash_from_snapshot(snap);
        CloseHandle(snap);

        for (int i = 0; i < HASH_SIZE; i++) {
            for (ProcEntry* cur = hash_table[i]; cur; cur = cur->next) {
                DWORD pid = cur->pid;
                if (is_handled(pid)) continue;

                int is_new = 1;
                unsigned pidx = hash_func(pid);
                for (ProcEntry* p = previous[pidx]; p; p = p->next) {
                    if (p->pid == pid) { is_new = 0; break; }
                }
                if (!is_new) continue;

                ProcMetadata meta;
                wcsncpy_s(meta.name, MAX_PATH, cur->name, _TRUNCATE);
                get_process_metadata(pid, &meta);

                if (is_whitelisted(&meta)) {
                    add_handled(pid);
                    continue;
                }

                if (matches_blacklist(&meta)) {
                    fast_log("BLACKLIST HIT → %ls (PID: %lu)\n", cur->name, pid);
                    add_tainted(pid);
                    suspend_process(pid);
                    kill_process_tree(pid);
                    add_handled(pid);
                }
                else if (has_tainted_ancestor(pid)) {
                    fast_log("CHILD OF TAINTED → %ls (PID: %lu)\n", cur->name, pid);
                    suspend_process(pid);
                    kill_process_tree(pid);
                    add_handled(pid);
                }
            }
        }

        // Clean up previous snapshot
        free_previous(previous);

        // Copy current snapshot to previous
        for (int i = 0; i < HASH_SIZE; i++) {
            for (ProcEntry* e = hash_table[i]; e; e = e->next) {
                ProcEntry* copy = malloc(sizeof(ProcEntry));
                if (copy) {
                    copy->pid = e->pid;
                    copy->ppid = e->ppid;
                    wcsncpy_s(copy->name, MAX_PATH, e->name, _TRUNCATE);
                    copy->next = previous[i];
                    previous[i] = copy;
                }
            }
        }
    }

    cleanup_all();
    return 0;
}
