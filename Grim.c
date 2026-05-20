#define _WIN32_WINNT 0x0600
#pragma comment(linker, "/SUBSYSTEM:WINDOWS")
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <string.h>

#define SLEEP_MS 20
#define HASH_SIZE 4096
#define MAX_BLACKLIST_ITEMS 100
#define MAX_WHITELIST_ITEMS 100
#define MAX_STR_LEN 256
#define CLEANUP_INTERVAL_MS 300000

wchar_t* blacklist[MAX_BLACKLIST_ITEMS];
int blacklist_count = 0;

wchar_t* whitelist[MAX_WHITELIST_ITEMS];
int whitelist_count = 0;

DWORD* handled_pids = NULL;
size_t handled_count = 0;
size_t handled_capacity = 0;

DWORD* tainted_pids = NULL;
size_t tainted_count = 0;
size_t tainted_capacity = 0;

typedef struct ProcEntry {
    DWORD pid;
    DWORD ppid;
    wchar_t name[MAX_PATH];
    struct ProcEntry* next;
} ProcEntry;

static ProcEntry* hash_table[HASH_SIZE] = { NULL };

static inline unsigned hash(DWORD pid) {
    return pid & (HASH_SIZE - 1);
}

void insert_proc(DWORD pid, DWORD ppid, const wchar_t* name) {
    unsigned idx = hash(pid);
    ProcEntry* e = (ProcEntry*)malloc(sizeof(ProcEntry));
    if (!e) return;
    e->pid = pid;
    e->ppid = ppid;
    wcsncpy_s(e->name, MAX_PATH, name, _TRUNCATE);
    e->next = hash_table[idx];
    hash_table[idx] = e;
}

ProcEntry* find_proc(DWORD pid) {
    unsigned idx = hash(pid);
    ProcEntry* cur = hash_table[idx];
    while (cur) {
        if (cur->pid == pid) return cur;
        cur = cur->next;
    }
    return NULL;
}

void clear_hash_table(void) {
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

void build_hash_from_snapshot(HANDLE snap) {
    clear_hash_table();
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap, &pe)) return;
    do {
        insert_proc(pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile);
    } while (Process32NextW(snap, &pe));
}

void load_list(const char* filename, wchar_t** list, int* count, int max_items) {
    FILE* f = fopen(filename, "r");
    if (!f) return;
    char line[MAX_STR_LEN];
    while (fgets(line, sizeof(line), f) && *count < max_items) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[--len] = '\0';
        if (len == 0) continue;
        wchar_t* wline = malloc((len+1) * sizeof(wchar_t));
        if (wline) {
            mbstowcs(wline, line, len+1);
            list[*count] = wline;
            (*count)++;
        }
    }
    fclose(f);
}

void free_lists(void) {
    for (int i = 0; i < blacklist_count; i++) free(blacklist[i]);
    for (int i = 0; i < whitelist_count; i++) free(whitelist[i]);
}

int matches_list(const wchar_t* text, wchar_t** list, int list_count) {
    if (!text || !*text) return 0;
    for (int i = 0; i < list_count; i++) {
        if (wcsstr(text, list[i]) != NULL) return 1;
    }
    return 0;
}

void cleanup_stale_arrays(void) {
    size_t new_count = 0;
    for (size_t i = 0; i < handled_count; i++) {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, handled_pids[i]);
        if (h) {
            CloseHandle(h);
            handled_pids[new_count++] = handled_pids[i];
        }
    }
    handled_count = new_count;

    new_count = 0;
    for (size_t i = 0; i < tainted_count; i++) {
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, tainted_pids[i]);
        if (h) {
            CloseHandle(h);
            tainted_pids[new_count++] = tainted_pids[i];
        }
    }
    tainted_count = new_count;
}

void suspend_process_native(DWORD pid) {
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(hThreadSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) {
                    SuspendThread(hThread);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hThreadSnap, &te));
    }
    CloseHandle(hThreadSnap);
}

void kill_process_native(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess) {
        TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
    }
}

static void collect_descendants(DWORD parent, DWORD** descendants, size_t* count, size_t* cap) {
    for (int i = 0; i < HASH_SIZE; i++) {
        for (ProcEntry* e = hash_table[i]; e; e = e->next) {
            if (e->ppid == parent && e->pid != parent) {
                if (*count >= *cap) {
                    *cap = *cap ? *cap * 2 : 16;
                    *descendants = (DWORD*)realloc(*descendants, *cap * sizeof(DWORD));
                }
                (*descendants)[(*count)++] = e->pid;
                collect_descendants(e->pid, descendants, count, cap);
            }
        }
    }
}

void kill_process_tree_native(DWORD root_pid) {
    DWORD* descendants = NULL;
    size_t desc_count = 0;
    size_t desc_cap = 0;
    collect_descendants(root_pid, &descendants, &desc_count, &desc_cap);
    for (size_t i = 0; i < desc_count; i++) {
        kill_process_native(descendants[i]);
    }
    kill_process_native(root_pid);
    free(descendants);
}

wchar_t* get_file_version_string(const wchar_t* file_path, const wchar_t* field) {
    DWORD ver_size = GetFileVersionInfoSizeW(file_path, NULL);
    if (ver_size == 0) return NULL;
    void* ver_data = malloc(ver_size);
    if (!ver_data) return NULL;
    if (!GetFileVersionInfoW(file_path, 0, ver_size, ver_data)) {
        free(ver_data);
        return NULL;
    }
    wchar_t* ret = NULL;
    struct LANGANDCODEPAGE { WORD wLanguage; WORD wCodePage; } *lpTranslate;
    UINT cbTranslate = 0;
    if (VerQueryValueW(ver_data, L"\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate)) {
        if (cbTranslate >= sizeof(struct LANGANDCODEPAGE)) {
            wchar_t subblock[256];
            swprintf_s(subblock, sizeof(subblock)/sizeof(wchar_t),
                       L"\\StringFileInfo\\%04X%04X\\%ls",
                       lpTranslate[0].wLanguage, lpTranslate[0].wCodePage, field);
            wchar_t* val = NULL;
            UINT val_len = 0;
            if (VerQueryValueW(ver_data, subblock, (LPVOID*)&val, &val_len)) {
                if (val && val_len > 0) {
                    size_t len = wcslen(val) + 1;
                    ret = (wchar_t*)malloc(len * sizeof(wchar_t));
                    if (ret) wcscpy_s(ret, len, val);
                }
            }
        }
    }
    free(ver_data);
    return ret;
}

typedef struct {
    wchar_t name[MAX_PATH];
    wchar_t path[MAX_PATH];
    wchar_t company[256];
    wchar_t product[256];
    wchar_t description[256];
} ProcMetadata;

void get_process_metadata(DWORD pid, ProcMetadata* meta) {
    meta->path[0] = L'\0';
    meta->company[0] = L'\0';
    meta->product[0] = L'\0';
    meta->description[0] = L'\0';
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h) {
        DWORD sz = MAX_PATH;
        QueryFullProcessImageNameW(h, 0, meta->path, &sz);
        CloseHandle(h);
    }
    if (meta->path[0] == L'\0') return;
    wchar_t* tmp = get_file_version_string(meta->path, L"CompanyName");
    if (tmp) { wcsncpy_s(meta->company, 256, tmp, _TRUNCATE); free(tmp); }
    tmp = get_file_version_string(meta->path, L"ProductName");
    if (tmp) { wcsncpy_s(meta->product, 256, tmp, _TRUNCATE); free(tmp); }
    tmp = get_file_version_string(meta->path, L"FileDescription");
    if (tmp) { wcsncpy_s(meta->description, 256, tmp, _TRUNCATE); free(tmp); }
}

int is_handled(DWORD pid) {
    for (size_t i = 0; i < handled_count; i++)
        if (handled_pids[i] == pid) return 1;
    return 0;
}

void add_handled(DWORD pid) {
    if (is_handled(pid)) return;
    if (handled_count >= handled_capacity) {
        handled_capacity = handled_capacity ? handled_capacity * 2 : 64;
        handled_pids = (DWORD*)realloc(handled_pids, handled_capacity * sizeof(DWORD));
    }
    handled_pids[handled_count++] = pid;
}

void add_tainted(DWORD pid) {
    for (size_t i = 0; i < tainted_count; i++)
        if (tainted_pids[i] == pid) return;
    if (tainted_count >= tainted_capacity) {
        tainted_capacity = tainted_capacity ? tainted_capacity * 2 : 64;
        tainted_pids = (DWORD*)realloc(tainted_pids, tainted_capacity * sizeof(DWORD));
    }
    tainted_pids[tainted_count++] = pid;
}

int is_tainted(DWORD pid) {
    for (size_t i = 0; i < tainted_count; i++)
        if (tainted_pids[i] == pid) return 1;
    return 0;
}

int has_tainted_ancestor(DWORD pid) {
    DWORD cur = pid;
    while (cur != 0) {
        if (is_tainted(cur)) return 1;
        ProcEntry* e = find_proc(cur);
        if (!e) break;
        cur = e->ppid;
    }
    return 0;
}

int is_whitelisted(ProcMetadata* meta) {
    if (matches_list(meta->name, whitelist, whitelist_count)) return 1;
    if (matches_list(meta->path, whitelist, whitelist_count)) return 1;
    if (matches_list(meta->company, whitelist, whitelist_count)) return 1;
    if (matches_list(meta->product, whitelist, whitelist_count)) return 1;
    if (matches_list(meta->description, whitelist, whitelist_count)) return 1;
    return 0;
}

int matches_blacklist(ProcMetadata* meta) {
    if (matches_list(meta->name, blacklist, blacklist_count)) return 1;
    if (matches_list(meta->path, blacklist, blacklist_count)) return 1;
    if (matches_list(meta->company, blacklist, blacklist_count)) return 1;
    if (matches_list(meta->product, blacklist, blacklist_count)) return 1;
    if (matches_list(meta->description, blacklist, blacklist_count)) return 1;
    return 0;
}

ProcEntry* copy_proc_entry(const ProcEntry* src) {
    ProcEntry* dst = (ProcEntry*)malloc(sizeof(ProcEntry));
    if (!dst) return NULL;
    dst->pid = src->pid;
    dst->ppid = src->ppid;
    wcsncpy_s(dst->name, MAX_PATH, src->name, _TRUNCATE);
    dst->next = NULL;
    return dst;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    FreeConsole();

    load_list("blacklist.txt", blacklist, &blacklist_count, MAX_BLACKLIST_ITEMS);
    load_list("whitelist.txt", whitelist, &whitelist_count, MAX_WHITELIST_ITEMS);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 1;
    build_hash_from_snapshot(snap);
    CloseHandle(snap);

    for (int i = 0; i < HASH_SIZE; i++) {
        for (ProcEntry* e = hash_table[i]; e; e = e->next) {
            if (is_handled(e->pid)) continue;
            ProcMetadata meta;
            wcscpy_s(meta.name, MAX_PATH, e->name);
            get_process_metadata(e->pid, &meta);
            if (is_whitelisted(&meta)) continue;
            if (matches_blacklist(&meta)) {
                add_tainted(e->pid);
                suspend_process_native(e->pid);
                kill_process_tree_native(e->pid);
                add_handled(e->pid);
            }
        }
    }

    ProcEntry* previous[HASH_SIZE] = { NULL };
    for (int i = 0; i < HASH_SIZE; i++) {
        for (ProcEntry* e = hash_table[i]; e; e = e->next) {
            ProcEntry* copy = copy_proc_entry(e);
            if (copy) {
                unsigned idx = hash(e->pid);
                copy->next = previous[idx];
                previous[idx] = copy;
            }
        }
    }

    DWORD last_cleanup = GetTickCount();

    while (1) {
        Sleep(SLEEP_MS);

        if (GetTickCount() - last_cleanup >= CLEANUP_INTERVAL_MS) {
            cleanup_stale_arrays();
            last_cleanup = GetTickCount();
        }

        snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) continue;
        build_hash_from_snapshot(snap);
        CloseHandle(snap);

        for (int i = 0; i < HASH_SIZE; i++) {
            for (ProcEntry* cur = hash_table[i]; cur; cur = cur->next) {
                DWORD pid = cur->pid;
                if (is_handled(pid)) continue;

                int found = 0;
                unsigned prev_idx = hash(pid);
                for (ProcEntry* prv = previous[prev_idx]; prv; prv = prv->next) {
                    if (prv->pid == pid) { found = 1; break; }
                }
                if (!found) {
                    ProcMetadata meta;
                    wcscpy_s(meta.name, MAX_PATH, cur->name);
                    get_process_metadata(pid, &meta);
                    if (is_whitelisted(&meta)) continue;

                    if (matches_blacklist(&meta)) {
                        add_tainted(pid);
                        suspend_process_native(pid);
                        kill_process_tree_native(pid);
                        add_handled(pid);
                    } else if (has_tainted_ancestor(pid)) {
                        suspend_process_native(pid);
                        kill_process_tree_native(pid);
                        add_handled(pid);
                    }
                }
            }
        }

        for (int i = 0; i < HASH_SIZE; i++) {
            ProcEntry* cur = previous[i];
            while (cur) {
                ProcEntry* next = cur->next;
                free(cur);
                cur = next;
            }
            previous[i] = NULL;
        }
        for (int i = 0; i < HASH_SIZE; i++) {
            for (ProcEntry* e = hash_table[i]; e; e = e->next) {
                ProcEntry* copy = copy_proc_entry(e);
                if (copy) {
                    unsigned idx = hash(e->pid);
                    copy->next = previous[idx];
                    previous[idx] = copy;
                }
            }
        }
    }

    free_lists();
    free(handled_pids);
    free(tainted_pids);
    clear_hash_table();
    return 0;
}
