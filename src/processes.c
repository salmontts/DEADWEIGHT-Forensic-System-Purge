/* ============================================================================
 *  processes.c  --  procesy: kill / monitor / lupa + ANTI-MASQUERADE
 * ----------------------------------------------------------------------------
 *  Najważniejsza zmiana vs wersja monolityczna:
 *  whitelist procesów krytycznych działa po (NAZWA + ŚCIEŻKA), nie po samej
 *  nazwie. Malware podszywające się pod svchost.exe z AppData NIE jest już
 *  oszczędzane. (MITRE T1036 - Masquerading)
 * ==========================================================================*/
#include "processes.h"
#include "log.h"
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>

/* Kopiuje src do dst (lowercase). dst musi mieć >= len. */
static void to_lower_copy(TCHAR* dst, const TCHAR* src, size_t len) {
    _tcsncpy(dst, src, len - 1);
    dst[len - 1] = _T('\0');
    _tcslwr(dst);
}

BOOL dw_get_process_path(DWORD pid, TCHAR* out, DWORD out_len) {
    out[0] = _T('\0');
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) {
        /* fallback do starszego prawa dostępu */
        h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!h) return FALSE;
    }
    DWORD len = out_len;
    BOOL ok = QueryFullProcessImageName(h, 0, out, &len);
    if (!ok) {
        /* drugi fallback */
        ok = (GetModuleFileNameEx(h, NULL, out, out_len) != 0);
    }
    CloseHandle(h);
    return ok;
}

BOOL dw_is_suspicious_path(const TCHAR* full_path) {
    if (!full_path || full_path[0] == _T('\0')) return FALSE;
    TCHAR low[MAX_PATH_LENGTH];
    to_lower_copy(low, full_path, MAX_PATH_LENGTH);
    for (size_t i = 0; i < DW_SUSPICIOUS_DIRS_COUNT; ++i) {
        if (_tcsstr(low, DW_SUSPICIOUS_DIRS[i])) return TRUE;
    }
    return FALSE;
}

BOOL dw_is_critical_process(const TCHAR* name, const TCHAR* full_path) {
    TCHAR nameLow[MAX_PATH];
    to_lower_copy(nameLow, name, MAX_PATH);

    for (size_t i = 0; i < DW_CRITICAL_PROCS_COUNT; ++i) {
        if (_tcscmp(nameLow, DW_CRITICAL_PROCS[i].name) != 0)
            continue;

        /* Nazwa pasuje. Teraz weryfikuj ścieżkę. */
        if (!full_path || full_path[0] == _T('\0')) {
            /* Brak dostępu do ścieżki - zwykle proces faktycznie protected
             * (prawdziwy lsass/csrss). Bezpieczniej OSZCZĘDZIĆ niż zabić
             * i wywołać BSOD. Logujemy że nie zweryfikowaliśmy ścieżki. */
            return TRUE;
        }

        TCHAR pathLow[MAX_PATH_LENGTH];
        to_lower_copy(pathLow, full_path, MAX_PATH_LENGTH);

        if (_tcsstr(pathLow, DW_CRITICAL_PROCS[i].required_dir)) {
            return TRUE;   /* nazwa + właściwa ścieżka = prawdziwy proces */
        }

        /* Nazwa systemowa, ale ZŁA ścieżka = masquerade. NIE krytyczny. */
        return FALSE;
    }
    return FALSE;  /* nazwa nie jest na liście krytycznych */
}

void dw_kill_non_essential(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID <= 4) continue;          /* System / Idle */
            if (pe.th32ProcessID == GetCurrentProcessId()) continue; /* my   */

            TCHAR path[MAX_PATH_LENGTH] = {0};
            BOOL havePath = dw_get_process_path(pe.th32ProcessID, path, MAX_PATH_LENGTH);

            if (dw_is_critical_process(pe.szExeFile, havePath ? path : NULL)) {
                if (!havePath)
                    dw_log_purgef(_T("Spared (critical, path unverified): %s"), pe.szExeFile);
                continue;
            }

            BOOL suspicious = havePath && dw_is_suspicious_path(path);

            HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
            if (h) {
                TerminateProcess(h, 0);
                CloseHandle(h);
                if (suspicious)
                    dw_log_purgef(_T("Killed [MASQUERADE?] %s  <- %s"), pe.szExeFile, path);
                else
                    dw_log_purgef(_T("Killed: %s"), pe.szExeFile);
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

void dw_analyze_processes(void) {
    _tprintf(_T("\n=== %s - PROCESS ANALYSIS (read-only) ===\n"), DW_NAME);
    _tprintf(_T("%-28s %-8s %-10s %s\n"), _T("Process"), _T("PID"), _T("Flag"), _T("Path"));
    _tprintf(_T("--------------------------------------------------------------------------------\n"));

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe = { sizeof(pe) };
    if (Process32First(snap, &pe)) {
        do {
            TCHAR path[MAX_PATH_LENGTH] = {0};
            BOOL havePath = dw_get_process_path(pe.th32ProcessID, path, MAX_PATH_LENGTH);

            const TCHAR* flag = _T("");
            /* nazwa systemowa w złej lokalizacji = mocny sygnał */
            TCHAR nameLow[MAX_PATH];
            to_lower_copy(nameLow, pe.szExeFile, MAX_PATH);
            BOOL knownName = FALSE;
            for (size_t i = 0; i < DW_CRITICAL_PROCS_COUNT; ++i)
                if (_tcscmp(nameLow, DW_CRITICAL_PROCS[i].name) == 0) { knownName = TRUE; break; }

            if (knownName && havePath && !dw_is_critical_process(pe.szExeFile, path))
                flag = _T("MASQUERADE");
            else if (havePath && dw_is_suspicious_path(path))
                flag = _T("SUSPECT");

            _tprintf(_T("%-28s %-8lu %-10s %s\n"),
                     pe.szExeFile, pe.th32ProcessID, flag,
                     havePath ? path : _T("(access denied)"));

            if (flag[0] != _T('\0'))
                dw_log(_T("analyze_proc"), pe.szExeFile);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

/* ---- Monitor (z wersji monolitycznej, oczyszczony) ----------------------*/
void dw_monitor_processes(int duration_seconds) {
    _tprintf(_T("\n=== %s - PROCESS MONITOR (%d s) ===\n"), DW_NAME, duration_seconds);

    DWORD endTime = GetTickCount() + (DWORD)duration_seconds * 1000;

    DWORD* knownPids = NULL;
    DWORD knownCount = 0;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = { sizeof(pe) };
        if (Process32First(snap, &pe)) {
            do {
                DWORD* tmp = (DWORD*)realloc(knownPids, (knownCount + 1) * sizeof(DWORD));
                if (!tmp) break;
                knownPids = tmp;
                knownPids[knownCount++] = pe.th32ProcessID;
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }

    while (GetTickCount() < endTime) {
        Sleep(1000);
        snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) continue;
        PROCESSENTRY32 pe = { sizeof(pe) };
        if (Process32First(snap, &pe)) {
            do {
                BOOL found = FALSE;
                for (DWORD i = 0; i < knownCount; ++i)
                    if (knownPids[i] == pe.th32ProcessID) { found = TRUE; break; }
                if (!found) {
                    TCHAR path[MAX_PATH_LENGTH] = {0};
                    BOOL hp = dw_get_process_path(pe.th32ProcessID, path, MAX_PATH_LENGTH);
                    const TCHAR* flag = (hp && dw_is_suspicious_path(path)) ? _T(" [SUSPECT]") : _T("");
                    _tprintf(_T("[NEW]%s PID:%6lu  %s  %s\n"),
                             flag, pe.th32ProcessID, pe.szExeFile, hp ? path : _T(""));
                    dw_log(_T("monitor"), pe.szExeFile);
                    /* dopisz do known, żeby nie spamować */
                    DWORD* tmp = (DWORD*)realloc(knownPids, (knownCount + 1) * sizeof(DWORD));
                    if (tmp) { knownPids = tmp; knownPids[knownCount++] = pe.th32ProcessID; }
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }
    free(knownPids);
    _tprintf(_T("Monitoring done.\n"));
}

/* ---- Lupa (szczegóły procesu) -------------------------------------------*/
void dw_lupa_mode(const TCHAR* process_name) {
    _tprintf(_T("\n=== %s - PROCESS DETAILS: %s ===\n"), DW_NAME, process_name);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) { _tprintf(_T("snapshot failed\n")); return; }

    PROCESSENTRY32 pe = { sizeof(pe) };
    DWORD targetPid = 0, parentPid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_tcsicmp(pe.szExeFile, process_name) == 0) {
                targetPid = pe.th32ProcessID;
                parentPid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    if (targetPid == 0) { _tprintf(_T("Process not found.\n")); CloseHandle(snap); return; }

    TCHAR path[MAX_PATH_LENGTH] = {0};
    BOOL hp = dw_get_process_path(targetPid, path, MAX_PATH_LENGTH);

    _tprintf(_T("  PID:        %lu\n"), targetPid);
    _tprintf(_T("  Parent PID: %lu\n"), parentPid);
    _tprintf(_T("  Path:       %s\n"), hp ? path : _T("(access denied)"));
    if (hp && dw_is_suspicious_path(path))
        _tprintf(_T("  [!] SUSPICIOUS LOCATION\n"));
    if (hp && !dw_is_critical_process(process_name, path)) {
        TCHAR nameLow[MAX_PATH]; to_lower_copy(nameLow, process_name, MAX_PATH);
        for (size_t i = 0; i < DW_CRITICAL_PROCS_COUNT; ++i)
            if (_tcscmp(nameLow, DW_CRITICAL_PROCS[i].name) == 0) {
                _tprintf(_T("  [!] NAME MATCHES SYSTEM PROCESS BUT WRONG PATH = MASQUERADE\n"));
                break;
            }
    }

    /* Pamięć */
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, targetPid);
    if (h) {
        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(h, &pmc, sizeof(pmc)))
            _tprintf(_T("  Memory:     %.2f MB\n"), (double)pmc.WorkingSetSize / (1024.0 * 1024.0));
        CloseHandle(h);
    }

    /* Moduły */
    _tprintf(_T("\n  Loaded modules:\n"));
    HANDLE ms = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, targetPid);
    if (ms != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me = { sizeof(me) };
        if (Module32First(ms, &me)) {
            do { _tprintf(_T("    %s\n"), me.szModule); } while (Module32Next(ms, &me));
        }
        CloseHandle(ms);
    }

    CloseHandle(snap);
    dw_log(_T("lupa"), process_name);
}
