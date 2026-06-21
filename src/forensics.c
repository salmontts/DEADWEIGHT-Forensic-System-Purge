/* ============================================================================
 *  forensics.c  --  analiza read-only: scan / prefetch / services / report
 * ----------------------------------------------------------------------------
 *  Wszystko tutaj jest NIEDESTRUKCYJNE - tylko czyta i raportuje.
 *  Naprawiono bug z analyze_services w wersji monolitycznej (continue
 *  przeskakiwał CloseServiceHandle -> wyciek uchwytów).
 * ==========================================================================*/
#include "forensics.h"
#include "log.h"
#include "processes.h"
#include "signature.h"
#include <stdio.h>
#include <shlwapi.h>
#include <psapi.h>

static ULONGLONG days_since(FILETIME ft) {
    FILETIME now; GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER n, a;
    n.LowPart = now.dwLowDateTime; n.HighPart = now.dwHighDateTime;
    a.LowPart = ft.dwLowDateTime;  a.HighPart = ft.dwHighDateTime;
    if (n.QuadPart < a.QuadPart) return 0;
    ULONGLONG sec = (n.QuadPart - a.QuadPart) / 10000000ULL;
    return sec / 86400ULL;
}

static void scan_recursive(const TCHAR* path, int daysThreshold,
                           int* fileCount, ULONGLONG* totalSize) {
    TCHAR search[MAX_PATH_LENGTH];
    _sntprintf(search, MAX_PATH_LENGTH, _T("%s\\*"), path);

    WIN32_FIND_DATA fd;
    HANDLE hFind = FindFirstFile(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (_tcscmp(fd.cFileName, _T(".")) == 0 ||
            _tcscmp(fd.cFileName, _T("..")) == 0) continue;

        TCHAR full[MAX_PATH_LENGTH];
        _sntprintf(full, MAX_PATH_LENGTH, _T("%s\\%s"), path, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            scan_recursive(full, daysThreshold, fileCount, totalSize);
        } else {
            ULONGLONG d = days_since(fd.ftLastAccessTime);
            if (d > (ULONGLONG)daysThreshold) {
                ULARGE_INTEGER sz;
                sz.LowPart = fd.nFileSizeLow; sz.HighPart = fd.nFileSizeHigh;
                *totalSize += sz.QuadPart;
                (*fileCount)++;
                SYSTEMTIME st; FileTimeToSystemTime(&fd.ftLastAccessTime, &st);
                _tprintf(_T("[%d] %s  (last: %04d-%02d-%02d, %.2f MB)\n"),
                         *fileCount, full, st.wYear, st.wMonth, st.wDay,
                         (double)sz.QuadPart / (1024.0 * 1024.0));
            }
        }
    } while (FindNextFile(hFind, &fd));
    FindClose(hFind);
}

void dw_scan_directory(const TCHAR* path, int daysThreshold) {
    _tprintf(_T("\n=== %s - DIRECTORY SCAN ===\n"), DW_NAME);
    _tprintf(_T("Path: %s | older than %d days\n\n"), path, daysThreshold);

    int fileCount = 0;
    ULONGLONG totalSize = 0;
    scan_recursive(path, daysThreshold, &fileCount, &totalSize);

    _tprintf(_T("\nTotal: %d files, %.2f GB\n"),
             fileCount, (double)totalSize / (1024.0 * 1024.0 * 1024.0));
    dw_log(_T("scan"), path);
}

void dw_analyze_prefetch(void) {
    _tprintf(_T("\n=== %s - PREFETCH ANALYSIS ===\n"), DW_NAME);

    TCHAR pf[MAX_PATH];
    GetWindowsDirectory(pf, MAX_PATH);
    PathAppend(pf, _T("Prefetch"));

    TCHAR search[MAX_PATH];
    _sntprintf(search, MAX_PATH, _T("%s\\*.pf"), pf);

    WIN32_FIND_DATA fd;
    HANDLE hFind = FindFirstFile(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        _tprintf(_T("No prefetch files (or access denied).\n"));
        return;
    }

    _tprintf(_T("%-44s %-12s %s\n"), _T("Application"), _T("Last run"), _T("Days"));
    _tprintf(_T("--------------------------------------------------------------------\n"));
    do {
        TCHAR name[MAX_PATH];
        _tcscpy(name, fd.cFileName);
        TCHAR* dot = _tcsrchr(name, _T('.'));
        if (dot) *dot = _T('\0');

        SYSTEMTIME st; FileTimeToSystemTime(&fd.ftLastAccessTime, &st);
        _tprintf(_T("%-44s %04d-%02d-%02d  %llu\n"),
                 name, st.wYear, st.wMonth, st.wDay,
                 days_since(fd.ftLastAccessTime));
    } while (FindNextFile(hFind, &fd));
    FindClose(hFind);
    dw_log(_T("prefetch"), _T("Prefetch analysis completed"));
}

void dw_analyze_services(void) {
    _tprintf(_T("\n=== %s - SERVICES ANALYSIS ===\n"), DW_NAME);

    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) { _tprintf(_T("Cannot open SCM.\n")); return; }

    DWORD needed = 0, count = 0;
    EnumServicesStatusEx(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                         SERVICE_STATE_ALL, NULL, 0, &needed, &count, NULL, NULL);
    if (needed == 0) { CloseServiceHandle(scm); return; }

    LPENUM_SERVICE_STATUS_PROCESS p =
        (LPENUM_SERVICE_STATUS_PROCESS)malloc(needed);
    if (!p) { CloseServiceHandle(scm); return; }

    if (EnumServicesStatusEx(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
            SERVICE_STATE_ALL, (LPBYTE)p, needed, &needed, &count, NULL, NULL)) {

        _tprintf(_T("%-36s %-9s %s\n"), _T("Service"), _T("State"), _T("Flag"));
        _tprintf(_T("--------------------------------------------------------------\n"));

        for (DWORD i = 0; i < count; ++i) {
            const TCHAR* state =
                (p[i].ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING)
                ? _T("Running") : _T("Stopped");

            const TCHAR* flag = _T("");
            SC_HANDLE svc = OpenService(scm, p[i].lpServiceName, SERVICE_QUERY_CONFIG);
            if (svc) {
                DWORD cfgSize = 0;
                QueryServiceConfig(svc, NULL, 0, &cfgSize);
                QUERY_SERVICE_CONFIG* cfg = (QUERY_SERVICE_CONFIG*)malloc(cfgSize);
                if (cfg && QueryServiceConfig(svc, cfg, cfgSize, &cfgSize)) {
                    if (cfg->lpBinaryPathName &&
                        dw_is_suspicious_path(cfg->lpBinaryPathName)) {
                        /* Podejrzana ścieżka to dopiero połowa sprawy. Sprawdź
                         * podpis: zaufana binarka (Defender, NVIDIA...) z
                         * ProgramData to NIE zagrożenie. Dopiero brak/zerwany
                         * podpis czyni z tego realny SUSPECT. */
                        DwSigStatus sig = dw_check_signature(cfg->lpBinaryPathName);
                        if (sig == DW_SIG_TRUSTED) {
                            flag = _T("(signed)");
                            dw_logf(_T("services"),
                                _T("OK signed-in-suspect-path: %s -> %s"),
                                p[i].lpServiceName, cfg->lpBinaryPathName);
                        } else {
                            flag = (sig == DW_SIG_UNSIGNED)
                                   ? _T("SUSPECT (unsigned)")
                                   : _T("SUSPECT (bad-sig)");
                            dw_logf(_T("services"),
                                _T("[!] SUSPECT %s | %s | path=%s"),
                                dw_sig_label(sig), p[i].lpServiceName,
                                cfg->lpBinaryPathName);
                        }
                    }
                }
                free(cfg);
                CloseServiceHandle(svc);   /* zawsze zamykamy - fix wycieku */
            }

            _tprintf(_T("%-36s %-9s %s\n"),
                     p[i].lpServiceName, state, flag);
        }
    }
    free(p);
    CloseServiceHandle(scm);
    dw_log(_T("services"), _T("Services analysis completed"));
}

void dw_generate_report(void) {
    _tprintf(_T("\n=== %s - SYSTEM REPORT ===\n"), DW_NAME);

    SYSTEM_INFO si; GetSystemInfo(&si);
    MEMORYSTATUSEX mem; mem.dwLength = sizeof(mem); GlobalMemoryStatusEx(&mem);

    _tprintf(_T("CPU cores: %lu\n"), si.dwNumberOfProcessors);
    _tprintf(_T("RAM: %.2f / %.2f GB (%lu%% used)\n"),
             (double)(mem.ullTotalPhys - mem.ullAvailPhys) / (1024.0*1024.0*1024.0),
             (double)mem.ullTotalPhys / (1024.0*1024.0*1024.0),
             mem.dwMemoryLoad);

    DWORD drives = GetLogicalDrives();
    _tprintf(_T("\nDisks:\n"));
    for (int i = 0; i < 26; ++i) {
        if (!(drives & (1u << i))) continue;
        TCHAR root[] = { (TCHAR)(_T('A') + i), _T(':'), _T('\\'), _T('\0') };
        ULARGE_INTEGER freeAvail, total, totalFree;
        if (GetDiskFreeSpaceEx(root, &freeAvail, &total, &totalFree)) {
            _tprintf(_T("  %s  %.1f GB free / %.1f GB\n"), root,
                     (double)freeAvail.QuadPart / (1024.0*1024.0*1024.0),
                     (double)total.QuadPart / (1024.0*1024.0*1024.0));
        }
    }

    dw_analyze_prefetch();
    dw_analyze_services();
    dw_log(_T("report"), _T("System report generated"));
}
