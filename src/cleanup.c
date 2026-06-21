/* ============================================================================
 *  cleanup.c  --  czyszczenie temp / staging / cache
 * ==========================================================================*/
#include "cleanup.h"
#include "log.h"
#include <stdio.h>

void dw_delete_folder_contents(const TCHAR* folder) {
    TCHAR search[MAX_PATH_LENGTH];
    _sntprintf(search, MAX_PATH_LENGTH, _T("%s\\*"), folder);

    WIN32_FIND_DATA fd;
    HANDLE hFind = FindFirstFile(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (_tcscmp(fd.cFileName, _T(".")) == 0 ||
            _tcscmp(fd.cFileName, _T("..")) == 0) continue;

        TCHAR full[MAX_PATH_LENGTH];
        _sntprintf(full, MAX_PATH_LENGTH, _T("%s\\%s"), folder, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            dw_delete_folder_contents(full);
            RemoveDirectory(full);
        } else {
            /* zdejmij read-only/system/hidden, żeby DeleteFile się udało */
            SetFileAttributes(full, FILE_ATTRIBUTE_NORMAL);
            DeleteFile(full);
        }
    } while (FindNextFile(hFind, &fd));
    FindClose(hFind);
}

BOOL dw_delete_tree(const TCHAR* folder) {
    TCHAR search[MAX_PATH_LENGTH];
    _sntprintf(search, MAX_PATH_LENGTH, _T("%s\\*"), folder);

    WIN32_FIND_DATA fd;
    HANDLE hFind = FindFirstFile(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return FALSE;

    do {
        if (_tcscmp(fd.cFileName, _T(".")) == 0 ||
            _tcscmp(fd.cFileName, _T("..")) == 0) continue;

        TCHAR full[MAX_PATH_LENGTH];
        _sntprintf(full, MAX_PATH_LENGTH, _T("%s\\%s"), folder, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!dw_delete_tree(full)) { FindClose(hFind); return FALSE; }
        } else {
            SetFileAttributes(full, FILE_ATTRIBUTE_NORMAL);
            if (!DeleteFile(full)) { FindClose(hFind); return FALSE; }
        }
    } while (FindNextFile(hFind, &fd));
    FindClose(hFind);

    return RemoveDirectory(folder);
}

void dw_purge_temp_locations(void) {
    TCHAR path[MAX_PATH];

    /* %TEMP% */
    if (GetTempPath(MAX_PATH, path)) {
        dw_delete_folder_contents(path);
        dw_log_purge(_T("Cleared %TEMP%"));
    }

    /* %WINDIR%\Temp, \Prefetch, \SoftwareDistribution\Download */
    for (size_t i = 0; i < DW_CLEAN_DIRS_COUNT; ++i) {
        GetWindowsDirectory(path, MAX_PATH);
        _tcsncat(path, DW_CLEAN_DIRS_RELATIVE[i],
                 MAX_PATH - _tcslen(path) - 1);
        dw_delete_folder_contents(path);
        dw_log_purgef(_T("Cleared %s"), path);
    }

    /* %LOCALAPPDATA%\Temp */
    TCHAR* local = _tgetenv(_T("LOCALAPPDATA"));
    if (local) {
        _sntprintf(path, MAX_PATH, _T("%s\\Temp"), local);
        dw_delete_folder_contents(path);
        dw_log_purge(_T("Cleared LocalAppData Temp"));
    }
}

void dw_clean_path_interactive(const TCHAR* folder_path) {
    _tprintf(_T("\n=== %s - DELETE TREE ===\n"), DW_NAME);
    _tprintf(_T("Target: %s\n"), folder_path);
    _tprintf(_T("Delete this folder and ALL contents? (y/n): "));

    TCHAR resp[8];
    if (!_fgetts(resp, 8, stdin)) return;
    if (_totlower(resp[0]) != _T('y')) {
        _tprintf(_T("Cancelled.\n"));
        dw_log(_T("clean"), _T("Cancelled by user"));
        return;
    }

    if (dw_delete_tree(folder_path)) {
        _tprintf(_T("Deleted.\n"));
        dw_log_purgef(_T("Deleted tree: %s"), folder_path);
    } else {
        _tprintf(_T("Error (files in use / access denied).\n"));
        dw_log(_T("clean"), _T("delete_tree failed"));
    }
}
