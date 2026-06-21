/* ============================================================================
 *  log.c  --  implementacja jednolitego logowania
 * ==========================================================================*/
#include "log.h"
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <shlwapi.h>

/* Zwraca pełną ścieżkę pliku logu obok pliku .exe (nie w CWD). */
static void dw_log_path(const TCHAR* filename, TCHAR* out, size_t out_len) {
    TCHAR exePath[MAX_PATH];
    GetModuleFileName(NULL, exePath, MAX_PATH);
    PathRemoveFileSpec(exePath);
    _sntprintf(out, out_len, _T("%s\\%s"), exePath, filename);
}

void dw_log_purge(const TCHAR* msg) {
    TCHAR path[MAX_PATH];
    dw_log_path(DW_LOG_PURGE, path, MAX_PATH);

    FILE* f = _tfopen(path, _T("a, ccs=UTF-8"));
    if (!f) return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    _ftprintf(f, _T("[%04d-%02d-%02d %02d:%02d:%02d] %s\n"),
              st.wYear, st.wMonth, st.wDay,
              st.wHour, st.wMinute, st.wSecond, msg);
    fclose(f);
}

void dw_log(const TCHAR* module, const TCHAR* message) {
    TCHAR path[MAX_PATH];
    dw_log_path(DW_LOG_ANALYSIS, path, MAX_PATH);

    FILE* f = _tfopen(path, _T("a, ccs=UTF-8"));
    if (!f) return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    _ftprintf(f, _T("[%04d-%02d-%02d %02d:%02d:%02d] | [%s] | %s\n"),
              st.wYear, st.wMonth, st.wDay,
              st.wHour, st.wMinute, st.wSecond, module, message);
    fclose(f);
}

void dw_log_purgef(const TCHAR* fmt, ...) {
    TCHAR buf[MAX_LOG_LENGTH];
    va_list args;
    va_start(args, fmt);
    _vsntprintf(buf, MAX_LOG_LENGTH, fmt, args);
    va_end(args);
    dw_log_purge(buf);
}

void dw_logf(const TCHAR* module, const TCHAR* fmt, ...) {
    TCHAR buf[MAX_LOG_LENGTH];
    va_list args;
    va_start(args, fmt);
    _vsntprintf(buf, MAX_LOG_LENGTH, fmt, args);
    va_end(args);
    dw_log(module, buf);
}
