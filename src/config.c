/* ============================================================================
 *  config.c  --  definicje tablic konfiguracyjnych
 * ----------------------------------------------------------------------------
 *  Tablice są zadeklarowane jako `extern const` w config.h, a zdefiniowane
 *  TUTAJ dokładnie raz. Dzięki temu nie dublują się w każdej jednostce
 *  kompilacji (to usuwa warningi "defined but not used" i zmniejsza binarkę).
 * ==========================================================================*/
#include "config.h"

const CriticalProc DW_CRITICAL_PROCS[] = {
    { _T("smss.exe"),        _T("\\windows\\system32\\") },
    { _T("csrss.exe"),       _T("\\windows\\system32\\") },
    { _T("wininit.exe"),     _T("\\windows\\system32\\") },
    { _T("services.exe"),    _T("\\windows\\system32\\") },
    { _T("lsass.exe"),       _T("\\windows\\system32\\") },
    { _T("winlogon.exe"),    _T("\\windows\\system32\\") },
    { _T("svchost.exe"),     _T("\\windows\\system32\\") },
    { _T("fontdrvhost.exe"), _T("\\windows\\system32\\") },
    { _T("explorer.exe"),    _T("\\windows\\") },
};
const size_t DW_CRITICAL_PROCS_COUNT =
    sizeof(DW_CRITICAL_PROCS) / sizeof(DW_CRITICAL_PROCS[0]);

const TCHAR* const DW_SUSPICIOUS_DIRS[] = {
    _T("\\appdata\\local\\temp\\"),
    _T("\\appdata\\roaming\\"),
    _T("\\windows\\temp\\"),
    _T("\\downloads\\"),
    _T("\\users\\public\\"),
    _T("\\programdata\\"),
    _T("\\$recycle.bin\\"),
};
const size_t DW_SUSPICIOUS_DIRS_COUNT =
    sizeof(DW_SUSPICIOUS_DIRS) / sizeof(DW_SUSPICIOUS_DIRS[0]);

const AutorunKey DW_AUTORUN_KEYS[] = {
    { HKEY_CURRENT_USER,  _T("Software\\Microsoft\\Windows\\CurrentVersion\\Run"),                  _T("HKCU Run") },
    { HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\Run"),                  _T("HKLM Run") },
    { HKEY_LOCAL_MACHINE, _T("Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"),     _T("HKLM Run (Wow64)") },
    { HKEY_CURRENT_USER,  _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),              _T("HKCU RunOnce") },
    { HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),              _T("HKLM RunOnce") },
};
const size_t DW_AUTORUN_KEYS_COUNT =
    sizeof(DW_AUTORUN_KEYS) / sizeof(DW_AUTORUN_KEYS[0]);

const TCHAR* const DW_CLEAN_DIRS_RELATIVE[] = {
    _T("\\Temp"),
    _T("\\Prefetch"),
    _T("\\SoftwareDistribution\\Download"),
};
const size_t DW_CLEAN_DIRS_COUNT =
    sizeof(DW_CLEAN_DIRS_RELATIVE) / sizeof(DW_CLEAN_DIRS_RELATIVE[0]);
