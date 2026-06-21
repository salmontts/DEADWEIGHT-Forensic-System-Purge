/* ============================================================================
 *  persistence.c  --  enumeracja + czyszczenie wektorów persistence
 * ----------------------------------------------------------------------------
 *  Zmiany vs wersja monolityczna:
 *   - usunięto DUPLIKACJĘ (stare sekcje 0b-0f i 6b-6f robiły to samo 2x)
 *   - USUNIĘTO kasowanie sterowników (vgk.sys, nvlddmkm.sys, *.inf) -
 *     to nie persistence, to bebechy systemu; bug murzył Windows
 *   - USUNIĘTO hardcode razer/nvidia/proton - zamiast krucjaty na vendorów,
 *     usługi oceniamy po PODEJRZANEJ ŚCIEŻCE binarki (forensyczne kryterium)
 *   - dodano tryb read-only (analyze) obok destrukcyjnego (purge)
 * ==========================================================================*/
#include "persistence.h"
#include "log.h"
#include "processes.h"   /* dw_is_suspicious_path */
#include "signature.h"   /* dw_check_signature   */
#include <stdio.h>

/* ---- AUTORUN (Run / RunOnce) --------------------------------------------*/

static void autorun_enum(BOOL destructive) {
    for (size_t i = 0; i < DW_AUTORUN_KEYS_COUNT; ++i) {
        HKEY hKey;
        REGSAM access = destructive ? KEY_ALL_ACCESS : KEY_READ;
        if (RegOpenKeyEx(DW_AUTORUN_KEYS[i].root, DW_AUTORUN_KEYS[i].subkey,
                         0, access, &hKey) != ERROR_SUCCESS)
            continue;

        DWORD idx = 0;
        for (;;) {
            TCHAR valName[512]; DWORD valNameLen = 512;
            BYTE  valData[2048]; DWORD valDataLen = sizeof(valData);
            DWORD type;
            LONG r = RegEnumValue(hKey, idx, valName, &valNameLen, NULL,
                                  &type, valData, &valDataLen);
            if (r != ERROR_SUCCESS) break;

            if (!destructive) {
                if (type == REG_SZ || type == REG_EXPAND_SZ) {
                    /* Sprawdź podpis pliku, na który wskazuje autorun.
                     * Niepodpisany autorun = wart uwagi w śledztwie. */
                    DwSigStatus sig = dw_check_signature((TCHAR*)valData);
                    const TCHAR* tag = (sig == DW_SIG_TRUSTED) ? _T("")
                                     : (sig == DW_SIG_UNSIGNED) ? _T("  [!] UNSIGNED")
                                     : (sig == DW_SIG_ERROR)    ? _T("")
                                     : _T("  [!] BAD-SIG");
                    _tprintf(_T("  [%s] %s = %s%s\n"),
                             DW_AUTORUN_KEYS[i].label, valName,
                             (TCHAR*)valData, tag);
                    if (sig == DW_SIG_UNSIGNED || sig == DW_SIG_UNTRUSTED)
                        dw_logf(_T("persistence"),
                            _T("[!] autorun %s | %s | %s = %s"),
                            dw_sig_label(sig), DW_AUTORUN_KEYS[i].label,
                            valName, (TCHAR*)valData);
                    else
                        dw_logf(_T("persistence"),
                            _T("autorun %s | %s = %s"),
                            DW_AUTORUN_KEYS[i].label, valName, (TCHAR*)valData);
                }
                ++idx;  /* przy read tylko idziemy dalej */
            } else {
                /* Przy kasowaniu enumerujemy zawsze index 0, bo lista się kurczy */
                RegDeleteValue(hKey, valName);
                dw_log_purgef(_T("Removed autorun: [%s] %s"),
                              DW_AUTORUN_KEYS[i].label, valName);
                /* idx zostaje 0 */
            }
        }
        RegCloseKey(hKey);
    }
}

/* ---- AppInit_DLLs --------------------------------------------------------*/

static void appinit_dlls(BOOL destructive) {
    HKEY h;
    REGSAM access = destructive ? KEY_ALL_ACCESS : KEY_READ;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        _T("Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"),
        0, access, &h) != ERROR_SUCCESS) return;

    if (destructive) {
        RegSetValueEx(h, _T("AppInit_DLLs"), 0, REG_SZ,
                      (const BYTE*)_T(""), sizeof(TCHAR));
        dw_log_purge(_T("Cleared AppInit_DLLs"));
    } else {
        TCHAR data[1024]; DWORD len = sizeof(data); DWORD type;
        if (RegQueryValueEx(h, _T("AppInit_DLLs"), NULL, &type,
                            (BYTE*)data, &len) == ERROR_SUCCESS && data[0])
            _tprintf(_T("  [AppInit_DLLs] %s\n"), data);
    }
    RegCloseKey(h);
}

/* ---- IFEO debuggers ------------------------------------------------------*/

static void ifeo_debuggers(BOOL destructive) {
    HKEY h;
    REGSAM access = destructive ? KEY_ALL_ACCESS : KEY_READ;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        _T("Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"),
        0, access, &h) != ERROR_SUCCESS) return;

    DWORD idx = 0;
    TCHAR sub[256];
    while (RegEnumKey(h, idx, sub, 256) == ERROR_SUCCESS) {
        HKEY hSub;
        if (RegOpenKeyEx(h, sub, 0, access, &hSub) == ERROR_SUCCESS) {
            TCHAR dbg[1024]; DWORD len = sizeof(dbg); DWORD type;
            if (RegQueryValueEx(hSub, _T("Debugger"), NULL, &type,
                                (BYTE*)dbg, &len) == ERROR_SUCCESS) {
                if (destructive) {
                    RegDeleteValue(hSub, _T("Debugger"));
                    dw_log_purgef(_T("Removed IFEO debugger on: %s"), sub);
                } else {
                    _tprintf(_T("  [IFEO] %s -> Debugger=%s\n"), sub, dbg);
                }
            }
            RegCloseKey(hSub);
        }
        ++idx;
    }
    RegCloseKey(h);
}

/* ---- Winlogon Shell ------------------------------------------------------*/

static void winlogon_shell(BOOL destructive) {
    HKEY h;
    REGSAM access = destructive ? KEY_ALL_ACCESS : KEY_READ;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
        _T("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
        0, access, &h) != ERROR_SUCCESS) return;

    TCHAR shell[1024]; DWORD len = sizeof(shell); DWORD type;
    BOOL haveShell = (RegQueryValueEx(h, _T("Shell"), NULL, &type,
                                      (BYTE*)shell, &len) == ERROR_SUCCESS);
    if (!destructive) {
        if (haveShell) _tprintf(_T("  [Winlogon Shell] %s\n"), shell);
    } else {
        /* przywróć do czystego explorer.exe tylko gdy ktoś zmienił */
        if (!haveShell || _tcsicmp(shell, _T("explorer.exe")) != 0) {
            const TCHAR* def = _T("explorer.exe");
            RegSetValueEx(h, _T("Shell"), 0, REG_SZ, (const BYTE*)def,
                          (DWORD)((_tcslen(def) + 1) * sizeof(TCHAR)));
            dw_log_purge(_T("Reset Winlogon Shell to explorer.exe"));
        }
    }
    RegCloseKey(h);
}

/* ---- WMI subscriptions ---------------------------------------------------
 * Uwaga: wmic jest deprecated na nowych Windows, ale zostawiamy jako
 * best-effort - czyści klasyczne WMI event-consumer persistence.            */
static void wmi_persistence(BOOL destructive) {
    if (!destructive) {
        _tprintf(_T("  [WMI] (enumeracja subskrypcji wymaga COM - pominięte w read-only)\n"));
        return;
    }
    system("wmic /namespace:\\\\root\\\\subscription PATH __EventFilter DELETE >nul 2>&1");
    system("wmic /namespace:\\\\root\\\\subscription PATH CommandLineEventConsumer DELETE >nul 2>&1");
    system("wmic /namespace:\\\\root\\\\subscription PATH FilterToConsumerBinding DELETE >nul 2>&1");
    dw_log_purge(_T("Removed WMI subscription persistence (best-effort)"));
}

/* ---- Scheduled tasks (spoza Microsoft/Windows) ---------------------------*/

static void scheduled_tasks(BOOL destructive) {
    FILE* fp = _tpopen(_T("schtasks /query /fo LIST /v"), _T("r"));
    if (!fp) return;
    TCHAR line[4096];
    while (_fgetts(line, 4096, fp)) {
        TCHAR* p = _tcsstr(line, _T("TaskName:"));
        if (!p) continue;
        p += _tcslen(_T("TaskName:"));
        while (*p == _T(' ') || *p == _T('\t')) ++p;
        /* utnij newline */
        TCHAR* nl = _tcspbrk(p, _T("\r\n"));
        if (nl) *nl = _T('\0');

        if (_tcsncmp(p, _T("\\Microsoft"), 10) == 0) continue;
        if (_tcsncmp(p, _T("\\Windows"), 8) == 0) continue;
        if (p[0] == _T('\0')) continue;

        if (!destructive) {
            _tprintf(_T("  [Task] %s\n"), p);
        } else {
            TCHAR cmd[1024];
            _sntprintf(cmd, 1024, _T("schtasks /delete /f /tn \"%s\" >nul 2>&1"), p);
            _tsystem(cmd);
            dw_log_purgef(_T("Removed scheduled task: %s"), p);
        }
    }
    _pclose(fp);
}

/* ---- Usługi z podejrzanych lokalizacji -----------------------------------
 * Zamiast hardcode'u nazw vendorów: flaguj/usuwaj usługi, których binarka
 * leży w Temp/AppData/Users itd. To forensyczne kryterium, nie krucjata.    */
static void suspicious_services(BOOL destructive) {
    SC_HANDLE scm = OpenSCManager(NULL, NULL,
        destructive ? SC_MANAGER_ALL_ACCESS : SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return;

    DWORD needed = 0, count = 0;
    EnumServicesStatusEx(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                         SERVICE_STATE_ALL, NULL, 0, &needed, &count, NULL, NULL);
    if (needed == 0) { CloseServiceHandle(scm); return; }

    LPENUM_SERVICE_STATUS_PROCESS p =
        (LPENUM_SERVICE_STATUS_PROCESS)malloc(needed);
    if (!p) { CloseServiceHandle(scm); return; }

    if (EnumServicesStatusEx(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
            SERVICE_STATE_ALL, (LPBYTE)p, needed, &needed, &count, NULL, NULL)) {
        for (DWORD i = 0; i < count; ++i) {
            SC_HANDLE svc = OpenService(scm, p[i].lpServiceName,
                SERVICE_QUERY_CONFIG | (destructive ? (DELETE | SERVICE_STOP) : 0));
            if (!svc) continue;

            DWORD cfgSize = 0;
            QueryServiceConfig(svc, NULL, 0, &cfgSize);
            QUERY_SERVICE_CONFIG* cfg = (QUERY_SERVICE_CONFIG*)malloc(cfgSize);
            if (cfg && QueryServiceConfig(svc, cfg, cfgSize, &cfgSize)) {
                if (cfg->lpBinaryPathName &&
                    dw_is_suspicious_path(cfg->lpBinaryPathName)) {
                    DwSigStatus sig = dw_check_signature(cfg->lpBinaryPathName);
                    BOOL trusted = (sig == DW_SIG_TRUSTED);

                    if (!destructive) {
                        if (trusted) {
                            _tprintf(_T("  [Service ok-signed] %s -> %s\n"),
                                     p[i].lpServiceName, cfg->lpBinaryPathName);
                        } else {
                            _tprintf(_T("  [Service SUSPECT %s] %s -> %s\n"),
                                     dw_sig_label(sig), p[i].lpServiceName,
                                     cfg->lpBinaryPathName);
                            dw_logf(_T("persistence"),
                                _T("[!] service SUSPECT %s | %s | %s"),
                                dw_sig_label(sig), p[i].lpServiceName,
                                cfg->lpBinaryPathName);
                        }
                    } else {
                        /* NUKE: kasuj tylko NIEzaufane usługi z podejrzanych
                         * ścieżek. Podpisany Defender/NVIDIA zostaje nietknięty. */
                        if (!trusted) {
                            SERVICE_STATUS s;
                            ControlService(svc, SERVICE_CONTROL_STOP, &s);
                            DeleteService(svc);
                            dw_log_purgef(
                                _T("Deleted suspicious service: %s (%s) [%s]"),
                                p[i].lpServiceName, cfg->lpBinaryPathName,
                                dw_sig_label(sig));
                        } else {
                            dw_log_purgef(
                                _T("Spared signed service in suspect path: %s"),
                                p[i].lpServiceName);
                        }
                    }
                }
            }
            free(cfg);
            CloseServiceHandle(svc);
        }
    }
    free(p);
    CloseServiceHandle(scm);
}

/* ---- Publiczne API -------------------------------------------------------*/

void dw_analyze_persistence(void) {
    _tprintf(_T("\n=== %s - PERSISTENCE ANALYSIS (read-only) ===\n"), DW_NAME);
    _tprintf(_T("\n-- Autorun (Run/RunOnce) --\n"));   autorun_enum(FALSE);
    _tprintf(_T("\n-- AppInit_DLLs --\n"));             appinit_dlls(FALSE);
    _tprintf(_T("\n-- IFEO debuggers --\n"));           ifeo_debuggers(FALSE);
    _tprintf(_T("\n-- Winlogon Shell --\n"));           winlogon_shell(FALSE);
    _tprintf(_T("\n-- WMI subscriptions --\n"));        wmi_persistence(FALSE);
    _tprintf(_T("\n-- Scheduled tasks (non-MS) --\n")); scheduled_tasks(FALSE);
    _tprintf(_T("\n-- Services in suspicious paths --\n")); suspicious_services(FALSE);
    dw_log(_T("persistence"), _T("Read-only analysis completed"));
}

void dw_purge_persistence(void) {
    autorun_enum(TRUE);
    appinit_dlls(TRUE);
    ifeo_debuggers(TRUE);
    winlogon_shell(TRUE);
    wmi_persistence(TRUE);
    scheduled_tasks(TRUE);
    suspicious_services(TRUE);
    dw_log_purge(_T("Persistence purge completed"));
}
