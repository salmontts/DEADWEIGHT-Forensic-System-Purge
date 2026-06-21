/* ============================================================================
 *  config.h  --  DEADWEIGHT: centralna konfiguracja
 * ----------------------------------------------------------------------------
 *  Wszystkie stałe, ścieżki i whitelisty w jednym miejscu.
 *  Dodajesz nowy wektor persistence / nową ścieżkę? Dopisujesz TUTAJ,
 *  nie grzebiesz w logice modułów. (Ten sam wzorzec co config.h we Flipsonie.)
 * ==========================================================================*/
#ifndef DEADWEIGHT_CONFIG_H
#define DEADWEIGHT_CONFIG_H

/* Wymuszamy Unicode na poziomie CRT i Win32 ZANIM wciągniemy nagłówki,
 * żeby _T()/TCHAR rozwijały się na wide-char (W) zgodnie z -municode. */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <tchar.h>

/* ---- Wersja --------------------------------------------------------------*/
#define DW_VERSION       _T("2.0")
#define DW_NAME          _T("DEADWEIGHT")

/* ---- Bufory --------------------------------------------------------------*/
#define MAX_LOG_LENGTH   1024
#define MAX_PATH_LENGTH  32768

/* ---- Pliki logów ---------------------------------------------------------*/
#define DW_LOG_PURGE     _T("deadweight_purge.log")   /* akcje destrukcyjne   */
#define DW_LOG_ANALYSIS  _T("deadweight.log")         /* analiza / forensics  */

/* ---- GUI control IDs -----------------------------------------------------*/
#define ID_BTN_CLEAN     1001
#define ID_BTN_SCANAPPS  1002
#define ID_LIST_APPS     1003
#define ID_BTN_CLEANSEL  1004
#define ID_BTN_ANALYZE   1005

/* ============================================================================
 *  WHITELIST PROCESÓW KRYTYCZNYCH  (anti-masquerading)
 * ----------------------------------------------------------------------------
 *  KLUCZOWA RÓŻNICA vs wersja monolityczna:
 *  Stary kod chronił procesy TYLKO po nazwie pliku ("svchost.exe").
 *  To jest dziura: malware nazwane svchost.exe siedzące w
 *  C:\Users\...\AppData\ było OSZCZĘDZANE. (MITRE T1036 - Masquerading)
 *
 *  Tu trzymamy parę (nazwa, wymagany_katalog). Proces jest "legit" tylko
 *  gdy nazwa pasuje ORAZ leży tam, gdzie systemowo powinien.
 *  Nazwa pasuje + zła ścieżka  =>  to impostor, leci jak każdy inny.
 * ==========================================================================*/
typedef struct {
    const TCHAR* name;       /* nazwa pliku exe (lowercase porównanie)        */
    const TCHAR* required_dir; /* fragment ścieżki, w którym MUSI leżeć       */
} CriticalProc;

/* Minimalny zestaw procesów, bez których system natychmiast pada (BSOD)
 * lub nie da się go używać. Definicja w config.c. */
extern const CriticalProc DW_CRITICAL_PROCS[];
extern const size_t DW_CRITICAL_PROCS_COUNT;

/* ============================================================================
 *  PODEJRZANE LOKALIZACJE
 * ----------------------------------------------------------------------------
 *  Fragmenty ścieżek, z których "porządne" oprogramowanie systemowe
 *  zwykle NIE działa. Proces/usługa stąd = warta flagowania.
 *  Zastępuje stary hardcode "razer/nvidia/proton/vgk" - zamiast krucjaty
 *  na konkretnych vendorów, generyczna heurystyka lokalizacyjna.
 * ==========================================================================*/
extern const TCHAR* const DW_SUSPICIOUS_DIRS[];
extern const size_t DW_SUSPICIOUS_DIRS_COUNT;

/* ============================================================================
 *  WEKTORY PERSISTENCE  (do enumeracji i czyszczenia)
 * ==========================================================================*/

/* Klucze autorun (Run / RunOnce) - HKCU i HKLM */
typedef struct {
    HKEY  root;
    const TCHAR* subkey;
    const TCHAR* label;
} AutorunKey;

extern const AutorunKey DW_AUTORUN_KEYS[];
extern const size_t DW_AUTORUN_KEYS_COUNT;

/* Foldery, które czyścimy z zawartości (staging / cache / temp).
 * Definicja w config.c. */
extern const TCHAR* const DW_CLEAN_DIRS_RELATIVE[];
extern const size_t DW_CLEAN_DIRS_COUNT;

/* ============================================================================
 *  TRYBY PRACY
 * ==========================================================================*/
typedef enum {
    DW_MODE_GUI = 0,     /* brak argumentów -> GUI                           */
    DW_MODE_ANALYZE,     /* --analyze : tylko enumeracja, ZERO kasowania     */
    DW_MODE_NUKE,        /* --nuke    : pełny scorched-earth                 */
    DW_MODE_SCAN,        /* --scan PATH [DAYS]                               */
    DW_MODE_LIVE,        /* --live SECONDS                                   */
    DW_MODE_CLEAN,       /* --clean PATH                                     */
    DW_MODE_LUPA,        /* --lupa PROCESS                                   */
    DW_MODE_REPORT,      /* --report                                         */
    DW_MODE_PERSIST,     /* --persistence                                    */
    DW_MODE_HELP,
    DW_MODE_UNKNOWN
} DwMode;

#endif /* DEADWEIGHT_CONFIG_H */
