/* ============================================================================
 *  main.c  --  DEADWEIGHT: router CLI/GUI
 * ----------------------------------------------------------------------------
 *  Cienki dispatcher. Nie zawiera logiki - tylko parsuje tryb i woła moduły.
 *  (Ten sam wzorzec co main.cpp we Flipsonie: router, nie silnik.)
 *
 *  Tryby:
 *    (brak)         -> GUI
 *    --analyze      -> pełna enumeracja read-only (nic nie kasuje) [DO POKAZU]
 *    --nuke         -> scorched-earth: persistence + temp + kill-all
 *    --scan P [D]   -> stare pliki w katalogu
 *    --live S       -> monitor procesów
 *    --clean P      -> usuń drzewo katalogów (z potwierdzeniem)
 *    --lupa NAME    -> szczegóły procesu
 *    --report       -> raport systemowy
 *    --persistence  -> enumeracja wektorów persistence
 *    --help
 * ==========================================================================*/
#include "config.h"
#include "log.h"
#include "persistence.h"
#include "processes.h"
#include "cleanup.h"
#include "forensics.h"
#include <stdio.h>
#include <commctrl.h>

/* (Biblioteki linkujemy przez flagi -l w komendzie kompilacji, nie przez
 *  #pragma comment - to ostatnie jest MSVC-specyficzne i GCC je ignoruje.)
 *  Build:
 *    x86_64-w64-mingw32-gcc  src(slash-gwiazdka).c  -o deadweight.exe \
 *        -municode -lshlwapi -lpsapi -lcomctl32
 */

/* ---- NUKE: pełna sekwencja scorched-earth --------------------------------*/
static void dw_run_nuke(BOOL skipConfirm) {
    if (!skipConfirm) {
        _tprintf(_T("\n"));
        _tprintf(_T("  ##############################################################\n"));
        _tprintf(_T("  #  DEADWEIGHT --nuke : SCORCHED EARTH                        #\n"));
        _tprintf(_T("  #                                                            #\n"));
        _tprintf(_T("  #  Zabije wszystkie procesy poza krytycznymi, wyczysci       #\n"));
        _tprintf(_T("  #  WSZYSTKIE wektory persistence, temp, prefetch, staging.   #\n"));
        _tprintf(_T("  #  System wpadnie w stan minimalny (zombie) az do rebootu.   #\n"));
        _tprintf(_T("  #                                                            #\n"));
        _tprintf(_T("  #  >> NIE startuj innego OS z dualboota przed rebootem. <<    #\n"));
        _tprintf(_T("  #  >> Uruchamiaj WYLACZNIE na wlasnym sprzecie/labie.   <<    #\n"));
        _tprintf(_T("  ##############################################################\n\n"));
        _tprintf(_T("  Wpisz NUKE aby kontynuowac: "));
        TCHAR resp[16];
        if (!_fgetts(resp, 16, stdin)) return;
        TCHAR* nl = _tcspbrk(resp, _T("\r\n")); if (nl) *nl = _T('\0');
        if (_tcscmp(resp, _T("NUKE")) != 0) {
            _tprintf(_T("  Anulowano.\n"));
            return;
        }
    }

    dw_log_purge(_T("=== NUKE START ==="));
    _tprintf(_T("\n[1/3] Czyszczenie persistence...\n"));
    dw_purge_persistence();
    _tprintf(_T("[2/3] Czyszczenie temp/staging...\n"));
    dw_purge_temp_locations();
    _tprintf(_T("[3/3] Ubijanie procesow (whitelist po sciezce)...\n"));
    dw_kill_non_essential();
    dw_log_purge(_T("=== NUKE END ==="));
    _tprintf(_T("\nGotowe. Zalecany reboot.\n"));
}

/* ---- ANALYZE: pełna enumeracja read-only ---------------------------------*/
static void dw_run_analyze(void) {
    _tprintf(_T("\n##### DEADWEIGHT --analyze : READ-ONLY (nic nie jest kasowane) #####\n"));
    dw_analyze_persistence();
    dw_analyze_processes();
    dw_log(_T("analyze"), _T("Full read-only sweep completed"));
    _tprintf(_T("\n##### Koniec analizy. Zero zmian w systemie. #####\n"));
}

/* ---- Parser trybu --------------------------------------------------------*/
static DwMode parse_mode(const TCHAR* arg) {
    if (_tcsicmp(arg, _T("--analyze"))     == 0) return DW_MODE_ANALYZE;
    if (_tcsicmp(arg, _T("--nuke"))        == 0) return DW_MODE_NUKE;
    if (_tcsicmp(arg, _T("--scan"))        == 0) return DW_MODE_SCAN;
    if (_tcsicmp(arg, _T("--live"))        == 0) return DW_MODE_LIVE;
    if (_tcsicmp(arg, _T("--clean"))       == 0) return DW_MODE_CLEAN;
    if (_tcsicmp(arg, _T("--lupa"))        == 0) return DW_MODE_LUPA;
    if (_tcsicmp(arg, _T("--report"))      == 0) return DW_MODE_REPORT;
    if (_tcsicmp(arg, _T("--persistence")) == 0) return DW_MODE_PERSIST;
    if (_tcsicmp(arg, _T("--help"))        == 0) return DW_MODE_HELP;
    return DW_MODE_UNKNOWN;
}

static void print_usage(void) {
    _tprintf(_T("\n%s v%s - Windows persistence analyzer / system nuke\n"), DW_NAME, DW_VERSION);
    _tprintf(_T("Usage: deadweight.exe [MODE] [ARG]\n\n"));
    _tprintf(_T("  --analyze            Pelna enumeracja read-only (NIC nie kasuje)\n"));
    _tprintf(_T("  --nuke               Scorched-earth: persistence + temp + kill-all\n"));
    _tprintf(_T("  --persistence        Enumeracja wektorow persistence (read-only)\n"));
    _tprintf(_T("  --scan PATH [DAYS]   Stare pliki w katalogu (domyslnie 30 dni)\n"));
    _tprintf(_T("  --live SECONDS       Monitor nowych/zakonczonych procesow\n"));
    _tprintf(_T("  --clean PATH         Usun drzewo katalogow (z potwierdzeniem)\n"));
    _tprintf(_T("  --lupa PROCESS.exe   Szczegolowa analiza procesu\n"));
    _tprintf(_T("  --report             Raport systemowy\n"));
    _tprintf(_T("  --help               Ta pomoc\n"));
    _tprintf(_T("\n  (brak argumentow -> GUI)\n"));
}

/* ---- GUI -----------------------------------------------------------------*/
LRESULT CALLBACK MainWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        CreateWindowEx(0, WC_BUTTON, _T("ANALYZE (safe)"),
                       WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                       30, 30, 150, 40, hWnd, (HMENU)ID_BTN_ANALYZE,
                       GetModuleHandle(NULL), NULL);
        CreateWindowEx(0, WC_BUTTON, _T("NUKE"),
                       WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                       200, 30, 100, 40, hWnd, (HMENU)ID_BTN_CLEAN,
                       GetModuleHandle(NULL), NULL);
        break;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_BTN_ANALYZE:
            MessageBox(hWnd,
                _T("Analiza read-only wypisuje wyniki w konsoli.\n")
                _T("Uruchom: deadweight.exe --analyze"),
                DW_NAME, MB_OK | MB_ICONINFORMATION);
            break;
        case ID_BTN_CLEAN: {
            int r = MessageBox(hWnd,
                _T("NUKE: ubije procesy, wyczysci persistence i temp.\n")
                _T("System przejdzie w stan minimalny do rebootu.\n\n")
                _T("Kontynuowac?"),
                DW_NAME, MB_YESNO | MB_ICONWARNING);
            if (r == IDYES) {
                dw_run_nuke(TRUE);  /* GUI: bez konsolowego potwierdzenia */
                MessageBox(hWnd, _T("Nuke wykonany. Zalecany reboot."),
                           DW_NAME, MB_OK | MB_ICONINFORMATION);
            }
            break;
        }
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}

static int run_gui(void) {
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    WNDCLASS wc = {0};
    wc.lpfnWndProc   = MainWndProc;
    wc.hInstance     = GetModuleHandle(NULL);
    wc.lpszClassName = _T("DeadweightMainWnd");
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    RegisterClass(&wc);

    HWND hWnd = CreateWindowEx(0, _T("DeadweightMainWnd"),
                    _T("DEADWEIGHT v2.0"),
                    WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                    CW_USEDEFAULT, CW_USEDEFAULT, 350, 140,
                    NULL, NULL, GetModuleHandle(NULL), NULL);
    ShowWindow(hWnd, SW_SHOWNORMAL);
    UpdateWindow(hWnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return (int)msg.wParam;
}

/* ---- Entry point ---------------------------------------------------------*/
int _tmain(int argc, TCHAR* argv[]) {
    if (argc < 2) return run_gui();

    switch (parse_mode(argv[1])) {
    case DW_MODE_ANALYZE:  dw_run_analyze(); break;
    case DW_MODE_NUKE:     dw_run_nuke(FALSE); break;
    case DW_MODE_PERSIST:  dw_analyze_persistence(); break;
    case DW_MODE_REPORT:   dw_generate_report(); break;

    case DW_MODE_SCAN:
        if (argc < 3) { _tprintf(_T("Brak sciezki.\n")); return 1; }
        dw_scan_directory(argv[2], argc >= 4 ? _ttoi(argv[3]) : 30);
        break;

    case DW_MODE_LIVE:
        if (argc < 3) { _tprintf(_T("Brak czasu.\n")); return 1; }
        { int s = _ttoi(argv[2]); dw_monitor_processes(s > 0 ? s : 15); }
        break;

    case DW_MODE_CLEAN:
        if (argc < 3) { _tprintf(_T("Brak sciezki.\n")); return 1; }
        dw_clean_path_interactive(argv[2]);
        break;

    case DW_MODE_LUPA:
        if (argc < 3) { _tprintf(_T("Brak nazwy procesu.\n")); return 1; }
        dw_lupa_mode(argv[2]);
        break;

    case DW_MODE_HELP:
        print_usage();
        break;

    default:
        _tprintf(_T("Nieznana komenda: %s\n"), argv[1]);
        print_usage();
        return 1;
    }
    return 0;
}
