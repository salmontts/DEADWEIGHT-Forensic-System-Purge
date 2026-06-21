/* ============================================================================
 *  signature.h  --  DEADWEIGHT: weryfikacja podpisu cyfrowego (Authenticode)
 * ----------------------------------------------------------------------------
 *  Pozwala odróżnić binarkę podpisaną przez zaufanego wydawcę (Microsoft,
 *  NVIDIA, itd.) od niepodpisanego pliku w tej samej "podejrzanej" lokalizacji.
 *
 *  To eliminuje false-positives: Windows Defender działa z ProgramData, ale
 *  jest podpisany przez Microsoft -> nie jest zagrożeniem. Malware w tym samym
 *  ProgramData zwykle NIE ma ważnego podpisu -> zostaje sflagowane.
 * ==========================================================================*/
#ifndef DEADWEIGHT_SIGNATURE_H
#define DEADWEIGHT_SIGNATURE_H

#include "config.h"

typedef enum {
    DW_SIG_TRUSTED = 0,   /* ważny podpis Authenticode, zaufany łańcuch     */
    DW_SIG_UNSIGNED,      /* brak podpisu                                    */
    DW_SIG_UNTRUSTED,     /* podpis jest, ale niezaufany / wygasły / zerwany */
    DW_SIG_ERROR          /* nie dało się zweryfikować (brak pliku, błąd)    */
} DwSigStatus;

/* Weryfikuje podpis Authenticode pliku pod podaną ścieżką.
 * Ścieżka może zawierać argumenty/cudzysłowy z rejestru - funkcja sama
 * wyłuska właściwą ścieżkę do .exe. */
DwSigStatus dw_check_signature(const TCHAR* path_with_args);

/* Pobiera nazwę wydawcy (subject) z certyfikatu, jeśli dostępna.
 * out może dostać np. "Microsoft Windows", "NVIDIA Corporation".
 * Zwraca FALSE jeśli nie udało się odczytać. */
BOOL dw_get_signer_name(const TCHAR* exe_path, TCHAR* out, DWORD out_len);

/* Pomocnik: wyłuskuje czystą ścieżkę .exe z ciągu typu
 * "\"C:\\Path\\app.exe\" --arg"  ->  C:\Path\app.exe                        */
void dw_extract_exe_path(const TCHAR* raw, TCHAR* out, size_t out_len);

/* Tekstowa etykieta statusu (do logów/outputu). */
const TCHAR* dw_sig_label(DwSigStatus s);

#endif /* DEADWEIGHT_SIGNATURE_H */
