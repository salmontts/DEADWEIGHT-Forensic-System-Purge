/* ============================================================================
 *  processes.h  --  DEADWEIGHT: procesy (kill + monitor + anti-masquerade)
 * ==========================================================================*/
#ifndef DEADWEIGHT_PROCESSES_H
#define DEADWEIGHT_PROCESSES_H

#include "config.h"

/* Czy proces (nazwa + pełna ścieżka) jest krytyczny dla systemu?
 * Sprawdza nazwę ORAZ czy leży w wymaganym katalogu (anti-masquerade).
 * full_path może być NULL/pusty (proces protected, brak dostępu) -> wtedy
 * dla bezpieczeństwa traktujemy znaną nazwę systemową jako krytyczną. */
BOOL dw_is_critical_process(const TCHAR* name, const TCHAR* full_path);

/* Czy ścieżka wskazuje na podejrzaną lokalizację (Temp/AppData/Downloads...)? */
BOOL dw_is_suspicious_path(const TCHAR* full_path);

/* Pobiera pełną ścieżkę exe dla danego PID. Zwraca FALSE jeśli brak dostępu. */
BOOL dw_get_process_path(DWORD pid, TCHAR* out, DWORD out_len);

/* NUKE: zabija wszystkie procesy poza krytycznymi (whitelist po ścieżce).
 * Procesy z podejrzanych lokalizacji oznacza w logu jako [MASQUERADE?]. */
void dw_kill_non_essential(void);

/* ANALYZE (read-only): wypisuje procesy, flagując podejrzane. Nic nie zabija. */
void dw_analyze_processes(void);

/* Monitor: śledzi nowe/zakończone procesy przez N sekund. */
void dw_monitor_processes(int duration_seconds);

/* Lupa: szczegółowa analiza jednego procesu po nazwie. */
void dw_lupa_mode(const TCHAR* process_name);

#endif /* DEADWEIGHT_PROCESSES_H */
