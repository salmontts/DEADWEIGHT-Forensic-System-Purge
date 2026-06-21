/* ============================================================================
 *  persistence.h  --  DEADWEIGHT: wektory persistence
 * ==========================================================================*/
#ifndef DEADWEIGHT_PERSISTENCE_H
#define DEADWEIGHT_PERSISTENCE_H

#include "config.h"

/* ANALYZE (read-only): wypisuje wszystkie znalezione wektory persistence.
 * Nic nie kasuje. Bezpieczne do pokazania na żywo. */
void dw_analyze_persistence(void);

/* NUKE: czyści wszystkie wektory persistence (Run/RunOnce, IFEO, AppInit,
 * Winlogon Shell, WMI subscriptions, scheduled tasks spoza Microsoft/Windows).
 *
 * UWAGA: NIE kasuje sterowników ani plików .inf - to był bug wersji
 * monolitycznej, który potrafił uszkodzić instalację Windows. */
void dw_purge_persistence(void);

#endif /* DEADWEIGHT_PERSISTENCE_H */
