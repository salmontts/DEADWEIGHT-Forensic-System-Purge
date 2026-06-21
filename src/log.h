/* ============================================================================
 *  log.h  --  DEADWEIGHT: jednolite logowanie
 * ----------------------------------------------------------------------------
 *  Stary kod miał DWA niezależne systemy logów (log_purge_action -> ANSI fopen,
 *  dump_log -> TCHAR _tfopen z modułem). Scalone w jeden interfejs.
 *
 *  dw_log_purge()    -> akcje destrukcyjne (deadweight_purge.log)
 *  dw_log()          -> analiza / forensics z nazwą modułu (deadweight.log)
 * ==========================================================================*/
#ifndef DEADWEIGHT_LOG_H
#define DEADWEIGHT_LOG_H

#include "config.h"

/* Log akcji destrukcyjnej (purge). Pisze do DW_LOG_PURGE z timestampem. */
void dw_log_purge(const TCHAR* msg);

/* Log analityczny z etykietą modułu. Pisze do DW_LOG_ANALYSIS. */
void dw_log(const TCHAR* module, const TCHAR* message);

/* Formatowany wariant dw_log (printf-style). Dla DFIR-grade znalezisk. */
void dw_logf(const TCHAR* module, const TCHAR* fmt, ...);

/* Wygodny wariant z printf-style formatowaniem dla logu purge. */
void dw_log_purgef(const TCHAR* fmt, ...);

#endif /* DEADWEIGHT_LOG_H */
