/* ============================================================================
 *  forensics.h  --  DEADWEIGHT: analiza read-only (scan / prefetch / report)
 * ==========================================================================*/
#ifndef DEADWEIGHT_FORENSICS_H
#define DEADWEIGHT_FORENSICS_H

#include "config.h"

void dw_scan_directory(const TCHAR* path, int daysThreshold);
void dw_analyze_prefetch(void);
void dw_analyze_services(void);
void dw_generate_report(void);

#endif /* DEADWEIGHT_FORENSICS_H */
