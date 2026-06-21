/* ============================================================================
 *  cleanup.h  --  DEADWEIGHT: czyszczenie temp / staging / cache
 * ==========================================================================*/
#ifndef DEADWEIGHT_CLEANUP_H
#define DEADWEIGHT_CLEANUP_H

#include "config.h"

/* Rekurencyjnie usuwa ZAWARTOŚĆ folderu (nie sam folder). */
void dw_delete_folder_contents(const TCHAR* folder);

/* Rekurencyjnie usuwa folder wraz z zawartością. Zwraca TRUE przy sukcesie. */
BOOL dw_delete_tree(const TCHAR* folder);

/* NUKE: czyści standardowe lokalizacje staging/temp/prefetch. */
void dw_purge_temp_locations(void);

/* CLI --clean: usuwa wskazane drzewo katalogów z potwierdzeniem. */
void dw_clean_path_interactive(const TCHAR* folder_path);

#endif /* DEADWEIGHT_CLEANUP_H */
