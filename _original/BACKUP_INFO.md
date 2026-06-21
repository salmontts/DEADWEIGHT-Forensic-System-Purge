# Backup oryginału — DEADWEIGHT

Oryginalny monolityczny `deadweight.c` (1517 linii) i README sprzed refaktoru
są zachowane w historii git na GitHubie:

  https://github.com/salmontts/DEADWEIGHT-Forensic-System-Purge

Jeśli kiedykolwiek chcesz wrócić do pierwotnej wersji:
  git log --oneline
  git checkout <hash_sprzed_refaktoru> -- deadweight.c

Refaktor (modułowy podział, fix driver-killing buga, whitelist-po-ścieżce,
tryby --nuke / --analyze) powstaje w folderze nadrzędnym tego katalogu.

Data rozpoczęcia refaktoru: 2026.
