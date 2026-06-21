# Build — DEADWEIGHT

## Wymagania

- **MinGW-w64** (cross-compile z Linuksa) lub **MSYS2/MinGW** na Windows
- Tylko standardowe biblioteki Windows — bez .NET, bez zewnętrznego runtime'u

## Kompilacja

Z katalogu głównego projektu:

```sh
gcc src/*.c -o deadweight.exe -municode -lshlwapi -lpsapi -lcomctl32 -lwintrust -lcrypt32

```

Flagi:
- `-municode` — wide-char entry point (`wmain`) + Unicode CRT.
  **Wymagane** — bez tego `_T()`/`TCHAR` rozjadą się na ANSI.
- `-lshlwapi` — `PathAppend`, `PathRemoveFileSpec`
- `-lpsapi` — `GetProcessMemoryInfo`, `GetModuleFileNameEx`
- `-lcomctl32` — kontrolki GUI
- `-lwintrust` — `WinVerifyTrust` (weryfikacja podpisu Authenticode)
- `-lcrypt32` — `CryptQueryObject`, odczyt nazwy wydawcy z certyfikatu

Kompilacja jest czysta: **zero warningów** nawet z `-Wall`.

## Uruchamianie (wymaga uprawnień administratora)

Większość operacji (HKLM, usługi, procesy systemowe) wymaga elevacji.
Uruchom konsolę jako administrator, potem:

```sh
deadweight.exe --analyze        # bezpieczny start: tylko enumeracja
deadweight.exe --help           # lista trybów
```

## Uwaga dla testów

- `--analyze`, `--report`, `--persistence`, `--scan`, `--lupa`, `--live`
  są **nieniszczące** — można je puszczać bez ryzyka.
- `--nuke` i `--clean` **modyfikują system**. Testuj na maszynie wirtualnej
  lub sprzęcie, który możesz odbudować. Po `--nuke` zrób reboot Windowsa
  zanim odpalisz inny OS (dualboot).

## Struktura

```
deadweight/
├── src/
│   ├── config.h / config.c     stałe, whitelisty, wektory persistence
│   ├── log.h / log.c           jednolite logowanie
│   ├── persistence.h / .c      enumeracja + czyszczenie persistence
│   ├── processes.h / .c        kill / monitor / lupa + anti-masquerade
│   ├── cleanup.h / .c          temp / prefetch / staging
│   ├── forensics.h / .c        scan / prefetch / services / report
│   ├── signature.h / .c        weryfikacja podpisu Authenticode (anti-FP)
│   └── main.c                  router CLI/GUI
├── README.md
├── BUILD.md
└── _original/                  backup info (oryginał w historii git)
```
