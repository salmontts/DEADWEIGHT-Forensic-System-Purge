# DEADWEIGHT

**Windows persistence analyzer & system nuke** — narzędzie, które powstało
w walce z uporczywą, samoodtwarzającą się infekcją. Filozofia jest prosta:
czasem szybciej **spalić i odbudować** niż gonić polimorficzny payload, który
wstaje z każdego rebootu.

> ⚠️ Narzędzie edukacyjne / lab. Uruchamiaj **wyłącznie na własnym sprzęcie**.
> Tryb `--nuke` celowo wprowadza system w stan minimalny do czasu restartu.

---

## Dwa tryby, jedna idea

DEADWEIGHT myśli jak atakujący (gdzie chowa się persistence?), żeby działać
jak obrońca (jak to wszystko naraz usunąć). Stąd dwa tryby:

| Tryb | Co robi | Destrukcyjny? |
|------|---------|---------------|
| `--analyze` | Enumeruje **wszystkie** wektory persistence + procesy, flaguje podejrzane | ❌ Nie — czysty read-only |
| `--nuke` | Czyści persistence, temp/staging i ubija procesy poza krytycznymi | ✅ Tak — scorched earth |

`--analyze` jest bezpieczny do uruchomienia na żywo — pokazuje, co narzędzie
*widzi*, zanim cokolwiek ruszy. `--nuke` to pełna gilotyna.

---

## Co DEADWEIGHT rozumie o persistence

Narzędzie zna miejsca, w których malware zaczepia się o system (mapowanie na
MITRE ATT&CK w nawiasach):

- **Autorun** — `Run` / `RunOnce`, HKCU + HKLM + Wow6432 (T1547.001)
- **IFEO debuggers** — Image File Execution Options (T1546.012)
- **AppInit_DLLs** — wstrzykiwanie DLL do procesów (T1546.010)
- **Winlogon Shell** — podmiana powłoki logowania (T1547.004)
- **WMI subscriptions** — event-consumer persistence (T1546.003)
- **Scheduled tasks** — zadania spoza `\Microsoft` / `\Windows` (T1053.005)
- **Usługi** — binarki w podejrzanych lokalizacjach (T1543.003)

---

## Anti-masquerading: dlaczego whitelist po ścieżce, nie po nazwie

Najważniejszy element trybu `--nuke`. Naiwny "kill all" oszczędza procesy po
**nazwie pliku** — i właśnie tu chowa się malware. Proces nazwany `svchost.exe`
siedzący w `C:\Users\...\AppData\Roaming\` nie jest prawdziwym `svchost`.
To klasyczny **masquerading** (MITRE T1036).

DEADWEIGHT weryfikuje **parę (nazwa + ścieżka)**:

```
svchost.exe  w  C:\Windows\System32\       -> prawdziwy, oszczędzony
svchost.exe  w  C:\Users\...\AppData\...    -> impostor, ubity + [MASQUERADE?] w logu
```

Prawdziwe procesy systemowe zawsze leżą tam, gdzie powinny. Wszystko inne,
co tylko *udaje* nazwę systemową, leci jak każdy inny śmieć.

---

## Weryfikacja podpisu cyfrowego: jak nie krzyczeć na Windows Defender

Flagowanie po samej ścieżce ma słaby punkt: mnóstwo **legalnego** softu działa
z `ProgramData` (Windows Defender, NVIDIA). Pierwsza wersja `--analyze`
rzetelnie oznaczała je wszystkie jako `SUSPECT` — czyli tonała w false-positives.
Narzędzie, które krzyczy na Defendera, jest bezużyteczne dla analityka.

Rozwiązanie: druga warstwa decyzji — **podpis Authenticode** (`WinVerifyTrust`).
Podejrzana ścieżka to dopiero sygnał; o flagowaniu decyduje dopiero brak
zaufanego podpisu:

```
Defender w ProgramData, podpisany przez Microsoft   -> OK (signed), nie flaguj
NVIDIA  w ProgramData, podpisany przez NVIDIA Corp.  -> OK (signed), nie flaguj
random.exe w AppData, niepodpisany                  -> SUSPECT (unsigned)
fake.exe w Temp, podpis zerwany / wygasły            -> SUSPECT (bad-sig)
```

To jest dokładnie kryterium, którego używają prawdziwe narzędzia DFIR:
nie *gdzie* leży plik, tylko *kto za niego ręczy*. W trybie `--nuke` ta sama
logika chroni podpisane usługi systemowe przed skasowaniem — nuke kasuje tylko
NIEzaufane binarki z podejrzanych lokalizacji.

---

## Znane ograniczenia

Oto granice DEADWEIGHT:

**1. Process injection (MITRE T1055) — najważniejsza ślepa plama.**
Weryfikacja podpisu sprawdza **plik na dysku**. Nie wykrywa sytuacji, gdy obcy
kod działa *wewnątrz* podpisanego, legalnego procesu — DLL injection, process
hollowing, reflective loading. Plik `explorer.exe` na dysku jest wtedy czysty
i podpisany, a w jego pamięci siedzi payload. Wykrycie tego wymaga **analizy
pamięci**: skan regionów RWX, porównanie modułów w pamięci z plikami na dysku,
wykrywanie hooków API. To kierunek dalszego rozwoju, nie obecna funkcja.

**2. Podpis ≠ zaufanie bezwzględne.** Ważny podpis mówi "ten plik jest tym, za
co się podaje, i ktoś za niego ręczy" — ale skradzione certyfikaty i
sign-then-compromise istnieją. Podpis podnosi poprzeczkę, nie daje gwarancji.

**3. Zależność od uprawnień.** Część procesów (PPL, protected) zwraca
"access denied" nawet z prawami administratora — DEADWEIGHT oznacza je jako
nieweryfikowalne i, dla bezpieczeństwa, oszczędza znane nazwy systemowe.

**4. WMI przez `wmic`.** Czyszczenie subskrypcji WMI używa deprecated `wmic`;
na najnowszych Windows należy to przepisać na COM (w roadmapie).

---

## Architektura

Modułowa — cienki router (`main.c`) plus samodzielne moduły, każdy z własnym
nagłówkiem. Cała konfiguracja (whitelisty, ścieżki, wektory) siedzi w jednym
`config.h`.

```
src/
├── config.h         Wszystkie stałe, whitelisty, wektory persistence
├── log.h / .c       Jednolite logowanie (purge + analysis)
├── persistence.h/.c Enumeracja + czyszczenie persistence (analyze | purge)
├── processes.h/.c   Kill / monitor / lupa + ANTI-MASQUERADE (ścieżka!)
├── cleanup.h/.c     Temp / prefetch / staging
├── forensics.h/.c   Scan / prefetch / services / report (read-only)
└── main.c           Router CLI/GUI + dispatch trybów
```

---

## Użycie

```sh
deadweight.exe --analyze          # pełna enumeracja, NIC nie kasuje (start tu)
deadweight.exe --persistence      # tylko wektory persistence
deadweight.exe --report           # raport systemowy (CPU/RAM/dyski/prefetch)
deadweight.exe --lupa svchost.exe # szczegóły procesu + wykrycie masquerade
deadweight.exe --live 30          # monitor procesów przez 30 s
deadweight.exe --scan D:\Downloads 60   # pliki nieużywane 60+ dni
deadweight.exe --clean C:\Temp\Stuff    # usuń drzewo (z potwierdzeniem)
deadweight.exe --nuke             # SCORCHED EARTH (wymaga wpisania "NUKE")
```

---

## ⚠️ Lekcja z własnej skóry

Pierwsza wersja tego narzędzia kasowała też sterowniki i pliki `.inf` z
DriverStore — w teorii "agresywne czyszczenie", w praktyce **uszkodzenie
instalacji Windows**. Raz po `--nuke` wystartowałem dualboota z Linuksa przed
rebootem Windowsa i system się już nie podniósł.

Refaktor to wyciął. Nuke nadal jest nukiem, ale celuje w
**persistence i procesy**, a nie w bebechy systemu.

> Jeśli masz dualboot: po `--nuke` **zrebootuj Windows**, zanim odpalisz
> inny system.

---

## Build

```sh
x86_64-w64-mingw32-gcc src/*.c -o deadweight.exe \
    -municode -lshlwapi -lpsapi -lcomctl32 -lwintrust -lcrypt32
```

Zależności: tylko standardowe biblioteki Windows. Bez .NET, bez runtime'u.
Szczegóły w `BUILD.md`.

---

## Status & roadmap

- [x] Modułowy refaktor (z monolitu 1517 linii)
- [x] Whitelist procesów po ścieżce (anti-masquerade)
- [x] Weryfikacja podpisu Authenticode (eliminacja false-positives)
- [x] DFIR-grade logowanie (faktyczne znaleziska, nie tylko "completed")
- [x] Tryb `--analyze` (read-only)
- [x] Usunięcie driver-killing buga
- [x] Dedup logiki persistence
- [ ] Odczyt nazwy wydawcy do outputu (CryptQueryObject już jest w kodzie)
- [ ] Detekcja process injection (skan RWX, moduły pamięć-vs-dysk) — T1055
- [ ] Enumeracja WMI przez COM (zamiast deprecated `wmic`)
- [ ] Export raportu do JSON (dla pipeline'u DFIR)
- [ ] Makefile + CI build

---

## Disclaimer

Narzędzie do nauki i autoryzowanych testów we własnym środowisku.
Nie uruchamiaj na cudzych systemach ani na produkcji.
