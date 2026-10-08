# DEADWEIGHT

**Windows Persistence Analyzer & System Nuke**

DEADWEIGHT to niskopoziomowe narzędzie Blue Team / DFIR przeznaczone do wykrywania oraz usuwania uporczywych mechanizmów autostartu (persistence) i złośliwych procesów w systemie Windows.

> ⚠️ **Uwaga:** Narzędzie przeznaczone do celów edukacyjnych i laboratoryjnych. Tryb `--nuke` sprowadza system do stanu minimalnego do momentu ponownego uruchomienia.

---

## Tryby pracy

Narzędzie oferuje dwa główne tryby operacyjne:

| Tryb | Opis działania | Charakterystyka |
| :--- | :--- | :--- |
| `--analyze` | Enumeracja procesów oraz wszystkich znanych wektorów persistence. | **Read-only** (bezpieczny do uruchomienia na żywo). |
| `--nuke` | Terminacja nieautoryzowanych procesów oraz czyszczenie punktów autostartu i plików tymczasowych. | **Destrukcyjny** (wymaga potwierdzenia wpisaniem `NUKE`). |

---

## Detekcja punktów persistence

DEADWEIGHT skanuje kluczowe obszary systemu Windows wykorzystywane do utrzymania uprawnień (z mapowaniem na MITRE ATT&CK):

* **Autorun:** Wpisy w rejestrze `Run` / `RunOnce` (HKCU, HKLM, WOW6432) *(T1547.001)*.
* **IFEO:** Injection przez Image File Execution Options *(T1546.012)*.
* **AppInit_DLLs:** Wstrzykiwanie bibliotek DLL *(T1546.010)*.
* **Winlogon:** Podmiana powłoki logowania *(T1547.004)*.
* **WMI Subscriptions:** Subskrypcje zdarzeń WMI *(T1546.003)*.
* **Scheduled Tasks:** Zadania harmonogramu spoza ścieżek `\Microsoft` i `\Windows` *(T1053.005)*.
* **Usługi systemowe:** Pliki wykonywalne usług zlokalizowane w niestandardowych ścieżkach *(T1543.003)*.

---

## Mechanizmy detekcji

### 1. Anti-Masquerading (Walidacja ścieżek)
Samo zweryfikowanie nazwy procesu jest niewystarczające ze względu na technikę **Masquerading** (MITRE T1036). DEADWEIGHT weryfikuje jednocześnie nazwę oraz ścieżkę pliku na dysku:

* **Poprawny:** `svchost.exe` w `C:\Windows\System32\` → Proces systemowy.
* **Anomalia:** `svchost.exe` w `C:\Users\...\AppData\` → Proces nieprawidłowy, podlegający terminacji i oznaczony w logach jako `[MASQUERADE?]`.

### 2. Weryfikacja podpisu cyfrowego (Authenticode)
Aby uniknąć fałszywych alarmów (False Positives) w odniesieniu do zaufanego oprogramowania uruchamianego z katalogów takich jak `ProgramData` (np. Windows Defender), zastosowano dwuetapową walidację opartą o `WinVerifyTrust`:

1. **Identyfikacja:** Wykrycie pliku w nierutynowej lokalizacji.
2. **Kwalifikacja:** Sprawdzenie podpisu Authenticode:
   * Plik w nierutynowej lokalizacji + **poprawny podpis Microsoft/Vendor** → Brak flagowania.
   * Plik niepodpisany, z wygasłym lub zerwanym podpisem → Oznaczenie jako `SUSPECT` / `bad-sig` i usunięcie w trybie `--nuke`.

---

## Ograniczenia techniczne

1. **Process Injection (MITRE T1055):** Narzędzie weryfikuje wyłącznie pliki wykonywalne na dysku. Kod wstrzyknięty do pamięci zaufanego procesu (np. `explorer.exe`) nie jest obecnie wykrywany (wymaga analizy pamięci RAM).
2. **Nadużycia certyfikatów:** Sam fakt posiadania ważnego podpisu cyfrowego nie gwarantuje braku złośliwego charakteru w przypadku użycia skradzionych certyfikatów.
3. **Uprawnienia PPL (Protected Process Light):** Procesy chronione mogą zwracać odmowę dostępu (`Access Denied`) nawet z uprawnieniami administratora.
4. **Interfejs WMI:** Moduł czyszczenia WMI opiera się obecnie na narzędziu `wmic` (planowana migracja na interfejs COM).

---

## Składniki projektu

```text
src/
├── config.h         # Konfiguracja stałych, whitelist i wektorów persistence
├── log.h / .c       # Zunifikowany moduł logowania zdarzeń
├── persistence.h/.c # Enumeracja oraz czyszczenie punktów autostartu
├── processes.h/.c   # Zarządzanie procesami i Anti-Masquerade
├── cleanup.h/.c     # Czyszczenie katalogów Temp, Prefetch i Staging
├── forensics.h/.c   # Generowanie raportów i pasywna analiza systemowa
└── main.c           # Punkt wejścia (CLI/GUI router)
```

---

## Przykłady użycia

```sh
# Pełna enumeracja systemu w trybie read-only (zalecany start)
deadweight.exe --analyze

# Analiza punktów persistence
deadweight.exe --persistence

# Generowanie raportu systemowego (CPU, RAM, Dysk, Prefetch)
deadweight.exe --report

# Szczegółowa analiza wskazanego procesu pod kątem masquerading
deadweight.exe --lupa svchost.exe

# Monitorowanie procesów w czasie rzeczywistym (np. przez 30s)
deadweight.exe --live 30

# Agresywne czyszczenie punktów persistence i nieautoryzowanych procesów
deadweight.exe --nuke
```

---

## Kompilacja

Projekt nie posiada zewnętrznych zależności (.NET/runtime). Kompilowany jest natywnie przy użyciu narzędzi MinGW-w64:

```sh
x86_64-w64-mingw32-gcc src/*.c -o deadweight.exe \
    -municode -lshlwapi -lpsapi -lcomctl32 -lwintrust -lcrypt32
```

---

## 📝 Lekcje z praktyki (Lessons Learned)

Pierwotna wersja narzędzia w trybie czyszczenia usuwała również pliki `.inf` oraz sterowniki z katalogu `DriverStore`. W założeniu miało to być bezkompromisowe usuwanie śladów infekcji, w praktyce doprowadziło do uszkodzenia struktury systemu (próba uruchomienia drugiego systemu z konfiguracji dual-boot po użyciu `--nuke` uniemożliwiła późniejszy start Windowsa).

Wycofano ten mechanizm w nowej wersji narzędzia. `DEADWEIGHT` celuje precyzyjnie w **procesy i punkty persistence**, omijając krytyczne pliki i sterowniki systemowe.

> **Wskazówka przy dual-boot:** Po wykonaniu operacji `--nuke` zawsze uruchom ponownie Windows, zanim przełączysz się na inny system operacyjny.

---

## Roadmap

- [x] Refaktoryzacja kodu do architektury modułowej
- [x] Weryfikacja procesów po parze nazwa + ścieżka (Anti-Masquerading)
- [x] Walidacja podpisów cyfrowych Authenticode (`WinVerifyTrust`)
- [x] Implementacja bezpiecznego trybu read-only (`--analyze`)
- [ ] Ekstrakcja szczegółowych danych wydawcy do raportów (`CryptQueryObject`)
- [ ] Detekcja Process Injection w pamięci operacyjnej (T1055)
- [ ] Migracja modułu WMI z `wmic` na API COM
- [ ] Eksport raportów do formatu JSON
