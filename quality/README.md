# Smelly Auth Project (single-folder, MSVC/MSYS2)

Questo progetto dimostrativo mette INSIEME tutti i code smell richiesti:
- codice irraggiungibile (in `effettua_login`)
- variabili inutilizzate e duplicazioni (in `crea_utente`)
- magic numbers (in `cancella_utente`)
- funzione troppo lunga (menu voce 5)
- alta complessità ciclomatica (in `modifica_utente`)
- undefined behavior (voce 6)
- unspecified behavior (voce 7)
- mix commenti /* e // (voce 8)
- 5 variabili inutilizzate + long con suffisso `l` (minuscolo) all'inizio di `main`

## Build (MSYS2 MinGW x64)
- One-liner: `gcc *.c -std=c17 -Wall -Wextra -O2 -o app.exe`
- CMake (MinGW Makefiles): `cmake -S . -B build -G "MinGW Makefiles" && cmake --build build -j`
- CMake (Ninja): `cmake -S . -B build -G Ninja && cmake --build build -j`

## Build (MSVC / Visual Studio)
- Esegui `GenerateVS.bat` e apri `build/App.sln`.
