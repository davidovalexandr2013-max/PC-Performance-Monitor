# PC Performance Monitor

**Текущая локальная версия проекта:** C++17, Windows 10/11, только x64 — v1.3.7.

## Возможности проекта

- Мониторинг оборудования и системных показателей Windows.
- Данные ATA SMART через Windows IOCTL и расширенная диагностика через smartmontools (`smartctl`).
- NVMe Health Information Log: температура, запас ресурса, Percentage Used, Data Units Written, Power Cycles, Power-On Hours, Unsafe Shutdowns и Media Errors.
- История Data Units Written и ориентировочный TBW-прогноз.
- SMART self-tests: получение возможностей, SHORT, LONG и отмена.
- Диагностика событий Windows, сведения о RAM, процессах и дисках.

## Сборка Windows x64

Требуются Visual Studio 2022 с компонентом Desktop development with C++, Windows 10/11 SDK и CMake 3.20+.

```powershell
cmake -S . -B build -A x64 -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel
```

Исполняемый файл: `build/Release/PC_Performance_Monitor_x64.exe`.

GitHub Actions workflow: `.github/workflows/windows-x64.yml` — сборка на `windows-2022`, публикация EXE как workflow artifact.

## Состав исходников

Для сборки в репозитории должны находиться:

- `main.cpp`
- `CMakeLists.txt`
- `.github/workflows/windows-x64.yml`

**Важно:** в ветке `ci/windows-x64-v1.3.5` пока не размещены `main.cpp` и `CMakeLists.txt`. Поэтому автоматическая сборка EXE пока не запускалась. Добавление только README или workflow не означает, что программа скомпилирована.

## Ограничения диагностики

- Доступность нативных NVMe/ATA запросов зависит от контроллера, драйвера и прав Windows.
- `smartctl.exe` должен быть установлен отдельно либо поставляться вместе с программой в последующей сборке.
- TBW-прогноз является линейной оценкой по сохранённым снимкам и паспортному TBW, а не гарантией остаточного срока службы.
- Программа не может достоверно определить число включений модулей RAM: стандартного счётчика включений памяти обычно нет.
- До успешной сборки MSVC x64 и проверки на реальном оборудовании версия не считается аппаратно подтверждённой.
