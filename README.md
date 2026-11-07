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


## Рекламный модуль v1.4.1 (локальный режим)

Сборка включает два x64-приложения:
- `PC_Performance_Monitor_v1_4_1_x64.exe` — основная программа с вращающимся кликабельным рекламным блоком.
- `PC_Performance_Monitor_AdServer_x64.exe` — локальный сервер и веб-панель управления.

Запустите AdServer и откройте в браузере `http://127.0.0.1:8765/admin`. В панели задаются строки в формате `Заголовок|URL рекламодателя|интервал_секунд`. Пример:

```text
Акция недели|https://example.com/promo|12
Новый продукт|https://example.org/offer|15
```

Сервер принимает соединения только на loopback-интерфейсе 127.0.0.1; удалённое управление с других компьютеров не включено. Для центрального управления рекламой на пользовательских ПК потребуется отдельное публичное размещение, HTTPS, аутентификация администратора и защита API.
