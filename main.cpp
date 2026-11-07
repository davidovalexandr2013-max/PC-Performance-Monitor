#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <psapi.h>
#include <knownfolders.h>
#include <tlhelp32.h>
#include <winver.h>
#include <winioctl.h>
#include <ntddstor.h>
#include <ntdddisk.h>
#include <evntrace.h>
#include <winevt.h>
#include <wbemidl.h>
#include <comdef.h>
#include <shellapi.h>
#include <shlobj.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "Comctl32.lib")
#pragma comment(lib, "Wbemuuid.lib")
#pragma comment(lib, "Wevtapi.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shell32.lib")

#ifndef SMART_GET_VERSION
#define SMART_GET_VERSION CTL_CODE(IOCTL_DISK_BASE, 0x0020, METHOD_BUFFERED, FILE_READ_ACCESS)
#endif
#ifndef SMART_RCV_DRIVE_DATA
#define SMART_RCV_DRIVE_DATA CTL_CODE(IOCTL_DISK_BASE, 0x0022, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#endif
#ifndef SMART_READ_DATA
#define SMART_READ_DATA 0xD0
#endif


namespace fs = std::filesystem;
static HINSTANCE g_instance{};
static HWND g_window{}, g_output{}, g_status{};
static std::mutex g_uiMutex;
static bool g_closing = false; // accessed on UI thread only
static std::atomic<unsigned> g_activeTasks{0};
static std::wstring g_smartctl = L"smartctl.exe";
static constexpr UINT WM_APP_RESULT = WM_APP + 41;

static std::wstring Widen(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    if (!n) return L"(conversion error)";
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n);
    return out;
}
static std::string Utf8(const std::wstring& s) {
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), n, nullptr, nullptr);
    return out;
}
static void Append(const std::wstring& s) {
    if (!g_output) return;
    int len = GetWindowTextLengthW(g_output);
    SendMessageW(g_output, EM_SETSEL, len, len);
    SendMessageW(g_output, EM_REPLACESEL, FALSE, (LPARAM)s.c_str());
}
static void SetStatus(const std::wstring& s) {
    if (g_status) SetWindowTextW(g_status, s.c_str());
}
static std::wstring Timestamp() {
    SYSTEMTIME t{}; GetLocalTime(&t);
    wchar_t b[64]; swprintf_s(b, L"%04u-%02u-%02u %02u:%02u:%02u",
        t.wYear,t.wMonth,t.wDay,t.wHour,t.wMinute,t.wSecond);
    return b;
}

static std::wstring g_sessionLogPath;
static std::mutex g_sessionMutex;
static std::map<DWORD,std::wstring> g_lastProcesses;
static unsigned g_sessionSnapshotCounter = 0;
static void SessionLog(const std::wstring& message) {
    if (g_sessionLogPath.empty()) return;
    std::lock_guard<std::mutex> lock(g_sessionMutex);
    std::wofstream f(g_sessionLogPath, std::ios::app);
    if (f) f << Timestamp() << L" | " << message << L"\r\n";
}
static void BeginSessionLog() {
    wchar_t temp[MAX_PATH]{};
    if (!GetTempPathW(MAX_PATH, temp)) return;
    g_sessionLogPath = std::wstring(temp) + L"PCPM_session_" + std::to_wstring(GetCurrentProcessId()) + L".log";
    DeleteFileW(g_sessionLogPath.c_str());
    SessionLog(L"SESSION_START");
    SessionLog(L"APP_PID | " + std::to_wstring(GetCurrentProcessId()));
}
static void CaptureProcessActivity() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) { SessionLog(L"PROCESS_SCAN_ERROR | " + std::to_wstring(GetLastError())); return; }
    std::map<DWORD,std::wstring> current;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) do { current.emplace(pe.th32ProcessID, pe.szExeFile); } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    for (const auto& item : current) if (g_lastProcesses.find(item.first) == g_lastProcesses.end())
        SessionLog(L"PROCESS_START | PID=" + std::to_wstring(item.first) + L" | " + item.second);
    for (const auto& item : g_lastProcesses) if (current.find(item.first) == current.end())
        SessionLog(L"PROCESS_EXIT | PID=" + std::to_wstring(item.first) + L" | " + item.second);
    g_lastProcesses.swap(current);
    if (++g_sessionSnapshotCounter % 5 == 0) {
        MEMORYSTATUSEX m{}; m.dwLength = sizeof(m);
        if (GlobalMemoryStatusEx(&m)) SessionLog(L"PROCESS_SNAPSHOT | running=" + std::to_wstring(g_lastProcesses.size()) + L" | RAM_load=" + std::to_wstring(m.dwMemoryLoad) + L"%");
    }
}
static void EndSessionLog() {
    SessionLog(L"SESSION_END");
    if (!g_sessionLogPath.empty()) {
        std::lock_guard<std::mutex> lock(g_sessionMutex);
        DeleteFileW(g_sessionLogPath.c_str());
        g_sessionLogPath.clear();
    }
    g_lastProcesses.clear();
}

static std::wstring RunCapture(const std::wstring& command, DWORD timeoutMs = 120000) {
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
    HANDLE readPipe{}, writePipe{};
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) return L"CreatePipe failed.";
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW si{}; si.cb = sizeof(si); si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; si.hStdOutput = writePipe; si.hStdError = writePipe; si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi{};
    std::wstring cmd = L"cmd.exe /d /s /c \"" + command + L"\"";
    BOOL ok = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(writePipe);
    if (!ok) { CloseHandle(readPipe); return L"Не удалось запустить команду. Проверьте наличие smartctl.exe."; }
    std::string bytes; bytes.reserve(8192);
    DWORD start = GetTickCount(), available = 0, got = 0;
    char buf[4096];
    bool finished = false;
    while (GetTickCount() - start < timeoutMs) {
        while (PeekNamedPipe(readPipe, nullptr, 0, nullptr, &available, nullptr) && available) {
            if (!ReadFile(readPipe, buf, (DWORD)std::min<DWORD>(available, sizeof(buf)), &got, nullptr) || !got) break;
            bytes.append(buf, got);
        }
        DWORD wait = WaitForSingleObject(pi.hProcess, 50);
        if (wait == WAIT_OBJECT_0) { finished = true; break; }
    }
    if (!finished) TerminateProcess(pi.hProcess, 124);
    while (PeekNamedPipe(readPipe, nullptr, 0, nullptr, &available, nullptr) && available) {
        if (!ReadFile(readPipe, buf, (DWORD)std::min<DWORD>(available, sizeof(buf)), &got, nullptr) || !got) break;
        bytes.append(buf, got);
    }
    DWORD exitCode = 0; GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess); CloseHandle(readPipe);
    // smartctl on Windows normally emits the active OEM code page; try UTF-8, then ACP.
    std::wstring result;
    if (!bytes.empty()) {
        int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), (int)bytes.size(), nullptr, 0);
        if (n) { result.resize(n); MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), (int)bytes.size(), result.data(), n); }
        else {
            n = MultiByteToWideChar(CP_ACP, 0, bytes.data(), (int)bytes.size(), nullptr, 0);
            result.resize(n); if (n) MultiByteToWideChar(CP_ACP, 0, bytes.data(), (int)bytes.size(), result.data(), n);
        }
    }
    if (!finished) result += L"\r\n[ВНИМАНИЕ: команда остановлена по тайм-ауту]\r\n";
    result += L"\r\n[Код завершения smartctl/команды: " + std::to_wstring(exitCode) + L"]\r\n";
    return result;
}
static std::wstring AppDataDir() {
    PWSTR p = nullptr; std::wstring out = L".";
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &p))) {
        out = p; CoTaskMemFree(p); out += L"\\PCPerformanceMonitor";
        CreateDirectoryW(out.c_str(), nullptr);
    }
    return out;
}
static std::wstring SnapshotPath() { return AppDataDir() + L"\\disk_write_history.csv"; }

struct NvmeHealth {
    bool ok = false;
    double temperatureC = 0;
    unsigned spare = 0, used = 0;
    // NVMe counters are 128-bit little-endian values. Keep their full decimal
    // representation; silently truncating to 64 bits corrupts long-running-drive statistics.
    std::wstring dataUnitsWritten, powerCycles, powerOnHours, unsafeShutdowns, mediaErrors;
    std::wstring error;
};

// Native NVMe Health Information Log Page (02h), via Windows storage protocol query.
static NvmeHealth ReadNvmeHealth(unsigned diskNo) {
    NvmeHealth r;
    std::wstring path = L"\\\\.\\PhysicalDrive" + std::to_wstring(diskNo);
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { r.error = L"Нет доступа к устройству"; return r; }

    struct Query {
        STORAGE_PROPERTY_QUERY query;
        STORAGE_PROTOCOL_SPECIFIC_DATA protocol;
    } q{};
    q.query.PropertyId = StorageDeviceProtocolSpecificProperty;
    q.query.QueryType = PropertyStandardQuery;
    q.protocol.ProtocolType = ProtocolTypeNvme;
    q.protocol.DataType = NVMeDataTypeLogPage;
    q.protocol.ProtocolDataRequestValue = 0x02; // SMART / Health Information
    q.protocol.ProtocolDataRequestSubValue = 0;
    q.protocol.ProtocolDataOffset = sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA);
    q.protocol.ProtocolDataLength = 512;

    std::array<BYTE, sizeof(STORAGE_PROTOCOL_DATA_DESCRIPTOR) + 512> buffer{};
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof(q),
        buffer.data(), (DWORD)buffer.size(), &returned, nullptr);
    CloseHandle(h);
    if (!ok || returned < sizeof(STORAGE_PROTOCOL_DATA_DESCRIPTOR)) {
        r.error = L"Windows не предоставила NVMe Health Log (драйвер/контроллер может не поддерживать запрос)";
        return r;
    }
    auto* desc = reinterpret_cast<STORAGE_PROTOCOL_DATA_DESCRIPTOR*>(buffer.data());
    auto* p = reinterpret_cast<STORAGE_PROTOCOL_SPECIFIC_DATA*>(&desc->ProtocolSpecificData);
    const size_t protocolBase = offsetof(STORAGE_PROTOCOL_DATA_DESCRIPTOR, ProtocolSpecificData);
    if (p->ProtocolDataOffset < sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA) ||
        protocolBase + p->ProtocolDataOffset + p->ProtocolDataLength > returned ||
        p->ProtocolDataLength < 176) {
        r.error = L"Некорректная длина NVMe Health Log"; return r;
    }
    const BYTE* d = reinterpret_cast<const BYTE*>(p) + p->ProtocolDataOffset;
    auto le128Decimal = [](const BYTE* x) -> std::wstring {
        // Convert an unsigned 128-bit little-endian integer without compiler-specific
        // __int128 support (MSVC does not provide that type).
        std::wstring decimal = L"0";
        for (int i = 15; i >= 0; --i) {
            unsigned carry = x[i];
            for (auto it = decimal.rbegin(); it != decimal.rend(); ++it) {
                const unsigned value = unsigned(*it - L'0') * 256u + carry;
                *it = wchar_t(L'0' + (value % 10u));
                carry = value / 10u;
            }
            while (carry) {
                decimal.insert(decimal.begin(), wchar_t(L'0' + (carry % 10u)));
                carry /= 10u;
            }
        }
        const auto nonzero = decimal.find_first_not_of(L'0');
        return nonzero == std::wstring::npos ? L"0" : decimal.substr(nonzero);
    };
    unsigned short kelvin = (unsigned short)(d[1] | (d[2] << 8));
    r.temperatureC = kelvin ? (double)kelvin - 273.15 : 0;
    r.spare = d[3]; r.used = d[5];
    r.dataUnitsWritten = le128Decimal(d + 48);
    r.powerCycles = le128Decimal(d + 112);
    r.powerOnHours = le128Decimal(d + 128);
    r.unsafeShutdowns = le128Decimal(d + 144);
    r.mediaErrors = le128Decimal(d + 160);
    r.ok = true;
    return r;
}

static std::wstring NativeNvmeReport() {
    std::wstringstream ss; ss << L"=== Нативный NVMe Health Log ===\r\n";
    bool any = false;
    for (unsigned i=0; i<32; ++i) {
        std::wstring p = L"\\\\.\\PhysicalDrive" + std::to_wstring(i);
        HANDLE h = CreateFileW(p.c_str(), 0, FILE_SHARE_READ|FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) continue;
        CloseHandle(h);
        auto n = ReadNvmeHealth(i);
        ss << L"\r\nPhysicalDrive" << i << L": ";
        if (!n.ok) { ss << n.error << L"\r\n"; continue; }
        any = true;
        ss << L"\r\nТемпература: " << std::fixed << std::setprecision(1) << n.temperatureC << L" °C"
           << L"\r\nЗапас ресурса: " << n.spare << L"%"
           << L"\r\nИзнос (Percentage Used): " << n.used << L"%"
           << L"\r\nData Units Written: " << n.dataUnitsWritten
           << L"\r\nPower Cycles: " << n.powerCycles
           << L"\r\nPower-On Hours: " << n.powerOnHours
           << L"\r\nUnsafe Shutdowns: " << n.unsafeShutdowns
           << L"\r\nMedia/Data Integrity Errors: " << n.mediaErrors << L"\r\n";
    }
    if (!any) ss << L"Нет доступных NVMe Health Log. Для полного отчёта используйте smartctl -x.\r\n";
    return ss.str();
}


static std::wstring AtaSmartReport(unsigned diskNo) {
    std::wstring path = L"\\\\.\\PhysicalDrive" + std::to_wstring(diskNo);
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return L"";
    GETVERSIONINPARAMS ver{}; DWORD returned = 0;
    if (!DeviceIoControl(h, SMART_GET_VERSION, nullptr, 0, &ver, sizeof(ver), &returned, nullptr) ||
        !ver.fCapabilities) { CloseHandle(h); return L""; }
    struct InBuffer { SENDCMDINPARAMS p; BYTE extra[1]; } in{};
    in.p.cBufferSize = 512; in.p.bDriveNumber = (BYTE)diskNo;
    in.p.irDriveRegs.bFeaturesReg = SMART_READ_DATA;
    in.p.irDriveRegs.bSectorCountReg = 1; in.p.irDriveRegs.bSectorNumberReg = 1;
    in.p.irDriveRegs.bCylLowReg = 0x4F; in.p.irDriveRegs.bCylHighReg = 0xC2;
    in.p.irDriveRegs.bDriveHeadReg = (BYTE)(0xA0 | ((diskNo & 1) << 4));
    in.p.irDriveRegs.bCommandReg = SMART_CMD;
    std::array<BYTE, sizeof(SENDCMDOUTPARAMS) + 512> out{};
    BOOL ok = DeviceIoControl(h, SMART_RCV_DRIVE_DATA, &in, sizeof(SENDCMDINPARAMS) - 1,
        out.data(), (DWORD)out.size(), &returned, nullptr);
    CloseHandle(h);
    if (!ok || returned < sizeof(SENDCMDOUTPARAMS) + 511) return L"";
#pragma pack(push, 1)
    struct AtaAttr { BYTE id; BYTE flags[2]; BYTE current; BYTE worst; BYTE raw[6]; BYTE reserved; };
    struct AtaData { BYTE revision[2]; AtaAttr attributes[30]; BYTE reserved[150]; };
#pragma pack(pop)
    const auto* d = reinterpret_cast<const AtaData*>(out.data() + sizeof(SENDCMDOUTPARAMS) - 1);
    std::wstringstream ss;
    ss << L"\r\n=== ATA SMART PhysicalDrive" << diskNo << L" ===\r\nID\tCurrent\tWorst\tRaw(hex)\r\n";
    for (const auto& a : d->attributes) if (a.id) {
        wchar_t raw[16]{};
        swprintf_s(raw, L"%02X%02X%02X%02X%02X%02X", a.raw[5], a.raw[4], a.raw[3], a.raw[2], a.raw[1], a.raw[0]);
        ss << (unsigned)a.id << L"\t" << (unsigned)a.current << L"\t" << (unsigned)a.worst << L"\t" << raw << L"\r\n";
    }
    ss << L"Raw-значения зависят от производителя; универсальная трактовка не гарантируется.\r\n";
    return ss.str();
}
static std::wstring NativeAtaReport() {
    std::wstring out = L"=== Нативный ATA SMART ===\r\n"; bool found = false;
    for (unsigned i = 0; i < 32; ++i) {
        auto r = AtaSmartReport(i);
        if (!r.empty()) { out += r; found = true; }
    }
    if (!found) out += L"ATA SMART IOCTL недоступен через storage-драйвер; используйте smartctl.\r\n";
    return out;
}

struct SmartctlDevice {
    std::wstring path;
    std::wstring options;
};
static std::vector<SmartctlDevice> SmartctlDevices() {
    std::vector<SmartctlDevice> devices;
    const std::wstring scan = RunCapture(L"\"" + g_smartctl + L"\" --scan-open", 30000);
    std::wistringstream lines(scan);
    std::wstring line;
    auto safeSmartctlToken = [](const std::wstring& token) {
        if (token.empty() || token.size() > 128) return false;
        return std::all_of(token.begin(), token.end(), [](wchar_t c) {
            return (c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
                   (c >= L'0' && c <= L'9') || c == L'_' || c == L'-' ||
                   c == L'.' || c == L',' || c == L':' || c == L'/';
        });
    };
    while (std::getline(lines, line)) {
        const auto first = line.find_first_not_of(L" \t\r");
        if (first == std::wstring::npos || line[first] != L'/') continue;
        const auto comment = line.find(L'#', first);
        const std::wstring data = line.substr(first, comment == std::wstring::npos ? comment : comment-first);
        std::wistringstream tokens(data);
        SmartctlDevice item;
        if (!(tokens >> item.path) || item.path.rfind(L"/dev/", 0) != 0 ||
            !safeSmartctlToken(item.path)) continue;
        std::wstring token;
        bool validOptions = true;
        while (tokens >> token) {
            if (!safeSmartctlToken(token)) { validOptions = false; break; }
            item.options += L" " + token;
        }
        if (!validOptions) continue;
        auto it = std::find_if(devices.begin(), devices.end(), [&](const SmartctlDevice& d) { return d.path == item.path; });
        if (it == devices.end()) devices.push_back(std::move(item));
        else if (it->options.empty()) it->options = item.options;
    }
    return devices;
}
static std::wstring SmartctlCommand(const std::wstring& args, const SmartctlDevice& device) {
    return L"\"" + g_smartctl + L"\"" + device.options + L" " + args + L" " + device.path;
}
static std::wstring SmartReport() {
    std::wstring report = NativeNvmeReport() + NativeAtaReport();
    report += L"\r\n=== smartctl --scan-open ===\r\n";
    report += RunCapture(L"\"" + g_smartctl + L"\" --scan-open", 30000);
    auto devices = SmartctlDevices();
    if (devices.empty()) {
        report += L"\r\nУстройства smartctl не обнаружены. Проверьте smartctl.exe и права администратора.\r\n";
        return report;
    }
    report += L"\r\n=== smartctl -x: полный отчёт по обнаруженным устройствам ===\r\n";
    for (const auto& device : devices) {
        report += L"\r\n--- " + device.path + device.options + L" ---\r\n";
        report += RunCapture(SmartctlCommand(L"-x", device), 120000);
    }
    return report;
}
static std::wstring SmartTests() {
    std::wstring report = L"=== Обнаружение устройств ===\r\n";
    report += RunCapture(L"\"" + g_smartctl + L"\" --scan-open", 30000);
    auto devices = SmartctlDevices();
    if (devices.empty()) return report + L"\r\nНет доступных устройств smartctl.\r\n";
    for (const auto& device : devices) {
        report += L"\r\n--- Self-test capabilities: " + device.path + device.options + L" ---\r\n";
        report += RunCapture(SmartctlCommand(L"-c", device), 30000);
    }
    return report;
}
static std::wstring RunSmartTest(const wchar_t* option) {
    auto devices = SmartctlDevices();
    if (devices.empty()) return L"Устройства smartctl не обнаружены.\r\n";
    std::wstring report;
    for (const auto& device : devices) {
        report += L"\r\n--- " + device.path + device.options + L" ---\r\n";
        report += RunCapture(SmartctlCommand(option, device), 120000);
    }
    return report;
}

static std::wstring DiskList() {
    std::wstringstream ss;
    for (unsigned i=0; i<32; ++i) {
        std::wstring p = L"\\\\.\\PhysicalDrive" + std::to_wstring(i);
        HANDLE h = CreateFileW(p.c_str(), 0, FILE_SHARE_READ|FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) continue;
        STORAGE_PROPERTY_QUERY q{}; q.PropertyId = StorageDeviceProperty; q.QueryType = PropertyStandardQuery;
        std::array<BYTE, 2048> b{}; DWORD ret = 0;
        if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof(q), b.data(), (DWORD)b.size(), &ret, nullptr)) {
            auto* d = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(b.data());
            ss << L"PhysicalDrive" << i;
            if (d->VendorIdOffset && d->VendorIdOffset < ret) ss << L" | " << Widen((char*)b.data()+d->VendorIdOffset);
            if (d->ProductIdOffset && d->ProductIdOffset < ret) ss << L" " << Widen((char*)b.data()+d->ProductIdOffset);
            ss << L"\r\n";
        } else ss << L"PhysicalDrive" << i << L"\r\n";
        CloseHandle(h);
    }
    return ss.str();
}

static void SaveNvmeSnapshots() {
    const std::wstring path = SnapshotPath();
    std::error_code sizeError;
    const auto existingSize = fs::exists(path, sizeError) && !sizeError ? fs::file_size(path, sizeError) : 0;
    std::wofstream f(path, std::ios::app);
    if (!f) return;
    if (existingSize == 0) f << L"timestamp,disk,data_units_written,power_on_hours,percentage_used\r\n";
    for (unsigned i=0; i<32; ++i) {
        auto n = ReadNvmeHealth(i);
        if (!n.ok) continue;
        f << Timestamp() << L"," << i << L"," << n.dataUnitsWritten << L"," << n.powerOnHours << L"," << n.used << L"\r\n";
    }
}
static std::wstring TbwReport() {
    SaveNvmeSnapshots();
    const std::wstring history = SnapshotPath();
    const std::wstring profile = AppDataDir() + L"\\ssd_tbw_profiles.csv";
    if (!fs::exists(profile)) {
        std::wofstream pf(profile);
        if (pf) pf << L"disk_number,rated_tbw_TB\r\n0,600\r\n";
    }
    struct Snap { long long epoch; std::wstring units; };
    auto normalizeDecimal = [](const std::wstring& value, std::wstring& result) -> bool {
        if (value.empty()) return false;
        for (wchar_t ch : value) if (ch < L'0' || ch > L'9') return false;
        const auto first = value.find_first_not_of(L'0');
        result = first == std::wstring::npos ? L"0" : value.substr(first);
        return true;
    };
    auto decimalToLongDouble = [](const std::wstring& value) -> long double {
        long double parsed = 0;
        for (wchar_t ch : value) parsed = parsed * 10.0L + static_cast<unsigned>(ch - L'0');
        return parsed;
    };
    auto subtractDecimal = [](const std::wstring& larger, const std::wstring& smaller) -> std::wstring {
        std::wstring result(larger);
        int borrow = 0;
        size_t i = larger.size(), j = smaller.size();
        while (i > 0) {
            --i;
            int digit = (larger[i] - L'0') - borrow;
            if (j > 0) digit -= (smaller[--j] - L'0');
            borrow = digit < 0 ? 1 : 0;
            if (borrow) digit += 10;
            result[i] = static_cast<wchar_t>(L'0' + digit);
        }
        const auto first = result.find_first_not_of(L'0');
        return first == std::wstring::npos ? L"0" : result.substr(first);
    };
    std::map<unsigned, std::vector<Snap>> snapshots;
    std::wifstream in(history);
    std::wstring line;
    std::getline(in, line);
    while (std::getline(in, line)) {
        std::wistringstream row(line);
        std::wstring stamp, diskText, unitsText, hoursText, usedText;
        if (!std::getline(row, stamp, L',') || !std::getline(row, diskText, L',') ||
            !std::getline(row, unitsText, L',') || !std::getline(row, hoursText, L',') ||
            !std::getline(row, usedText, L',')) continue;
        int y=0, mo=0, d=0, hh=0, mm=0, sec=0;
        unsigned disk=0; std::wstring units;
        if (swscanf_s(stamp.c_str(), L"%d-%d-%d %d:%d:%d", &y,&mo,&d,&hh,&mm,&sec) != 6) continue;
        try { disk=(unsigned)std::stoul(diskText); } catch (...) { continue; }
        if (!normalizeDecimal(unitsText, units)) continue;
        std::tm tm{}; tm.tm_year=y-1900; tm.tm_mon=mo-1; tm.tm_mday=d;
        tm.tm_hour=hh; tm.tm_min=mm; tm.tm_sec=sec;
        snapshots[disk].push_back({(long long)_mkgmtime(&tm), units});
    }
    std::map<unsigned, double> rated;
    std::wifstream pf(profile);
    std::getline(pf, line);
    while (std::getline(pf, line)) {
        std::wistringstream row(line); std::wstring ds, tbw;
        if (!std::getline(row, ds, L',') || !std::getline(row, tbw, L',')) continue;
        try { rated[(unsigned)std::stoul(ds)] = std::stod(tbw); } catch (...) {}
    }
    std::wstringstream ss;
    ss << L"=== История записи и оценка TBW ===\r\nИстория: " << history
       << L"\r\nПрофиль ресурса: " << profile
       << L"\r\nNVMe Data Units Written: одна единица = 512 000 байт.\r\n";
    for (auto& item : snapshots) {
        auto& v = item.second;
        if (v.empty()) continue;
        std::sort(v.begin(), v.end(), [](const Snap& a, const Snap& b){ return a.epoch < b.epoch; });
        const auto& first = v.front(); const auto& last = v.back();
        const double totalTB = static_cast<double>(decimalToLongDouble(last.units) * 512000.0L / 1.0e12L);
        ss << L"\r\nPhysicalDrive" << item.first << L": накопленная запись ≈ "
           << std::fixed << std::setprecision(3) << totalTB << L" TB.";
        if (v.size() < 2 || last.epoch <= first.epoch ||
            last.units.size() < first.units.size() ||
            (last.units.size() == first.units.size() && last.units < first.units)) {
            ss << L" Для расчёта темпа нужны два корректных снимка.\r\n"; continue;
        }
        const double days = (last.epoch - first.epoch) / 86400.0;
        const std::wstring writtenUnits = subtractDecimal(last.units, first.units);
        const double writtenTB = static_cast<double>(decimalToLongDouble(writtenUnits) * 512000.0L / 1.0e12L);
        const double perDay = writtenTB / days;
        ss << L"\r\nПериод наблюдения: " << days << L" дней; запись за период: "
           << writtenTB << L" TB; средний темп: " << perDay << L" TB/день.";
        auto it = rated.find(item.first);
        if (it != rated.end() && it->second > 0) {
            const double remaining = std::max(0.0, it->second - totalTB);
            ss << L"\r\nПаспортный ресурс: " << it->second << L" TBW; условный остаток: "
               << remaining << L" TB.";
            if (perDay > 0) ss << L"\r\nЛинейная оценка до TBW: " << remaining / perDay << L" дней.";
        } else {
            ss << L"\r\nПрогноз не рассчитан: укажите паспортный TBW в профиле.";
        }
        ss << L"\r\n";
    }
    ss << L"\r\nОткройте ssd_tbw_profiles.csv и укажите фактический паспортный TBW для каждого диска. "
       << L"Прогноз линейный, зависит от периода наблюдения и не является гарантией срока службы.\r\n";
    return ss.str();
}

static std::wstring HResultText(HRESULT hr) {
    wchar_t b[32]{}; swprintf_s(b,L"0x%08X",(unsigned)hr); return b;
}
static std::wstring WmiQuery(const wchar_t* query, const wchar_t* property) {
    HRESULT init=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
    const bool uninit=(init==S_OK||init==S_FALSE);
    if(FAILED(init)&&init!=RPC_E_CHANGED_MODE)
        return L"[Ошибка инициализации COM: "+HResultText(init)+L"]\r\n";
    IWbemLocator* loc=nullptr; IWbemServices* svc=nullptr; IEnumWbemClassObject* en=nullptr;
    std::wstringstream out; HRESULT hr=CoCreateInstance(CLSID_WbemLocator,nullptr,CLSCTX_INPROC_SERVER,IID_IWbemLocator,(void**)&loc);
    if(FAILED(hr)) { out<<L"[WMI: CoCreateInstance: "<<HResultText(hr)<<L"]\r\n"; if(uninit) CoUninitialize(); return out.str(); }
    BSTR ns=SysAllocString(L"ROOT\\CIMV2");
    hr=loc->ConnectServer(ns,nullptr,nullptr,nullptr,0,nullptr,nullptr,&svc); SysFreeString(ns);
    if(FAILED(hr)) { out<<L"[WMI: ConnectServer: "<<HResultText(hr)<<L"]\r\n"; loc->Release(); if(uninit) CoUninitialize(); return out.str(); }
    hr=CoSetProxyBlanket(svc,RPC_C_AUTHN_WINNT,RPC_C_AUTHZ_NONE,nullptr,RPC_C_AUTHN_LEVEL_CALL,RPC_C_IMP_LEVEL_IMPERSONATE,nullptr,EOAC_NONE);
    if(FAILED(hr)) out<<L"[Предупреждение WMI: CoSetProxyBlanket: "<<HResultText(hr)<<L"]\r\n";
    BSTR language=SysAllocString(L"WQL"), q=SysAllocString(query);
    hr=svc->ExecQuery(language,q,WBEM_FLAG_FORWARD_ONLY,nullptr,&en);
    SysFreeString(language); SysFreeString(q);
    if(FAILED(hr)) out<<L"[WMI: ExecQuery: "<<HResultText(hr)<<L"]\r\n";
    else if(en) {
        for(;;) {
            IWbemClassObject* obj=nullptr; ULONG count=0;
            hr=en->Next(5000,1,&obj,&count);
            if(hr==WBEM_S_TIMEDOUT||hr==WBEM_S_FALSE||count==0) break;
            if(FAILED(hr)) { out<<L"[WMI: Next: "<<HResultText(hr)<<L"]\r\n"; break; }
            VARIANT v; VariantInit(&v);
            HRESULT get=obj->Get(property,0,&v,nullptr,nullptr);
            if(SUCCEEDED(get)&&v.vt!=VT_NULL&&v.vt!=VT_EMPTY) {
                VARIANT converted; VariantInit(&converted);
                if(SUCCEEDED(VariantChangeType(&converted,&v,0,VT_BSTR))&&converted.bstrVal)
                    out<<converted.bstrVal<<L"\r\n";
                else out<<L"(тип данных не поддержан)\r\n";
                VariantClear(&converted);
            }
            VariantClear(&v); obj->Release();
        }
        en->Release();
    }
    svc->Release(); loc->Release(); if(uninit) CoUninitialize();
    return out.str();
}
static std::wstring NativeCpuName() {
    HKEY key{}; wchar_t value[512]{}; DWORD bytes=sizeof(value),type=0;
    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",0,KEY_QUERY_VALUE,&key)==ERROR_SUCCESS) {
        LONG rc=RegQueryValueExW(key,L"ProcessorNameString",nullptr,&type,(BYTE*)value,&bytes); RegCloseKey(key);
        if(rc==ERROR_SUCCESS&&value[0]) return value;
    }
    return L"Не удалось определить модель CPU через реестр Windows";
}
static std::wstring HardwareReport() {
    std::wstringstream ss;
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    MEMORYSTATUSEX memory{}; memory.dwLength=sizeof(memory); GlobalMemoryStatusEx(&memory);
    ULONGLONG installedKB=0; const BOOL haveInstalled=GetPhysicallyInstalledSystemMemory(&installedKB);
    ss<<L"=== ОБОРУДОВАНИЕ КОМПЬЮТЕРА ===\r\n";
    ss<<L"Источник базовых данных: API Windows; расширенные сведения: WMI (если служба доступна).\r\n";
    ss<<L"\r\n=== ПРОЦЕССОР ===\r\n";
    std::wstring cpu=WmiQuery(L"SELECT Name FROM Win32_Processor",L"Name");
    if(cpu.empty()||cpu[0]==L'[') cpu=NativeCpuName()+L"\r\n";
    ss<<L"Модель: "<<cpu;
    ss<<L"Логических процессоров: "<<si.dwNumberOfProcessors<<L"\r\n";
    ss<<L"\r\n=== ОПЕРАТИВНАЯ ПАМЯТЬ ===\r\n";
    ss<<L"Установлено: ";
    if(haveInstalled) ss<<std::fixed<<std::setprecision(2)<<(double)installedKB/1048576.0<<L" ГБ\r\n";
    else ss<<L"не удалось определить через Windows API\r\n";
    ss<<L"Доступно сейчас: "<<std::fixed<<std::setprecision(2)<<(double)memory.ullAvailPhys/1073741824.0<<L" ГБ из "<<(double)memory.ullTotalPhys/1073741824.0<<L" ГБ\r\n";
    ss<<L"\r\n=== МОДУЛИ ПАМЯТИ (WMI) ===\r\n";
    ss<<L"Производитель: "<<WmiQuery(L"SELECT Manufacturer FROM Win32_PhysicalMemory",L"Manufacturer");
    ss<<L"Модель/Part Number: "<<WmiQuery(L"SELECT PartNumber FROM Win32_PhysicalMemory",L"PartNumber");
    ss<<L"Объём одного модуля (байт): "<<WmiQuery(L"SELECT Capacity FROM Win32_PhysicalMemory",L"Capacity");
    ss<<L"Скорость (MT/s): "<<WmiQuery(L"SELECT Speed FROM Win32_PhysicalMemory",L"Speed");
    ss<<L"Настроенная скорость (MT/s): "<<WmiQuery(L"SELECT ConfiguredClockSpeed FROM Win32_PhysicalMemory",L"ConfiguredClockSpeed");
    ss<<L"\r\n=== МАТЕРИНСКАЯ ПЛАТА / СИСТЕМА ===\r\n";
    ss<<L"Производитель: "<<WmiQuery(L"SELECT Manufacturer FROM Win32_ComputerSystem",L"Manufacturer");
    ss<<L"Модель: "<<WmiQuery(L"SELECT Model FROM Win32_ComputerSystem",L"Model");
    ss<<L"Плата: "<<WmiQuery(L"SELECT Manufacturer FROM Win32_BaseBoard",L"Manufacturer");
    ss<<L"Модель платы: "<<WmiQuery(L"SELECT Product FROM Win32_BaseBoard",L"Product");
    ss<<L"\r\n=== ВИДЕОАДАПТЕРЫ ===\r\n";
    ss<<WmiQuery(L"SELECT Name FROM Win32_VideoController",L"Name");
    ss<<L"\r\n=== НАКОПИТЕЛИ ===\r\n";
    ss<<WmiQuery(L"SELECT Model FROM Win32_DiskDrive",L"Model");
    ss<<L"\r\n=== BIOS ===\r\n";
    ss<<WmiQuery(L"SELECT SMBIOSBIOSVersion FROM Win32_BIOS",L"SMBIOSBIOSVersion");
    ss<<L"\r\n=== ТЕМПЕРАТУРНЫЕ ЗОНЫ ACPI (если доступны) ===\r\n";
    ss<<WmiQuery(L"SELECT CurrentTemperature FROM MSAcpi_ThermalZoneTemperature",L"CurrentTemperature");
    ss<<L"Примечание: WMI/ACPI может не предоставлять температуры CPU/GPU на современных ПК. Если WMI недоступен, базовые сведения CPU и RAM всё равно выводятся через API Windows.\r\n";
    return ss.str();
}

static std::wstring EventReport(const wchar_t* channel, const wchar_t* label, DWORD maxEvents = 250) {
    std::wstringstream ss; ss << L"=== " << label << L" ===\r\n";
    EVT_HANDLE query = EvtQuery(nullptr, channel, L"*", EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!query) { ss << L"Журнал недоступен (код " << GetLastError() << L").\r\n"; return ss.str(); }
    std::array<EVT_HANDLE, 32> events{}; DWORD returned = 0, total = 0;
    while (total < maxEvents && EvtNext(query, (DWORD)events.size(), events.data(), 1000, 0, &returned)) {
        for (DWORD i=0; i<returned && total<maxEvents; ++i, ++total) {
            DWORD used = 0, props = 0;
            EvtRender(nullptr, events[i], EvtRenderEventXml, 0, nullptr, &used, &props);
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && used) {
                std::vector<wchar_t> xml(used/sizeof(wchar_t)+1);
                if (EvtRender(nullptr, events[i], EvtRenderEventXml, used, xml.data(), &used, &props))
                    ss << xml.data() << L"\r\n";
            }
            EvtClose(events[i]);
        }
    }
    EvtClose(query);
    ss << L"\r\nПоказано событий: " << total << L"\r\n";
    return ss.str();
}
static std::wstring DiagnosticsReport() {
    return EventReport(L"System", L"WHEA / аппаратные ошибки") +
        EventReport(L"Microsoft-Windows-MemoryDiagnostics-Results/Operational", L"Windows Memory Diagnostics");
}

struct ProcessRow {
    DWORD pid{};
    double cpuPercent{};
    SIZE_T workingSet{};
    std::wstring name, description;
};
static std::wstring ProcessFileDescription(DWORD pid, const wchar_t* fallback) {
    HANDLE p=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
    if(!p) return L"Описание недоступно (нет доступа)";
    std::wstring path(32768,L'\0'); DWORD n=(DWORD)path.size();
    bool ok=QueryFullProcessImageNameW(p,0,path.data(),&n)!=FALSE;
    CloseHandle(p);
    if(!ok) return L"Системный процесс Windows";
    path.resize(n);
    DWORD handle=0, bytes=GetFileVersionInfoSizeW(path.c_str(),&handle);
    if(!bytes) return L"Приложение: "+std::wstring(fallback);
    std::vector<BYTE> data(bytes);
    if(!GetFileVersionInfoW(path.c_str(),0,bytes,data.data())) return L"Приложение: "+std::wstring(fallback);
    struct LANGANDCODEPAGE { WORD language, codepage; };
    LANGANDCODEPAGE* translations=nullptr; UINT count=0;
    if(!VerQueryValueW(data.data(),L"\\VarFileInfo\\Translation",(LPVOID*)&translations,&count)||count<sizeof(LANGANDCODEPAGE))
        return L"Приложение: "+std::wstring(fallback);
    wchar_t query[128]{};
    swprintf_s(query,L"\\StringFileInfo\\%04x%04x\\FileDescription",translations[0].language,translations[0].codepage);
    wchar_t* value=nullptr; UINT length=0;
    if(VerQueryValueW(data.data(),query,(LPVOID*)&value,&length)&&value&&length) return value;
    return L"Приложение: "+std::wstring(fallback);
}
static std::vector<ProcessRow> EnumerateProcessRows() {
    auto processTime=[](DWORD pid, ULONGLONG& value)->bool {
        HANDLE p=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
        if(!p) return false;
        FILETIME c{},e{},k{},u{}; bool ok=GetProcessTimes(p,&c,&e,&k,&u)!=FALSE; CloseHandle(p);
        if(ok) value=((ULONGLONG)k.dwHighDateTime<<32|k.dwLowDateTime)+((ULONGLONG)u.dwHighDateTime<<32|u.dwLowDateTime);
        return ok;
    };
    auto systemTime=[](ULONGLONG& value)->bool {
        FILETIME idle{},kernel{},user{};
        if(!GetSystemTimes(&idle,&kernel,&user)) return false;
        value=((ULONGLONG)kernel.dwHighDateTime<<32|kernel.dwLowDateTime)+((ULONGLONG)user.dwHighDateTime<<32|user.dwLowDateTime);
        return true;
    };
    std::map<DWORD,ULONGLONG> before;
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snap==INVALID_HANDLE_VALUE) return {};
    PROCESSENTRY32W pe{}; pe.dwSize=sizeof(pe);
    if(Process32FirstW(snap,&pe)) do { ULONGLONG t=0; if(processTime(pe.th32ProcessID,t)) before[pe.th32ProcessID]=t; } while(Process32NextW(snap,&pe));
    CloseHandle(snap);
    ULONGLONG sysBefore=0,sysAfter=0; systemTime(sysBefore);
    Sleep(500);
    systemTime(sysAfter);
    std::vector<ProcessRow> rows;
    snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snap==INVALID_HANDLE_VALUE) return rows;
    pe={}; pe.dwSize=sizeof(pe);
    const ULONGLONG systemDelta=sysAfter>sysBefore?sysAfter-sysBefore:0;
    if(Process32FirstW(snap,&pe)) do {
        ProcessRow row; row.pid=pe.th32ProcessID; row.name=pe.szExeFile;
        ULONGLONG after=0;
        if(systemDelta && processTime(row.pid,after)) {
            auto it=before.find(row.pid);
            if(it!=before.end()&&after>=it->second) row.cpuPercent=100.0*(double)(after-it->second)/(double)systemDelta;
        }
        HANDLE p=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_VM_READ,FALSE,row.pid);
        if(p) { PROCESS_MEMORY_COUNTERS_EX pm{}; pm.cb=sizeof(pm); if(GetProcessMemoryInfo(p,(PROCESS_MEMORY_COUNTERS*)&pm,sizeof(pm))) row.workingSet=pm.WorkingSetSize; CloseHandle(p); }
        row.description=ProcessFileDescription(row.pid,row.name.c_str());
        rows.push_back(std::move(row));
    } while(Process32NextW(snap,&pe));
    CloseHandle(snap);
    std::sort(rows.begin(),rows.end(),[](const ProcessRow&a,const ProcessRow&b){return a.cpuPercent>b.cpuPercent;});
    return rows;
}
static HWND g_processManager{},g_processList{};
static void RefreshProcessList() {
    if(!g_processList) return;
    SendMessageW(g_processList,LVM_DELETEALLITEMS,0,0);
    auto rows=EnumerateProcessRows();
    for(const auto& p:rows) {
        wchar_t pid[32]{},cpu[32]{},mem[64]{};
        swprintf_s(pid,L"%lu",p.pid); swprintf_s(cpu,L"%.1f%%",p.cpuPercent);
        swprintf_s(mem,L"%.1f МБ",p.workingSet/1048576.0);
        LVITEMW item{}; item.mask=LVIF_TEXT|LVIF_PARAM; item.iItem=(int)SendMessageW(g_processList,LVM_GETITEMCOUNT,0,0);
        item.pszText=pid; item.lParam=(LPARAM)p.pid;
        int index=(int)SendMessageW(g_processList,LVM_INSERTITEMW,0,(LPARAM)&item);
        ListView_SetItemText(g_processList,index,1,cpu);
        ListView_SetItemText(g_processList,index,2,mem);
        ListView_SetItemText(g_processList,index,3,const_cast<LPWSTR>(p.name.c_str()));
        ListView_SetItemText(g_processList,index,4,const_cast<LPWSTR>(p.description.c_str()));
    }
}
static void TerminateSelectedProcess(HWND hwnd) {
    int selected=ListView_GetNextItem(g_processList,-1,LVNI_SELECTED);
    if(selected<0) { MessageBoxW(hwnd,L"Выберите процесс в списке.",L"Завершение процесса",MB_OK|MB_ICONINFORMATION); return; }
    wchar_t pidText[32]{}; ListView_GetItemText(g_processList,selected,0,pidText,32);
    DWORD pid=wcstoul(pidText,nullptr,10);
    wchar_t name[512]{}; ListView_GetItemText(g_processList,selected,3,name,512);
    std::wstring question=L"Принудительно завершить процесс?\r\n\r\n"+std::wstring(name)+L" (PID "+std::to_wstring(pid)+L")\r\n\r\nНесохранённые данные приложения могут быть потеряны. Не завершайте системные процессы Windows.";
    if(MessageBoxW(hwnd,question.c_str(),L"Подтверждение",MB_YESNO|MB_ICONWARNING)!=IDYES) return;
    HANDLE p=OpenProcess(PROCESS_TERMINATE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
    if(!p) { MessageBoxW(hwnd,L"Нет доступа к процессу. Возможно, он защищён системой.",L"Ошибка",MB_OK|MB_ICONERROR); return; }
    BOOL ok=TerminateProcess(p,1); DWORD error=ok?0:GetLastError(); CloseHandle(p);
    if(ok) { MessageBoxW(hwnd,L"Команда завершения отправлена.",L"Готово",MB_OK|MB_ICONINFORMATION); RefreshProcessList(); }
    else { std::wstring msg=L"Не удалось завершить процесс. Код Windows: "+std::to_wstring(error); MessageBoxW(hwnd,msg.c_str(),L"Ошибка",MB_OK|MB_ICONERROR); }
}
static LRESULT CALLBACK ProcessManagerProc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp) {
    switch(msg) {
    case WM_CREATE: {
        g_processManager=hwnd;
        g_processList=CreateWindowExW(WS_EX_CLIENTEDGE,WC_LISTVIEWW,L"",WS_CHILD|WS_VISIBLE|LVS_REPORT|LVS_SINGLESEL|LVS_SHOWSELALWAYS,10,10,1180,560,hwnd,(HMENU)5201,g_instance,nullptr);
        ListView_SetExtendedListViewStyle(g_processList,LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES|LVS_EX_DOUBLEBUFFER);
        const wchar_t* titles[]={L"PID",L"CPU",L"ОЗУ",L"Процесс",L"Описание / назначение"};
        const int widths[]={80,80,100,220,650};
        for(int i=0;i<5;++i) { LVCOLUMNW c{}; c.mask=LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM; c.pszText=const_cast<LPWSTR>(titles[i]); c.cx=widths[i]; c.iSubItem=i; ListView_InsertColumn(g_processList,i,&c); }
        CreateWindowW(L"BUTTON",L"Завершить процесс",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,10,582,190,34,hwnd,(HMENU)5202,g_instance,nullptr);
        CreateWindowW(L"BUTTON",L"Обновить список",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,210,582,150,34,hwnd,(HMENU)5203,g_instance,nullptr);
        CreateWindowW(L"STATIC",L"CPU — доля общей мощности процессора за интервал 0,5 с; ОЗУ — текущая рабочая память процесса.",WS_CHILD|WS_VISIBLE,380,588,800,24,hwnd,(HMENU)5204,g_instance,nullptr);
        RefreshProcessList(); return 0;
    }
    case WM_SIZE: if(g_processList) MoveWindow(g_processList,10,10,LOWORD(lp)-20,HIWORD(lp)-70,TRUE); return 0;
    case WM_COMMAND:
        if(LOWORD(wp)==5202) { TerminateSelectedProcess(hwnd); return 0; }
        if(LOWORD(wp)==5203) { RefreshProcessList(); return 0; }
        break;
    case WM_DESTROY: g_processManager=nullptr; g_processList=nullptr; return 0;
    }
    return DefWindowProcW(hwnd,msg,wp,lp);
}
static void OpenProcessManager() {
    if(g_processManager) { ShowWindow(g_processManager,SW_SHOWNORMAL); SetForegroundWindow(g_processManager); return; }
    WNDCLASSW wc{}; wc.lpfnWndProc=ProcessManagerProc; wc.hInstance=g_instance; wc.lpszClassName=L"PCPM_PROCESS_MANAGER"; wc.hCursor=LoadCursor(nullptr,IDC_ARROW); wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);
    if(!RegisterClassW(&wc)&&GetLastError()!=ERROR_CLASS_ALREADY_EXISTS) { MessageBoxW(g_window,L"Не удалось зарегистрировать окно процессов.",L"Ошибка",MB_OK|MB_ICONERROR); return; }
    HWND w=CreateWindowW(wc.lpszClassName,L"Процессы Windows — мониторинг и управление",WS_OVERLAPPEDWINDOW|WS_VISIBLE,CW_USEDEFAULT,CW_USEDEFAULT,1240,700,g_window,nullptr,g_instance,nullptr);
    if(!w) MessageBoxW(g_window,L"Не удалось открыть окно процессов.",L"Ошибка",MB_OK|MB_ICONERROR);
}
static std::wstring ProcessReport() {
    auto rows=EnumerateProcessRows(); std::wstringstream ss;
    ss<<L"PID\tCPU %\tОЗУ (МБ)\tПроцесс\tОписание / назначение\r\n";
    for(const auto& p:rows) ss<<p.pid<<L"\t"<<std::fixed<<std::setprecision(1)<<p.cpuPercent<<L"%\t"<<(p.workingSet/1048576.0)<<L"\t"<<p.name<<L"\t"<<p.description<<L"\r\n";
    return ss.str();
}
struct StartupEntry {
    HKEY hive{};
    std::wstring hiveName, subkey, valueName, command;
    REGSAM view{};
};
static std::vector<StartupEntry> g_startupEntries;
static HWND g_startupManager{}, g_startupList{};

static std::vector<StartupEntry> EnumerateStartupEntries() {
    std::vector<StartupEntry> entries;
    const wchar_t* paths[] = {
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    };
    struct Root { HKEY key; const wchar_t* name; REGSAM view; };
    const Root roots[] = {
        {HKEY_CURRENT_USER,L"HKCU",KEY_WOW64_64KEY},
        {HKEY_LOCAL_MACHINE,L"HKLM",KEY_WOW64_64KEY}
    };
    for (const auto& root : roots) for (const auto* path : paths) {
        HKEY key{};
        if (RegOpenKeyExW(root.key,path,0,KEY_READ|root.view,&key)!=ERROR_SUCCESS) continue;
        DWORD valueCount=0,maxName=0,maxData=0;
        if (RegQueryInfoKeyW(key,nullptr,nullptr,nullptr,nullptr,nullptr,nullptr,
            &valueCount,&maxName,&maxData,nullptr,nullptr)!=ERROR_SUCCESS) {
            RegCloseKey(key); continue;
        }
        std::vector<wchar_t> name((size_t)maxName+2);
        std::vector<BYTE> data((size_t)maxData+sizeof(wchar_t)+2);
        for (DWORD i=0;i<valueCount;++i) {
            DWORD nameLen=(DWORD)name.size(), dataLen=(DWORD)data.size(), type=0;
            LONG rc=RegEnumValueW(key,i,name.data(),&nameLen,nullptr,&type,
                data.data(),&dataLen);
            if (rc!=ERROR_SUCCESS || (type!=REG_SZ && type!=REG_EXPAND_SZ)) continue;
            StartupEntry e;
            e.hive=root.key; e.hiveName=root.name; e.subkey=path;
            e.valueName.assign(name.data(),nameLen);
            e.command.assign(reinterpret_cast<const wchar_t*>(data.data()),
                dataLen/sizeof(wchar_t));
            while (!e.command.empty() && e.command.back()==L'\0') e.command.pop_back();
            e.view=root.view;
            entries.push_back(std::move(e));
        }
        RegCloseKey(key);
    }
    return entries;
}
static void RefreshStartupList() {
    if (!g_startupList) return;
    g_startupEntries=EnumerateStartupEntries();
    SendMessageW(g_startupList,LB_RESETCONTENT,0,0);
    for (const auto& e:g_startupEntries) {
        std::wstring line=L"["+e.hiveName+L"] "+e.valueName+L" — "+e.command;
        SendMessageW(g_startupList,LB_ADDSTRING,0,(LPARAM)line.c_str());
    }
}
static LRESULT CALLBACK StartupManagerProc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp) {
    switch(msg) {
    case WM_CREATE:
        g_startupManager=hwnd;
        g_startupList=CreateWindowExW(WS_EX_CLIENTEDGE,L"LISTBOX",L"",
            WS_CHILD|WS_VISIBLE|WS_VSCROLL|WS_HSCROLL|LBS_NOTIFY|LBS_NOINTEGRALHEIGHT,
            12,12,820,360,hwnd,(HMENU)5101,g_instance,nullptr);
        CreateWindowW(L"BUTTON",L"Удалить из автозагрузки",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
            12,384,220,32,hwnd,(HMENU)5102,g_instance,nullptr);
        CreateWindowW(L"BUTTON",L"Обновить",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
            244,384,110,32,hwnd,(HMENU)5103,g_instance,nullptr);
        CreateWindowW(L"BUTTON",L"Закрыть",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
            722,384,110,32,hwnd,(HMENU)5104,g_instance,nullptr);
        RefreshStartupList();
        return 0;
    case WM_SIZE:
        if(g_startupList) MoveWindow(g_startupList,12,12,LOWORD(lp)-24,HIWORD(lp)-72,TRUE);
        return 0;
    case WM_COMMAND:
        if(LOWORD(wp)==5103) { RefreshStartupList(); return 0; }
        if(LOWORD(wp)==5104) { DestroyWindow(hwnd); return 0; }
        if(LOWORD(wp)==5102) {
            LRESULT selected=SendMessageW(g_startupList,LB_GETCURSEL,0,0);
            if(selected==LB_ERR || (size_t)selected>=g_startupEntries.size()) {
                MessageBoxW(hwnd,L"Сначала выберите запись автозагрузки.",L"Автозагрузка",MB_OK|MB_ICONINFORMATION);
                return 0;
            }
            const StartupEntry entry=g_startupEntries[(size_t)selected];
            std::wstring question=L"Удалить только запись автозапуска?\r\n\r\n"+
                entry.hiveName+L"\\ "+entry.subkey+L"\r\n"+entry.valueName+
                L" = "+entry.command+L"\r\n\r\nСамо приложение и его файлы останутся на компьютере.";
            if(MessageBoxW(hwnd,question.c_str(),L"Подтверждение удаления",MB_YESNO|MB_ICONWARNING)!=IDYES) return 0;
            HKEY key{};
            LONG rc=RegOpenKeyExW(entry.hive,entry.subkey.c_str(),0,KEY_SET_VALUE|entry.view,&key);
            if(rc==ERROR_SUCCESS) {
                rc=RegDeleteValueW(key,entry.valueName.c_str());
                RegCloseKey(key);
            }
            if(rc==ERROR_SUCCESS) {
                MessageBoxW(hwnd,L"Запись удалена из автозагрузки. Приложение не деинсталлировано.",L"Готово",MB_OK|MB_ICONINFORMATION);
                RefreshStartupList();
            } else {
                std::wstring err=L"Не удалось удалить запись. Код Windows: "+std::to_wstring(rc)+
                    L". Для записей HKLM может потребоваться запуск программы от имени администратора.";
                MessageBoxW(hwnd,err.c_str(),L"Ошибка удаления",MB_OK|MB_ICONERROR);
            }
            return 0;
        }
        break;
    case WM_DESTROY:
        g_startupManager=nullptr; g_startupList=nullptr; g_startupEntries.clear();
        return 0;
    }
    return DefWindowProcW(hwnd,msg,wp,lp);
}
static void OpenStartupManager() {
    if(g_startupManager) { ShowWindow(g_startupManager,SW_SHOWNORMAL); SetForegroundWindow(g_startupManager); return; }
    WNDCLASSW wc{}; wc.lpfnWndProc=StartupManagerProc; wc.hInstance=g_instance;
    wc.lpszClassName=L"PCPM_STARTUP_MANAGER"; wc.hCursor=LoadCursor(nullptr,IDC_ARROW);
    wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);
    if(!RegisterClassW(&wc) && GetLastError()!=ERROR_CLASS_ALREADY_EXISTS) {
        MessageBoxW(g_window,L"Не удалось зарегистрировать окно управления автозагрузкой.",L"Ошибка",MB_OK|MB_ICONERROR); return;
    }
    HWND w=CreateWindowW(wc.lpszClassName,L"Управление автозагрузкой Windows",
        WS_OVERLAPPEDWINDOW|WS_VISIBLE,CW_USEDEFAULT,CW_USEDEFAULT,860,470,
        g_window,nullptr,g_instance,nullptr);
    if(!w) MessageBoxW(g_window,L"Не удалось открыть управление автозагрузкой.",L"Ошибка",MB_OK|MB_ICONERROR);
}

static std::wstring StartupReport() {
    std::wstringstream ss;
    const wchar_t* paths[] = {
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    };
    for (auto hive : { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE }) for (auto path : paths) {
        ss << L"\r\n[" << (hive==HKEY_CURRENT_USER?L"HKCU":L"HKLM") << L"\\" << path << L"]\r\n";
        HKEY key{}; if (RegOpenKeyExW(hive,path,0,KEY_READ| (hive==HKEY_LOCAL_MACHINE?KEY_WOW64_64KEY:0),&key)!=ERROR_SUCCESS) continue;
        for (DWORD i=0;;++i) {
            wchar_t name[512], value[2048]; DWORD ns=512, vs=sizeof(value), type=0;
            LONG rc=RegEnumValueW(key,i,name,&ns,nullptr,&type,(BYTE*)value,&vs);
            if (rc==ERROR_NO_MORE_ITEMS) break; if (rc!=ERROR_SUCCESS) continue;
            if (type==REG_SZ || type==REG_EXPAND_SZ) ss << name << L" = " << value << L"\r\n";
        }
        RegCloseKey(key);
    }
    ss << L"\r\nРежим просмотра: автоматическое изменение записей не выполняется.\r\n";
    return ss.str();
}

static std::wstring TempScan() {
    std::vector<std::wstring> dirs;
    wchar_t t[MAX_PATH]{}, w[MAX_PATH]{};
    GetTempPathW(MAX_PATH,t); dirs.push_back(t);
    if (GetWindowsDirectoryW(w,MAX_PATH)) dirs.push_back(std::wstring(w)+L"\\Temp");
    unsigned long long bytes=0, files=0, errors=0;
    for (const auto& d:dirs) {
        std::error_code ec;
        for (fs::recursive_directory_iterator it(d, fs::directory_options::skip_permission_denied, ec), end; it!=end; it.increment(ec)) {
            if (ec) { ++errors; ec.clear(); continue; }
            if (!it->is_regular_file(ec)) continue;
            auto sz=it->file_size(ec); if (!ec) { bytes+=sz; ++files; } else { ++errors; ec.clear(); }
        }
    }
    std::wstringstream ss; ss << L"=== Временные файлы (только анализ) ===\r\nКаталогов: " << dirs.size()
        << L"\r\nФайлов: " << files << L"\r\nОбъём: " << (bytes/1048576.0) << L" MiB\r\nОшибок доступа: " << errors
        << L"\r\nУдаление не выполняется. Это защищает открытые и нужные приложениям файлы.\r\n";
    return ss.str();
}

static std::wstring RamIndex() {
    MEMORYSTATUSEX m{}; m.dwLength=sizeof(m); GlobalMemoryStatusEx(&m);
    unsigned score=99; std::wstring reason=L"Нагрузка памяти умеренная.";
    if (m.dwMemoryLoad>=95) { score=25; reason=L"Критически высокая занятость RAM."; }
    else if (m.dwMemoryLoad>=85) { score=50; reason=L"Высокая занятость RAM."; }
    else if (m.dwMemoryLoad>=70) { score=75; reason=L"Повышенная занятость RAM."; }
    std::wstringstream ss; ss << L"=== Индекс оперативной памяти (эвристика) ===\r\nОценка: " << score << L"%\r\n"
        << L"Занято: " << m.dwMemoryLoad << L"%\r\n" << reason
        << L"\r\nЭто оценка текущей нагрузки, а не физического износа модулей.\r\n"
        << L"Стандартного счётчика включений/выключений RAM-модулей обычно нет.\r\n";
    return ss.str();
}

static std::wstring Benchmark() {
    wchar_t temp[MAX_PATH]{}; GetTempPathW(MAX_PATH,temp);
    std::wstring path=std::wstring(temp)+L"PCPM_benchmark.tmp";
    constexpr size_t total=128ull*1024*1024;
    std::vector<BYTE> block(4*1024*1024,0x5A);
    HANDLE h=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_SEQUENTIAL_SCAN,nullptr);
    if(h==INVALID_HANDLE_VALUE) return L"Не удалось создать временный файл для теста.";
    auto a=std::chrono::steady_clock::now(); size_t written=0; DWORD n=0; bool ok=true;
    while(written<total) { if(!WriteFile(h,block.data(),(DWORD)block.size(),&n,nullptr)||!n){ok=false;break;} written+=n; }
    FlushFileBuffers(h); CloseHandle(h); auto b=std::chrono::steady_clock::now();
    std::error_code ec; fs::remove(path,ec);
    double sec=std::chrono::duration<double>(b-a).count();
    std::wstringstream ss; ss << L"=== Последовательная запись (временный файл) ===\r\nОбъём: " << written/1048576
        << L" MiB\r\nВремя: " << sec << L" с\r\nСкорость: " << (sec>0?written/1048576.0/sec:0) << L" MiB/s\r\n"
        << L"Результат: " << (ok?L"завершён":L"ошибка записи") << L"\r\n"
        << L"Тест кратковременный и зависит от кэша ОС/накопителя; не является полным бенчмарком SSD.\r\n";
    return ss.str();
}

static void ShowResult(std::wstring* p) {
    if (!p) return;
    if (g_window && !g_closing) {
        SetWindowTextW(g_output, p->c_str());
        SetStatus(L"Готово");
    }
    delete p;
}
static void StartTask(const std::wstring& name, std::function<std::wstring()> fn) {
    if (g_closing || !g_window) return;
    SessionLog(L"TASK_STARTED | " + name);
    SetStatus(L"Выполняется: " + name);
    EnableWindow(g_window, FALSE);
    ++g_activeTasks;
    HWND target = g_window;
    std::thread([target, name, fn=std::move(fn)]() {
        std::wstring body;
        try { body = fn(); }
        catch (const std::exception& e) { body = L"Ошибка фоновой задачи (std::exception)."; }
        catch (...) { body = L"Неизвестная ошибка фоновой задачи."; }
        SessionLog(L"TASK_FINISHED | " + name);
        {
            std::lock_guard<std::mutex> lock(g_sessionMutex);
            std::wofstream log(g_sessionLogPath, std::ios::app);
            if (log) log << L"TASK_OUTPUT_BEGIN | " << name << L"\r\n" << body << L"\r\n";
        }
        auto* result = new std::wstring(L"[" + name + L"]\r\n" + Timestamp() + L"\r\n\r\n" + body);
        // WM_CLOSE is deferred until all workers report completion, so target remains valid.
        if (!PostMessageW(target, WM_APP_RESULT, 0, (LPARAM)result)) {
            delete result;
            --g_activeTasks;
        }
    }).detach();
}
static void AddButton(HWND parent, const wchar_t* label, int id, int x, int y, int w=150) {
    CreateWindowW(L"BUTTON",label,WS_CHILD|WS_VISIBLE|BS_OWNERDRAW,x,y,w,32,parent,(HMENU)(INT_PTR)id,g_instance,nullptr);
}
enum { ID_HARDWARE=100, ID_SMART, ID_TEST_STATUS, ID_TEST_SHORT, ID_TEST_LONG, ID_DISKS, ID_DIAG, ID_PROCESSES,
       ID_STARTUP, ID_RAM, ID_TBW, ID_TEMP, ID_BENCH, ID_SAVE, ID_CANCEL_TEST };
static COLORREF ButtonColor(int id) {
    switch(id) {
    case ID_HARDWARE: case ID_SMART: case ID_DISKS: return RGB(18,145,190);
    case ID_TEST_STATUS: case ID_TEST_SHORT: case ID_TEST_LONG: case ID_CANCEL_TEST: return RGB(105,78,195);
    case ID_DIAG: case ID_PROCESSES: case ID_STARTUP: return RGB(20,150,125);
    case ID_RAM: case ID_TBW: return RGB(40,115,195);
    case ID_TEMP: case ID_BENCH: return RGB(195,120,35);
    default: return RGB(45,105,175);
    }
}
static void DrawColorButton(const DRAWITEMSTRUCT* d) {
    RECT r=d->rcItem; COLORREF c=ButtonColor((int)d->CtlID);
    if(d->itemState&ODS_DISABLED) c=RGB(75,82,100);
    if(d->itemState&ODS_SELECTED) c=RGB(35,65,105);
    for(int y=r.top;y<r.bottom;++y) {
        int k=((y-r.top)*30)/((r.bottom-r.top)>1?(r.bottom-r.top):1);
        COLORREF line=RGB((BYTE)std::max(0,(int)GetRValue(c)-k),(BYTE)std::max(0,(int)GetGValue(c)-k),(BYTE)std::max(0,(int)GetBValue(c)-k));
        HPEN p=CreatePen(PS_SOLID,1,line); HGDIOBJ old=SelectObject(d->hDC,p);
        MoveToEx(d->hDC,r.left+4,y,nullptr); LineTo(d->hDC,r.right-4,y);
        SelectObject(d->hDC,old); DeleteObject(p);
    }
    HPEN edge=CreatePen(PS_SOLID,1,RGB(95,190,225)); HGDIOBJ op=SelectObject(d->hDC,edge);
    HGDIOBJ ob=SelectObject(d->hDC,GetStockObject(NULL_BRUSH));
    RoundRect(d->hDC,r.left+1,r.top+1,r.right-1,r.bottom-1,10,10);
    SelectObject(d->hDC,op); SelectObject(d->hDC,ob); DeleteObject(edge);
    SetBkMode(d->hDC,TRANSPARENT); SetTextColor(d->hDC,RGB(255,255,255));
    wchar_t label[256]{}; GetWindowTextW(d->hwndItem,label,256);
    DrawTextW(d->hDC,label,-1,&r,DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
    if(d->itemState&ODS_FOCUS) { InflateRect(&r,-4,-4); DrawFocusRect(d->hDC,&r); }
}
static void SaveReport() {
    wchar_t file[MAX_PATH]=L"PC_Performance_Report.txt";
    OPENFILENAMEW ofn{}; ofn.lStructSize=sizeof(ofn); ofn.hwndOwner=g_window; ofn.lpstrFilter=L"Текстовые файлы (*.txt)\0*.txt\0Все файлы\0*.*\0";
    ofn.lpstrFile=file; ofn.nMaxFile=MAX_PATH; ofn.Flags=OFN_OVERWRITEPROMPT|OFN_PATHMUSTEXIST; ofn.lpstrDefExt=L"txt";
    if(GetSaveFileNameW(&ofn)) {
        int n=GetWindowTextLengthW(g_output); std::wstring s(n+1,L'\0'); GetWindowTextW(g_output,s.data(),n+1); s.resize(n);
        std::wofstream f(file);
        if(f) {
            f << s << L"\r\n\r\n=== АВТОМАТИЧЕСКИЙ ЖУРНАЛ ТЕКУЩЕГО СЕАНСА ===\r\n";
            std::lock_guard<std::mutex> lock(g_sessionMutex);
            std::wifstream log(g_sessionLogPath);
            if(log) f << log.rdbuf();
            else f << L"Журнал текущего сеанса недоступен.\r\n";
            SetStatus(L"Отчёт и журнал сеанса сохранены");
        } else {
            SetStatus(L"Не удалось сохранить отчёт");
            SessionLog(L"REPORT_SAVE_ERROR | " + std::to_wstring(GetLastError()));
        }
    }
}
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch(msg) {
    case WM_CREATE: {
        g_window=hwnd;
        SetTimer(hwnd, 1, 2000, nullptr);
        SessionLog(L"MAIN_WINDOW_CREATED");
        CaptureProcessActivity();
        AddButton(hwnd,L"Оборудование",ID_HARDWARE,10,10);
        AddButton(hwnd,L"SMART / NVMe",ID_SMART,168,10);
        AddButton(hwnd,L"Диски",ID_DISKS,326,10);
        AddButton(hwnd,L"Self-test статус",ID_TEST_STATUS,484,10);
        AddButton(hwnd,L"Self-test SHORT",ID_TEST_SHORT,642,10);
        AddButton(hwnd,L"Self-test LONG",ID_TEST_LONG,800,10);
        AddButton(hwnd,L"Отмена теста",ID_CANCEL_TEST,958,10);
        AddButton(hwnd,L"WHEA / RAM events",ID_DIAG,10,48);
        AddButton(hwnd,L"Процессы",ID_PROCESSES,168,48);
        AddButton(hwnd,L"Автозагрузка",ID_STARTUP,326,48);
        AddButton(hwnd,L"Индекс RAM",ID_RAM,484,48);
        AddButton(hwnd,L"TBW / история",ID_TBW,642,48);
        AddButton(hwnd,L"Временные файлы",ID_TEMP,800,48);
        AddButton(hwnd,L"Тест записи",ID_BENCH,958,48);
        AddButton(hwnd,L"Сохранить отчёт",ID_SAVE,10,86);
        g_output=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"PC Performance Monitor C++ x64\r\nВыберите модуль сверху.",
            WS_CHILD|WS_VISIBLE|WS_VSCROLL|WS_HSCROLL|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY|ES_NOHIDESEL,
            10,126,1110,570,hwnd,(HMENU)200,g_instance,nullptr);
        g_status=CreateWindowW(L"STATIC",L"Готово",WS_CHILD|WS_VISIBLE,10,704,1100,24,hwnd,(HMENU)201,g_instance,nullptr);
        return 0;
    }
    case WM_ERASEBKGND: {
        RECT r{}; GetClientRect(hwnd,&r); HBRUSH b=CreateSolidBrush(RGB(13,20,38));
        FillRect((HDC)wp,&r,b); DeleteObject(b); return 1;
    }
    case WM_DRAWITEM: {
        const DRAWITEMSTRUCT* d=(const DRAWITEMSTRUCT*)lp;
        if(d && d->CtlType==ODT_BUTTON) { DrawColorButton(d); return TRUE; }
        break;
    }
    case WM_CTLCOLORSTATIC: {
        HDC dc=(HDC)wp; SetTextColor(dc,RGB(195,220,245)); SetBkColor(dc,RGB(13,20,38));
        static HBRUSH b=CreateSolidBrush(RGB(13,20,38)); return (LRESULT)b;
    }
    case WM_CTLCOLOREDIT: {
        HDC dc=(HDC)wp; SetTextColor(dc,RGB(220,235,250)); SetBkColor(dc,RGB(20,31,52));
        static HBRUSH b=CreateSolidBrush(RGB(20,31,52)); return (LRESULT)b;
    }
    case WM_SIZE: {
        if(g_output) MoveWindow(g_output,10,126,LOWORD(lp)-20,HIWORD(lp)-160,TRUE);
        if(g_status) MoveWindow(g_status,10,HIWORD(lp)-28,LOWORD(lp)-20,22,TRUE);
        return 0;
    }
    case WM_TIMER:
        if (wp == 1 && !g_closing) CaptureProcessActivity();
        return 0;
    case WM_COMMAND:
        switch(LOWORD(wp)) {
        case ID_HARDWARE: StartTask(L"Оборудование",HardwareReport); break;
        case ID_SMART: StartTask(L"SMART и NVMe",SmartReport); break;
        case ID_DISKS: StartTask(L"Список накопителей",DiskList); break;
        case ID_TEST_STATUS: StartTask(L"Статус SMART self-test",SmartTests); break;
        case ID_TEST_SHORT: {
            if(MessageBoxW(hwnd,L"Запустить короткий SMART-тест на всех обнаруженных smartctl дисках? Команда зависит от поддержки накопителя.",L"Подтверждение",MB_YESNO|MB_ICONQUESTION)==IDYES)
                StartTask(L"SMART SHORT",[] { return RunSmartTest(L"-t short"); });
            break;
        }
        case ID_TEST_LONG: {
            if(MessageBoxW(hwnd,L"Запустить длительный SMART-тест на всех обнаруженных smartctl дисках?",L"Подтверждение",MB_YESNO|MB_ICONWARNING)==IDYES)
                StartTask(L"SMART LONG",[] { return RunSmartTest(L"-t long"); });
            break;
        }
        case ID_CANCEL_TEST:
            if(MessageBoxW(hwnd,L"Отменить SMART self-test на всех обнаруженных smartctl устройствах?",L"Подтверждение",MB_YESNO|MB_ICONWARNING)==IDYES)
                StartTask(L"Отмена SMART self-test",[] { return RunSmartTest(L"-X"); });
            break;
        case ID_DIAG: StartTask(L"Системные события",DiagnosticsReport); break;
        case ID_PROCESSES: OpenProcessManager(); break;
        case ID_STARTUP: OpenStartupManager(); break;
        case ID_RAM: StartTask(L"Индекс RAM",RamIndex); break;
        case ID_TBW: StartTask(L"История TBW",TbwReport); break;
        case ID_TEMP: StartTask(L"Анализ временных файлов",TempScan); break;
        case ID_BENCH: if(MessageBoxW(hwnd,L"Выполнить запись тестового файла 128 MiB на системный временный каталог? Данные теста будут удалены.",L"Подтверждение",MB_YESNO|MB_ICONWARNING)==IDYES) StartTask(L"Тест записи",Benchmark); break;
        case ID_SAVE: SaveReport(); break;
        }
        return 0;
    case WM_APP_RESULT: {
        ShowResult((std::wstring*)lp);
        const unsigned remaining = --g_activeTasks;
        if (g_closing && remaining == 0) DestroyWindow(hwnd);
        else if (!g_closing) { EnableWindow(hwnd,TRUE); SetForegroundWindow(hwnd); }
        return 0;
    }
    case WM_CLOSE:
        g_closing = true;
        if (g_activeTasks.load() != 0) {
            SetStatus(L"Завершение фоновой операции перед закрытием...");
            EnableWindow(hwnd, FALSE);
            return 0;
        }
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        KillTimer(hwnd, 1);
        SessionLog(L"MAIN_WINDOW_DESTROYED");
        EndSessionLog();
        PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hwnd,msg,wp,lp);
}

static void StartupLog(const wchar_t* stage, DWORD errorCode=0) {
    std::wofstream f(AppDataDir()+L"\\startup.log",std::ios::app);
    if(f) f<<Timestamp()<<L" | "<<stage<<L" | GetLastError="<<errorCode<<L"\r\n";
}
int WINAPI wWinMain(HINSTANCE hInst,HINSTANCE, PWSTR,int) {
    g_instance=hInst; BeginSessionLog(); SessionLog(L"PROCESS_STARTED"); StartupLog(L"process started");
    INITCOMMONCONTROLSEX ic{sizeof(ic),ICC_STANDARD_CLASSES|ICC_LISTVIEW_CLASSES};
    if(!InitCommonControlsEx(&ic)) StartupLog(L"InitCommonControlsEx failed",GetLastError());
    WNDCLASSW wc{}; wc.lpfnWndProc=WndProc; wc.hInstance=hInst; wc.lpszClassName=L"PCPM_CPP_X64";
    wc.hCursor=LoadCursor(nullptr,IDC_ARROW); wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);
    if(!RegisterClassW(&wc) && GetLastError()!=ERROR_CLASS_ALREADY_EXISTS) {
        DWORD e=GetLastError(); StartupLog(L"RegisterClassW failed",e);
        MessageBoxW(nullptr,L"Не удалось зарегистрировать окно. См. startup.log",L"PC Performance Monitor",MB_OK|MB_ICONERROR); return (int)e;
    }
    StartupLog(L"window class registered");
    HWND hwnd=CreateWindowExW(0,wc.lpszClassName,L"PC Performance Monitor — C++ x64 v1.3.8",
        WS_OVERLAPPEDWINDOW,CW_USEDEFAULT,CW_USEDEFAULT,1180,820,nullptr,nullptr,hInst,nullptr);
    if(!hwnd) {
        DWORD e=GetLastError(); StartupLog(L"CreateWindowExW failed",e);
        MessageBoxW(nullptr,L"Не удалось создать окно. См. %LOCALAPPDATA%\\PCPerformanceMonitor\\startup.log",L"PC Performance Monitor",MB_OK|MB_ICONERROR); return (int)e;
    }
    StartupLog(L"main window created"); ShowWindow(hwnd,SW_SHOWNORMAL); SetForegroundWindow(hwnd); UpdateWindow(hwnd);
    StartupLog(IsWindowVisible(hwnd)?L"window shown":L"window not visible",GetLastError());
    MSG msg{};
    for(;;) {
        BOOL r=GetMessageW(&msg,nullptr,0,0);
        if(r==0) break;
        if(r==-1) { DWORD e=GetLastError(); StartupLog(L"GetMessageW failed",e); return (int)e; }
        TranslateMessage(&msg); DispatchMessageW(&msg);
    }
    StartupLog(L"message loop ended"); return (int)msg.wParam;
}