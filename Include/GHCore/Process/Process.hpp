#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <cstdint>
#include <string>
#include <vector>

namespace GHCore::Process {

struct ModuleInfo {
    std::wstring name;
    uintptr_t    base = 0;
    DWORD        size = 0;
};

// Find a process ID by its executable name (e.g. L"game.exe")
inline DWORD GetPidByName(const std::wstring& processName) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W entry{ sizeof(entry) };
    if (Process32FirstW(snap, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, processName.c_str()) == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return pid;
}

// Open a handle on a remote process
inline HANDLE Open(DWORD pid, DWORD access = PROCESS_ALL_ACCESS) {
    return ::OpenProcess(access, FALSE, pid);
}

// Base address of a module loaded in the current process (nullptr = main exe)
inline uintptr_t GetModuleBase(const char* moduleName = nullptr) {
    return reinterpret_cast<uintptr_t>(GetModuleHandleA(moduleName));
}

// Base address of a module loaded in a remote process
inline uintptr_t GetModuleBaseEx(HANDLE hProcess, const std::wstring& moduleName) {
    HANDLE snap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(hProcess));
    if (snap == INVALID_HANDLE_VALUE) return 0;
    uintptr_t base = 0;
    MODULEENTRY32W entry{ sizeof(entry) };
    if (Module32FirstW(snap, &entry)) {
        do {
            if (_wcsicmp(entry.szModule, moduleName.c_str()) == 0) {
                base = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
                break;
            }
        } while (Module32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return base;
}

// List all modules loaded in a remote process
inline std::vector<ModuleInfo> GetModules(HANDLE hProcess) {
    std::vector<ModuleInfo> modules;
    HANDLE snap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(hProcess));
    if (snap == INVALID_HANDLE_VALUE) return modules;
    MODULEENTRY32W entry{ sizeof(entry) };
    if (Module32FirstW(snap, &entry)) {
        do {
            modules.push_back({
                entry.szModule,
                reinterpret_cast<uintptr_t>(entry.modBaseAddr),
                entry.modBaseSize
            });
        } while (Module32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return modules;
}

// List all thread IDs belonging to a process
inline std::vector<DWORD> GetThreadIds(DWORD pid) {
    std::vector<DWORD> ids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return ids;
    THREADENTRY32 entry{ sizeof(entry) };
    if (Thread32First(snap, &entry)) {
        do {
            if (entry.th32OwnerProcessID == pid)
                ids.push_back(entry.th32ThreadID);
        } while (Thread32Next(snap, &entry));
    }
    CloseHandle(snap);
    return ids;
}

// Resolve a RIP-relative instruction found in a remote/local scan.
// e.g.  lea rax, [rip+disp32]  →  instrAddr + instrSize + disp32
//   offsetPos = byte position of the 4-byte displacement
//   instrSize = total instruction size
inline uintptr_t ResolveRip(uintptr_t instrAddr, int offsetPos, int instrSize) {
    int32_t disp = *reinterpret_cast<const int32_t*>(instrAddr + offsetPos);
    return instrAddr + instrSize + disp;
}

} // namespace GHCore::Process
