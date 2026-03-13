#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace GHCore::Memory {

// ── Internal (same process) ───────────────────────────────────────────────────

template<typename T>
inline T Read(uintptr_t address) {
    return *reinterpret_cast<T*>(address);
}

template<typename T>
inline void Write(uintptr_t address, const T& value) {
    *reinterpret_cast<T*>(address) = value;
}

// Read without crashing on invalid pages
template<typename T>
inline bool SafeRead(uintptr_t address, T& out) {
    __try {
        out = *reinterpret_cast<T*>(address);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// Follow a multi-level pointer chain: base -> [base] + off[0] -> ... + off[n]
inline uintptr_t FollowPointer(uintptr_t base, const std::vector<uintptr_t>& offsets) {
    uintptr_t cur = base;
    for (auto off : offsets) {
        cur = Read<uintptr_t>(cur);
        if (!cur) return 0;
        cur += off;
    }
    return cur;
}

// ── External (remote process) ─────────────────────────────────────────────────

template<typename T>
inline T ReadEx(HANDLE hProcess, uintptr_t address) {
    T buf{};
    ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(address), &buf, sizeof(T), nullptr);
    return buf;
}

template<typename T>
inline bool WriteEx(HANDLE hProcess, uintptr_t address, const T& value) {
    SIZE_T written = 0;
    return WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(address),
                              &value, sizeof(T), &written) && written == sizeof(T);
}

inline std::string ReadStringEx(HANDLE hProcess, uintptr_t address, size_t maxLen = 256) {
    std::string buf(maxLen, '\0');
    SIZE_T read = 0;
    ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(address), buf.data(), maxLen, &read);
    buf.resize(strnlen(buf.data(), read));
    return buf;
}

inline uintptr_t FollowPointerEx(HANDLE hProcess, uintptr_t base,
                                  const std::vector<uintptr_t>& offsets) {
    uintptr_t cur = base;
    for (auto off : offsets) {
        cur = ReadEx<uintptr_t>(hProcess, cur);
        if (!cur) return 0;
        cur += off;
    }
    return cur;
}

// ── Page protection / allocation ──────────────────────────────────────────────

inline bool Unprotect(uintptr_t address, size_t size,
                       DWORD newProtect = PAGE_EXECUTE_READWRITE,
                       DWORD* oldProtect = nullptr) {
    DWORD old = 0;
    bool ok = VirtualProtect(reinterpret_cast<LPVOID>(address), size, newProtect, &old);
    if (oldProtect) *oldProtect = old;
    return ok;
}

inline uintptr_t AllocEx(HANDLE hProcess, size_t size,
                          DWORD protect = PAGE_EXECUTE_READWRITE) {
    return reinterpret_cast<uintptr_t>(
        VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, protect));
}

inline void FreeEx(HANDLE hProcess, uintptr_t address) {
    VirtualFreeEx(hProcess, reinterpret_cast<LPVOID>(address), 0, MEM_RELEASE);
}

} // namespace GHCore::Memory
