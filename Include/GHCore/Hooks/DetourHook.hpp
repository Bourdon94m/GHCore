#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <array>

namespace GHCore::Hook {

// Inline detour hook using a JMP trampoline (x86 & x64).
//
// Usage:
//   DetourHook hook;
//   hook.Install((uintptr_t)target, (uintptr_t)MyHook);
//   // call original via hook.Trampoline() cast to the right function type
//   hook.Remove();
class DetourHook {
public:
#ifdef _WIN64
    // FF 25 00000000 <8-byte abs addr>
    static constexpr size_t kJmpSize = 14;
#else
    // E9 <4-byte rel offset>
    static constexpr size_t kJmpSize = 5;
#endif

    DetourHook()                             = default;
    DetourHook(const DetourHook&)            = delete;
    DetourHook& operator=(const DetourHook&) = delete;
    ~DetourHook() { Remove(); }

    bool Install(uintptr_t target, uintptr_t detour) {
        if (m_installed) return false;
        m_target = target;

        memcpy(m_savedBytes.data(), reinterpret_cast<void*>(target), kJmpSize);

        // Allocate the trampoline: original bytes + jmp back to (target + kJmpSize)
        m_trampoline = reinterpret_cast<uintptr_t>(
            VirtualAlloc(nullptr, kJmpSize * 2,
                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (!m_trampoline) return false;

        memcpy(reinterpret_cast<void*>(m_trampoline),
               reinterpret_cast<void*>(target), kJmpSize);
        WriteJmp(m_trampoline + kJmpSize, target + kJmpSize);

        // Patch the target with a jmp to detour
        DWORD old = 0;
        VirtualProtect(reinterpret_cast<void*>(target), kJmpSize,
                        PAGE_EXECUTE_READWRITE, &old);
        WriteJmp(target, detour);
        VirtualProtect(reinterpret_cast<void*>(target), kJmpSize, old, &old);

        m_installed = true;
        return true;
    }

    void Remove() {
        if (!m_installed) return;
        DWORD old = 0;
        VirtualProtect(reinterpret_cast<void*>(m_target), kJmpSize,
                        PAGE_EXECUTE_READWRITE, &old);
        memcpy(reinterpret_cast<void*>(m_target), m_savedBytes.data(), kJmpSize);
        VirtualProtect(reinterpret_cast<void*>(m_target), kJmpSize, old, &old);

        if (m_trampoline) {
            VirtualFree(reinterpret_cast<void*>(m_trampoline), 0, MEM_RELEASE);
            m_trampoline = 0;
        }
        m_installed = false;
    }

    // Cast and call the original via the trampoline
    template<typename Fn, typename... Args>
    auto CallOriginal(Args&&... args) {
        return reinterpret_cast<Fn>(m_trampoline)(std::forward<Args>(args)...);
    }

    uintptr_t Trampoline()  const { return m_trampoline; }
    bool      IsInstalled() const { return m_installed; }

private:
    static void WriteJmp(uintptr_t from, uintptr_t to) {
#ifdef _WIN64
        uint8_t jmp[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
                             0,0,0,0,0,0,0,0 };
        memcpy(jmp + 6, &to, 8);
        memcpy(reinterpret_cast<void*>(from), jmp, sizeof(jmp));
#else
        uint8_t jmp[5];
        jmp[0] = 0xE9;
        int32_t rel = static_cast<int32_t>(to - from - 5);
        memcpy(jmp + 1, &rel, 4);
        memcpy(reinterpret_cast<void*>(from), jmp, sizeof(jmp));
#endif
    }

    uintptr_t m_target     = 0;
    uintptr_t m_trampoline = 0;
    bool      m_installed  = false;
    std::array<uint8_t, kJmpSize> m_savedBytes{};
};

} // namespace GHCore::Hook
