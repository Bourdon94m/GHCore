#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstring>

namespace GHCore::Hook {

// Patches an entry in a module's Import Address Table.
// Intercepts any call to a named Windows API without touching the function itself.
//
// Usage:
//   IatHook hook;
//   hook.Install(nullptr, "MessageBoxA", &MyMessageBoxA);
//   auto* orig = hook.Original<decltype(MessageBoxA)*>();
//   hook.Remove();
class IatHook {
public:
    IatHook()                          = default;
    IatHook(const IatHook&)            = delete;
    IatHook& operator=(const IatHook&) = delete;
    ~IatHook() { Remove(); }

    // hModule: module whose IAT to patch (nullptr = main exe)
    // importName: undecorated function name as it appears in the import table
    bool Install(HMODULE hModule, const char* importName, void* detour) {
        if (!hModule) hModule = GetModuleHandleA(nullptr);

        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(hModule);
        auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(
                        reinterpret_cast<uint8_t*>(hModule) + dos->e_lfanew);

        auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!importDir.VirtualAddress) return false;

        auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            reinterpret_cast<uint8_t*>(hModule) + importDir.VirtualAddress);

        for (; desc->Name; ++desc) {
            auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
                reinterpret_cast<uint8_t*>(hModule) + desc->FirstThunk);
            auto* orig  = reinterpret_cast<IMAGE_THUNK_DATA*>(
                reinterpret_cast<uint8_t*>(hModule) + desc->OriginalFirstThunk);

            for (; thunk->u1.Function; ++thunk, ++orig) {
                if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)) continue;

                auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                    reinterpret_cast<uint8_t*>(hModule) + orig->u1.AddressOfData);

                if (_stricmp(ibn->Name, importName) == 0) {
                    DWORD old = 0;
                    VirtualProtect(&thunk->u1.Function, sizeof(uintptr_t),
                                   PAGE_EXECUTE_READWRITE, &old);
                    m_patchSlot = reinterpret_cast<uintptr_t*>(&thunk->u1.Function);
                    m_original  = reinterpret_cast<void*>(*m_patchSlot);
                    *m_patchSlot = reinterpret_cast<uintptr_t>(detour);
                    VirtualProtect(&thunk->u1.Function, sizeof(uintptr_t), old, &old);
                    m_installed = true;
                    return true;
                }
            }
        }
        return false;
    }

    void Remove() {
        if (!m_installed || !m_patchSlot) return;
        DWORD old = 0;
        VirtualProtect(m_patchSlot, sizeof(uintptr_t),
                        PAGE_EXECUTE_READWRITE, &old);
        *m_patchSlot = reinterpret_cast<uintptr_t>(m_original);
        VirtualProtect(m_patchSlot, sizeof(uintptr_t), old, &old);
        m_installed = false;
    }

    template<typename Fn>
    Fn Original() const { return reinterpret_cast<Fn>(m_original); }

    bool IsInstalled() const { return m_installed; }

private:
    uintptr_t* m_patchSlot = nullptr;
    void*      m_original  = nullptr;
    bool       m_installed = false;
};

} // namespace GHCore::Hook
