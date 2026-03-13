#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>

namespace GHCore::Hook {

// Replaces a virtual function slot in an object's vtable.
//
// Usage:
//   void* original = VmtHook::Hook(pObj, 0, &MyFunc);
//   VmtHook::Unhook(pObj, 0, original);
class VmtHook {
public:
    // Returns the original function pointer so you can call through it.
    static void* Hook(void* pObject, size_t slotIndex, void* newFunc) {
        uintptr_t* vtable = *reinterpret_cast<uintptr_t**>(pObject);
        DWORD old = 0;
        VirtualProtect(&vtable[slotIndex], sizeof(uintptr_t),
                        PAGE_EXECUTE_READWRITE, &old);
        void* original        = reinterpret_cast<void*>(vtable[slotIndex]);
        vtable[slotIndex]     = reinterpret_cast<uintptr_t>(newFunc);
        VirtualProtect(&vtable[slotIndex], sizeof(uintptr_t), old, &old);
        return original;
    }

    static void Unhook(void* pObject, size_t slotIndex, void* originalFunc) {
        uintptr_t* vtable = *reinterpret_cast<uintptr_t**>(pObject);
        DWORD old = 0;
        VirtualProtect(&vtable[slotIndex], sizeof(uintptr_t),
                        PAGE_EXECUTE_READWRITE, &old);
        vtable[slotIndex] = reinterpret_cast<uintptr_t>(originalFunc);
        VirtualProtect(&vtable[slotIndex], sizeof(uintptr_t), old, &old);
    }

    static void* GetOriginal(void* pObject, size_t slotIndex) {
        uintptr_t* vtable = *reinterpret_cast<uintptr_t**>(pObject);
        return reinterpret_cast<void*>(vtable[slotIndex]);
    }
};

} // namespace GHCore::Hook
