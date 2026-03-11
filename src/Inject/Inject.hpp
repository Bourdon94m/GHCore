#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <string>
#include <vector>
#include <fstream>

namespace GHCore::Inject {

// ── Method 1: LoadLibrary via CreateRemoteThread ──────────────────────────────
//
// Classic injection. Least stealthy but reliable on most games.
inline bool LoadLibrary(HANDLE hProcess, const std::wstring& dllPath) {
    size_t pathBytes = (dllPath.size() + 1) * sizeof(wchar_t);

    LPVOID remotePath = VirtualAllocEx(hProcess, nullptr, pathBytes,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remotePath) return false;

    if (!WriteProcessMemory(hProcess, remotePath, dllPath.c_str(), pathBytes, nullptr)) {
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(
        hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW")),
        remotePath, 0, nullptr);

    if (!hThread) {
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
    return true;
}

// ── Method 2: Raw shellcode via CreateRemoteThread ────────────────────────────
//
// Write arbitrary shellcode into the target and run it.
// wait: block until the shellcode thread finishes.
inline bool Shellcode(HANDLE hProcess, const uint8_t* code, size_t size, bool wait = true) {
    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, size,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) return false;

    if (!WriteProcessMemory(hProcess, remoteMem, code, size, nullptr)) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(
        hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteMem),
        nullptr, 0, nullptr);

    if (!hThread) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

    if (wait) WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    // Memory is intentionally kept alive after the thread finishes
    // so the code remains executable if wait == false.
    if (wait) VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    return true;
}

// ── Method 3: APC injection (QueueUserAPC) ────────────────────────────────────
//
// Queues a LoadLibraryW call on every alertable thread of the target process.
// Fires when any thread enters an alertable wait (SleepEx, WaitForSingleObjectEx…).
inline bool Apc(HANDLE hProcess, DWORD pid, const std::wstring& dllPath) {
    size_t pathBytes = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID remotePath = VirtualAllocEx(hProcess, nullptr, pathBytes,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remotePath) return false;
    WriteProcessMemory(hProcess, remotePath, dllPath.c_str(), pathBytes, nullptr);

    auto* pfnLoadLibW = reinterpret_cast<PAPCFUNC>(
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW"));

    bool queued = false;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te{ sizeof(te) };
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != pid) continue;
                HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (hThread) {
                    if (QueueUserAPC(pfnLoadLibW, hThread,
                                     reinterpret_cast<ULONG_PTR>(remotePath)))
                        queued = true;
                    CloseHandle(hThread);
                }
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }

    if (!queued) VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
    return queued;
}

// ── Method 4: Thread hijacking ────────────────────────────────────────────────
//
// Suspends the first thread found, redirects its RIP/EIP to a shellcode stub
// that calls LoadLibraryW then restores execution at the original instruction.
//
// The stub is built at runtime for the target architecture.
inline bool ThreadHijack(HANDLE hProcess, DWORD pid, const std::wstring& dllPath) {
    // Allocate path + stub memory in the target
    size_t pathBytes = (dllPath.size() + 1) * sizeof(wchar_t);

#ifdef _WIN64
    // x64 stub:
    //   sub  rsp, 0x28
    //   mov  rcx, <path ptr>        ; LoadLibraryW arg
    //   mov  rax, <LoadLibraryW>
    //   call rax
    //   add  rsp, 0x28
    //   mov  rax, <original rip>
    //   jmp  rax
    constexpr size_t kStubSize = 56;
#else
    // x86 stub:
    //   push <path ptr>
    //   call <LoadLibraryA>
    //   add  esp, 4
    //   jmp  <original eip>
    constexpr size_t kStubSize = 20;
#endif

    size_t totalSize = pathBytes + kStubSize;
    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, totalSize,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) return false;

    uintptr_t remoteBase = reinterpret_cast<uintptr_t>(remoteMem);
    uintptr_t remotePath = remoteBase;
    uintptr_t remoteStub = remoteBase + pathBytes;

    WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(remotePath),
                       dllPath.c_str(), pathBytes, nullptr);

    // Find and suspend the first thread of the target
    DWORD targetTid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te{ sizeof(te) };
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    targetTid = te.th32ThreadID;
                    break;
                }
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }
    if (!targetTid) { VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE); return false; }

    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                                 THREAD_SUSPEND_RESUME, FALSE, targetTid);
    if (!hThread) { VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE); return false; }

    SuspendThread(hThread);

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        ResumeThread(hThread);
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return false;
    }

#ifdef _WIN64
    uintptr_t originalRip = ctx.Rip;
    uintptr_t pfnLoad = reinterpret_cast<uintptr_t>(
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW"));

    // Build the stub
    uint8_t stub[kStubSize] = {};
    size_t  o = 0;
    // sub rsp, 0x28
    stub[o++] = 0x48; stub[o++] = 0x83; stub[o++] = 0xEC; stub[o++] = 0x28;
    // movabs rcx, remotePath
    stub[o++] = 0x48; stub[o++] = 0xB9;
    memcpy(stub + o, &remotePath, 8); o += 8;
    // movabs rax, LoadLibraryW
    stub[o++] = 0x48; stub[o++] = 0xB8;
    memcpy(stub + o, &pfnLoad, 8); o += 8;
    // call rax
    stub[o++] = 0xFF; stub[o++] = 0xD0;
    // add rsp, 0x28
    stub[o++] = 0x48; stub[o++] = 0x83; stub[o++] = 0xC4; stub[o++] = 0x28;
    // movabs rax, originalRip
    stub[o++] = 0x48; stub[o++] = 0xB8;
    memcpy(stub + o, &originalRip, 8); o += 8;
    // jmp rax
    stub[o++] = 0xFF; stub[o++] = 0xE0;

    WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(remoteStub), stub, o, nullptr);
    ctx.Rip = remoteStub;
#else
    uintptr_t originalEip = ctx.Eip;
    uintptr_t pfnLoad = reinterpret_cast<uintptr_t>(
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW"));

    uint8_t stub[kStubSize] = {};
    size_t  o = 0;
    // push remotePath
    stub[o++] = 0x68; memcpy(stub + o, &remotePath, 4); o += 4;
    // call LoadLibraryW (relative)
    stub[o++] = 0xE8;
    int32_t rel = static_cast<int32_t>(pfnLoad - (remoteStub + o + 4));
    memcpy(stub + o, &rel, 4); o += 4;
    // add esp, 4
    stub[o++] = 0x83; stub[o++] = 0xC4; stub[o++] = 0x04;
    // push originalEip
    stub[o++] = 0x68; memcpy(stub + o, &originalEip, 4); o += 4;
    // ret (jmp to originalEip via stack)
    stub[o++] = 0xC3;

    WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(remoteStub), stub, o, nullptr);
    ctx.Eip = static_cast<DWORD>(remoteStub);
#endif

    SetThreadContext(hThread, &ctx);
    ResumeThread(hThread);
    CloseHandle(hThread);
    return true;
}

// ── Method 5: Manual Map ─────────────────────────────────────────────────────
//
// Maps a DLL into the target process manually:
//   1. Reads the file, validates the PE headers
//   2. Allocates SizeOfImage bytes in the target
//   3. Copies headers and sections
//   4. Writes a loader stub + ManualMapData struct into the target
//   5. Runs the stub via CreateRemoteThread; the stub:
//        - fixes base relocations
//        - resolves imports
//        - calls DllMain(DLL_PROCESS_ATTACH)
//
// The DLL leaves no LoadLibrary trace in the module list.

namespace detail {

#pragma pack(push, 1)
struct ManualMapData {
    uintptr_t                imageBase  = 0;
    DWORD                    delta      = 0;   // relocation delta
    PIMAGE_BASE_RELOCATION   pBaseReloc = nullptr;
    PIMAGE_IMPORT_DESCRIPTOR pImports   = nullptr;

    using FnLoadLibraryA   = HMODULE(WINAPI*)(LPCSTR);
    using FnGetProcAddress = FARPROC(WINAPI*)(HMODULE, LPCSTR);
    using FnDllMain        = BOOL(WINAPI*)(HMODULE, DWORD, LPVOID);

    FnLoadLibraryA   pfnLoadLibraryA   = nullptr;
    FnGetProcAddress pfnGetProcAddress = nullptr;
    FnDllMain        pfnDllMain        = nullptr;
};
#pragma pack(pop)

// This stub runs inside the target process.
// It must only reference data through the pData pointer (no globals, no CRT).
#pragma optimize("", off)
static DWORD WINAPI MapperStub(ManualMapData* pData) {
    // Fix base relocations
    if (pData->delta && pData->pBaseReloc) {
        auto* reloc = pData->pBaseReloc;
        while (reloc->VirtualAddress) {
            DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            auto* entry = reinterpret_cast<WORD*>(reloc + 1);
            for (DWORD i = 0; i < count; ++i) {
                int type = entry[i] >> 12;
                if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) {
                    auto* slot = reinterpret_cast<uintptr_t*>(
                        pData->imageBase + reloc->VirtualAddress + (entry[i] & 0xFFF));
                    *slot += pData->delta;
                }
            }
            reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                reinterpret_cast<uint8_t*>(reloc) + reloc->SizeOfBlock);
        }
    }

    // Resolve imports
    if (pData->pImports) {
        for (auto* imp = pData->pImports; imp->Name; ++imp) {
            HMODULE hLib = pData->pfnLoadLibraryA(
                reinterpret_cast<char*>(pData->imageBase + imp->Name));
            auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
                pData->imageBase + imp->FirstThunk);
            auto* orig  = reinterpret_cast<IMAGE_THUNK_DATA*>(
                pData->imageBase + imp->OriginalFirstThunk);
            while (thunk->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)) {
                    thunk->u1.Function = reinterpret_cast<uintptr_t>(
                        pData->pfnGetProcAddress(
                            hLib, reinterpret_cast<LPCSTR>(IMAGE_ORDINAL(orig->u1.Ordinal))));
                } else {
                    auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                        pData->imageBase + orig->u1.AddressOfData);
                    thunk->u1.Function = reinterpret_cast<uintptr_t>(
                        pData->pfnGetProcAddress(hLib, ibn->Name));
                }
                ++thunk; ++orig;
            }
        }
    }

    // Call DllMain
    if (pData->pfnDllMain)
        pData->pfnDllMain(reinterpret_cast<HMODULE>(pData->imageBase),
                          DLL_PROCESS_ATTACH, nullptr);
    return 0;
}
#pragma optimize("", on)
static void MapperStubEnd() {} // marker to measure stub size

} // namespace detail

inline bool ManualMap(HANDLE hProcess, const std::wstring& dllPath) {
    // Read DLL from disk
    std::ifstream file(dllPath, std::ios::binary | std::ios::ate);
    if (!file) return false;
    auto fileSize = static_cast<size_t>(file.tellg());
    file.seekg(0);
    std::vector<uint8_t> raw(fileSize);
    file.read(reinterpret_cast<char*>(raw.data()), fileSize);
    file.close();

    // Validate PE
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(raw.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(raw.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)  return false;

    // Allocate image memory in target (try preferred base first)
    auto remoteImage = reinterpret_cast<uintptr_t>(
        VirtualAllocEx(hProcess,
                        reinterpret_cast<LPVOID>(nt->OptionalHeader.ImageBase),
                        nt->OptionalHeader.SizeOfImage,
                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!remoteImage) {
        remoteImage = reinterpret_cast<uintptr_t>(
            VirtualAllocEx(hProcess, nullptr, nt->OptionalHeader.SizeOfImage,
                           MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    }
    if (!remoteImage) return false;

    DWORD delta = static_cast<DWORD>(remoteImage - nt->OptionalHeader.ImageBase);

    // Write PE headers
    WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(remoteImage),
                       raw.data(), nt->OptionalHeader.SizeOfHeaders, nullptr);

    // Write each section
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!sec->SizeOfRawData) continue;
        WriteProcessMemory(hProcess,
                           reinterpret_cast<LPVOID>(remoteImage + sec->VirtualAddress),
                           raw.data() + sec->PointerToRawData,
                           sec->SizeOfRawData, nullptr);
    }

    // Build the loader data
    detail::ManualMapData data{};
    data.imageBase        = remoteImage;
    data.delta            = delta;
    data.pfnLoadLibraryA  = ::LoadLibraryA;
    data.pfnGetProcAddress = ::GetProcAddress;
    data.pfnDllMain       = reinterpret_cast<detail::ManualMapData::FnDllMain>(
                                remoteImage + nt->OptionalHeader.AddressOfEntryPoint);

    auto& dd = nt->OptionalHeader.DataDirectory;
    if (dd[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
        data.pBaseReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                              remoteImage + dd[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    if (dd[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
        data.pImports = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
                            remoteImage + dd[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    // Copy stub + data into target
    size_t stubSize = reinterpret_cast<uintptr_t>(detail::MapperStubEnd) -
                      reinterpret_cast<uintptr_t>(detail::MapperStub);

    uintptr_t remoteStubMem = reinterpret_cast<uintptr_t>(
        VirtualAllocEx(hProcess, nullptr, stubSize + sizeof(detail::ManualMapData),
                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!remoteStubMem) {
        VirtualFreeEx(hProcess, reinterpret_cast<LPVOID>(remoteImage), 0, MEM_RELEASE);
        return false;
    }

    uintptr_t remoteData = remoteStubMem + stubSize;
    WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(remoteStubMem),
                       reinterpret_cast<void*>(detail::MapperStub), stubSize, nullptr);
    WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(remoteData),
                       &data, sizeof(data), nullptr);

    // Execute stub
    HANDLE hThread = CreateRemoteThread(
        hProcess, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteStubMem),
        reinterpret_cast<LPVOID>(remoteData), 0, nullptr);
    if (!hThread) {
        VirtualFreeEx(hProcess, reinterpret_cast<LPVOID>(remoteImage),   0, MEM_RELEASE);
        VirtualFreeEx(hProcess, reinterpret_cast<LPVOID>(remoteStubMem), 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, reinterpret_cast<LPVOID>(remoteStubMem), 0, MEM_RELEASE);
    return true;
}

} // namespace GHCore::Inject
