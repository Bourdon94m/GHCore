# GHCore

A **C++17 header-only** library for Windows targeting game hacking and reverse engineering workflows.  
Drop it into any project via CMake — no compilation step required.

---

## Requirements

| | |
|---|---|
| **OS** | Windows (x86 / x64) |
| **C++ Standard** | C++17 or later |
| **CMake** | 3.16 or later |

---

## Integration

### Option A — CMake FetchContent

```cmake
include(FetchContent)
FetchContent_Declare(
    GHCore
    GIT_REPOSITORY https://github.com/Bourdon94m/GHCore.git
    GIT_TAG        main
)
FetchContent_MakeAvailable(GHCore)

target_link_libraries(your_target PRIVATE GHCore)
```

### Option B — Git submodule

```bash
git submodule add https://github.com/Bourdon94m/GHCore.git third_party/GHCore
```

```cmake
add_subdirectory(third_party/GHCore)
target_link_libraries(your_target PRIVATE GHCore)
```

### Option C — Manual copy

Copy the `src/` folder into your project and add the include path to your build system.

---

## Usage

Include everything at once:

```cpp
#include "GHCore.hpp"
```

Or include only what you need:

```cpp
#include "Memory/Memory.hpp"
#include "Memory/Scan.hpp"
#include "Process/Process.hpp"
#include "Hooks/VmtHook.hpp"
#include "Hooks/DetourHook.hpp"
#include "Hooks/IatHook.hpp"
#include "Inject/Inject.hpp"
#include "Utils/Utils.hpp"
```

---

## Modules

### `GHCore::Memory`

Read and write memory in the current process or a remote one.

```cpp
// Internal (same process)
int hp = GHCore::Memory::Read<int>(address);
GHCore::Memory::Write<int>(address, 100);

// Safe read — won't crash on invalid pages
int val;
if (GHCore::Memory::SafeRead<int>(address, val)) { ... }

// Multi-level pointer chain
uintptr_t final = GHCore::Memory::FollowPointer(base, { 0x30, 0x10, 0x4C });

// External (remote process)
int remoteHp = GHCore::Memory::ReadEx<int>(hProcess, address);
GHCore::Memory::WriteEx<int>(hProcess, address, 100);

// Page protection & allocation
GHCore::Memory::Unprotect(address, size);
uintptr_t remoteMem = GHCore::Memory::AllocEx(hProcess, 0x1000);
GHCore::Memory::FreeEx(hProcess, remoteMem);
```

---

### `GHCore::Scan`

IDA-style pattern scanning with a rich result type.

```cpp
// Scan a loaded module
auto result = GHCore::Scan::FindInModule(nullptr, "48 89 5C 24 ?? 57 48 83 EC ??");

// Scan a specific PE section
auto result = GHCore::Scan::FindInSection(nullptr, ".text", "48 8B 05 ?? ?? ?? ??");

// Scan a raw range
auto result = GHCore::Scan::Find(base, size, "CC CC CC");

// Find all occurrences
auto all = GHCore::Scan::FindAll(base, size, "CC CC CC");
```

`ScanResult` helpers:

```cpp
if (result) {
    uintptr_t off    = result.Offset(+3);          // address ± offset
    uintptr_t rip    = result.ResolveRip(3, 7);    // resolve RIP-relative displacement
    uintptr_t deref  = result.Deref();             // dereference pointer at address
    float     value  = result.Read<float>(0x8);    // read typed value at address + offset
}
```

---

### `GHCore::Process`

Process and module enumeration utilities.

```cpp
DWORD pid   = GHCore::Process::GetPidByName(L"game.exe");
HANDLE hProc = GHCore::Process::Open(pid);

// Module bases
uintptr_t base       = GHCore::Process::GetModuleBase();                       // current exe
uintptr_t remoteBase = GHCore::Process::GetModuleBaseEx(hProc, L"test.exe");   // remote

// List modules and threads
auto modules = GHCore::Process::GetModules(hProc);
auto threads = GHCore::Process::GetThreadIds(pid);

// Resolve a RIP-relative instruction
uintptr_t target = GHCore::Process::ResolveRip(instrAddr, 3, 7);
```

---

### `GHCore::Hook::DetourHook`

Inline JMP trampoline hook. Works on both x86 and x64. Allocates a trampoline so the original function can still be called.

```cpp
using tMessageBox = int(WINAPI*)(HWND, LPCSTR, LPCSTR, UINT);

int WINAPI MyMessageBox(HWND hWnd, LPCSTR text, LPCSTR caption, UINT type) {
    // call original
    return hook.CallOriginal<tMessageBox>(hWnd, text, "Hooked!", type);
}

GHCore::Hook::DetourHook hook;
hook.Install(reinterpret_cast<uintptr_t>(&MessageBoxA),
             reinterpret_cast<uintptr_t>(&MyMessageBox));

// ...

hook.Remove();
```

---

### `GHCore::Hook::VmtHook`

Replace a virtual function slot directly in an object's vtable.

```cpp
// Save the original and patch slot 2
void* original = GHCore::Hook::VmtHook::Hook(pObject, 2, &MyVirtFunc);

// Restore
GHCore::Hook::VmtHook::Unhook(pObject, 2, original);
```

---

### `GHCore::Hook::IatHook`

Patch an entry in a module's Import Address Table. Intercepts calls to a Windows API without modifying the function itself.

```cpp
GHCore::Hook::IatHook iatHook;
iatHook.Install(nullptr, "MessageBoxA", &MyMessageBoxA);

// Call the real function through the saved original
auto orig = iatHook.Original<decltype(&MessageBoxA)>();
orig(nullptr, "text", "caption", MB_OK);

iatHook.Remove();
```

---

### `GHCore::Inject`

Three DLL / shellcode injection strategies.

```cpp
HANDLE hProc = GHCore::Process::Open(pid);

// Classic LoadLibrary via CreateRemoteThread
GHCore::Inject::LoadLibrary(hProc, L"C:\\payload.dll");

// Raw shellcode
GHCore::Inject::Shellcode(hProc, shellcode, sizeof(shellcode));

// APC injection (fires on alertable threads)
GHCore::Inject::Apc(hProc, pid, L"C:\\payload.dll");
```

---

### `GHCore::Utils`

Thread-safe logger with optional console window and file output. Useful when running as an injected DLL.

```cpp
auto& log = GHCore::Utils::Logger::Get();

log.AllocConsole("My Tool");          // open a console window
log.OpenFile("log.txt");              // also write to file
log.SetMinLevel(GHCore::Utils::LogLevel::Debug);

log.Debug("debug message");
log.Info("info message");
log.Warning("something odd");
log.Error("something broke");
```

Output format: `[HH:MM:SS][LEVEL] message`

---

## Project structure

```
GHCore/
├── src/
│   ├── GHCore.hpp          ← single include
│   ├── Memory/
│   │   ├── Memory.hpp
│   │   └── Scan.hpp
│   ├── Process/
│   │   └── Process.hpp
│   ├── Hooks/
│   │   ├── DetourHook.hpp
│   │   ├── VmtHook.hpp
│   │   └── IatHook.hpp
│   ├── Inject/
│   │   └── Inject.hpp
│   ├── Utils/
│   │   └── Utils.hpp
│   └── example/
│       └── main.cpp
└── CMakeLists.txt
```

---

## Building the example

```bash
cmake -S . -B build
cmake --build build
```

To skip the example:

```bash
cmake -S . -B build -DGHCORE_BUILD_EXAMPLE=OFF
```

---

## License

This project is provided for educational purposes. Use responsibly and only on software you own or have explicit permission to modify.
