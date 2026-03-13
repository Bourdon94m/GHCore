#include "GHCore/GHCore.hpp"
#include <iostream>

// ── Scan examples ─────────────────────────────────────────────────────────────
void ScanExamples() {
    // Basic IDA-style scan in the main module
    auto result = GHCore::Scan::FindInModule(nullptr, "48 89 5C 24 ?? 57 48 83 EC ??");
    if (result) {
        std::cout << "Found at: " << GHCore::Utils::ToHex(result) << '\n';

        // Address + positive offset
        uintptr_t addr1 = result.Offset(+3);
        // Address - negative offset
        uintptr_t addr2 = result.Offset(-5);
        // Resolve a RIP-relative lea/mov (lea rax,[rip+disp32], instrSize=7, dispPos=3)
        uintptr_t addr3 = result.ResolveRip(3, 7);
        // Dereference the pointer at result.address + 0
        uintptr_t addr4 = result.Deref();

        std::cout << "+3  : " << GHCore::Utils::ToHex(addr1) << '\n';
        std::cout << "-5  : " << GHCore::Utils::ToHex(addr2) << '\n';
        std::cout << "RIP : " << GHCore::Utils::ToHex(addr3) << '\n';
        std::cout << "Deref: " << GHCore::Utils::ToHex(addr4) << '\n';
    }

    // Scan only the .text section
    auto inText = GHCore::Scan::FindInSection(nullptr, ".text", "48 8B 05 ?? ?? ?? ??");

    // Find every occurrence in a range
    uintptr_t base = GHCore::Process::GetModuleBase();
    auto all = GHCore::Scan::FindAll(base, 0x1000000, "CC CC CC");
    std::cout << "Found " << all.size() << " int3 pads\n";
}

// ── Memory examples ───────────────────────────────────────────────────────────
void MemoryExamples() {
    int value = 1337;
    uintptr_t addr = reinterpret_cast<uintptr_t>(&value);

    int read = GHCore::Memory::Read<int>(addr);
    std::cout << "Read: " << read << '\n';

    GHCore::Memory::Write<int>(addr, 9999);
    std::cout << "After write: " << value << '\n';

    // Multi-level pointer
    int*      p1  = &value;
    int**     p2  = &p1;
    uintptr_t base = reinterpret_cast<uintptr_t>(p2);
    uintptr_t resolved = GHCore::Memory::FollowPointer(base, { 0x0 });
    std::cout << "Followed ptr: " << GHCore::Utils::ToHex(resolved) << '\n';
}

// ── Injection example (external) ─────────────────────────────────────────────
void InjectExample() {
    DWORD pid = GHCore::Process::GetPidByName(L"notepad.exe");
    if (!pid) { std::cout << "notepad.exe not found\n"; return; }

    HANDLE hProc = GHCore::Process::Open(pid);
    if (!hProc) return;

    // Pick one method:
    // GHCore::Inject::LoadLibrary(hProc, L"C:\\payload.dll");
    // GHCore::Inject::Apc(hProc, pid, L"C:\\payload.dll");
    // GHCore::Inject::ThreadHijack(hProc, pid, L"C:\\payload.dll");
    // GHCore::Inject::ManualMap(hProc, L"C:\\payload.dll");

    CloseHandle(hProc);
}

int main() {
    auto& log = GHCore::Utils::Logger::Get();
    log.AllocConsole("GHCore Example");
    log.OpenFile("ghcore.log");

    GHCORE_LOG_INFO("GHCore loaded");
    GHCORE_LOG_DBG("Module base: " + GHCore::Utils::ToHex(GHCore::Process::GetModuleBase()));

    ScanExamples();
    MemoryExamples();
    InjectExample();

    std::cin.get();
    return 0;
}
