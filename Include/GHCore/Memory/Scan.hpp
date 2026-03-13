#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <string_view>
#include <string>
#include <vector>

namespace GHCore::Scan {

// ── ScanResult ────────────────────────────────────────────────────────────────
//
// Wraps a found address and provides helpers to derive
// other addresses from it without having to do pointer arithmetic manually.

struct ScanResult {
    uintptr_t address = 0;

    operator bool()      const { return address != 0; }
    operator uintptr_t() const { return address; }

    // Return address ± offset (positive or negative)
    uintptr_t Offset(ptrdiff_t offset) const {
        return address + static_cast<uintptr_t>(offset);
    }

    // Resolve a RIP-relative instruction stored at (address + offsetPos).
    // e.g. for: lea rax, [rip+disp32]  →  ResolveRip(3, 7)
    //   offsetPos = byte index of the 4-byte displacement
    //   instrSize = total size of the instruction
    uintptr_t ResolveRip(int offsetPos, int instrSize) const {
        if (!address) return 0;
        int32_t disp = *reinterpret_cast<const int32_t*>(address + offsetPos);
        return address + instrSize + disp;
    }

    // Dereference the pointer stored at (address + offset)
    uintptr_t Deref(ptrdiff_t offset = 0) const {
        if (!address) return 0;
        return *reinterpret_cast<const uintptr_t*>(address + offset);
    }

    // Read a typed value at (address + offset)
    template<typename T>
    T Read(ptrdiff_t offset = 0) const {
        return *reinterpret_cast<const T*>(address + offset);
    }
};

// ── Internal helpers ──────────────────────────────────────────────────────────

namespace detail {

// Parse an IDA-style hex pattern string into a byte array + mask string.
// "48 8B ?? 05 ??" → bytes = {0x48, 0x8B, 0x00, 0x05, 0x00}
//                    mask  = "xx??x" (but we use '?' not 'x'/'?')
inline void ParsePattern(std::string_view pat,
                          std::vector<uint8_t>& outBytes,
                          std::string&          outMask)
{
    outBytes.clear();
    outMask.clear();
    size_t i = 0;
    while (i < pat.size()) {
        while (i < pat.size() && pat[i] == ' ') ++i;
        if (i >= pat.size()) break;

        if (pat[i] == '?') {
            outBytes.push_back(0x00);
            outMask.push_back('?');
            while (i < pat.size() && (pat[i] == '?' || pat[i] == ' ')) ++i;
        } else {
            outBytes.push_back(static_cast<uint8_t>(
                std::stoul(std::string(pat.substr(i, 2)), nullptr, 16)));
            outMask.push_back('x');
            i += 2;
        }
    }
}

inline bool Match(const uint8_t* data,
                   const uint8_t* bytes,
                   const char*    mask,
                   size_t         len) {
    for (size_t i = 0; i < len; ++i)
        if (mask[i] == 'x' && data[i] != bytes[i])
            return false;
    return true;
}

} // namespace detail

// ── Scan functions ────────────────────────────────────────────────────────────

// Scan a raw memory range with pre-built bytes + C-string mask ("xx??x")
inline ScanResult FindMasked(uintptr_t   start,
                               size_t      size,
                               const char* bytes,
                               const char* mask)
{
    size_t len = strlen(mask);
    if (size < len) return {};
    const auto* mem = reinterpret_cast<const uint8_t*>(start);
    for (size_t i = 0; i <= size - len; ++i)
        if (detail::Match(mem + i,
                          reinterpret_cast<const uint8_t*>(bytes), mask, len))
            return { start + i };
    return {};
}

// Scan an IDA-style pattern in an arbitrary memory range
inline ScanResult Find(uintptr_t start, size_t size, std::string_view pattern) {
    std::vector<uint8_t> bytes;
    std::string mask;
    detail::ParsePattern(pattern, bytes, mask);
    if (size < bytes.size()) return {};
    const auto* mem = reinterpret_cast<const uint8_t*>(start);
    for (size_t i = 0; i <= size - bytes.size(); ++i)
        if (detail::Match(mem + i, bytes.data(), mask.c_str(), bytes.size()))
            return { start + i };
    return {};
}

// Scan an IDA-style pattern in a loaded module.
// Pass nullptr to scan the main executable module.
inline ScanResult FindInModule(const char* moduleName, std::string_view pattern) {
    HMODULE hMod = GetModuleHandleA(moduleName);
    if (!hMod) return {};
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(hMod);
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(
                    reinterpret_cast<uint8_t*>(hMod) + dos->e_lfanew);
    return Find(reinterpret_cast<uintptr_t>(hMod),
                nt->OptionalHeader.SizeOfImage, pattern);
}

// Scan only a specific PE section (e.g. ".text", ".rdata")
inline ScanResult FindInSection(const char*     moduleName,
                                 const char*     sectionName,
                                 std::string_view pattern)
{
    HMODULE hMod = GetModuleHandleA(moduleName);
    if (!hMod) return {};
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(hMod);
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(
                    reinterpret_cast<uint8_t*>(hMod) + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        char name[9] = {};
        memcpy(name, sec->Name, 8);
        if (_stricmp(name, sectionName) == 0)
            return Find(reinterpret_cast<uintptr_t>(hMod) + sec->VirtualAddress,
                        sec->Misc.VirtualSize, pattern);
    }
    return {};
}

// Return ALL matches in a range (for non-unique patterns)
inline std::vector<ScanResult> FindAll(uintptr_t start, size_t size,
                                        std::string_view pattern)
{
    std::vector<uint8_t> bytes;
    std::string mask;
    detail::ParsePattern(pattern, bytes, mask);
    std::vector<ScanResult> results;
    if (size < bytes.size()) return results;
    const auto* mem = reinterpret_cast<const uint8_t*>(start);
    size_t len = bytes.size();
    for (size_t i = 0; i <= size - len; ++i)
        if (detail::Match(mem + i, bytes.data(), mask.c_str(), len))
            results.push_back({ start + i });
    return results;
}

// Find all matches inside a full module
inline std::vector<ScanResult> FindAllInModule(const char*      moduleName,
                                                std::string_view pattern)
{
    HMODULE hMod = GetModuleHandleA(moduleName);
    if (!hMod) return {};
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(hMod);
    auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(
                    reinterpret_cast<uint8_t*>(hMod) + dos->e_lfanew);
    return FindAll(reinterpret_cast<uintptr_t>(hMod),
                   nt->OptionalHeader.SizeOfImage, pattern);
}

} // namespace GHCore::Scan
