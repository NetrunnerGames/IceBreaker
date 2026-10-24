#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>

namespace IceBreaker {

class Scanner {
public:
    // Finds pattern in the specified module (e.g. "steamclient64.dll" or "steamui.dll")
    // Pattern format: "48 89 5C 24 ? 57 48 83 EC 20" or IDA style "48 89 5C 24 ?? 57"
    static uintptr_t FindPattern(HMODULE module, const std::string& pattern);
    static uintptr_t FindPattern(const std::wstring& moduleName, const std::string& pattern);

    // Fast masked scan restricted to the module's executable sections (ScanModule).
    static uintptr_t ScanModule(HMODULE module, const std::string& pattern);
    static std::vector<std::pair<uintptr_t, size_t>> ExecutableRanges(HMODULE module);

    // Scans a specific memory range
    static uintptr_t Scan(uintptr_t start, size_t length, const std::string& pattern);

    // True if addr lies inside module's mapped image
    static bool IsInModule(HMODULE module, uintptr_t addr);

private:
    static std::vector<int> ParsePattern(const std::string& pattern);
};

} // namespace IceBreaker
