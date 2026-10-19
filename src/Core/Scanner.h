#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>

namespace IceBreaker {

class Scanner {
public:
    // Finds pattern in the specified module (e.g. "steamclient64.dll" or "steamui.dll")
    // Pattern format: "48 89 5C 24 ? 57 48 83 EC 20" or IDA style "48 89 5C 24 ?? 57"
    static uintptr_t FindPattern(HMODULE module, const std::string& pattern);
    static uintptr_t FindPattern(const std::wstring& moduleName, const std::string& pattern);
    
    // Scans a specific memory range
    static uintptr_t Scan(uintptr_t start, size_t length, const std::string& pattern);

private:
    static std::vector<int> ParsePattern(const std::string& pattern);
};

} // namespace IceBreaker
