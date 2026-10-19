#include "Scanner.h"
#include <psapi.h>
#include <sstream>
#include <iostream>

#pragma comment(lib, "psapi.lib")

namespace IceBreaker {

std::vector<int> Scanner::ParsePattern(const std::string& pattern) {
    std::vector<int> bytes;
    std::istringstream stream(pattern);
    std::string byteStr;

    while (stream >> byteStr) {
        if (byteStr == "?" || byteStr == "??") {
            bytes.push_back(-1); // Wildcard
        } else {
            try {
                bytes.push_back(std::stoi(byteStr, nullptr, 16));
            } catch (...) {
                bytes.push_back(-1);
            }
        }
    }
    return bytes;
}

uintptr_t Scanner::Scan(uintptr_t start, size_t length, const std::string& pattern) {
    std::vector<int> patternBytes = ParsePattern(pattern);
    if (patternBytes.empty() || length < patternBytes.size()) return 0;

    const uint8_t* scanBytes = reinterpret_cast<const uint8_t*>(start);
    size_t patternSize = patternBytes.size();

    for (size_t i = 0; i <= length - patternSize; ++i) {
        bool match = true;
        for (size_t j = 0; j < patternSize; ++j) {
            if (patternBytes[j] != -1 && scanBytes[i + j] != static_cast<uint8_t>(patternBytes[j])) {
                match = false;
                break;
            }
        }
        if (match) {
            return start + i;
        }
    }
    return 0;
}

uintptr_t Scanner::FindPattern(HMODULE module, const std::string& pattern) {
    if (!module) return 0;

    MODULEINFO modInfo = { 0 };
    if (!GetModuleInformation(GetCurrentProcess(), module, &modInfo, sizeof(MODULEINFO))) {
        return 0;
    }

    return Scan(reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll), modInfo.SizeOfImage, pattern);
}

uintptr_t Scanner::FindPattern(const std::wstring& moduleName, const std::string& pattern) {
    HMODULE hMod = GetModuleHandleW(moduleName.c_str());
    if (!hMod) return 0;
    return FindPattern(hMod, pattern);
}

} // namespace IceBreaker
