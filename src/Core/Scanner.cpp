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

uintptr_t Scanner::ScanModule(HMODULE module, const std::string& pattern) {
    if (!module) return 0;
    for (const auto& [base, size] : ExecutableRanges(module)) {
        if (uintptr_t hit = Scan(base, size, pattern)) return hit;
    }
    return 0;
}

std::vector<std::pair<uintptr_t, size_t>> Scanner::ExecutableRanges(HMODULE module) {
    std::vector<std::pair<uintptr_t, size_t>> ranges;

    MODULEINFO modInfo = { 0 };
    if (!GetModuleInformation(GetCurrentProcess(), module, &modInfo, sizeof(MODULEINFO))) {
        return ranges;
    }

    auto* base = reinterpret_cast<const uint8_t*>(modInfo.lpBaseOfDll);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return ranges;

    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return ranges;

    auto section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            ranges.emplace_back(reinterpret_cast<uintptr_t>(base + section->VirtualAddress), section->Misc.VirtualSize);
        }
    }

    // Fallback: no executable section found (unexpected) — scan the whole image.
    if (ranges.empty()) {
        ranges.emplace_back(reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll), modInfo.SizeOfImage);
    }
    return ranges;
}

bool Scanner::IsInModule(HMODULE module, uintptr_t addr) {
    if (!module) return false;
    MODULEINFO modInfo = { 0 };
    if (!GetModuleInformation(GetCurrentProcess(), module, &modInfo, sizeof(MODULEINFO))) return false;
    uintptr_t base = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
    return addr >= base && addr < base + modInfo.SizeOfImage;
}

uintptr_t Scanner::FindPattern(HMODULE module, const std::string& pattern) {
    return ScanModule(module, pattern);
}

uintptr_t Scanner::FindPattern(const std::wstring& moduleName, const std::string& pattern) {
    HMODULE hMod = GetModuleHandleW(moduleName.c_str());
    if (!hMod) return 0;
    return FindPattern(hMod, pattern);
}

} // namespace IceBreaker
