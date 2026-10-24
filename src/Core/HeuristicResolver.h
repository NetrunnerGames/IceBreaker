#pragma once
#include <windows.h>
#include <psapi.h>
#include <string>
#include <vector>
#include "Scanner.h"
#include "HookManager.h"

namespace IceBreaker {

/// <summary>
/// Autonomous in-memory heuristic pattern resolver that recovers target routines
/// when static AOB scans fail due to compiler or Steam updates.
/// </summary>
class HeuristicResolver {
public:
    /// <summary>
    /// Searches module executable memory backwards from an identifiable code point
    /// or forwards from a known anchor to locate the standard x64 prologue:
    /// (e.g. `push rbp`, `sub rsp, XX`, or `mov [rsp+XX], ...`)
    /// </summary>
    static uintptr_t FindPrologue(uintptr_t codeAddress, size_t maxBacktrack = 0x200) {
        if (!codeAddress) return 0;

        const uint8_t* ptr = reinterpret_cast<const uint8_t*>(codeAddress);
        for (size_t i = 1; i <= maxBacktrack; ++i) {
            const uint8_t* p = ptr - i;

            // Check for CC / 90 (int 3 or nop alignment padding preceding a function)
            if (p[-1] == 0xCC || p[-1] == 0x90) {
                // Typical prologues:
                // 40 53 (push rbx)
                // 48 83 EC (sub rsp, XX)
                // 48 89 5C 24 (mov [rsp+XX], rbx)
                // 48 8B C4 (mov rax, rsp)
                // 41 56 (push r14)
                if ((p[0] == 0x48 && p[1] == 0x89) ||
                    (p[0] == 0x48 && p[1] == 0x8B && p[2] == 0xC4) ||
                    (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xEC) ||
                    (p[0] == 0x40 && (p[1] >= 0x50 && p[1] <= 0x57)) ||
                    (p[0] >= 0x50 && p[0] <= 0x57)) {
                    return reinterpret_cast<uintptr_t>(p);
                }
            }
        }
        return 0;
    }

    /// <summary>
    /// Locates an ASCII string literal in the module's read-only data,
    /// then finds the code reference (LEA/MOV) in the executable sections.
    /// </summary>
    static uintptr_t FindXref(HMODULE hMod, const std::string& str) {
        if (!hMod) return 0;

        MODULEINFO info = { 0 };
        if (!GetModuleInformation(GetCurrentProcess(), hMod, &info, sizeof(info))) return 0;

        const uint8_t* base = reinterpret_cast<const uint8_t*>(info.lpBaseOfDll);
        size_t size = info.SizeOfImage;

        // 1. Find string in binary
        const uint8_t* strBytes = reinterpret_cast<const uint8_t*>(str.c_str());
        size_t strLen = str.length();

        const uint8_t* strAddr = nullptr;
        for (size_t i = 0; i <= size - strLen; ++i) {
            if (memcmp(base + i, strBytes, strLen) == 0) {
                strAddr = base + i;
                break;
            }
        }

        if (!strAddr) return 0;

        // 2. Scan executable ranges for 32-bit RIP-relative reference to strAddr
        // e.g. 48 8D 0D [rel32] or 48 8D 15 [rel32]
        for (const auto& [rangeBase, rangeSize] : Scanner::ExecutableRanges(hMod)) {
            const uint8_t* code = reinterpret_cast<const uint8_t*>(rangeBase);
            for (size_t i = 0; i <= rangeSize - 7; ++i) {
                if (code[i] == 0x48 && code[i + 1] == 0x8D) { // LEA reg, [rip + disp32]
                    int32_t disp = *reinterpret_cast<const int32_t*>(code + i + 3);
                    const uint8_t* target = code + i + 7 + disp;
                    if (target == strAddr) {
                        return reinterpret_cast<uintptr_t>(code + i);
                    }
                }
            }
        }

        return 0;
    }
};

} // namespace IceBreaker
