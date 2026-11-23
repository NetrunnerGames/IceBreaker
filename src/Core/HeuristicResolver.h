#pragma once
#include <windows.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include "Scanner.h"
#include "HookManager.h"

namespace IceBreaker {

/// <summary>
/// Autonomous in-memory heuristic pattern resolver that recovers target routines
/// when static AOB scans fail due to compiler or Steam updates.
/// Also provides pattern synthesis to capture and cache new signatures automatically.
/// </summary>
class HeuristicResolver {
public:
    /// <summary>
    /// Searches module executable memory backwards from an identifiable code point
    /// or forwards from a known anchor to locate standard x64 prologues:
    /// </summary>
    static uintptr_t FindPrologue(uintptr_t codeAddress, size_t maxBacktrack = 0x300) {
        if (!codeAddress) return 0;

        const uint8_t* ptr = reinterpret_cast<const uint8_t*>(codeAddress);
        for (size_t i = 1; i <= maxBacktrack; ++i) {
            const uint8_t* p = ptr - i;

            // Check for CC / 90 (int 3 or nop alignment padding preceding a function)
            if (p[-1] == 0xCC || p[-1] == 0x90) {
                // Typical prologues:
                // 40 53 (push rbx)
                // 40 55 (push rbp)
                // 41 56 (push r14)
                // 41 57 (push r15)
                // 48 83 EC (sub rsp, XX)
                // 48 81 EC (sub rsp, XXXX)
                // 48 89 5C 24 (mov [rsp+XX], rbx)
                // 48 8B C4 (mov rax, rsp)
                if ((p[0] == 0x48 && p[1] == 0x89) ||
                    (p[0] == 0x48 && p[1] == 0x8B && p[2] == 0xC4) ||
                    (p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xEC) ||
                    (p[0] == 0x48 && p[1] == 0x81 && p[2] == 0xEC) ||
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
    /// then finds code references (LEA/MOV/CALL) in executable sections.
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
        // e.g. 48 8D 0D [rel32] or 48 8D 15 [rel32] (LEA rcx/rdx/r8, [rip + disp32])
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

    /// <summary>
    /// Scans executable ranges for immediate 32-bit integer constant (e.g. 0x090CD6, 8903).
    /// </summary>
    static uintptr_t FindConst32(HMODULE hMod, uint32_t val) {
        if (!hMod) return 0;

        for (const auto& [rangeBase, rangeSize] : Scanner::ExecutableRanges(hMod)) {
            const uint8_t* code = reinterpret_cast<const uint8_t*>(rangeBase);
            for (size_t i = 0; i <= rangeSize - 6; ++i) {
                // e.g. B8 [val32] (mov eax, val), 3D [val32] (cmp eax, val), 81 F9 [val32] (cmp ecx, val)
                if (code[i] == 0x3D || code[i] == 0xB8) {
                    if (*reinterpret_cast<const uint32_t*>(code + i + 1) == val) {
                        return reinterpret_cast<uintptr_t>(code + i);
                    }
                } else if (code[i] == 0x81 && (code[i + 1] >= 0xF8 && code[i + 1] <= 0xFF)) {
                    if (*reinterpret_cast<const uint32_t*>(code + i + 2) == val) {
                        return reinterpret_cast<uintptr_t>(code + i);
                    }
                }
            }
        }
        return 0;
    }

    /// <summary>
    /// Synthesizes an IDA-style AOB pattern from a resolved function entrypoint.
    /// Replaces volatile displacement and offset bytes with ?? wildcards so the signature
    /// can survive future minor builds.
    /// </summary>
    static std::string SynthesizePattern(uintptr_t funcAddr, size_t length = 24) {
        if (!funcAddr) return "";

        const uint8_t* bytes = reinterpret_cast<const uint8_t*>(funcAddr);
        std::ostringstream ss;

        size_t idx = 0;
        while (idx < length) {
            // Check for common volatile instructions
            // 48 83 EC [imm8] -> sub rsp, ??
            if (idx + 3 <= length && bytes[idx] == 0x48 && bytes[idx + 1] == 0x83 && bytes[idx + 2] == 0xEC) {
                ss << "48 83 EC ?? ";
                idx += 4; // opcode(3) + imm(1)
                continue;
            }
            // 48 89 5C 24 [disp8] -> mov [rsp+??], rbx
            if (idx + 4 <= length && bytes[idx] == 0x48 && bytes[idx + 1] == 0x89 && bytes[idx + 2] == 0x5C && bytes[idx + 3] == 0x24) {
                ss << "48 89 5C 24 ?? ";
                idx += 5; // opcode(4) + disp(1)
                continue;
            }
            // 48 8B 05 [rel32] -> mov reg, [rip+??]
            if (idx + 7 <= length && bytes[idx] == 0x48 && bytes[idx + 1] == 0x8B && bytes[idx + 2] == 0x05) {
                ss << "48 8B 05 ?? ?? ?? ?? ";
                idx += 7;
                continue;
            }
            // 89 54 24 [disp8] -> mov [rsp+??], edx
            if (idx + 3 <= length && bytes[idx] == 0x89 && bytes[idx + 1] == 0x54 && bytes[idx + 2] == 0x24) {
                ss << "89 54 24 ?? ";
                idx += 4;
                continue;
            }

            // Default byte output
            ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[idx]) << " ";
            idx++;
        }

        std::string pat = ss.str();
        if (!pat.empty() && pat.back() == ' ') pat.pop_back();
        return pat;
    }
};

} // namespace IceBreaker
