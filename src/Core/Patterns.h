#pragma once
#include <string>
#include <vector>

namespace IceBreaker {

struct PatternDefinition {
    const char* name;
    const char* moduleName;
    const char* pattern;
    int offset; // byte offset from matched address if needed
};

// Clean, verified AOB signatures.
// Note: steamui.dll is optional because modern Steam renders the library in CEF,
// which can be controlled via Chrome DevTools Protocol (--remote-debugging-port).
inline const std::vector<PatternDefinition> g_SteamUIPatterns = {
    {
        "ShouldShowAppInLibrary",
        "steamui.dll",
        "40 53 48 83 EC 20 48 8B 01 48 8B D9 FF 10 3D D6 0C 09 00",
        0
    },
};

inline const std::vector<PatternDefinition> g_SteamClientPatterns = {
    {
        "CheckAppOwnership",
        "steamclient64.dll",
        "48 8B C4 89 50 10 48 89 48 08 55 53",
        0
    },
};

} // namespace IceBreaker
