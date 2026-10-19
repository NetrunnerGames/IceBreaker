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

// Verified patterns for Steam 64-bit client (Build 1791918634 and surrounding builds)
inline const std::vector<PatternDefinition> g_SteamUIPatterns = {
    {
        "AddProtobufAsBinary",
        "steamui.dll",
        "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 41 8B F8 48 8B DA 48 8B F1 49 8B 10 48 85 D2",
        0
    },
    {
        "BuildCompleteAppOverviewChange",
        "steamui.dll",
        "40 53 48 83 EC 20 48 8B D9 E8 ?? ?? ?? ?? 48 85 C0 74 08 48 8B C8 E8 ?? ?? ?? ?? 48 8B C3 48 83 C4 20 5B C3",
        0
    },
    {
        "FillInAppOverview",
        "steamui.dll",
        "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 48 8B FA 48 8B D9 48 85 D2 75 0C",
        0
    },
    {
        "GetAppByID",
        "steamui.dll",
        "89 54 24 10 48 83 EC 28 8B 54 24 30 48 8D 4C 24 38 E8 ?? ?? ?? ?? 48 8B 00 48 83 C4 28 C3",
        0
    },
    {
        "SetAppOverviewFlag",
        "steamui.dll",
        "40 53 48 83 EC 20 44 8B 44 24 38 48 8B D9 89 54 24 10",
        0
    },
    {
        "ShouldShowAppInLibrary",
        "steamui.dll",
        "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B DA 48 8B F9 48 85 D2 74 13 48 8B 02",
        0
    }
};

inline const std::vector<PatternDefinition> g_SteamClientPatterns = {
    {
        "LoadDepotDecryptionKey",
        "steamclient64.dll",
        "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F9 48 8B DA 48 85 D2 74 38",
        0
    },
    {
        "CheckAppOwnership",
        "steamclient64.dll",
        "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F9 8B F2 48 85 C9 74 1E",
        0
    },
    {
        "KeyValues_ReadAsBinary",
        "steamclient64.dll",
        "40 55 53 56 57 41 54 41 56 41 57 48 8D 6C 24 C0 48 81 EC 40 01 00 00 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 45 30",
        0
    },
    {
        "RegisterForAppOverviewNotification",
        "steamclient64.dll",
        "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 48 8B F9 48 8B EA 48 85 D2 74 3B",
        0
    }
};

} // namespace IceBreaker
