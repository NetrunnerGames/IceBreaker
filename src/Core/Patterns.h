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

// Signatures sourced from the community-maintained steam-monitor pattern branch
// (OpenSteam001/steam-monitor) and verified by byte-scanning the deployed
// steamui.dll / steamclient64.dll. Each pattern below matches exactly once in
// the verified build, so hooking at first match is safe.

inline const std::vector<PatternDefinition> g_SteamUIPatterns = {
    {
        "ShouldShowAppInLibrary",
        "steamui.dll",
        "40 53 48 83 EC 20 48 8B 01 48 8B D9 FF 10 3D D6 0C 09 00",
        0
    },
    {
        "GetAppByID",
        "steamui.dll",
        "89 54 24 10 53 48 83 EC 40 48 8B 05 ?? ?? ?? ??",
        0
    },
    {
        "FillInAppOverview",
        "steamui.dll",
        "48 89 54 24 10 48 89 4C 24 08 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 E1 48 81 EC B8 00 00 00",
        0
    },
    {
        "BuildCompleteAppOverviewChange",
        "steamui.dll",
        "4C 89 44 24 18 48 89 54 24 10 48 89 4C 24 08 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 E1",
        0
    },
    {
        "AddProtobufAsBinary",
        "steamui.dll",
        "40 53 55 56 57 48 83 EC 28 48 8B 05 ?? ?? ?? ?? 48 8B F2",
        0
    },
    {
        "CSteamUIAppControllerRunFrame",
        "steamui.dll",
        "48 89 5C 24 10 48 89 6C 24 18 56 57 41 54 41 56 41 57 48 83 EC 40 0F 29 74 24 30",
        0
    },
    {
        "MarkAppChange",
        "steamui.dll",
        "48 83 EC 78 48 8B 05 ?? ?? ?? ?? 48 89 74 24 70",
        0
    },
    {
        "RepeatedFieldUint32_Add",
        "steamui.dll",
        "48 89 74 24 10 48 89 7C 24 18 41 56 48 83 EC 20 8B 31 48 8B F9 8B 49 04",
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
    {
        "GetPackageInfo",
        "steamclient64.dll",
        "48 89 5C 24 18 89 54 24 10 55 56 57 48 83 EC 20 44 8B 49 20",
        0
    },
    {
        "CUtlMemoryGrow",
        "steamclient64.dll",
        "48 89 5C 24 10 57 48 83 EC 30 8B FA 48 8B D9 8B 51 08 8B 49 10 8D 04 39",
        0
    },
    {
        "MarkLicenseAsChanged",
        "steamclient64.dll",
        "48 89 5C 24 20 89 54 24 10 55 56 57 48 83 EC 20",
        0
    },
    {
        "ProcessPendingLicenseUpdates",
        "steamclient64.dll",
        "41 56 41 57 48 83 EC 38 83 B9 ?? ?? 00 00",
        0
    },
    {
        "LoadDepotDecryptionKey",
        "steamclient64.dll",
        "40 53 55 56 57 48 83 EC 38 48 63 FA 49 8B E9",
        0
    },
    {
        "KeyValues_ReadAsBinary",
        "steamclient64.dll",
        "48 8B C4 44 88 48 20 55 48 8D 68 A9",
        0
    },
    {
        "GetDecryptionKey",
        "steamclient64.dll",
        "40 53 55 56 57 48 81 EC 48 01 00 00 8B FA",
        0
    },
    {
        "LoadPackage",
        "steamclient64.dll",
        "44 89 44 24 18 53 55 56 57 41 55",
        0
    },
    {
        "GetAppDataFromAppInfo",
        "steamclient64.dll",
        "40 53 55 56 57 41 56 41 57 48 81 EC 78 01 00 00",
        0
    },
    {
        "IPCProcessMessage",
        "steamclient64.dll",
        "48 89 5C 24 18 48 89 6C 24 20 57 41 54 41 55 41 56 41 57 48 83 EC 30",
        0
    },
    {
        "CUtlBufferEnsureCapacity",
        "steamclient64.dll",
        "48 89 5C 24 08 57 48 83 EC 30 48 8B D9 8D 7A 01",
        0
    },
};

} // namespace IceBreaker
