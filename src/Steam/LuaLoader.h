#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace IceBreaker {

class LuaLoader {
public:
    // Scans <Steam>\config\stplug-in\ for .lua files and parses AppIDs & DLC mappings
    static bool LoadPluginManifests();

private:
    static std::wstring GetSteamPluginDir();
    static void ParseLuaFile(const std::wstring& filePath);
};

} // namespace IceBreaker
