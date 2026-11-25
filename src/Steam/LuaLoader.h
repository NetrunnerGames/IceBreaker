#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <atomic>
#include <unordered_map>
#include <unordered_set>

namespace IceBreaker {

class LuaLoader {
public:
    // Scans <Steam>\config\stplug-in\ for .lua files and parses AppIDs & DLC mappings
    static bool LoadPluginManifests();

    // Hot-reload: watches the plugin dir and re-parses manifests on change
    static void StartReloadWatcher();
    static void StopReloadWatcher();
    static void ReloadAll();

private:
    static std::wstring GetSteamPluginDir();
    static void ParseLuaFile(const std::wstring& filePath,
                             std::unordered_map<uint32_t, uint32_t>& appToPackage,
                             std::unordered_map<uint32_t, std::unordered_set<uint32_t>>& appDLCs,
                             std::unordered_map<uint32_t, std::vector<uint8_t>>& depotKeys,
                             std::unordered_map<uint32_t, uint64_t>& accessTokens);
    static void WatcherLoop(std::wstring pluginDir);
    static std::atomic<bool> s_stopFlag;
    static std::atomic<bool> s_watcherRunning;
};

} // namespace IceBreaker
