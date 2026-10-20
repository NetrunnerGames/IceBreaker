#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <atomic>

namespace IceBreaker {

class LuaLoader {
public:
    // Scans <Steam>\config\stplug-in\ for .lua files and parses AppIDs & DLC mappings
    static bool LoadPluginManifests();

    // Hot-reload: watches the plugin dir and re-parses manifests on change
    static void StartReloadWatcher();
    static void StopReloadWatcher();

private:
    static std::wstring GetSteamPluginDir();
    static void ParseLuaFile(const std::wstring& filePath);
    static void ReloadAll();
    static void WatcherLoop(std::wstring pluginDir);
    static std::atomic<bool> s_stopFlag;
    static std::atomic<bool> s_watcherRunning;
};

} // namespace IceBreaker
