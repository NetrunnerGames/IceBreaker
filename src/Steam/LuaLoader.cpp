#include "LuaLoader.h"
#include "AppManager.h"
#include "../Core/HookManager.h"
#include <windows.h>
#include <fstream>
#include <sstream>
#include <regex>
#include <thread>

namespace IceBreaker {

std::atomic<bool> LuaLoader::s_stopFlag{ false };
std::atomic<bool> LuaLoader::s_watcherRunning{ false };

std::wstring LuaLoader::GetSteamPluginDir() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring path(exePath);
    size_t lastSlash = path.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) {
        return path.substr(0, lastSlash) + L"\\config\\stplug-in";
    }
    return L"";
}

void LuaLoader::ParseLuaFile(const std::wstring& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) return;

    std::string line;
    // Common patterns in stplug-in lua manifests:
    // addappid(480) or addappid( 480 ) or addappid(480, 1, "...")
    // set_dlc(480, 520) or setdlc(...)
    std::regex addAppRegex(R"(addappid\s*\(\s*(\d+))", std::regex_constants::icase);
    std::regex dlcRegex(R"((?:set_dlc|add_dlc|setdlc)\s*\(\s*(\d+)\s*,\s*(\d+))", std::regex_constants::icase);
    std::regex rawAppRegex(R"(app(?:id)?\s*=\s*(\d+))", std::regex_constants::icase);

    while (std::getline(file, line)) {
        std::smatch match;
        if (std::regex_search(line, match, addAppRegex)) {
            uint32_t appId = std::stoul(match[1].str());
            AppManager::Get().AddUnlockedApp(appId);
        } else if (std::regex_search(line, match, dlcRegex)) {
            uint32_t appId = std::stoul(match[1].str());
            uint32_t dlcId = std::stoul(match[2].str());
            AppManager::Get().SetAppDLCs(appId, { dlcId });
            AppManager::Get().AddUnlockedApp(dlcId);
        } else if (std::regex_search(line, match, rawAppRegex)) {
            uint32_t appId = std::stoul(match[1].str());
            AppManager::Get().AddUnlockedApp(appId);
        }
    }
}

void LuaLoader::ReloadAll() {
    std::wstring pluginDir = GetSteamPluginDir();
    if (pluginDir.empty()) return;

    AppManager::Get().Clear();

    std::wstring searchPattern = pluginDir + L"\\*.lua";
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPattern.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    size_t count = 0;
    do {
        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            std::wstring fullPath = pluginDir + L"\\" + findData.cFileName;
            ParseLuaFile(fullPath);
            count++;
        }
    } while (FindNextFileW(hFind, &findData));

    FindClose(hFind);
    HookManager::Log("Reloaded " + std::to_string(count) + " Lua manifests. Total unlocked AppIDs: " +
                     std::to_string(AppManager::Get().GetUnlockedCount()));
}

bool LuaLoader::LoadPluginManifests() {
    std::wstring pluginDir = GetSteamPluginDir();
    if (pluginDir.empty()) return false;

    // Narrow log conversion is best-effort for the ASCII-only Steam-root case.
    std::string dirNarrow;
    dirNarrow.reserve(pluginDir.size());
    for (wchar_t ch : pluginDir) dirNarrow.push_back(static_cast<char>(ch));
    HookManager::Log("Scanning for manifests in: " + dirNarrow);

    ReloadAll();
    if (AppManager::Get().GetUnlockedCount() == 0) {
        HookManager::Log("No .lua files found in plugin directory.");
        return false;
    }
    return true;
}

void LuaLoader::WatcherLoop(std::wstring pluginDir) {
    HANDLE hChange = FindFirstChangeNotificationW(pluginDir.c_str(), FALSE,
                                                  FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME);
    if (hChange == INVALID_HANDLE_VALUE) return;

    while (!s_stopFlag.load()) {
        DWORD wait = WaitForSingleObject(hChange, 500);
        if (s_stopFlag.load()) break;
        if (wait == WAIT_OBJECT_0) {
            // Editors often write multiple times in quick succession; debounce.
            Sleep(500);
            ReloadAll();
            if (!FindNextChangeNotification(hChange)) break;
        }
    }
    FindCloseChangeNotification(hChange);
}

void LuaLoader::StartReloadWatcher() {
    std::wstring pluginDir = GetSteamPluginDir();
    if (pluginDir.empty()) return;
    bool expected = false;
    if (!s_watcherRunning.compare_exchange_strong(expected, true)) return; // already running
    s_stopFlag.store(false);
    std::thread(WatcherLoop, pluginDir).detach();
    HookManager::Log("Manifest hot-reload watcher started.");
}

void LuaLoader::StopReloadWatcher() {
    s_stopFlag.store(true);
    s_watcherRunning.store(false);
}

} // namespace IceBreaker
