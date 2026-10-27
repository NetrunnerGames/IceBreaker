#include "LuaLoader.h"
#include "AppManager.h"
#include "../Core/HookManager.h"
#include "../Core/PatchEngine.h"
#include <fstream>
#include <regex>
#include <string>
#include <thread>
#include <windows.h>
#include <vector>

namespace IceBreaker {

std::atomic<bool> LuaLoader::s_stopFlag{false};
std::atomic<bool> LuaLoader::s_watcherRunning{false};

static uint8_t ParseHexNibble(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    return 0;
}

static std::vector<uint8_t> ParseHex64(const std::string& hex) {
    std::vector<uint8_t> bytes;
    if (hex.length() != 64) return bytes;
    bytes.reserve(32);
    for (size_t i = 0; i < 64; i += 2) {
        bytes.push_back(static_cast<uint8_t>((ParseHexNibble(hex[i]) << 4) | ParseHexNibble(hex[i + 1])));
    }
    return bytes;
}

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
    // addappid(480) or addappid( 480 ) or addappid(480, 0, "de1f...")
    // set_dlc(480, 520) or setdlc(...)
    std::regex addAppKeyRegex(R"(addappid\s*\(\s*(\d+)(?:\s*,\s*\d+\s*,\s*["']([a-fA-F0-9]{64})["'])?)", std::regex_constants::icase);
    std::regex dlcRegex(R"((?:set_dlc|add_dlc|setdlc)\s*\(\s*(\d+)\s*,\s*(\d+))", std::regex_constants::icase);
    std::regex addTokenRegex(R"(addtoken\s*\(\s*(\d+)\s*,\s*["'](\d+)["']\s*\))", std::regex_constants::icase);
    std::regex rawAppRegex(R"(app(?:id)?\s*=\s*(\d+))", std::regex_constants::icase);

    while (std::getline(file, line)) {
        std::smatch match;
        if (std::regex_search(line, match, addAppKeyRegex)) {
            uint32_t appId = std::stoul(match[1].str());
            AppManager::Get().AddUnlockedApp(appId);
            if (match.size() > 2 && match[2].matched) {
                std::string keyHex = match[2].str();
                std::vector<uint8_t> keyBytes = ParseHex64(keyHex);
                if (keyBytes.size() == 32) {
                    AppManager::Get().SetDepotKey(appId, keyBytes);
                }
            }
        } else if (std::regex_search(line, match, addTokenRegex)) {
            uint32_t appId = std::stoul(match[1].str());
            uint64_t token = std::stoull(match[2].str());
            AppManager::Get().SetAccessToken(appId, token);
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

    PatchEngine::NotifyLicenseChanged();
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
