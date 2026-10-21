#include "IpcServer.h"
#include "../Core/HookManager.h"
#include "../Steam/AppManager.h"
#include "../Steam/LuaLoader.h"
#include <windows.h>
#include <thread>
#include <atomic>
#include <vector>
#include <sstream>

namespace IceBreaker {

static const wchar_t* kPipeName = L"\\\\.\\pipe\\IceBreaker_IPC";
static std::atomic<bool> s_running{ false };
static std::thread s_worker;
static HANDLE s_pipeHandle = INVALID_HANDLE_VALUE;

std::string IpcServer::ProcessCommand(const std::string& raw) {
    // Trim whitespace and newlines
    std::string cmd = raw;
    while (!cmd.empty() && (cmd.back() == '\r' || cmd.back() == '\n' || cmd.back() == ' ')) {
        cmd.pop_back();
    }
    size_t start = cmd.find_first_not_of(" \t\r\n");
    if (start != std::string::npos) {
        cmd = cmd.substr(start);
    } else {
        return "ERROR: empty command\n";
    }

    if (cmd == "PING") {
        return "PONG\n";
    }
    if (cmd == "VERSION") {
        return "IceBreaker 2.2.0\n";
    }
    if (cmd == "STATUS") {
        size_t count = AppManager::Get().GetUnlockedCount();
        return "OK unlocked=" + std::to_string(count) + "\n";
    }
    if (cmd == "GET_UNLOCKED") {
        std::vector<uint32_t> apps;
        AppManager::Get().GetUnlockedApps(apps);
        std::ostringstream ss;
        for (size_t i = 0; i < apps.size(); ++i) {
            if (i > 0) ss << ",";
            ss << apps[i];
        }
        ss << "\n";
        return ss.str();
    }
    if (cmd == "RELOAD") {
        LuaLoader::ReloadAll();
        return "OK reloaded\n";
    }
    if (cmd.rfind("UNLOCK ", 0) == 0) {
        std::string arg = cmd.substr(7);
        try {
            uint32_t appId = std::stoul(arg);
            AppManager::Get().AddUnlockedApp(appId);
            HookManager::Log("IPC: dynamically unlocked appId " + std::to_string(appId));
            return "OK unlocked " + std::to_string(appId) + "\n";
        } catch (...) {
            return "ERROR: invalid appId\n";
        }
    }
    if (cmd.rfind("LOCK ", 0) == 0) {
        std::string arg = cmd.substr(5);
        try {
            uint32_t appId = std::stoul(arg);
            AppManager::Get().RemoveUnlockedApp(appId);
            HookManager::Log("IPC: dynamically locked appId " + std::to_string(appId));
            return "OK locked " + std::to_string(appId) + "\n";
        } catch (...) {
            return "ERROR: invalid appId\n";
        }
    }

    return "ERROR: unknown command\n";
}

void IpcServer::WorkerThread() {
    HookManager::Log("IPC: named pipe server starting on " + std::string("\\\\.\\pipe\\IceBreaker_IPC"));

    while (s_running.load()) {
        HANDLE hPipe = CreateNamedPipeW(
            kPipeName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            4096,
            4096,
            0,
            NULL
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            HookManager::Log("IPC: CreateNamedPipe failed, error: " + std::to_string(GetLastError()));
            Sleep(1000);
            continue;
        }

        s_pipeHandle = hPipe;

        BOOL connected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (connected && s_running.load()) {
            char buffer[4096];
            DWORD bytesRead = 0;

            while (s_running.load() && ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                std::string response = ProcessCommand(buffer);
                DWORD bytesWritten = 0;
                WriteFile(hPipe, response.c_str(), static_cast<DWORD>(response.length()), &bytesWritten, NULL);
                FlushFileBuffers(hPipe);
            }
        }

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
        s_pipeHandle = INVALID_HANDLE_VALUE;
    }

    HookManager::Log("IPC: named pipe server stopped.");
}

void IpcServer::Start() {
    if (s_running.exchange(true)) return;
    s_worker = std::thread(WorkerThread);
}

void IpcServer::Stop() {
    if (!s_running.exchange(false)) return;

    if (s_pipeHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(s_pipeHandle);
        s_pipeHandle = INVALID_HANDLE_VALUE;
    }

    // Connect briefly to unblock ConnectNamedPipe if waiting
    HANDLE hClient = CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hClient != INVALID_HANDLE_VALUE) {
        CloseHandle(hClient);
    }

    if (s_worker.joinable()) {
        s_worker.join();
    }
}

} // namespace IceBreaker
