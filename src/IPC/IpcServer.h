#pragma once
#include <string>

namespace IceBreaker {

/// <summary>
/// IPC Named Pipe server running inside version.dll in the Steam process.
/// Allows external tools (like DataJackUI or sidecars) to query status,
/// dynamically unlock apps, and trigger manifest reloads over \\.\pipe\IceBreaker_IPC.
/// </summary>
class IpcServer {
public:
    static void Start();
    static void Stop();

private:
    static void WorkerThread();
    static std::string ProcessCommand(const std::string& command);
};

} // namespace IceBreaker
