#ifndef FILE_CHECKER_H
#define FILE_CHECKER_H

#include <string>
#include <vector>
#include <filesystem> // C++17

// Forward declarations
class Logger;
struct Config;
struct IOCData;

namespace FileChecker {

// --- Public Interface ---
void scanC2Connections(const Config& config, const IOCData& iocData, Logger& logger);
bool isELF(const std::filesystem::path& filepath, Logger& logger);
void searchStringsInPlainFile(const std::filesystem::path& filepath,
                               const IOCData& iocData,
                               const Config& config,
                               Logger& logger);
void searchStringsInGzipFile(const std::filesystem::path& filepath,
                              const IOCData& iocData,
                              const Config& config,
                              Logger& logger);
void searchStringsInBzip2File(const std::filesystem::path& filepath,
                               const IOCData& iocData,
                               const Config& config,
                               Logger& logger);
bool executeCommand(const std::string& command, std::vector<std::string>& outputLines, Logger& logger);

// --- Внутренние функции убраны из заголовка ---
// std::string findIOCStringMatch(...)
// std::string formatMatchOutput(...)

}; // namespace FileChecker

#endif // FILE_CHECKER_H
