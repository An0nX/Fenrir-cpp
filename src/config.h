#ifndef CONFIG_H
#define CONFIG_H

#include <string>
#include <vector>
#include <unordered_set>
#include <cstdint> // For uintmax_t
#include <syslog.h> // <<< ДОБАВЛЕНО для LOG_LOCAL4

// Forward declaration для Logger, чтобы избежать циклической зависимости
class Logger;

struct Config {
    // Logging
    std::string logFilePattern = "./FENRIR_{HOSTNAME}_{DATE}.log";
    bool logToFile = true;
    bool logToSyslog = false;
    bool logToCmdLine = true;
    int syslogFacility = LOG_LOCAL4; // Теперь константа должна быть видна
    std::string syslogIdent = "fenrir";

    // IOC Files
    std::string hashIOCFile = "./iocs/hash-iocs.txt";
    std::string stringIOCFile = "./iocs/string-iocs.txt";
    std::string filenameIOCFile = "./iocs/filename-iocs.txt";
    std::string c2IOCFile = "./iocs/c2-iocs.txt";

    // Checks
    bool enableC2Check = true;
    bool enableTypeCheck = true;
    bool enableHashCheck = true;
    bool checkHotTimeframe = false;

    // Performance
    uintmax_t maxFileSizeKB = 8000;
    bool checkOnlyRelevantExtensions = true;
    std::unordered_set<std::string> relevantExtensions; // Use set for fast lookup
    size_t fileReadBufferSize = 65536; // 64KB read buffer

    // Exclusions
    std::vector<std::string> excludedDirs; // Store as vector of prefixes
    std::vector<std::string> excludeLogStrings;

    // Inclusions
    std::vector<std::string> forcedStringMatchDirs; // Store as vector of prefixes

    // Hot Time Frame
    long long minHotEpoch = 0; // Use long long for epoch time
    long long maxHotEpoch = 0;

    // Debug
    bool debugMode = false;

    // Function to load config from file
    // Используем Logger&, теперь объявление корректно благодаря forward declaration
    bool loadFromFile(const std::string& filename, Logger& logger);

private: // Функции должны быть объявлены *после* private
    // Helper to parse a specific line
    void parseLine(const std::string& line, const std::string& currentSection, Logger& logger);
    // Helper to parse comma-separated string into vector
    std::vector<std::string> parseCommaSeparated(const std::string& value);
     // Helper to parse comma-separated string into set
    std::unordered_set<std::string> parseCommaSeparatedSet(const std::string& value);
     // Helper to map string facility name to syslog int constant
     int mapFacilityStringToInt(const std::string& facilityStr) const;
};

#endif // CONFIG_H
