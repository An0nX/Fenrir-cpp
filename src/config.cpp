#include "config.h"
#include "logger.h" // Logger теперь известен
#include "utils.h" // Включаем для Utils::
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <limits>
#include <syslog.h>

bool Config::loadFromFile(const std::string& filename, Logger& logger) {
    std::ifstream configFile(filename);
    if (!configFile.is_open()) {
        logger.error("Failed to open configuration file: " + filename);
        return false;
    }

    logger.info("Loading configuration from: " + filename);

    std::string line;
    std::string currentSection;
    int lineNumber = 0;

    relevantExtensions = {"jsp", "jspx", "txt", "tmp", "pl", "war", "sh", "log", "jar"};
    excludedDirs.clear();
    forcedStringMatchDirs.clear();
    excludeLogStrings.clear();


    while (getline(configFile, line)) {
        lineNumber++;
        line = Utils::trim(line); // <<< Utils::

        if (line.empty() || line[0] == '#') {
            continue;
        }

        if (line[0] == '[' && line.back() == ']') {
            currentSection = Utils::trim(line.substr(1, line.length() - 2)); // <<< Utils::
        } else {
            try {
                parseLine(line, currentSection, logger);
            } catch (const std::exception& e) {
                logger.warning("Error parsing line " + std::to_string(lineNumber) + " in config file: " + line + " - " + e.what());
            }
        }
    }

    configFile.close();
    logger.info("Configuration loaded successfully.");
    return true;
}

void Config::parseLine(const std::string& line, const std::string& currentSection, Logger& logger) {
    size_t equalsPos = line.find('=');
    if (equalsPos == std::string::npos) {
        logger.warning("Malformed line (missing '=') in section [" + currentSection + "]: " + line);
        return;
    }

    std::string key = Utils::trim(line.substr(0, equalsPos)); // <<< Utils::
    std::string value = Utils::trim(line.substr(equalsPos + 1)); // <<< Utils::

    if (currentSection == "Logging") {
        if (key == "LogFilePattern") logFilePattern = value;
        else if (key == "LogToFile") logToFile = Utils::stringToBool(value); // <<< Utils::
        else if (key == "LogToSyslog") logToSyslog = Utils::stringToBool(value); // <<< Utils::
        else if (key == "LogToCmdLine") logToCmdLine = Utils::stringToBool(value); // <<< Utils::
        else if (key == "SyslogFacility") syslogFacility = mapFacilityStringToInt(value);
        else if (key == "SyslogIdent") syslogIdent = value;
    }
    else if (currentSection == "IOCs") {
        if (key == "HashIOCFile") hashIOCFile = value;
        else if (key == "StringIOCFile") stringIOCFile = value;
        else if (key == "FilenameIOCFile") filenameIOCFile = value;
        else if (key == "C2IOCFile") c2IOCFile = value;
    }
    else if (currentSection == "Checks") {
        if (key == "EnableC2Check") enableC2Check = Utils::stringToBool(value); // <<< Utils::
        else if (key == "EnableTypeCheck") enableTypeCheck = Utils::stringToBool(value); // <<< Utils::
        else if (key == "EnableHashCheck") enableHashCheck = Utils::stringToBool(value); // <<< Utils::
        else if (key == "CheckHotTimeframe") checkHotTimeframe = Utils::stringToBool(value); // <<< Utils::
    }
    else if (currentSection == "Performance") {
        if (key == "MaxFileSizeKB") {
            try { maxFileSizeKB = std::stoull(value); }
            catch (...) { logger.warning("Invalid value for MaxFileSizeKB: " + value); maxFileSizeKB = 8000; }
        } else if (key == "CheckOnlyRelevantExtensions") checkOnlyRelevantExtensions = Utils::stringToBool(value); // <<< Utils::
        else if (key == "RelevantExtensions") relevantExtensions = parseCommaSeparatedSet(value);
        else if (key == "FileReadBufferSize") {
             try { fileReadBufferSize = std::stoull(value); }
             catch (...) { logger.warning("Invalid value for FileReadBufferSize: " + value); fileReadBufferSize = 65536; }
             if (fileReadBufferSize == 0) {
                 logger.warning("FileReadBufferSize cannot be zero, setting to default 65536.");
                 fileReadBufferSize = 65536;
             }
        }
    }
    else if (currentSection == "Exclusions") {
        if (key == "ExcludedDirs") excludedDirs = parseCommaSeparated(value);
        else if (key == "ExcludeLogStrings") excludeLogStrings = parseCommaSeparated(value);
    }
     else if (currentSection == "Inclusions") {
        if (key == "ForcedStringMatchDirs") forcedStringMatchDirs = parseCommaSeparated(value);
    }
    else if (currentSection == "HotTimeFrame") {
        if (key == "MinHotEpoch") {
            try { minHotEpoch = std::stoll(value); }
            catch (...) { logger.warning("Invalid value for MinHotEpoch: " + value); minHotEpoch = 0; }
        } else if (key == "MaxHotEpoch") {
            try { maxHotEpoch = std::stoll(value); }
            catch (...) { logger.warning("Invalid value for MaxHotEpoch: " + value); maxHotEpoch = 0; }
        }
    }
    else if (currentSection == "Debug") {
        if (key == "DebugMode") debugMode = Utils::stringToBool(value); // <<< Utils::
    } else {
        logger.warning("Unknown section in config file: [" + currentSection + "]");
    }
}

std::vector<std::string> Config::parseCommaSeparated(const std::string& value) {
    std::vector<std::string> result;
    std::stringstream ss(value);
    std::string item;
    while (getline(ss, item, ',')) {
        std::string trimmedItem = Utils::trim(item); // <<< Utils::
        if (!trimmedItem.empty()) {
            result.push_back(trimmedItem);
        }
    }
    return result;
}
std::unordered_set<std::string> Config::parseCommaSeparatedSet(const std::string& value) {
    std::unordered_set<std::string> result;
    std::stringstream ss(value);
    std::string item;
    while (getline(ss, item, ',')) {
        std::string trimmedItem = Utils::trim(item); // <<< Utils::
        if (!trimmedItem.empty()) {
             if (trimmedItem[0] == '.') {
                 trimmedItem = trimmedItem.substr(1);
             }
            result.insert(Utils::toLower(trimmedItem)); // <<< Utils::
        }
    }
    return result;
}

int Config::mapFacilityStringToInt(const std::string& facilityStr) const {
    std::string lowerStr = Utils::toLower(facilityStr); // <<< Utils::
    if (lowerStr == "local0") return LOG_LOCAL0;
    if (lowerStr == "local1") return LOG_LOCAL1;
    if (lowerStr == "local2") return LOG_LOCAL2;
    if (lowerStr == "local3") return LOG_LOCAL3;
    if (lowerStr == "local4") return LOG_LOCAL4;
    if (lowerStr == "local5") return LOG_LOCAL5;
    if (lowerStr == "local6") return LOG_LOCAL6;
    if (lowerStr == "local7") return LOG_LOCAL7;
    if (lowerStr == "user") return LOG_USER;
    if (lowerStr == "daemon") return LOG_DAEMON;
    return LOG_LOCAL4;
}
