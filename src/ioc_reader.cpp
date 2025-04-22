#include "ioc_reader.h"
#include "logger.h"
#include "utils.h" // Для Utils::
#include <fstream>
#include <sstream>

namespace IOCReader {

bool readGenericList(const std::string& filename, std::vector<std::string>& targetList, const std::string& iocType, Logger& logger) {
    std::ifstream iocFile(filename);
    if (!iocFile.is_open()) {
        logger.warning("Failed to open " + iocType + " IOC file: " + filename + ". Skipping.");
        return false;
    }

    logger.info("Reading " + iocType + " IOCs from: " + filename);
    targetList.clear();

    std::string line;
    int lineNumber = 0;
    int loadedCount = 0;
    while (getline(iocFile, line)) {
        lineNumber++;
        std::string trimmedLine = Utils::trim(line); // <<< Utils::

        if (trimmedLine.empty() || trimmedLine[0] == '#') {
            continue;
        }

        if (trimmedLine.length() > 4096) {
            logger.warning("Skipping potentially excessively long IOC line " + std::to_string(lineNumber) + " in " + filename);
            continue;
        }

        targetList.push_back(trimmedLine);
        loadedCount++;
    }

    iocFile.close();
    logger.info("Loaded " + std::to_string(loadedCount) + " " + iocType + " IOCs.");
    return true;
}


bool readHashIOCs(const std::string& filename, IOCData& iocData, Logger& logger) {
    std::ifstream iocFile(filename);
    if (!iocFile.is_open()) {
        logger.warning("Failed to open Hash IOC file: " + filename + ". Skipping.");
        return false;
    }

    logger.info("Reading Hash IOCs from: " + filename);
    iocData.hashIOCs.clear();

    std::string line;
    int lineNumber = 0;
    int loadedCount = 0;
    while (getline(iocFile, line)) {
        lineNumber++;
        std::string trimmedLine = Utils::trim(line); // <<< Utils::

        if (trimmedLine.empty() || trimmedLine[0] == '#') {
            continue;
        }

        size_t separatorPos = trimmedLine.find(';');
        if (separatorPos == std::string::npos) {
            logger.warning("Malformed hash IOC line " + std::to_string(lineNumber) + " (missing ';'): " + filename);
            continue;
        }

        std::string hashStr = Utils::trim(trimmedLine.substr(0, separatorPos)); // <<< Utils::
        std::string description = Utils::trim(trimmedLine.substr(separatorPos + 1)); // <<< Utils::

        if (hashStr.empty() || hashStr.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) {
             logger.warning("Invalid hash format on line " + std::to_string(lineNumber) + ": " + hashStr);
             continue;
        }
         if (hashStr.length() != 32 && hashStr.length() != 40 && hashStr.length() != 64) {
             logger.warning("Suspicious hash length on line " + std::to_string(lineNumber) + ": " + hashStr);
         }

        hashStr = Utils::toLower(hashStr); // <<< Utils::

        if (iocData.hashIOCs.count(hashStr)) {
            logger.warning("Duplicate hash IOC found on line " + std::to_string(lineNumber) + ": " + hashStr + ". Overwriting description.");
        }

        iocData.hashIOCs[hashStr] = description;
        loadedCount++;
    }

    iocFile.close();
    logger.info("Loaded " + std::to_string(loadedCount) + " Hash IOCs.");
    return true;
}

bool readStringIOCs(const std::string& filename, IOCData& iocData, Logger& logger) {
    return readGenericList(filename, iocData.stringIOCs, "String", logger);
}

bool readFilenameIOCs(const std::string& filename, IOCData& iocData, Logger& logger) {
    return readGenericList(filename, iocData.filenameIOCs, "Filename", logger);
}

bool readC2IOCs(const std::string& filename, IOCData& iocData, Logger& logger) {
    return readGenericList(filename, iocData.c2IOCs, "C2", logger);
}

} // namespace IOCReader
