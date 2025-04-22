#ifndef SCANNER_H
#define SCANNER_H

#include <filesystem> // C++17

// Forward declarations
class Logger;
struct Config;
struct IOCData;

class Scanner {
public:
    Scanner(const Config& config, const IOCData& iocData, Logger& logger);

    // Start the recursive scan from a given directory
    void scanDirectory(const std::filesystem::path& startPath);

private:
    // Process a single regular file
    void processFile(const std::filesystem::path& filePath);

    // --- Helper Checks ---
    // Check if path is within an excluded directory prefix
    bool isExcludedDir(const std::string& pathStr) const;
    // Check if path is within a forced string match directory prefix
    bool isForcedStringDir(const std::string& pathStr) const;
    // Check if the extension is relevant (lowercase, no dot)
    bool isRelevantExtension(const std::string& extension) const;

    // --- Individual IOC Checks ---
    void checkFilename(const std::string& pathStr);
    void checkString(const std::filesystem::path& filePath, const std::string& extension);
    void checkHashes(const std::filesystem::path& filePath);
    void checkDate(const std::filesystem::path& filePath);


    const Config& config_;
    const IOCData& iocData_;
    Logger& logger_;

    // Precompute lowercase relevant extensions for faster lookup? (Done in Config loading)
};

#endif // SCANNER_H
