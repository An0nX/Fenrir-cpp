#ifndef IOC_READER_H
#define IOC_READER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

// Forward declaration
class Logger;

// Structure to hold all loaded IOCs
struct IOCData {
    // Hash IOCs: map[hash] = description
    std::unordered_map<std::string, std::string> hashIOCs;
    // Pseudo Hash Optimization: map[pseudo_hash_int] = true (or count for collisions)
    // This is complex to implement safely with potential collisions.
    // Let's stick to direct hash checking for robustness, maybe optimize later if needed.
    // std::unordered_map<uint32_t, bool> pseudoHashMap;

    // String IOCs: Simple list of strings to search for
    std::vector<std::string> stringIOCs;
    // Filename IOCs: List of substrings to check against full path
    std::vector<std::string> filenameIOCs;
    // C2 IOCs: List of C2 domains/IPs
    std::vector<std::string> c2IOCs;
};

namespace IOCReader {

// Reads hash IOCs (hash;description format)
bool readHashIOCs(const std::string& filename, IOCData& iocData, Logger& logger);

// Reads simple string IOCs (one per line)
bool readStringIOCs(const std::string& filename, IOCData& iocData, Logger& logger);

// Reads filename IOCs (one per line)
bool readFilenameIOCs(const std::string& filename, IOCData& iocData, Logger& logger);

// Reads C2 IOCs (one per line)
bool readC2IOCs(const std::string& filename, IOCData& iocData, Logger& logger);

// Helper to read generic list IOCs
bool readGenericList(const std::string& filename, std::vector<std::string>& targetList, const std::string& iocType, Logger& logger);

} // namespace IOCReader

#endif // IOC_READER_H
