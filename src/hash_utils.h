#ifndef HASH_UTILS_H
#define HASH_UTILS_H

#include <string>
#include <filesystem> // C++17
#include <vector>
#include <cstdint> // For uint32_t

// Forward declarations
class Logger;
typedef struct evp_md_st EVP_MD; // From OpenSSL

namespace HashUtils {

// --- Public functions ---
bool calculateFileMD5(const std::filesystem::path& filepath, std::string& hash_out, size_t buffer_size, Logger& logger);
bool calculateFileSHA1(const std::filesystem::path& filepath, std::string& hash_out, size_t buffer_size, Logger& logger);
bool calculateFileSHA256(const std::filesystem::path& filepath, std::string& hash_out, size_t buffer_size, Logger& logger);
uint32_t calculatePseudoHash(const std::string& fullHash);

// --- Internal Implementation Detail (Hidden in .cpp file) ---
// Убираем объявление calculateFileHashEVP из заголовка, делая его приватным для .cpp файла
// bool calculateFileHashEVP(const std::filesystem::path& filepath, const EVP_MD* md_type, std::string& hash_out, size_t buffer_size, Logger& logger);

} // namespace HashUtils

#endif // HASH_UTILS_H
