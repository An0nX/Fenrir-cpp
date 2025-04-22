#include "hash_utils.h"
#include "logger.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <fstream>
#include <vector>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace HashUtils {

// --- Объявление и определение внутренней функции здесь ---
// Делаем её static, чтобы она была видна только внутри этого файла (.cpp)
static bool calculateFileHashEVP(const std::filesystem::path& filepath, const EVP_MD* md_type, std::string& hash_out, size_t buffer_size, Logger& logger) {
    hash_out.clear();
    if (buffer_size == 0) {
        logger.error("Hash buffer size cannot be zero for file: " + filepath.string());
        return false;
    }

    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        logger.debug("Cannot open file for hashing (check permissions?): " + filepath.string());
        return false;
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        logger.error("Failed to create OpenSSL EVP context for: " + filepath.string());
        return false;
    }

    struct CTX_Guard {
        EVP_MD_CTX* ctx;
        ~CTX_Guard() { if (ctx) EVP_MD_CTX_free(ctx); }
    } ctx_guard{mdctx};


    if (1 != EVP_DigestInit_ex(mdctx, md_type, nullptr)) {
        logger.error("Failed to initialize OpenSSL EVP digest for: " + filepath.string());
        return false;
    }

    std::vector<char> buffer(buffer_size);
    while (file.good()) {
        file.read(buffer.data(), buffer.size());
        std::streamsize bytes_read = file.gcount();
        if (bytes_read > 0) {
            if (1 != EVP_DigestUpdate(mdctx, buffer.data(), static_cast<size_t>(bytes_read))) {
                logger.error("Failed to update OpenSSL EVP digest for: " + filepath.string());
                return false;
            }
        }
    }

    if (!file.eof() && file.fail()) {
        logger.warning("File read error during hashing: " + filepath.string());
        return false;
    }


    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (1 != EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
        logger.error("Failed to finalize OpenSSL EVP digest for: " + filepath.string());
        return false;
    }

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < hash_len; ++i) {
        ss << std::setw(2) << static_cast<unsigned>(hash[i]);
    }
    hash_out = ss.str();

    return true;
}


// --- Публичные функции, использующие calculateFileHashEVP ---
bool calculateFileMD5(const std::filesystem::path& filepath, std::string& hash_out, size_t buffer_size, Logger& logger) {
    return calculateFileHashEVP(filepath, EVP_md5(), hash_out, buffer_size, logger);
}

bool calculateFileSHA1(const std::filesystem::path& filepath, std::string& hash_out, size_t buffer_size, Logger& logger) {
    return calculateFileHashEVP(filepath, EVP_sha1(), hash_out, buffer_size, logger);
}

bool calculateFileSHA256(const std::filesystem::path& filepath, std::string& hash_out, size_t buffer_size, Logger& logger) {
    return calculateFileHashEVP(filepath, EVP_sha256(), hash_out, buffer_size, logger);
}


// --- Pseudo Hash Implementation ---
uint32_t calculatePseudoHash(const std::string& fullHash) {
     if (fullHash.length() < 8) {
         return 0;
     }
     std::string shortHashStr = fullHash.substr(0, 8);

     try {
         unsigned long long parsed_val = std::stoull("0x" + shortHashStr, nullptr, 16);
         return static_cast<uint32_t>(parsed_val);
     } catch (const std::invalid_argument& e) {
         return 0;
     } catch (const std::out_of_range& e) {
         return 0;
     }
 }


} // namespace HashUtils
