#include "scanner.h"
#include "config.h"
#include "ioc_reader.h"
#include "logger.h"
#include "utils.h" // Для Utils::
#include "hash_utils.h"
#include "file_checker.h"

#include <system_error>
#include <iostream>
#include <limits> // <<< ДОБАВЛЕНО для numeric_limits в searchStringsInPlainFile


Scanner::Scanner(const Config& config, const IOCData& iocData, Logger& logger)
    : config_(config), iocData_(iocData), logger_(logger)
{}

void Scanner::scanDirectory(const std::filesystem::path& startPath) {
    logger_.info("Starting recursive scan in directory: " + startPath.string());

    std::error_code ec;
    if (!std::filesystem::exists(startPath, ec) || ec) {
        logger_.error("Start path does not exist or cannot be accessed: " + startPath.string() + (ec ? " (" + ec.message() + ")" : ""));
        return;
    }
    if (!std::filesystem::is_directory(startPath, ec) || ec) {
        logger_.error("Start path is not a directory: " + startPath.string() + (ec ? " (" + ec.message() + ")" : ""));
        return;
    }


    try {
        for (const auto& dir_entry : std::filesystem::recursive_directory_iterator(
                 startPath,
                 std::filesystem::directory_options::skip_permission_denied))
        {
            const auto& current_path = dir_entry.path();
            std::error_code file_ec;
            bool is_regular = std::filesystem::is_regular_file(current_path, file_ec);

            if (file_ec) {
                logger_.debug("Error checking file type for " + current_path.string() + ": " + file_ec.message());
                continue;
            }

            if (is_regular) {
                processFile(current_path);
            }
        }
    } catch (const std::filesystem::filesystem_error& e) {
        logger_.error("Filesystem error during scan iteration: " + std::string(e.what()) +
                     " Path1: " + e.path1().string() + " Path2: " + e.path2().string());
    } catch (const std::exception& e) {
        logger_.error("Standard exception during scan: " + std::string(e.what()));
    } catch (...) {
        logger_.error("Unknown exception during scan.");
    }

    logger_.info("Finished recursive scan in directory: " + startPath.string());
}


void Scanner::processFile(const std::filesystem::path& filePath) {
    std::string filePathStr = filePath.string();
    logger_.debug("Processing file: " + filePathStr);

    if (isExcludedDir(filePathStr)) {
        logger_.debug("Skipping file in excluded directory: " + filePathStr);
        return;
    }

    std::string filename = filePath.filename().string();
    // Используем Utils::toLower
    std::string extension = filePath.has_extension() ? Utils::toLower(filePath.extension().string().substr(1)) : "";


    bool do_string_check = true;
    bool do_hash_check = config_.enableHashCheck;
    bool do_filename_check = true;
    bool do_date_check = config_.checkHotTimeframe;


    bool is_elf = false;
    if (config_.enableTypeCheck) {
        is_elf = FileChecker::isELF(filePath, logger_);
    }

    if (config_.checkOnlyRelevantExtensions && !is_elf) {
        if (!isRelevantExtension(extension)) {
            logger_.debug("Deactivating hash/string checks due to irrelevant extension: " + filePathStr);
            do_string_check = false;
            do_hash_check = false;
        }
    }

    std::error_code size_ec;
    uintmax_t file_size_bytes = std::filesystem::file_size(filePath, size_ec);

    if (size_ec) {
        logger_.warning("Could not get file size for " + filePathStr + ": " + size_ec.message() + ". Disabling size-dependent checks.");
        do_string_check = false;
        do_hash_check = false;
    } else {
        uintmax_t file_size_kb = file_size_bytes / 1024;
        if (file_size_kb > config_.maxFileSizeKB) {
            logger_.debug("Deactivating hash/string checks due to size (" + std::to_string(file_size_kb) + " KB > " + std::to_string(config_.maxFileSizeKB) + " KB): " + filePathStr);
            do_string_check = false;
            do_hash_check = false;
        }
    }

    if (!do_string_check && isForcedStringDir(filePathStr)) {
         logger_.debug("Re-activating string check due to forced directory: " + filePathStr);
         do_string_check = true;
    }

    if (do_filename_check) {
        checkFilename(filePathStr);
    }
    if (do_string_check) {
        checkString(filePath, extension);
    }
    if (do_hash_check) {
        checkHashes(filePath);
    }
    if (do_date_check) {
        checkDate(filePath);
    }
}


// --- Helper Check Implementations ---

bool Scanner::isExcludedDir(const std::string& pathStr) const {
    for (const auto& excluded : config_.excludedDirs) {
        // Используем Utils::startsWith
        if (!excluded.empty() && Utils::startsWith(pathStr, excluded)) {
             return true;
        }
    }
    return false;
}

bool Scanner::isForcedStringDir(const std::string& pathStr) const {
    for (const auto& forcedDir : config_.forcedStringMatchDirs) {
        // Используем Utils::startsWith
        if (!forcedDir.empty() && Utils::startsWith(pathStr, forcedDir)) {
            return true;
        }
    }
    return false;
}

bool Scanner::isRelevantExtension(const std::string& extension) const {
    if (extension.empty()) return false;
    return config_.relevantExtensions.count(extension) > 0;
}


// --- Individual IOC Check Implementations ---

void Scanner::checkFilename(const std::string& pathStr) {
    for (const auto& fn_ioc : iocData_.filenameIOCs) {
        // Используем Utils::contains
        if (!fn_ioc.empty() && Utils::contains(pathStr, fn_ioc)) {
            logger_.warning("[!] Filename match found FILE: " + pathStr + " INDICATOR: " + fn_ioc);
        }
    }
}

void Scanner::checkString(const std::filesystem::path& filePath, const std::string& extension) {
    logger_.debug("Performing string check on: " + filePath.string());
    if (extension == "gz") {
         FileChecker::searchStringsInGzipFile(filePath, iocData_, config_, logger_);
    } else if (extension == "bz2") {
         FileChecker::searchStringsInBzip2File(filePath, iocData_, config_, logger_);
    } else {
         FileChecker::searchStringsInPlainFile(filePath, iocData_, config_, logger_);
    }
}

void Scanner::checkHashes(const std::filesystem::path& filePath) {
     logger_.debug("Performing hash check on: " + filePath.string());

     std::string md5_hash, sha1_hash, sha256_hash;
     bool md5_ok = HashUtils::calculateFileMD5(filePath, md5_hash, config_.fileReadBufferSize, logger_);
     bool sha1_ok = false;
     bool sha256_ok = false;
     if (md5_ok) {
          sha1_ok = HashUtils::calculateFileSHA1(filePath, sha1_hash, config_.fileReadBufferSize, logger_);
          if (sha1_ok) {
              sha256_ok = HashUtils::calculateFileSHA256(filePath, sha256_hash, config_.fileReadBufferSize, logger_);
          }
     }

     if (md5_ok) {
         auto it = iocData_.hashIOCs.find(md5_hash);
         if (it != iocData_.hashIOCs.end()) {
             logger_.warning("[!] Hash match found FILE: " + filePath.string() +
                            " HASH: " + md5_hash + " (MD5)" +
                            " DESC: " + it->second);
         }
     }
     if (sha1_ok) {
         auto it = iocData_.hashIOCs.find(sha1_hash);
         if (it != iocData_.hashIOCs.end()) {
             logger_.warning("[!] Hash match found FILE: " + filePath.string() +
                            " HASH: " + sha1_hash + " (SHA1)" +
                            " DESC: " + it->second);
         }
     }
     if (sha256_ok) {
         auto it = iocData_.hashIOCs.find(sha256_hash);
         if (it != iocData_.hashIOCs.end()) {
              logger_.warning("[!] Hash match found FILE: " + filePath.string() +
                             " HASH: " + sha256_hash + " (SHA256)" +
                             " DESC: " + it->second);
         }
     }
}

void Scanner::checkDate(const std::filesystem::path& filePath) {
     if (config_.minHotEpoch <= 0 || config_.maxHotEpoch <= 0 || config_.minHotEpoch >= config_.maxHotEpoch) {
         if (config_.checkHotTimeframe) {
             logger_.debug("Hot timeframe check skipped due to invalid min/max epoch settings.");
         }
         return;
     }

     logger_.debug("Performing date check on: " + filePath.string());

     std::error_code ec;
     // Используем Utils::getFileModTimeEpoch
     long long fileEpoch = Utils::getFileModTimeEpoch(filePath, ec);

     if (ec) {
         logger_.warning("Could not get file modification time for " + filePath.string() + ": " + ec.message());
         return;
     }

     if (fileEpoch > config_.minHotEpoch && fileEpoch < config_.maxHotEpoch) {
         // Используем Utils::getCurrentTimestamp (хотя лучше бы конвертер эпохи в строку)
         logger_.warning("[!] File modified in hot timeframe FILE: " + filePath.string() +
                        " EPOCH: " + std::to_string(fileEpoch) +
                        " UTC_TIME: " + Utils::getCurrentTimestamp());
     }
}
