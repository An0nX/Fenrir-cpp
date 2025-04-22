#include "file_checker.h"
#include "config.h"
#include "ioc_reader.h"
#include "logger.h"
#include "utils.h" // Теперь все функции Utils должны быть доступны

#include <cstdio>
#include <memory>
#include <array>
#include <iostream>
#include <stdexcept>
#include <cstring>
#include <system_error>
#include <sys/wait.h> // <<< ДОБАВЛЕНО для WIFEXITED, WEXITSTATUS и т.д.

#include <magic.h>
#include <zlib.h>
#include <bzlib.h>

namespace FileChecker {

// --- Объявление и определение внутренних хелперов ---
static std::string findIOCStringMatch(const std::string& line,
                               const std::vector<std::string>& stringIOCs,
                               const std::vector<std::string>& c2IOCs)
{
    // Проверяем сначала обычные строки
    for (const auto& ioc : stringIOCs) {
        // Используем Utils::contains
        if (!ioc.empty() && Utils::contains(line, ioc)) {
            return ioc;
        }
    }
    // Проверяем C2 IOC (они тоже ищутся в файлах)
     for (const auto& ioc : c2IOCs) {
        // Используем Utils::contains
        if (!ioc.empty() && Utils::contains(line, ioc)) {
            return ioc;
        }
    }
    return ""; // Нет совпадений
}

static std::string formatMatchOutput(const std::string& fullMatchLine) {
     const size_t MAX_MATCH_LEN = 150;
     if (fullMatchLine.length() > MAX_MATCH_LEN) {
         return fullMatchLine.substr(0, MAX_MATCH_LEN) + "... (truncated)";
     }
     return fullMatchLine;
 }


// --- Реализации публичных функций ---

bool executeCommand(const std::string& command, std::vector<std::string>& outputLines, Logger& logger) {
    outputLines.clear();
    std::array<char, 256> buffer;

    // Игнорируем атрибут -Wignored-attributes
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wignored-attributes"
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
    #pragma GCC diagnostic pop

    if (!pipe) {
        logger.error("popen() failed for command: " + command + " Error: " + strerror(errno));
        return false;
    }

    std::string currentLine;
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        currentLine += buffer.data();
        if (!currentLine.empty() && currentLine.back() == '\n') {
             currentLine.pop_back();
             if (!currentLine.empty() && currentLine.back() == '\r') {
                 currentLine.pop_back();
             }
             outputLines.push_back(currentLine);
             currentLine.clear();
        }
    }
     if (!currentLine.empty()) {
         outputLines.push_back(currentLine);
     }

    // release() нужен перед явным вызовом pclose для проверки статуса
    FILE* pipe_ptr = pipe.release();
    int status = pclose(pipe_ptr);

    if (status == -1) {
         logger.warning("pclose() failed after running command: " + command + " Error: " + strerror(errno));
    } else if (WIFEXITED(status)) { // Теперь макросы видны из <sys/wait.h>
         int exit_code = WEXITSTATUS(status);
         if (exit_code != 0) {
             logger.warning("Command '" + command + "' exited with status code " + std::to_string(exit_code));
         }
    } else if (WIFSIGNALED(status)) {
         logger.warning("Command '" + command + "' terminated by signal " + std::to_string(WTERMSIG(status)));
    }

    return true;
}


void scanC2Connections(const Config& config, const IOCData& iocData, Logger& logger) {
    logger.info("Scanning for C2 servers in 'lsof' output...");
    const std::vector<std::string> lsof_commands = {"lsof -i -n -P", "lsof -i -P"};

    for (const auto& cmd : lsof_commands) {
        logger.debug("Executing: " + cmd);
        std::vector<std::string> outputLines;
        if (!executeCommand(cmd, outputLines, logger)) {
            logger.error("Failed to execute or read from command: " + cmd);
            continue;
        }

        logger.debug("Processing " + std::to_string(outputLines.size()) + " lines from " + cmd);

        for (const std::string& line : outputLines) {
             std::string trimmedLine = Utils::trim(line); // Используем Utils::trim
             if (trimmedLine.empty()) continue;

            for (const auto& c2 : iocData.c2IOCs) {
                // Используем Utils::contains
                if (!c2.empty() && Utils::contains(trimmedLine, c2)) {
                     bool is_loopback_match = Utils::contains(trimmedLine, "127.0.0.1") || Utils::contains(trimmedLine, "::1");
                     bool c2_is_loopback = (c2 == "127.0.0.1" || c2 == "::1");
                     if (!is_loopback_match || c2_is_loopback) {
                         logger.warning("[!] C2 server found in lsof output SERVER: " + c2 + " LSOF_LINE: " + trimmedLine);
                     }
                }
            }

            // Используем Utils::startsWith и Utils::contains
            if ( (Utils::startsWith(trimmedLine, "bash ") || Utils::startsWith(trimmedLine, "sh ")) &&
                 !Utils::contains(trimmedLine, "127.0.0.1") && !Utils::contains(trimmedLine, "::1") &&
                  Utils::contains(trimmedLine, "TCP") )
            {
                 logger.notice("[!] Shell potentially involved in network connection found in lsof output (check carefully): LSOF_LINE: " + trimmedLine);
            }
        }
    }
    logger.info("Finished C2 scan.");
}

bool isELF(const std::filesystem::path& filepath, Logger& logger) {
    magic_t magic_cookie = magic_open(MAGIC_NONE | MAGIC_ERROR);
    if (magic_cookie == nullptr) {
        logger.error("Failed to initialize libmagic library.");
        return false;
    }

    struct MagicGuard {
        magic_t cookie;
        ~MagicGuard() { if (cookie) magic_close(cookie); }
    } guard{magic_cookie};

    if (magic_load(magic_cookie, nullptr) != 0) {
        logger.error("Failed to load libmagic database: " + std::string(magic_error(magic_cookie)));
        return false;
    }

    const char* description = magic_file(magic_cookie, filepath.c_str());
    if (description == nullptr) {
        logger.debug("libmagic failed to check file (" + std::string(magic_error(magic_cookie)) + "): " + filepath.string());
        return false;
    }

    std::string desc_str(description);
    logger.debug("File type for " + filepath.string() + ": " + desc_str);
    return Utils::contains(desc_str, "ELF"); // Используем Utils::contains
}

// --- File Content Searching ---

void searchStringsInPlainFile(const std::filesystem::path& filepath,
                               const IOCData& iocData,
                               const Config& config,
                               Logger& logger)
{
    std::ifstream file(filepath);
    if (!file.is_open()) {
        logger.debug("Could not open plain file for string search: " + filepath.string());
        return;
    }

    std::string line;
    size_t lineNum = 0;
    while (getline(file, line)) {
        lineNum++;
        // Теперь findIOCStringMatch видна
        std::string matchedIOC = findIOCStringMatch(line, iocData.stringIOCs, iocData.c2IOCs);
        if (!matchedIOC.empty()) {
            // Теперь formatMatchOutput видна
            logger.warning("[!] String match found FILE: " + filepath.string() +
                           " LINE: " + std::to_string(lineNum) +
                           " IOC: " + matchedIOC +
                           " TYPE: plain" +
                           " MATCH: " + formatMatchOutput(line));
        }

        if (line.length() > config.fileReadBufferSize * 4 && file.good()) {
             logger.warning("Potentially very long line detected (> " + std::to_string(config.fileReadBufferSize*4) +
                            " bytes) without newline in file " + filepath.string() + " at line " + std::to_string(lineNum) + ". Skipping rest of line check.");
             file.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        }
    }
}

void searchStringsInGzipFile(const std::filesystem::path& filepath,
                             const IOCData& iocData,
                             const Config& config,
                             Logger& logger)
{
    gzFile file = gzopen(filepath.c_str(), "rb");
    if (file == nullptr) {
        logger.debug("Could not open gzip file for string search: " + filepath.string());
        return;
    }

    struct GzGuard {
        gzFile f;
        ~GzGuard() { if (f) gzclose(f); }
    } guard{file};

    std::vector<char> buffer(config.fileReadBufferSize);
    std::string currentLine;
    size_t lineNum = 0;

    while (true) {
        int bytes_read = gzread(file, buffer.data(), buffer.size());

        if (bytes_read < 0) {
            int err_no = 0;
            const char* error_msg = gzerror(file, &err_no);
            logger.warning("Error reading gzip file " + filepath.string() + ": " + (err_no == Z_ERRNO ? strerror(errno) : error_msg));
            break;
        }

        if (bytes_read == 0) {
            if (!currentLine.empty()) {
                lineNum++;
                 std::string matchedIOC = findIOCStringMatch(currentLine, iocData.stringIOCs, iocData.c2IOCs);
                 if (!matchedIOC.empty()) {
                    logger.warning("[!] String match found FILE: " + filepath.string() +
                                   " LINE: ~" + std::to_string(lineNum) +
                                   " IOC: " + matchedIOC +
                                   " TYPE: gzip" +
                                   " MATCH: " + formatMatchOutput(currentLine));
                 }
            }
            break;
        }

        const char* p = buffer.data();
        const char* end = buffer.data() + bytes_read;
        while (p < end) {
             const char* nl = static_cast<const char*>(memchr(p, '\n', end - p));
             if (nl != nullptr) {
                 currentLine.append(p, nl - p);
                 lineNum++;
                 std::string matchedIOC = findIOCStringMatch(currentLine, iocData.stringIOCs, iocData.c2IOCs);
                 if (!matchedIOC.empty()) {
                     logger.warning("[!] String match found FILE: " + filepath.string() +
                                    " LINE: ~" + std::to_string(lineNum) +
                                    " IOC: " + matchedIOC +
                                    " TYPE: gzip" +
                                    " MATCH: " + formatMatchOutput(currentLine));
                 }
                 currentLine.clear();
                 p = nl + 1;
             } else {
                 currentLine.append(p, end - p);
                 if (currentLine.length() > config.fileReadBufferSize * 4) {
                      logger.warning("Potentially very long line detected (> " + std::to_string(config.fileReadBufferSize * 4) +
                                     " bytes) without newline in gzip file " + filepath.string() + ". Skipping rest of line check.");
                      currentLine.clear();
                 }
                 p = end;
             }
        }
    }
}

void searchStringsInBzip2File(const std::filesystem::path& filepath,
                              const IOCData& iocData,
                              const Config& config,
                              Logger& logger)
{
    FILE* f_raw = fopen(filepath.c_str(), "rb");
    if (!f_raw) {
        logger.debug("Could not open bzip2 file (raw): " + filepath.string());
        return;
    }

    int bzError = BZ_OK;
    BZFILE* bzFile = BZ2_bzReadOpen(&bzError, f_raw, 0, 0, nullptr, 0);
    if (bzError != BZ_OK || bzFile == nullptr) {
        BZ2_bzReadClose(&bzError, bzFile);
        fclose(f_raw);
        logger.warning("Could not open bzip2 stream for file: " + filepath.string() + " (Error code: " + std::to_string(bzError) + ")");
        return;
    }

     struct BzGuard {
         BZFILE* bzf = nullptr;
         FILE* rawf = nullptr;
         ~BzGuard() {
             int err = BZ_OK;
             if (bzf) BZ2_bzReadClose(&err, bzf);
             if (rawf) fclose(rawf);
         }
     } guard{bzFile, f_raw};


    std::vector<char> buffer(config.fileReadBufferSize);
    std::string currentLine;
    size_t lineNum = 0;

    while (bzError == BZ_OK || bzError == BZ_STREAM_END) {
         int bytes_read = BZ2_bzRead(&bzError, bzFile, buffer.data(), buffer.size());

         if (bzError != BZ_OK && bzError != BZ_STREAM_END) {
             logger.warning("Error reading bzip2 file " + filepath.string() + ": Code " + std::to_string(bzError));
             break;
         }

         if (bytes_read > 0) {
             const char* p = buffer.data();
             const char* end = buffer.data() + bytes_read;
             while (p < end) {
                 const char* nl = static_cast<const char*>(memchr(p, '\n', end - p));
                 if (nl != nullptr) {
                     currentLine.append(p, nl - p);
                     lineNum++;
                     std::string matchedIOC = findIOCStringMatch(currentLine, iocData.stringIOCs, iocData.c2IOCs);
                     if (!matchedIOC.empty()) {
                         logger.warning("[!] String match found FILE: " + filepath.string() +
                                        " LINE: ~" + std::to_string(lineNum) +
                                        " IOC: " + matchedIOC +
                                        " TYPE: bzip2" +
                                        " MATCH: " + formatMatchOutput(currentLine));
                     }
                     currentLine.clear();
                     p = nl + 1;
                 } else {
                     currentLine.append(p, end - p);
                      if (currentLine.length() > config.fileReadBufferSize * 4) {
                         logger.warning("Potentially very long line detected (> " + std::to_string(config.fileReadBufferSize * 4) +
                                        " bytes) without newline in bzip2 file " + filepath.string() + ". Skipping rest of line check.");
                         currentLine.clear();
                      }
                     p = end;
                 }
             }
         }

         if (bzError == BZ_STREAM_END) {
              if (!currentLine.empty()) {
                 lineNum++;
                  std::string matchedIOC = findIOCStringMatch(currentLine, iocData.stringIOCs, iocData.c2IOCs);
                  if (!matchedIOC.empty()) {
                      logger.warning("[!] String match found FILE: " + filepath.string() +
                                     " LINE: ~" + std::to_string(lineNum) +
                                     " IOC: " + matchedIOC +
                                     " TYPE: bzip2" +
                                     " MATCH: " + formatMatchOutput(currentLine));
                  }
              }
             break;
         }
     } // end while
}


} // namespace FileChecker
