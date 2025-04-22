#include "config.h"
#include "logger.h"
#include "ioc_reader.h"
#include "scanner.h"
#include "utils.h" // Для Utils::
#include "file_checker.h"
#include "hash_utils.h"

#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <stdexcept>
#include <magic.h>
#include <openssl/evp.h>

// --- Function Prototypes ---
void printBanner(const std::string& version);
void printUsage(const char* appName);
bool checkRequirements(const Config& config, Logger& logger);

// --- Global Version ---
const std::string FENRIR_VERSION = "1.0.0-cpp";

int main(int argc, char* argv[]) {
    if (argc != 2) {
        printBanner(FENRIR_VERSION);
        printUsage(argv[0]);
        return 1;
    }

    std::filesystem::path startDir;
    try {
         startDir = std::filesystem::weakly_canonical(argv[1]);
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Invalid start directory path: " << argv[1] << " - " << e.what() << std::endl;
        return 1;
    }

    Logger logger;
    Config config;
    std::string configFilePath = "./fenrir.conf";

    if (!config.loadFromFile(configFilePath, logger)) {
        logger.error("Using default configuration due to loading failure.");
    }

    logger.configure(config.logToFile, config.logToSyslog, config.logToCmdLine,
                     config.logFilePattern, config.syslogFacility, config.syslogIdent,
                     config.excludeLogStrings, config.debugMode);

    printBanner(FENRIR_VERSION);
    logger.info("Started FENRIR Scan - version " + FENRIR_VERSION);
    logger.info("Using configuration file: " + configFilePath);
    logger.info("Scan target directory: " + startDir.string());
    logger.info("Logging configured.");

    logger.info("--- System Information ---");
    // Используем Utils::
    logger.info("HOSTNAME: " + Utils::getHostname());
    try {
        // Используем Utils::
        std::vector<std::string> ips = Utils::getIPAddresses();
        std::string ip_str;
        for(size_t i=0; i < ips.size(); ++i) { ip_str += ips[i] + (i == ips.size()-1 ? "" : ", "); }
        logger.info("IP Addresses: " + (ips.empty() ? "N/A" : ip_str));
    } catch (const std::exception& e) {
        logger.warning("Could not retrieve IP addresses: " + std::string(e.what()));
    }
    // Используем Utils::
    logger.info("OS Info: " + Utils::getOsRelease());
    // Используем Utils::
    logger.info("Kernel: " + Utils::getKernelVersion());
    logger.info("--------------------------");

    if (!checkRequirements(config, logger)) {
        logger.critical("Essential requirements missing. Aborting scan.");
        return 1;
    }

    logger.info("--- Loading IOCs ---");
    IOCData iocData;
    bool iocsLoaded = true;
    if (config.enableHashCheck) {
        iocsLoaded &= IOCReader::readHashIOCs(config.hashIOCFile, iocData, logger);
    }
    iocsLoaded &= IOCReader::readStringIOCs(config.stringIOCFile, iocData, logger);
    iocsLoaded &= IOCReader::readFilenameIOCs(config.filenameIOCFile, iocData, logger);
    if (config.enableC2Check || !iocData.stringIOCs.empty()) {
         iocsLoaded &= IOCReader::readC2IOCs(config.c2IOCFile, iocData, logger);
    }
    logger.info("--------------------");

    try {
        if (config.enableC2Check) {
            FileChecker::scanC2Connections(config, iocData, logger);
        } else {
            logger.info("C2 connection check disabled by configuration.");
        }

        Scanner scanner(config, iocData, logger);
        scanner.scanDirectory(startDir);

    } catch (const std::exception& e) {
        logger.critical("Unhandled exception during scan execution: " + std::string(e.what()));
        return 1;
    } catch (...) {
         logger.critical("Unknown unhandled exception during scan execution.");
         return 1;
    }

    logger.info("Finished FENRIR Scan.");
    return 0;
}


// --- Helper Functions ---

void printBanner(const std::string& version) {
    std::cout << "##############################################################" << std::endl;
    std::cout << "    ____             _     " << std::endl;
    std::cout << "   / __/__ ___  ____(_)___ " << std::endl;
    std::cout << "  / _// -_) _ \\/ __/ / __/ " << std::endl;
    std::cout << " /_/  \\__/_//_/_/ /_/_/    " << std::endl;
    std::cout << " v" << version << std::endl;
    std::cout << " " << std::endl;
    std::cout << " Simple C++ IOC Checker" << std::endl;
    std::cout << " Based on bash script by Florian Roth" << std::endl;
    std::cout << "##############################################################" << std::endl;
    std::cout << std::endl;
}

void printUsage(const char* appName) {
    std::cerr << "Usage: " << appName << " <DIRECTORY>" << std::endl;
    std::cerr << std::endl;
    std::cerr << "  <DIRECTORY> : Start point of the recursive scan (e.g., / or /home)" << std::endl;
    std::cerr << std::endl;
    std::cerr << "Configuration is loaded from './fenrir.conf' by default." << std::endl;
    std::cerr << "IOC files are loaded based on paths in the configuration file." << std::endl;
    std::cerr << std::endl;
}

bool checkRequirements(const Config& config, Logger& logger) {
    logger.info("Checking requirements...");
    bool ok = true;

    if (config.enableTypeCheck) {
        magic_t magic_cookie = magic_open(MAGIC_NONE);
        if (magic_cookie == nullptr) {
             logger.error("Libmagic initialization failed (required for type checking).");
             ok = false;
        } else {
             if (magic_load(magic_cookie, nullptr) != 0) {
                 logger.warning("Failed to load default libmagic database: " + std::string(magic_error(magic_cookie)) + ". Type checking might be inaccurate.");
             }
             magic_close(magic_cookie);
        }
    }

    if (config.enableC2Check) {
        std::vector<std::string> lines;
        if (!FileChecker::executeCommand("lsof -v", lines, logger)) {
             logger.error("Could not execute 'lsof' (required for C2 check). Is it installed and in PATH?");
             ok = false;
        }
    }

    const EVP_MD* md = EVP_md5();
    if (md == nullptr) {
        logger.error("OpenSSL EVP initialization failed (required for hashing). OpenSSL library might be corrupted or missing.");
        ok = false;
    }

    if (ok) {
        logger.info("Basic requirements check passed.");
    } else {
        logger.error("One or more requirements check failed. Functionality may be limited.");
    }
    return ok;
}
