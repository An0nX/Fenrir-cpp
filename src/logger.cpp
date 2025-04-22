#include "logger.h"
#include "utils.h" // Для Utils::
#include <iostream>
#include <syslog.h>
#include <stdexcept>

// --- Logger Implementation ---

Logger::Logger() = default;

Logger::~Logger() {
    if (logFileStream_.is_open()) {
        logFileStream_.close();
    }
    if (logToSyslog_) {
        closelog();
    }
}

void Logger::configure(bool logToFile, bool logToSyslog, bool logToCmdLine,
                       const std::string& logFilePattern, int syslogFacility,
                       const std::string& syslogIdent,
                       const std::vector<std::string>& excludeStrings,
                       bool debugMode)
{
    std::lock_guard<std::mutex> lock(logMutex_);

    if (configured_) {
        warning("Logger already configured. Reconfiguration attempt ignored.");
        return;
    }

    logToFile_ = logToFile;
    logToSyslog_ = logToSyslog;
    logToCmdLine_ = logToCmdLine;
    syslogFacility_ = syslogFacility;
    syslogIdent_ = syslogIdent.empty() ? "fenrir" : syslogIdent;
    excludeStrings_ = excludeStrings;
    debugMode_ = debugMode;

    if (logToFile_) {
        logFilePath_ = logFilePattern;
        try {
            // Используем Utils::
            logFilePath_ = Utils::replaceAll(logFilePath_, "{HOSTNAME}", Utils::getHostname());
            logFilePath_ = Utils::replaceAll(logFilePath_, "{DATE}", Utils::getCurrentDate());
        } catch (const std::exception& e) {
             std::cerr << "ERROR: Failed to create log file path from pattern '" << logFilePattern << "': " << e.what() << std::endl;
             logToFile_ = false;
        }

        if (logToFile_) {
             logFileStream_.open(logFilePath_, std::ios::app);
             if (!logFileStream_.is_open()) {
                 std::cerr << "ERROR: Failed to open log file: " << logFilePath_ << std::endl;
                 logToFile_ = false;
             } else {
                  info("Logging to file: " + logFilePath_);
             }
        }
    }

    if (logToSyslog_) {
        openlog(syslogIdent_.c_str(), LOG_PID | LOG_CONS, syslogFacility_);
        info("Logging to syslog with facility " + std::to_string(syslogFacility_) + " and ident " + syslogIdent_);
    }

    configured_ = true;
}

void Logger::log(LogLevel level, const std::string& message) {
     if (!configured_) {
          std::cerr << "Logger not configured. Message lost: [" << static_cast<int>(level) << "] " << message << std::endl;
          return;
     }
    processLog(level, message);
}

void Logger::processLog(LogLevel level, const std::string& raw_message) {
    if (level == LogLevel::DEBUG && !debugMode_) {
        return;
    }

    for (const auto& exclude : excludeStrings_) {
        // Используем Utils::
        if (!exclude.empty() && Utils::contains(raw_message, exclude)) {
            return;
        }
    }

    // Используем Utils::
    std::string message = Utils::replaceAll(raw_message, "\n", " ");
    message = Utils::replaceAll(message, "\r", "");

    std::lock_guard<std::mutex> lock(logMutex_);

    if (logToCmdLine_) {
        std::cerr << "[" << logLevelToString(level) << "] " << message << std::endl;
    }

    if (logToFile_ && logFileStream_.is_open()) {
        // Используем Utils::
        logFileStream_ << Utils::getCurrentTimestamp() << " " << logLevelToString(level) << " " << message << std::endl;
    }

    if (logToSyslog_) {
        syslog(mapLogLevelToSyslog(level), "%s", message.c_str());
    }
}


// --- Convenience Methods ---
void Logger::debug(const std::string& message) { log(LogLevel::DEBUG, message); }
void Logger::info(const std::string& message) { log(LogLevel::INFO, message); }
void Logger::notice(const std::string& message) { log(LogLevel::NOTICE, message); }
void Logger::warning(const std::string& message) { log(LogLevel::WARNING, message); }
void Logger::error(const std::string& message) { log(LogLevel::ERROR, message); }
void Logger::critical(const std::string& message) { log(LogLevel::CRITICAL, message); }

// --- Private Helper Methods ---

int Logger::mapLogLevelToSyslog(LogLevel level) const {
    switch (level) {
        case LogLevel::DEBUG:     return LOG_DEBUG;
        case LogLevel::INFO:      return LOG_INFO;
        case LogLevel::NOTICE:    return LOG_NOTICE;
        case LogLevel::WARNING:   return LOG_WARNING;
        case LogLevel::ERROR:     return LOG_ERR;
        case LogLevel::CRITICAL:  return LOG_CRIT;
        case LogLevel::ALERT:     return LOG_ALERT;
        case LogLevel::EMERGENCY: return LOG_EMERG;
        default:                  return LOG_INFO;
    }
}

const char* Logger::logLevelToString(LogLevel level) const {
     switch (level) {
        case LogLevel::DEBUG:     return "DEBUG";
        case LogLevel::INFO:      return "INFO";
        case LogLevel::NOTICE:    return "NOTICE";
        case LogLevel::WARNING:   return "WARN";
        case LogLevel::ERROR:     return "ERROR";
        case LogLevel::CRITICAL:  return "CRIT";
        case LogLevel::ALERT:     return "ALERT";
        case LogLevel::EMERGENCY: return "EMERG";
        default:                  return "UNKNOWN";
    }
}
