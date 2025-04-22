#ifndef LOGGER_H
#define LOGGER_H

#include "utils.h" // For LogLevel
#include <string>
#include <fstream>
#include <vector>
#include <mutex>    // For potential future thread safety
#include <syslog.h> // <<< ДОБАВЛЕНО для LOG_LOCAL4 и других констант syslog

class Logger {
public:
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    Logger();
    ~Logger();

    void configure(bool logToFile, bool logToSyslog, bool logToCmdLine,
                   const std::string& logFilePattern, int syslogFacility,
                   const std::string& syslogIdent,
                   const std::vector<std::string>& excludeStrings,
                   bool debugMode);

    void log(LogLevel level, const std::string& message);

    void debug(const std::string& message);
    void info(const std::string& message);
    void notice(const std::string& message);
    void warning(const std::string& message);
    void error(const std::string& message);
    void critical(const std::string& message);


private:
    void processLog(LogLevel level, const std::string& message);

    bool configured_ = false;
    bool logToFile_ = false;
    bool logToSyslog_ = false;
    bool logToCmdLine_ = true;
    bool debugMode_ = false;
    std::string logFilePath_;
    std::ofstream logFileStream_;
    int syslogFacility_ = LOG_LOCAL4; // Теперь константа видна
    std::string syslogIdent_ = "fenrir";
    std::vector<std::string> excludeStrings_;
    std::mutex logMutex_;

    int mapLogLevelToSyslog(LogLevel level) const;
    const char* logLevelToString(LogLevel level) const;
};

#endif // LOGGER_H
