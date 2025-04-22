#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>
#include <chrono>
#include <filesystem> // Requires C++17
#include <system_error> // Для std::error_code в getFileModTimeEpoch

// Log levels matching syslog priorities for simplicity
enum class LogLevel {
    DEBUG = 7,
    INFO = 6,
    NOTICE = 5,
    WARNING = 4,
    ERROR = 3,
    CRITICAL = 2,
    ALERT = 1,
    EMERGENCY = 0
};

// Объявляем все функции внутри namespace
namespace Utils {

// Функции для времени и системы
std::string getCurrentTimestamp();
std::string getCurrentDate();
std::string getHostname();
std::vector<std::string> getIPAddresses();
std::string getOsRelease();
std::string getKernelVersion();

// Функции для работы со строками
std::string trim(const std::string& str);
std::vector<std::string> split(const std::string& s, char delimiter);
std::string toLower(const std::string& str);
std::string replaceAll(std::string str, const std::string& from, const std::string& to);
bool startsWith(const std::string& str, const std::string& prefix);
bool contains(const std::string& haystack, const std::string& needle);
bool stringToBool(const std::string& str);

// Функции для работы с файлами
long long getFileModTimeEpoch(const std::filesystem::path& file_path, std::error_code& ec);

} // namespace Utils

#endif // UTILS_H
