#include "utils.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <unistd.h>
#include <sys/utsname.h>
#include <fstream>
#include <vector>
#include <string>
#include <cstring> // Для strerror

#include <cstdio>
#include <array>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace Utils {

// --- Реализации функций работы со строками (нужны раньше getIPAddresses) ---

std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\n\r\f\v");
    if (std::string::npos == first) {
        return str;
    }
    size_t last = str.find_last_not_of(" \t\n\r\f\v");
    return str.substr(first, (last - first + 1));
}

std::vector<std::string> split(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(trim(token)); // Используем trim, который уже определен
    }
    if (!s.empty() && s.back() == delimiter) {
         tokens.push_back("");
    }
    return tokens;
}

std::string toLower(const std::string& str) {
    std::string lower_str = str;
    std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return lower_str;
}

std::string replaceAll(std::string str, const std::string& from, const std::string& to) {
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length();
    }
    return str;
}

bool startsWith(const std::string& str, const std::string& prefix) {
     return str.rfind(prefix, 0) == 0;
}

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

bool stringToBool(const std::string& str) {
    std::string lower_str = toLower(trim(str)); // Используем toLower и trim
    return (lower_str == "true" || lower_str == "1" || lower_str == "yes" || lower_str == "on");
}


// --- Реализации функций времени и системы ---

std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_c), "%Y-%m-%d_%H:%M:%S");
    return ss.str();
}

std::string getCurrentDate() {
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_c), "%Y%m%d");
    return ss.str();
}

std::string getHostname() {
    std::array<char, 256> hostname_buf;
    if (gethostname(hostname_buf.data(), hostname_buf.size()) == 0) {
        hostname_buf[hostname_buf.size() - 1] = '\0';
        return std::string(hostname_buf.data());
    }
    return "unknown_host";
}

// Теперь startsWith доступна здесь
std::vector<std::string> getIPAddresses() {
    std::vector<std::string> ips;
    struct ifaddrs *ifaddr, *ifa;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return ips;
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;

        int family = ifa->ifa_addr->sa_family;

        if (family == AF_INET || family == AF_INET6) {
            int s = getnameinfo(ifa->ifa_addr,
                                (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                                host, NI_MAXHOST,
                                nullptr, 0, NI_NUMERICHOST);
            if (s != 0) {
                continue;
            }

            std::string ip_str(host);
            // Используем startsWith, который теперь определен выше
            if (ip_str != "127.0.0.1" && ip_str != "::1" && !startsWith(ip_str, "fe80::")) {
                 ips.push_back(ip_str);
            }
        }
    }

    freeifaddrs(ifaddr);
    std::sort(ips.begin(), ips.end());
    ips.erase(std::unique(ips.begin(), ips.end()), ips.end());
    return ips;
}


std::string getOsRelease() {
    std::ifstream file("/etc/os-release");
    std::string line;
    std::stringstream ss;
    bool first = true;
    if (file.is_open()) {
        while (getline(file, line)) {
            line = trim(line); // Используем trim
            if (!line.empty() && line.find('=') != std::string::npos) {
                if (!first) ss << "; ";
                ss << line;
                first = false;
            }
        }
        file.close();
        if (!first) return ss.str();
    }

    std::ifstream issue_file("/etc/issue");
     if (issue_file.is_open()) {
         getline(issue_file, line);
         issue_file.close();
         line = trim(line); // Используем trim
         size_t last_char = line.find_last_not_of(" \\nl");
         if (last_char != std::string::npos) {
             line = line.substr(0, last_char + 1);
         }
         if (!line.empty()) {
             return line;
         }
     }

    return "Unknown OS";
}

std::string getKernelVersion() {
    struct utsname buffer;
    if (uname(&buffer) == 0) {
        std::stringstream ss;
        ss << buffer.sysname << " " << buffer.release << " " << buffer.version << " " << buffer.machine;
        return ss.str();
    }
    return "Unknown Kernel";
}

// --- Реализации функций для работы с файлами ---

long long getFileModTimeEpoch(const std::filesystem::path& file_path, std::error_code& ec) {
    try {
        auto ftime = std::filesystem::last_write_time(file_path, ec);
        if (ec) {
            return 0;
        }
        auto sctp = std::chrono::time_point_cast<std::chrono::seconds>(ftime);
        return sctp.time_since_epoch().count();
    } catch (const std::filesystem::filesystem_error& e) {
        ec = e.code();
        return 0;
    } catch (...) {
        ec = std::make_error_code(std::errc::invalid_argument);
        return 0;
    }
}


} // namespace Utils
